"""PromptStore — the runtime resolver for active prompt templates (M9).

The engine never reads a prompt from a file. It calls
``PromptStore.get_active(task_type, target_model, target_provider)`` which
returns the most specific currently-active row from ``prompt_templates``.

Resolution order (most specific first):

  1. exact ``target_model`` AND exact ``target_provider``
  2. exact ``target_model`` AND wildcard provider (``'*'``)
  3. wildcard model (``'*'``) AND exact provider
  4. wildcard model AND wildcard provider

The first hit wins. This mirrors how the connector / provider plug-in system
prefers explicit configuration over fallbacks.

The active set is cached in memory because the resolver is on every chain /
rule synthesis hot path. ``invalidate()`` flushes the cache; every endpoint
that mutates the table (activate / patch / create) calls it before
responding so the next call sees fresh state. The cache is per-process —
multiple API workers will each rebuild it lazily after a flip, which is fine
because a stale lookup just routes to the previous active prompt for at most
one request.
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.db.models import PromptTemplate

logger = structlog.get_logger(__name__)

WILDCARD = "*"


@dataclass(frozen=True)
class PromptTemplateView:
    """Immutable snapshot of a prompt row used by callers + the cache.

    Returned by ``get_active`` instead of the ORM row so callers can't
    accidentally mutate cached state. Fields mirror the DB row 1:1.
    """

    id: uuid.UUID
    name: str
    task_type: str
    target_model: str
    target_provider: str
    version: int
    system_prompt: str
    user_template: str
    is_active: bool
    notes: str | None = None

    @classmethod
    def from_row(cls, row: PromptTemplate) -> "PromptTemplateView":
        return cls(
            id=row.id,
            name=row.name,
            task_type=row.task_type,
            target_model=row.target_model,
            target_provider=row.target_provider,
            version=int(row.version),
            system_prompt=row.system_prompt or "",
            user_template=row.user_template or "",
            is_active=bool(row.is_active),
            notes=row.notes,
        )


# ---------------------------------------------------------------------------
# In-memory cache
# ---------------------------------------------------------------------------


class _ActiveCache:
    """Process-local cache of ``(name, target_model, target_provider) -> view``.

    Built lazily on first miss. ``invalidate()`` drops everything; the next
    call refills with fresh DB state. Thread-safe so the FastAPI worker pool
    doesn't race with the seed script running in the same process.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loaded: bool = False
        # keyed by (task_type, target_model, target_provider) — only
        # is_active=True rows. The engine resolves prompts by task_type, so a
        # cloned-and-renamed template (name != task_type) must still resolve.
        self._by_key: dict[tuple[str, str, str], PromptTemplateView] = {}

    def is_loaded(self) -> bool:
        return self._loaded

    def get(
        self, task_type: str, target_model: str, target_provider: str
    ) -> PromptTemplateView | None:
        with self._lock:
            return self._by_key.get((task_type, target_model, target_provider))

    def fill(self, rows: list[PromptTemplate]) -> None:
        snapshot: dict[tuple[str, str, str], PromptTemplateView] = {}
        for row in rows:
            if not row.is_active:
                continue
            key = (row.task_type, row.target_model, row.target_provider)
            snapshot[key] = PromptTemplateView.from_row(row)
        with self._lock:
            self._by_key = snapshot
            self._loaded = True

    def invalidate(self) -> None:
        with self._lock:
            self._by_key = {}
            self._loaded = False


_cache = _ActiveCache()


def _global_cache() -> _ActiveCache:
    return _cache


# ---------------------------------------------------------------------------
# PromptStore
# ---------------------------------------------------------------------------


class PromptStore:
    """Async accessor for prompt templates.

    Constructed per request / per task with an ``AsyncSession``. The cache
    layer is process-global so a worker pool shares a single warmed cache.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # -- read paths ------------------------------------------------------

    async def get_active(
        self,
        task_type: str,
        target_model: str,
        target_provider: str = "litellm",
    ) -> PromptTemplateView | None:
        """Return the most specific active template for ``(task, model, provider)``.

        Lookup hierarchy: exact → wildcard provider → wildcard model →
        wildcard both. ``task_type`` is the canonical name (``chain_generation``
        / ``rule_generation`` / ``coverage_verify``) — it doubles as
        ``name`` for the seeded defaults.
        """
        cache = _global_cache()
        if not cache.is_loaded():
            await self._reload_cache()

        for model_key, provider_key in (
            (target_model, target_provider),
            (target_model, WILDCARD),
            (WILDCARD, target_provider),
            (WILDCARD, WILDCARD),
        ):
            hit = cache.get(task_type, model_key, provider_key)
            if hit is not None:
                return hit
        return None

    async def get(self, template_id: uuid.UUID) -> PromptTemplateView | None:
        row = await self._session.get(PromptTemplate, template_id)
        if row is None:
            return None
        return PromptTemplateView.from_row(row)

    async def list(
        self,
        *,
        task_type: str | None = None,
        target_model: str | None = None,
        target_provider: str | None = None,
        active_only: bool = False,
    ) -> list[PromptTemplateView]:
        stmt = select(PromptTemplate)
        if task_type is not None:
            stmt = stmt.where(PromptTemplate.task_type == task_type)
        if target_model is not None:
            stmt = stmt.where(PromptTemplate.target_model == target_model)
        if target_provider is not None:
            stmt = stmt.where(PromptTemplate.target_provider == target_provider)
        if active_only:
            stmt = stmt.where(PromptTemplate.is_active.is_(True))
        stmt = stmt.order_by(
            PromptTemplate.name,
            PromptTemplate.target_model,
            PromptTemplate.target_provider,
            PromptTemplate.version.desc(),
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [PromptTemplateView.from_row(r) for r in rows]

    # -- write paths -----------------------------------------------------

    async def create_version(
        self,
        *,
        name: str,
        task_type: str,
        system_prompt: str,
        user_template: str,
        target_model: str = WILDCARD,
        target_provider: str = WILDCARD,
        created_by: str | None = None,
        notes: str | None = None,
        activate: bool = False,
    ) -> PromptTemplateView:
        """Insert a new version row.

        Version number = (max existing for the same ``name + target_model +
        target_provider``) + 1, computed inside the call so the API never
        has to pick a version.
        """
        max_stmt = select(PromptTemplate.version).where(
            PromptTemplate.name == name,
            PromptTemplate.target_model == target_model,
            PromptTemplate.target_provider == target_provider,
        ).order_by(PromptTemplate.version.desc()).limit(1)
        max_existing = (await self._session.execute(max_stmt)).scalar_one_or_none()
        next_version = int(max_existing or 0) + 1

        row = PromptTemplate(
            name=name,
            task_type=task_type,
            target_model=target_model,
            target_provider=target_provider,
            version=next_version,
            system_prompt=system_prompt,
            user_template=user_template,
            is_active=False,
            created_by=created_by,
            notes=notes,
        )
        self._session.add(row)
        await self._session.flush()

        if activate:
            await self._activate(row)

        await self._session.commit()
        _global_cache().invalidate()
        logger.info(
            "prompt.template.created",
            id=str(row.id),
            name=name,
            version=next_version,
            target_model=target_model,
            target_provider=target_provider,
            activated=activate,
        )
        return PromptTemplateView.from_row(row)

    async def patch_as_new_version(
        self,
        template_id: uuid.UUID,
        *,
        system_prompt: str | None = None,
        user_template: str | None = None,
        notes: str | None = None,
        created_by: str | None = None,
        activate: bool = False,
    ) -> PromptTemplateView:
        """Create a NEW version derived from ``template_id``. Never mutates the source.

        ``system_prompt`` / ``user_template`` default to the source row's
        values when not provided. ``activate`` flips the new row active and
        deactivates whatever is currently active for the same key.
        """
        source = await self._session.get(PromptTemplate, template_id)
        if source is None:
            raise PromptNotFoundError(template_id)
        return await self.create_version(
            name=source.name,
            task_type=source.task_type,
            target_model=source.target_model,
            target_provider=source.target_provider,
            system_prompt=system_prompt if system_prompt is not None else source.system_prompt,
            user_template=user_template if user_template is not None else source.user_template,
            created_by=created_by,
            notes=notes if notes is not None else source.notes,
            activate=activate,
        )

    async def activate(self, template_id: uuid.UUID) -> PromptTemplateView:
        """Make ``template_id`` active for its (name, target_model, target_provider).

        Deactivates any other active row matching that key in the same
        transaction so the partial unique index never sees two actives.
        """
        row = await self._session.get(PromptTemplate, template_id)
        if row is None:
            raise PromptNotFoundError(template_id)
        await self._activate(row)
        await self._session.commit()
        _global_cache().invalidate()
        logger.info(
            "prompt.template.activated",
            id=str(row.id),
            name=row.name,
            version=row.version,
            target_model=row.target_model,
            target_provider=row.target_provider,
        )
        return PromptTemplateView.from_row(row)

    async def _activate(self, row: PromptTemplate) -> None:
        # Deactivate every currently-active row for the same key, then flip
        # the target on. Done in a single transaction (committed by the
        # caller) so the partial-unique index never sees two actives.
        await self._session.execute(
            update(PromptTemplate)
            .where(
                PromptTemplate.task_type == row.task_type,
                PromptTemplate.target_model == row.target_model,
                PromptTemplate.target_provider == row.target_provider,
                PromptTemplate.id != row.id,
                PromptTemplate.is_active.is_(True),
            )
            .values(is_active=False)
        )
        row.is_active = True
        await self._session.flush()

    # -- diff -----------------------------------------------------------

    async def diff(
        self, a_id: uuid.UUID, b_id: uuid.UUID
    ) -> dict[str, Any]:
        """Compute a unified-diff between two templates.

        Returns the system/user diffs as lists of unified-diff lines plus
        the raw before/after for clients that want to render their own diff.
        """
        a = await self._session.get(PromptTemplate, a_id)
        b = await self._session.get(PromptTemplate, b_id)
        if a is None:
            raise PromptNotFoundError(a_id)
        if b is None:
            raise PromptNotFoundError(b_id)
        return {
            "a": {
                "id": str(a.id),
                "name": a.name,
                "version": a.version,
                "target_model": a.target_model,
                "target_provider": a.target_provider,
                "system_prompt": a.system_prompt or "",
                "user_template": a.user_template or "",
            },
            "b": {
                "id": str(b.id),
                "name": b.name,
                "version": b.version,
                "target_model": b.target_model,
                "target_provider": b.target_provider,
                "system_prompt": b.system_prompt or "",
                "user_template": b.user_template or "",
            },
            "system_prompt_diff": _unified_diff_lines(
                a.system_prompt or "",
                b.system_prompt or "",
                f"a/system_prompt@v{a.version}",
                f"b/system_prompt@v{b.version}",
            ),
            "user_template_diff": _unified_diff_lines(
                a.user_template or "",
                b.user_template or "",
                f"a/user_template@v{a.version}",
                f"b/user_template@v{b.version}",
            ),
        }

    # -- cache plumbing --------------------------------------------------

    async def _reload_cache(self) -> None:
        stmt = select(PromptTemplate).where(PromptTemplate.is_active.is_(True))
        rows = (await self._session.execute(stmt)).scalars().all()
        _global_cache().fill(list(rows))

    @staticmethod
    def invalidate_cache() -> None:
        """Drop the global active-prompt cache. Safe to call from anywhere."""
        _global_cache().invalidate()


class PromptNotFoundError(Exception):
    """Raised when a template id doesn't exist in the DB."""

    def __init__(self, template_id: uuid.UUID) -> None:
        super().__init__(f"prompt template {template_id} not found")
        self.template_id = template_id


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _unified_diff_lines(a: str, b: str, a_label: str, b_label: str) -> list[str]:
    import difflib

    return list(
        difflib.unified_diff(
            a.splitlines(keepends=False),
            b.splitlines(keepends=False),
            fromfile=a_label,
            tofile=b_label,
            lineterm="",
        )
    )


__all__ = [
    "PromptStore",
    "PromptTemplateView",
    "PromptNotFoundError",
    "WILDCARD",
]
