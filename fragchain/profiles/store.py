"""Logsource profile store (M13).

A profile encodes everything M15's rule generator needs to know about a
specific detection environment:

* ``sigma_product`` / ``sigma_service`` — the literal values written into
  a Sigma rule's ``logsource`` block.
* ``field_conventions`` — names + types of the fields a rule writer will
  reach for (e.g. ``Image``, ``CommandLine`` on Sysmon; ``a0``, ``exe``
  on auditd). Stored as a JSON dict so the prompt can quote the names
  verbatim.
* ``example_rules`` — two or three hand-crafted Sigma documents to use
  as few-shot prompt context. Each entry is ``{"title", "yaml",
  "explanation"}``.

This module wraps the ORM with read helpers (``get``, ``get_enabled``)
and one writer (``upsert_builtin``) used by ``scripts/seed_profiles.py``
to install + refresh the built-ins idempotently. ``build_prompt_context``
shapes a profile into the dict the rule-generator prompt expects.

API mutation (create custom, enable / disable, etc.) is owned by
``fragchain.api.routers.profiles`` — keeping the store purely about
storage + serialization keeps the test surface small.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.db.models import LogsourceProfile

logger = structlog.get_logger(__name__)


VALID_PLATFORMS: frozenset[str] = frozenset(
    {"linux", "windows", "network", "cloud"}
)


class ProfileNotFoundError(LookupError):
    """Raised by :meth:`ProfileStore.get` when the profile doesn't exist."""


class BuiltinProfileImmutableError(PermissionError):
    """Raised when an API caller tries to PATCH an is_builtin=true profile."""


@dataclass(frozen=True)
class ProfileView:
    """Read-only snapshot of a profile row.

    Stable shape for callers (router, store, rule generator). Built off
    the ORM row so the rest of the codebase doesn't hold sessions open
    just to read field names.
    """

    id: uuid.UUID
    name: str
    display_name: str
    description: str | None
    platform: str
    sigma_product: str | None
    sigma_service: str | None
    field_conventions: dict[str, Any] = field(default_factory=dict)
    example_rules: list[Any] = field(default_factory=list)
    enabled: bool = True
    is_builtin: bool = False

    @classmethod
    def from_row(cls, row: LogsourceProfile) -> "ProfileView":
        return cls(
            id=row.id,
            name=row.name,
            display_name=row.display_name,
            description=row.description,
            platform=row.platform,
            sigma_product=row.sigma_product,
            sigma_service=row.sigma_service,
            field_conventions=dict(row.field_conventions or {}),
            example_rules=list(row.example_rules or []),
            enabled=bool(row.enabled),
            is_builtin=bool(row.is_builtin),
        )


class ProfileStore:
    """Thin async wrapper around the ``logsource_profiles`` table."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def list_all(self) -> list[ProfileView]:
        """Return every profile, ordered by platform then name."""
        rows = (
            (
                await self.session.execute(
                    select(LogsourceProfile).order_by(
                        LogsourceProfile.platform,
                        LogsourceProfile.name,
                    )
                )
            )
            .scalars()
            .all()
        )
        return [ProfileView.from_row(r) for r in rows]

    async def get_enabled(self) -> list[ProfileView]:
        """Return all enabled profiles. M15 consumes this list."""
        rows = (
            (
                await self.session.execute(
                    select(LogsourceProfile)
                    .where(LogsourceProfile.enabled.is_(True))
                    .order_by(
                        LogsourceProfile.platform,
                        LogsourceProfile.name,
                    )
                )
            )
            .scalars()
            .all()
        )
        return [ProfileView.from_row(r) for r in rows]

    async def get(self, name_or_id: str | uuid.UUID) -> ProfileView:
        """Return one profile by name (preferred) or UUID.

        Raises :class:`ProfileNotFoundError` if missing.
        """
        row = await self._get_row(name_or_id)
        if row is None:
            raise ProfileNotFoundError(f"profile {name_or_id!r} not found")
        return ProfileView.from_row(row)

    async def _get_row(
        self, name_or_id: str | uuid.UUID
    ) -> LogsourceProfile | None:
        if isinstance(name_or_id, uuid.UUID):
            return await self.session.get(LogsourceProfile, name_or_id)
        if isinstance(name_or_id, str):
            try:
                as_uuid = uuid.UUID(name_or_id)
            except ValueError:
                as_uuid = None
            if as_uuid is not None:
                row = await self.session.get(LogsourceProfile, as_uuid)
                if row is not None:
                    return row
            stmt = select(LogsourceProfile).where(
                LogsourceProfile.name == name_or_id
            )
            return (await self.session.execute(stmt)).scalar_one_or_none()
        return None

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    async def create_custom(
        self,
        *,
        name: str,
        display_name: str,
        platform: str,
        description: str | None = None,
        sigma_product: str | None = None,
        sigma_service: str | None = None,
        field_conventions: dict[str, Any] | None = None,
        example_rules: list[Any] | None = None,
        enabled: bool = True,
    ) -> ProfileView:
        """Insert a new operator-defined profile (``is_builtin=false``).

        The session is left dirty (no commit). Callers control the
        transaction boundary.
        """
        _validate_platform(platform)
        row = LogsourceProfile(
            name=name,
            display_name=display_name,
            description=description,
            platform=platform,
            sigma_product=sigma_product,
            sigma_service=sigma_service,
            field_conventions=field_conventions or {},
            example_rules=example_rules or [],
            enabled=enabled,
            is_builtin=False,
        )
        self.session.add(row)
        await self.session.flush()
        await self.session.refresh(row)
        logger.info(
            "profile.created",
            name=name,
            platform=platform,
            is_builtin=False,
        )
        return ProfileView.from_row(row)

    async def update_custom(
        self,
        name_or_id: str | uuid.UUID,
        *,
        display_name: str | None = None,
        description: str | None = None,
        platform: str | None = None,
        sigma_product: str | None = None,
        sigma_service: str | None = None,
        field_conventions: dict[str, Any] | None = None,
        example_rules: list[Any] | None = None,
        enabled: bool | None = None,
    ) -> ProfileView:
        """Patch a non-builtin profile.

        Raises :class:`BuiltinProfileImmutableError` if the row is
        ``is_builtin=true`` — only ``set_enabled`` may flip a built-in's
        enabled flag.
        """
        row = await self._get_row(name_or_id)
        if row is None:
            raise ProfileNotFoundError(f"profile {name_or_id!r} not found")
        if row.is_builtin:
            raise BuiltinProfileImmutableError(
                f"profile {row.name!r} is built-in and cannot be patched"
            )
        if platform is not None:
            _validate_platform(platform)
            row.platform = platform
        if display_name is not None:
            row.display_name = display_name
        if description is not None:
            row.description = description
        if sigma_product is not None:
            row.sigma_product = sigma_product
        if sigma_service is not None:
            row.sigma_service = sigma_service
        if field_conventions is not None:
            row.field_conventions = dict(field_conventions)
        if example_rules is not None:
            row.example_rules = list(example_rules)
        if enabled is not None:
            row.enabled = bool(enabled)
        await self.session.flush()
        await self.session.refresh(row)
        logger.info("profile.updated", name=row.name, profile_id=str(row.id))
        return ProfileView.from_row(row)

    async def set_enabled(
        self, name_or_id: str | uuid.UUID, *, enabled: bool
    ) -> ProfileView:
        """Flip the enabled flag. Works on built-in and custom rows.

        Built-in rows always have ``is_builtin=true``; this is the only
        mutation allowed on them via the API surface.
        """
        row = await self._get_row(name_or_id)
        if row is None:
            raise ProfileNotFoundError(f"profile {name_or_id!r} not found")
        if row.enabled == enabled:
            return ProfileView.from_row(row)
        row.enabled = bool(enabled)
        await self.session.flush()
        await self.session.refresh(row)
        logger.info(
            "profile.enabled" if enabled else "profile.disabled",
            name=row.name,
            profile_id=str(row.id),
        )
        return ProfileView.from_row(row)

    async def delete_custom(self, name_or_id: str | uuid.UUID) -> None:
        """Remove a non-builtin row. Built-in rows return 400 elsewhere."""
        row = await self._get_row(name_or_id)
        if row is None:
            raise ProfileNotFoundError(f"profile {name_or_id!r} not found")
        if row.is_builtin:
            raise BuiltinProfileImmutableError(
                f"profile {row.name!r} is built-in and cannot be deleted"
            )
        await self.session.delete(row)
        await self.session.flush()
        logger.info("profile.deleted", name=row.name, profile_id=str(row.id))

    # ------------------------------------------------------------------
    # Seed helper — used by scripts/seed_profiles.py
    # ------------------------------------------------------------------

    async def upsert_builtin(
        self,
        *,
        name: str,
        display_name: str,
        platform: str,
        description: str | None,
        sigma_product: str | None,
        sigma_service: str | None,
        field_conventions: dict[str, Any],
        example_rules: list[Any],
        default_enabled: bool,
    ) -> tuple[str, ProfileView]:
        """Insert or refresh one built-in profile idempotently.

        Returns ``(state, view)`` where ``state`` is one of:

        * ``"created"`` — row did not exist; inserted with the supplied
          ``default_enabled`` value.
        * ``"updated"`` — row existed and the body fields changed.
        * ``"unchanged"`` — row existed and the body matched. Never
          flips ``enabled`` on a re-seed: operator preference wins.

        The seed helper never alters the ``enabled`` flag on an
        existing row. Operators may have intentionally disabled
        ``windows-security`` (or enabled ``network-zeek``); re-running
        the seed must not stomp those decisions.
        """
        _validate_platform(platform)
        stmt = select(LogsourceProfile).where(LogsourceProfile.name == name)
        row = (await self.session.execute(stmt)).scalar_one_or_none()
        if row is None:
            row = LogsourceProfile(
                name=name,
                display_name=display_name,
                description=description,
                platform=platform,
                sigma_product=sigma_product,
                sigma_service=sigma_service,
                field_conventions=field_conventions,
                example_rules=example_rules,
                enabled=default_enabled,
                is_builtin=True,
            )
            self.session.add(row)
            await self.session.flush()
            await self.session.refresh(row)
            return ("created", ProfileView.from_row(row))

        changed = False
        if row.display_name != display_name:
            row.display_name = display_name
            changed = True
        if row.description != description:
            row.description = description
            changed = True
        if row.platform != platform:
            row.platform = platform
            changed = True
        if row.sigma_product != sigma_product:
            row.sigma_product = sigma_product
            changed = True
        if row.sigma_service != sigma_service:
            row.sigma_service = sigma_service
            changed = True
        if dict(row.field_conventions or {}) != field_conventions:
            row.field_conventions = field_conventions
            changed = True
        if list(row.example_rules or []) != example_rules:
            row.example_rules = example_rules
            changed = True
        if not row.is_builtin:
            # The row exists under the same name but was created as
            # custom. Promote it to built-in so the seed contract holds.
            row.is_builtin = True
            changed = True
        if changed:
            await self.session.flush()
            await self.session.refresh(row)
            return ("updated", ProfileView.from_row(row))
        return ("unchanged", ProfileView.from_row(row))

    # ------------------------------------------------------------------
    # Prompt context — consumed by M15
    # ------------------------------------------------------------------

    @staticmethod
    def build_prompt_context(profile: ProfileView) -> dict[str, Any]:
        """Shape a profile into the dict M15's prompt expects.

        Returns a dict with stable keys so the prompt template can
        reference each one by name:

        * ``name`` / ``display_name`` / ``platform`` — labels.
        * ``logsource`` — ``{"product", "service"}`` block ready to
          drop into a Sigma YAML body.
        * ``field_conventions`` — verbatim mapping passed to the LLM
          ("use these field names, do not invent others").
        * ``example_rules`` — list of ``{"title", "yaml", "explanation"}``
          for few-shot prompting. Always a list (empty if none).

        Keeping the shape here (not in the prompt module) means
        regression tests can compare a built-in's prompt context
        without spinning up Postgres.
        """
        return {
            "name": profile.name,
            "display_name": profile.display_name,
            "platform": profile.platform,
            "logsource": {
                "product": profile.sigma_product,
                "service": profile.sigma_service,
            },
            "field_conventions": dict(profile.field_conventions),
            "example_rules": list(profile.example_rules),
        }


def _validate_platform(platform: str) -> None:
    if platform not in VALID_PLATFORMS:
        raise ValueError(
            f"platform must be one of {sorted(VALID_PLATFORMS)}, got {platform!r}"
        )


__all__ = [
    "BuiltinProfileImmutableError",
    "ProfileNotFoundError",
    "ProfileStore",
    "ProfileView",
    "VALID_PLATFORMS",
]
