"""Sigma source repo management.

Read-side of M12: clone or update each configured Sigma source repo, walk
the rule tree, parse the YAML, and upsert one ``sigma_rules`` row per
rule. New / changed rules are queued for embedding via the M8 task
``embed_sigma_rule`` so the semantic-search coverage phase (M14) can pick
them up.

Local checkouts live under ``data/sigma-repos/{source_id}/``. The path is
overridable via ``Settings.SIGMA_REPOS_DIR`` for tests / non-default
deployments.

Authentication: token-only for HTTPS clones. ``auth_credentials_ref`` is
either an env var name (preferred) or the literal token; the resolver
walks env first so secrets never live in the DB. If the resolved token is
non-empty, it's injected into the URL as ``https://<token>@host/...`` for
the duration of the clone/pull. The DB-stored URL stays clean.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.config import get_settings
from fragchain.db.models import SigmaRule, SigmaSource
from fragchain.sigma.parser import ParsedSigmaRule, parse_sigma_yaml

logger = structlog.get_logger(__name__)


VALID_AUTH_TYPES = {"none", "token"}


@dataclass
class RuleFilePass:
    parsed: int = 0
    skipped: int = 0
    errors: int = 0


@dataclass
class SourceRefreshResult:
    source_id: str
    source_name: str
    status: str  # 'ok' | 'error' | 'disabled' | 'skipped'
    head_commit: str | None = None
    rules_parsed: int = 0
    rules_inserted: int = 0
    rules_updated: int = 0
    rules_unchanged: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    message: str = ""
    embed_queued: list[str] = field(default_factory=list)


@dataclass
class RefreshAllResult:
    total_sources: int = 0
    successes: int = 0
    failures: int = 0
    per_source: list[SourceRefreshResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Auth token resolution
# ---------------------------------------------------------------------------


def _resolve_token(ref: str | None) -> str | None:
    """Resolve ``auth_credentials_ref`` to a real token.

    Preferred form is an env var name (``SIGMAHQ_TOKEN``). If the env var
    doesn't exist, the value is treated as a literal token. ``None`` /
    empty returns ``None`` (no auth).
    """
    if not ref:
        return None
    val = os.environ.get(ref)
    if val is not None and val.strip():
        return val.strip()
    return ref.strip() or None


_HTTPS_URL_RE = re.compile(r"^(https?://)(.+)$")


def _inject_token(url: str, token: str | None) -> str:
    """Embed the token in an HTTPS clone URL.

    ``https://x-access-token:<token>@host/...`` works for both GitHub PATs
    and GitHub App installation tokens; GitLab accepts the same shape.
    """
    if not token:
        return url
    m = _HTTPS_URL_RE.match(url)
    if not m:
        return url
    scheme, rest = m.group(1), m.group(2)
    # Strip any pre-existing auth segment
    if "@" in rest.split("/", 1)[0]:
        rest = rest.split("@", 1)[1]
    return f"{scheme}x-access-token:{token}@{rest}"


# ---------------------------------------------------------------------------
# Local checkout management (gitpython)
# ---------------------------------------------------------------------------


def _repos_root() -> Path:
    settings = get_settings()
    root = getattr(settings, "SIGMA_REPOS_DIR", None) or "data/sigma-repos"
    return Path(root).expanduser().resolve()


def _checkout_dir(source_id: uuid.UUID) -> Path:
    return _repos_root() / str(source_id)


def _sync_repo(
    *,
    checkout: Path,
    git_url: str,
    branch: str,
    token: str | None,
) -> str:
    """Clone or fast-forward the local checkout. Returns the HEAD SHA.

    Runs synchronously (gitpython is sync) — the orchestrator wraps the
    call in ``asyncio.to_thread`` so the event loop stays free.
    """
    try:
        import git  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - gitpython is a hard dep
        raise RuntimeError(
            "gitpython not installed; add 'gitpython' to project deps"
        ) from exc

    checkout.parent.mkdir(parents=True, exist_ok=True)
    auth_url = _inject_token(git_url, token)

    if (checkout / ".git").is_dir():
        repo = git.Repo(checkout)
        try:
            # Update remote URL in case the token rotated
            origin = repo.remote("origin")
            origin.set_url(auth_url)
        except git.GitCommandError:
            pass
        try:
            origin.fetch(prune=True)
        except git.GitCommandError as exc:
            raise RuntimeError(f"fetch failed: {exc}") from exc
        # Try the configured branch; fall back to whatever the default is.
        try:
            repo.git.checkout(branch)
            repo.git.reset("--hard", f"origin/{branch}")
        except git.GitCommandError:
            try:
                head = repo.remotes.origin.refs[0].name.split("/")[-1]
                repo.git.checkout(head)
                repo.git.reset("--hard", f"origin/{head}")
            except (IndexError, git.GitCommandError) as exc:
                raise RuntimeError(f"checkout failed: {exc}") from exc
    else:
        if checkout.exists():
            shutil.rmtree(checkout, ignore_errors=True)
        try:
            git.Repo.clone_from(
                auth_url,
                str(checkout),
                branch=branch,
                depth=1,
                single_branch=True,
                # F-011 (SAST S-020): pin gitpython's safe-defaults
                # explicitly so a dependency drift can't silently
                # re-enable --upload-pack=<script> or ext::<cmd>.
                allow_unsafe_options=False,
                allow_unsafe_protocols=False,
                # F-012 (SAST S-005): hooks neutralization. ``clone``
                # itself doesn't execute hooks, but a subsequent fetch/
                # checkout will run ``post-checkout`` / ``post-merge``
                # if the cloned repo's config sets ``core.hooksPath``.
                # Pin both the hooks dir to /dev/null and the protocol
                # allowlist to ``user`` (no ``ext::``, no transports
                # with helpers) in the cloned working copy's config.
                multi_options=[
                    "-c", "core.hooksPath=/dev/null",
                    "-c", "protocol.allow=user",
                ],
            )
        except git.GitCommandError:
            # Fall back without specifying a branch (some repos have a
            # different default than ``main``).
            try:
                git.Repo.clone_from(
                    auth_url,
                    str(checkout),
                    depth=1,
                    allow_unsafe_options=False,
                    allow_unsafe_protocols=False,
                    multi_options=[
                        "-c", "core.hooksPath=/dev/null",
                        "-c", "protocol.allow=user",
                    ],
                )
            except git.GitCommandError as exc:
                raise RuntimeError(f"clone failed: {exc}") from exc

    repo = git.Repo(checkout)
    return str(repo.head.commit.hexsha)


# ---------------------------------------------------------------------------
# Rule walker + upsert
# ---------------------------------------------------------------------------


def _walk_rule_files(root: Path, path_filter: str | None) -> list[Path]:
    """Return every ``.yml`` / ``.yaml`` file under the configured subtree.

    Symlinks are followed for the top-level pointer only — we don't follow
    them inside the tree to avoid infinite loops.
    """
    base = root
    if path_filter:
        candidate = (root / path_filter).resolve()
        # Defensive: never let a malicious path_filter escape the checkout.
        try:
            candidate.relative_to(root.resolve())
            if candidate.is_dir():
                base = candidate
        except ValueError:
            base = root

    out: list[Path] = []
    for ext in ("*.yml", "*.yaml"):
        out.extend(base.rglob(ext))
    return sorted(out)


async def _upsert_rule(
    session: AsyncSession,
    parsed: ParsedSigmaRule,
    *,
    source_id: uuid.UUID,
    rel_path: str,
) -> tuple[SigmaRule, str]:
    """Upsert one ``sigma_rules`` row. Returns ``(row, change_status)``.

    ``change_status`` is one of ``'inserted'``, ``'updated'``, ``'unchanged'``.
    The lookup key is ``sigma_uuid`` when present, otherwise
    ``(source_id, source_rel_path)`` — Sigma rules without an ``id`` field
    do exist (SigmaHQ has a few) but the path is stable across pulls.
    """
    existing: SigmaRule | None = None
    if parsed.sigma_uuid is not None:
        q = await session.execute(
            select(SigmaRule).where(SigmaRule.sigma_uuid == parsed.sigma_uuid)
        )
        existing = q.scalar_one_or_none()
    if existing is None:
        q = await session.execute(
            select(SigmaRule).where(
                SigmaRule.source_id == source_id,
                SigmaRule.source_rel_path == rel_path,
            )
        )
        existing = q.scalar_one_or_none()

    if existing is None:
        row = SigmaRule(
            sigma_uuid=parsed.sigma_uuid,
            title=parsed.title,
            sigma_yaml=parsed.sigma_yaml,
            technique_ids=parsed.technique_ids or None,
            tags=parsed.tags or None,
            logsource_product=parsed.logsource_product,
            logsource_service=parsed.logsource_service,
            detection_level=parsed.detection_level,
            tlp=parsed.tlp,
            status="merged",
            origin="imported",
            source_id=source_id,
            source_rel_path=rel_path,
            content_hash=parsed.content_hash,
            merged_at=datetime.now(timezone.utc),
        )
        session.add(row)
        await session.flush()
        return row, "inserted"

    if existing.content_hash == parsed.content_hash:
        return existing, "unchanged"

    existing.title = parsed.title
    existing.sigma_yaml = parsed.sigma_yaml
    existing.technique_ids = parsed.technique_ids or None
    existing.tags = parsed.tags or None
    existing.logsource_product = parsed.logsource_product
    existing.logsource_service = parsed.logsource_service
    existing.detection_level = parsed.detection_level
    existing.tlp = parsed.tlp
    existing.source_id = source_id
    existing.source_rel_path = rel_path
    existing.content_hash = parsed.content_hash
    if existing.origin == "imported" and existing.merged_at is None:
        existing.merged_at = datetime.now(timezone.utc)
    return existing, "updated"


def _queue_embed(row: SigmaRule) -> bool:
    """Best-effort dispatch of the M8 embed task. Returns True on dispatch."""
    try:
        from fragchain.worker.celery import celery_app

        celery_app.send_task(
            "fragchain.worker.tasks.embed_sigma_rule",
            kwargs={
                "rule_id": str(row.id),
                "title": row.title,
                "technique_ids": list(row.technique_ids or []),
                "yaml_body": row.sigma_yaml,
                "sigma_uuid": str(row.sigma_uuid) if row.sigma_uuid else None,
                "status": row.status,
                "logsource_product": row.logsource_product,
                "logsource_service": row.logsource_service,
                "origin": row.origin,
            },
        )
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "sigma.embed.dispatch_failed",
            rule_id=str(row.id),
            error=str(exc),
        )
        return False


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------


class SigmaSourceClient:
    """Async wrapper around the sigma source refresh primitives.

    Construct with an :class:`AsyncSession` and call :meth:`refresh_all` or
    :meth:`refresh_one`. The client owns no state; instances are cheap and
    are typically constructed per-request / per-task.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def refresh_all(self) -> RefreshAllResult:
        rows = (
            (
                await self.session.execute(
                    select(SigmaSource).where(SigmaSource.enabled.is_(True))
                )
            )
            .scalars()
            .all()
        )
        result = RefreshAllResult(total_sources=len(rows))
        for source in rows:
            outcome = await self._refresh(source)
            result.per_source.append(outcome)
            if outcome.status == "ok":
                result.successes += 1
            elif outcome.status == "error":
                result.failures += 1
        return result

    async def refresh_one(self, source_id: uuid.UUID) -> SourceRefreshResult | None:
        source = await self.session.get(SigmaSource, source_id)
        if source is None:
            return None
        return await self._refresh(source)

    async def _refresh(self, source: SigmaSource) -> SourceRefreshResult:
        if not source.enabled:
            return SourceRefreshResult(
                source_id=str(source.id),
                source_name=source.name,
                status="disabled",
                message="source disabled",
            )

        token = _resolve_token(source.auth_credentials_ref)
        checkout = _checkout_dir(source.id)
        head_sha: str | None = None
        try:
            head_sha = await asyncio.to_thread(
                _sync_repo,
                checkout=checkout,
                git_url=source.git_url,
                branch=source.branch or "main",
                token=token,
            )
        except RuntimeError as exc:
            source.last_pull_at = datetime.now(timezone.utc)
            source.last_pull_status = "error"
            source.last_error = str(exc)[:1000]
            await self.session.commit()
            logger.warning(
                "sigma.refresh.failed",
                source_id=str(source.id),
                source_name=source.name,
                error=str(exc),
            )
            return SourceRefreshResult(
                source_id=str(source.id),
                source_name=source.name,
                status="error",
                message=str(exc),
            )

        # Parse + upsert
        files = _walk_rule_files(checkout, source.path_filter)
        outcome = SourceRefreshResult(
            source_id=str(source.id),
            source_name=source.name,
            status="ok",
            head_commit=head_sha,
            files_scanned=len(files),
        )

        repo_root = checkout.resolve()
        for file_path in files:
            try:
                text = file_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                outcome.files_skipped += 1
                continue
            parsed_rules = parse_sigma_yaml(text)
            if not parsed_rules:
                outcome.files_skipped += 1
                continue
            try:
                rel_path = str(file_path.resolve().relative_to(repo_root))
            except ValueError:
                rel_path = str(file_path.name)

            for parsed in parsed_rules:
                outcome.rules_parsed += 1
                row, change = await _upsert_rule(
                    self.session, parsed, source_id=source.id, rel_path=rel_path
                )
                if change == "inserted":
                    outcome.rules_inserted += 1
                elif change == "updated":
                    outcome.rules_updated += 1
                else:
                    outcome.rules_unchanged += 1

                if change in ("inserted", "updated"):
                    if _queue_embed(row):
                        outcome.embed_queued.append(str(row.id))

        source.last_pull_at = datetime.now(timezone.utc)
        source.last_pull_status = "ok"
        source.last_pull_commit = head_sha
        source.last_error = None
        source.rules_imported = (
            outcome.rules_inserted + outcome.rules_updated + outcome.rules_unchanged
        )

        await self.session.commit()

        logger.info(
            "sigma.refresh.complete",
            source_id=str(source.id),
            source_name=source.name,
            head_commit=head_sha,
            files_scanned=outcome.files_scanned,
            rules_parsed=outcome.rules_parsed,
            inserted=outcome.rules_inserted,
            updated=outcome.rules_updated,
            unchanged=outcome.rules_unchanged,
            embed_queued=len(outcome.embed_queued),
        )
        return outcome

    async def test_one(self, source_id: uuid.UUID) -> dict[str, Any] | None:
        """Lightweight ``ls-remote`` style connectivity check.

        Doesn't clone — just calls ``git ls-remote`` so the operator can
        verify auth + reachability without populating local disk.
        """
        source = await self.session.get(SigmaSource, source_id)
        if source is None:
            return None
        token = _resolve_token(source.auth_credentials_ref)
        auth_url = _inject_token(source.git_url, token)

        def _probe() -> dict[str, Any]:
            try:
                import git  # type: ignore[import-not-found]
            except ImportError as exc:
                return {"ok": False, "message": f"gitpython missing: {exc}"}
            try:
                refs = git.cmd.Git().ls_remote(auth_url, "HEAD")
                head_sha = refs.split()[0] if refs else None
                return {"ok": True, "message": "ls-remote ok", "head": head_sha}
            except Exception as exc:  # noqa: BLE001
                return {"ok": False, "message": f"ls-remote failed: {exc}"}

        return await asyncio.to_thread(_probe)


__all__ = [
    "RefreshAllResult",
    "RuleFilePass",
    "SigmaSourceClient",
    "SourceRefreshResult",
    "VALID_AUTH_TYPES",
]
