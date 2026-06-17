"""First-run bootstrap of intelligence commons.

On a fresh deployment, ``bootstrap_all()`` walks every enabled
``commons_sources`` row in priority order and imports its latest release
pack. Subsequent calls are safe — already-imported chains are skipped via
``commons_chains`` uniqueness on ``(source_id, cve_id, version)``.

If the configured source can't be reached and
``COMMONS_ALLOW_MOCK_FALLBACK=true``, the bootstrap routine falls back to a
mock release pack so M11 still has chains to develop against on an offline
sandbox. Operators turn the fallback off once the real public commons ships.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.commons.sources import list_enabled_sources
from fragchain.commons.transport import (
    CommonsRelease,
    CommonsTransport,
    MockTransport,
)
from fragchain.config import get_settings
from fragchain.db.models import CommonsChain, CommonsSource

logger = structlog.get_logger(__name__)


class CommonsBootstrapError(RuntimeError):
    """Raised when a commons source cannot be bootstrapped and the mock
    fallback is disabled. Surfaces as a startup failure so operators
    notice unreachable commons immediately rather than silently running
    against a stub release pack (Phase 4 audit Should-fix #5).
    """


@dataclass
class SourceImportResult:
    source_id: str
    source_name: str
    status: str  # "ok" | "no_release" | "fallback" | "skipped" | "error"
    release_version: str | None = None
    chains_imported: int = 0
    chains_skipped: int = 0
    message: str = ""


@dataclass
class BootstrapResult:
    total_sources: int = 0
    successes: int = 0
    failures: int = 0
    per_source: list[SourceImportResult] = field(default_factory=list)


async def import_release(
    session: AsyncSession,
    source: CommonsSource,
    release: CommonsRelease,
) -> tuple[int, int]:
    """Import every chain in ``release`` for ``source``.

    Returns ``(imported, skipped)``. Uses an upsert on the unique
    ``(source_id, cve_id, version)`` so re-running bootstrap is idempotent.
    """
    if not release.chains:
        return (0, 0)

    # Public commons (community trust) is tlp:clear only (§7). Higher TLP
    # belongs in deployment-local DB or restricted partner/internal feeds, so
    # only community sources are filtered — partner/internal may carry amber+.
    community = source.trust_level == "community"

    imported = 0
    skipped = 0
    for chain in release.chains:
        if community and (chain.tlp or "tlp:clear").lower() != "tlp:clear":
            skipped += 1
            logger.warning(
                "commons.import.non_clear_skipped",
                source_id=str(source.id),
                cve_id=chain.cve_id,
                tlp=chain.tlp,
            )
            continue
        stmt = (
            pg_insert(CommonsChain)
            .values(
                source_id=source.id,
                cve_id=chain.cve_id,
                version=chain.version,
                content_hash=chain.content_hash,
                tlp=chain.tlp,
                data=chain.data,
            )
            .on_conflict_do_nothing(
                index_elements=["source_id", "cve_id", "version"]
            )
            .returning(CommonsChain.id)
        )
        result = await session.execute(stmt)
        if result.scalar_one_or_none() is not None:
            imported += 1
        else:
            skipped += 1
    return (imported, skipped)


async def bootstrap_source(
    session: AsyncSession,
    source: CommonsSource,
    transport: CommonsTransport,
    *,
    allow_mock_fallback: bool | None = None,
) -> SourceImportResult:
    """Bootstrap a single source. Never raises — failures are reported."""
    settings = get_settings()
    if allow_mock_fallback is None:
        allow_mock_fallback = settings.COMMONS_ALLOW_MOCK_FALLBACK

    try:
        release = await transport.fetch_latest_release()
    except Exception as exc:  # noqa: BLE001
        release = None
        logger.warning(
            "commons.bootstrap.fetch_failed",
            source_id=str(source.id),
            error=str(exc),
        )
        if not allow_mock_fallback:
            source.last_sync_status = "error"
            source.last_error = f"fetch failed: {exc}"
            source.last_sync_at = datetime.now(timezone.utc)
            raise CommonsBootstrapError(
                f"Commons source unreachable: {source.url}. "
                f"Set COMMONS_ALLOW_MOCK_FALLBACK=true for development, "
                f"or configure a reachable commons source."
            ) from exc

    fallback_used = False
    if release is None:
        if not allow_mock_fallback:
            source.last_sync_status = "no_release"
            source.last_error = "no release found"
            source.last_sync_at = datetime.now(timezone.utc)
            raise CommonsBootstrapError(
                f"Commons source has no published release: {source.url}. "
                f"Set COMMONS_ALLOW_MOCK_FALLBACK=true for development, "
                f"or configure a reachable commons source."
            )
        logger.info(
            "commons.bootstrap.fallback_to_mock",
            source_id=str(source.id),
            source_name=source.name,
        )
        mock = MockTransport()
        release = await mock.fetch_latest_release()
        await mock.aclose()
        fallback_used = True

    assert release is not None  # for type-checkers
    try:
        imported, skipped = await import_release(session, source, release)
    except Exception as exc:  # noqa: BLE001
        source.last_sync_status = "error"
        source.last_error = f"import failed: {exc}"
        source.last_sync_at = datetime.now(timezone.utc)
        logger.exception("commons.bootstrap.import_failed", source_id=str(source.id))
        return SourceImportResult(
            source_id=str(source.id),
            source_name=source.name,
            status="error",
            release_version=release.version,
            message=f"import failed: {exc}",
        )

    source.last_sync_at = datetime.now(timezone.utc)
    source.last_release_version = release.version
    source.last_sync_status = "fallback" if fallback_used else "ok"
    source.last_error = None
    source.chains_imported = (source.chains_imported or 0) + imported

    logger.info(
        "commons.bootstrap.source_done",
        source_id=str(source.id),
        source_name=source.name,
        release_version=release.version,
        imported=imported,
        skipped=skipped,
        fallback=fallback_used,
    )
    return SourceImportResult(
        source_id=str(source.id),
        source_name=source.name,
        status="fallback" if fallback_used else "ok",
        release_version=release.version,
        chains_imported=imported,
        chains_skipped=skipped,
        message="ok (mock fallback)" if fallback_used else "ok",
    )


async def bootstrap_all(
    session: AsyncSession,
    *,
    transport_factory=None,
    allow_mock_fallback: bool | None = None,
) -> BootstrapResult:
    """Run bootstrap across every enabled commons source.

    ``transport_factory(source) -> CommonsTransport`` lets callers (tests,
    the worker, the API) inject their preferred transport implementation.
    Defaults to the module-level :func:`default_transport_factory`.
    """
    if transport_factory is None:
        from fragchain.commons.factory import default_transport_factory
        transport_factory = default_transport_factory

    sources = await list_enabled_sources(session)
    summary = BootstrapResult(total_sources=len(sources))
    for source in sources:
        transport = transport_factory(source)
        try:
            outcome = await bootstrap_source(
                session,
                source,
                transport,
                allow_mock_fallback=allow_mock_fallback,
            )
        finally:
            try:
                await transport.aclose()
            except Exception:  # noqa: BLE001
                pass
        summary.per_source.append(outcome)
        if outcome.status in ("ok", "fallback"):
            summary.successes += 1
        else:
            summary.failures += 1
    await session.commit()
    logger.info(
        "commons.bootstrap.complete",
        sources=summary.total_sources,
        successes=summary.successes,
        failures=summary.failures,
    )
    return summary


async def has_been_bootstrapped(session: AsyncSession) -> bool:
    """True if any enabled source has a non-null ``last_sync_at``."""
    result = await session.execute(
        select(CommonsSource).where(
            CommonsSource.sync_enabled.is_(True),
            CommonsSource.last_sync_at.is_not(None),
        ).limit(1)
    )
    return result.scalar_one_or_none() is not None
