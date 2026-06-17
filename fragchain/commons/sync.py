"""Hourly delta sync per commons source.

The sync routine is intentionally simple in v1: if the remote's latest
release tag differs from the row's ``last_release_version``, pull the new
release and re-import. ``ON CONFLICT DO NOTHING`` on the unique
``(source_id, cve_id, version)`` means re-imports are idempotent — already-
known chain versions are skipped while new ones land.

Once M11 starts authoring new chain versions per CVE, the schema is ready:
each chain carries its own ``version`` field and the unique constraint lets
multiple versions coexist for the same CVE in the same source.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.commons.bootstrap import import_release
from fragchain.commons.sources import list_enabled_sources
from fragchain.commons.transport import CommonsTransport
from fragchain.db.models import CommonsSource

logger = structlog.get_logger(__name__)


@dataclass
class SyncResult:
    source_id: str
    source_name: str
    status: str  # "ok" | "up_to_date" | "no_release" | "skipped" | "error"
    previous_version: str | None = None
    new_version: str | None = None
    chains_imported: int = 0
    chains_skipped: int = 0
    message: str = ""


@dataclass
class SyncAllResult:
    total_sources: int = 0
    successes: int = 0
    failures: int = 0
    per_source: list[SyncResult] = field(default_factory=list)


async def sync_source(
    session: AsyncSession,
    source: CommonsSource,
    transport: CommonsTransport,
) -> SyncResult:
    """Pull the latest release for one source; import if new.

    Never raises — failures are recorded on the row and surfaced via the
    returned :class:`SyncResult`.
    """
    if not source.sync_enabled:
        return SyncResult(
            source_id=str(source.id),
            source_name=source.name,
            status="skipped",
            message="sync_enabled=False",
        )

    try:
        release = await transport.fetch_latest_release()
    except Exception as exc:  # noqa: BLE001
        source.last_sync_status = "error"
        source.last_error = f"fetch failed: {exc}"
        source.last_sync_at = datetime.now(timezone.utc)
        logger.warning(
            "commons.sync.fetch_failed",
            source_id=str(source.id),
            error=str(exc),
        )
        return SyncResult(
            source_id=str(source.id),
            source_name=source.name,
            status="error",
            previous_version=source.last_release_version,
            message=f"fetch failed: {exc}",
        )

    if release is None:
        source.last_sync_status = "no_release"
        source.last_error = None
        source.last_sync_at = datetime.now(timezone.utc)
        return SyncResult(
            source_id=str(source.id),
            source_name=source.name,
            status="no_release",
            previous_version=source.last_release_version,
            message="no release found on remote",
        )

    previous_version = source.last_release_version
    if previous_version and previous_version == release.version:
        # Still touch last_sync_at so operators can see the timer ticked.
        source.last_sync_at = datetime.now(timezone.utc)
        source.last_sync_status = "ok"
        source.last_error = None
        return SyncResult(
            source_id=str(source.id),
            source_name=source.name,
            status="up_to_date",
            previous_version=previous_version,
            new_version=release.version,
            message="already at latest release",
        )

    try:
        imported, skipped = await import_release(session, source, release)
    except Exception as exc:  # noqa: BLE001
        source.last_sync_status = "error"
        source.last_error = f"import failed: {exc}"
        source.last_sync_at = datetime.now(timezone.utc)
        logger.exception("commons.sync.import_failed", source_id=str(source.id))
        return SyncResult(
            source_id=str(source.id),
            source_name=source.name,
            status="error",
            previous_version=previous_version,
            new_version=release.version,
            message=f"import failed: {exc}",
        )

    source.last_sync_at = datetime.now(timezone.utc)
    source.last_release_version = release.version
    source.last_sync_status = "ok"
    source.last_error = None
    source.chains_imported = (source.chains_imported or 0) + imported

    logger.info(
        "commons.sync.source_done",
        source_id=str(source.id),
        source_name=source.name,
        previous_version=previous_version,
        new_version=release.version,
        imported=imported,
        skipped=skipped,
    )
    return SyncResult(
        source_id=str(source.id),
        source_name=source.name,
        status="ok",
        previous_version=previous_version,
        new_version=release.version,
        chains_imported=imported,
        chains_skipped=skipped,
        message="ok",
    )


async def sync_all(
    session: AsyncSession,
    *,
    transport_factory=None,
) -> SyncAllResult:
    """Sync every enabled commons source."""
    if transport_factory is None:
        from fragchain.commons.factory import default_transport_factory
        transport_factory = default_transport_factory

    sources = await list_enabled_sources(session)
    summary = SyncAllResult(total_sources=len(sources))
    for source in sources:
        transport = transport_factory(source)
        try:
            outcome = await sync_source(session, source, transport)
        finally:
            try:
                await transport.aclose()
            except Exception:  # noqa: BLE001
                pass
        summary.per_source.append(outcome)
        if outcome.status in ("ok", "up_to_date", "no_release", "skipped"):
            summary.successes += 1
        else:
            summary.failures += 1
    await session.commit()
    logger.info(
        "commons.sync.complete",
        sources=summary.total_sources,
        successes=summary.successes,
        failures=summary.failures,
    )
    return summary
