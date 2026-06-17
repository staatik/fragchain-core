"""Budget enforcement worker (M6).

Runs every 5 minutes. Two responsibilities:

  1. Drain ``pending`` historical CVEs into the enrichment task as long as
     we're under ``MAX_HISTORICAL_CVE_PER_DAY``.
  2. Drain ``pending`` live CVEs into enrichment (these aren't budget-bound,
     but we may have queued them earlier when the live-rate window was full).

The budget task NEVER drops a CVE. Anything that can't be processed right now
stays in ``pending`` and will be picked up on the next tick.
"""
from __future__ import annotations

from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.db.models import CVE
from fragchain.ingest.rate_limit import check_daily_budget
from fragchain.notifications import emit_event

logger = structlog.get_logger(__name__)


async def enforce_budget_tick(session: AsyncSession) -> dict[str, int]:
    """One iteration of the budget loop. Returns a counts dict."""
    budget = await check_daily_budget(session)

    live_result = await session.execute(
        select(CVE)
        .where(CVE.processing_status == "pending")
        .where(CVE.import_mode == "live")
        .order_by(CVE.created_at)
        .limit(50)
    )
    live_rows = list(live_result.scalars().all())

    historical_rows: list[CVE] = []
    if budget.remaining > 0:
        historical_result = await session.execute(
            select(CVE)
            .where(CVE.processing_status == "pending")
            .where(CVE.import_mode == "historical")
            .order_by(CVE.approved_at, CVE.created_at)
            .limit(min(budget.remaining, 50))
        )
        historical_rows = list(historical_result.scalars().all())

    queued = 0
    try:
        from fragchain.worker.celery import celery_app
    except Exception:  # noqa: BLE001 — Celery missing in unit tests
        celery_app = None  # type: ignore[assignment]

    for cve in [*live_rows, *historical_rows]:
        if celery_app is not None:
            try:
                celery_app.send_task(
                    "fragchain.worker.tasks.enrich_cve",
                    kwargs={"cve_id": cve.cve_id},
                )
                queued += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "budget.enqueue_failed",
                    cve_id=cve.cve_id,
                    error=str(exc),
                )

    emit_event(
        "budget_status",
        {
            "daily_limit": budget.daily_limit,
            "used_today": budget.used_today,
            "remaining": budget.remaining,
            "queued": queued,
            "live_pending": len(live_rows),
            "historical_pending": len(historical_rows),
            "tick_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    return {
        "queued": queued,
        "live_pending": len(live_rows),
        "historical_pending": len(historical_rows),
        "remaining_budget": budget.remaining,
        "daily_limit": budget.daily_limit,
    }


async def poll_connectors_tick(session: AsyncSession) -> dict[str, int]:
    """Pull new CVEs from every installed SOURCE_STREAM connector.

    Polls the connector's ``stream_new`` since either its last poll watermark
    or 24h ago. Newly-discovered CVEs are persisted via the live ingestion
    path and become ``pending``.
    """
    from fragchain.connectors import ConnectorType, get_orchestrator
    from fragchain.ingest.service import upsert_cve_from_record

    orchestrator = get_orchestrator()
    sources = orchestrator.get_connectors(
        type=ConnectorType.SOURCE_STREAM, enabled_only=True, healthy_only=False
    )
    now = datetime.now(timezone.utc)
    since = now.replace(microsecond=0)
    # Default to last 1h for poll cadence — connectors that need broader
    # windows expose their own override.
    from datetime import timedelta
    since = now - timedelta(hours=1)

    ingested = 0
    by_connector: dict[str, int] = {}
    for connector in sources:
        count = 0
        try:
            async for record in orchestrator.stream_new_cves(
                connector.name, since=since, limit=100
            ):
                await upsert_cve_from_record(
                    session,
                    record,
                    import_mode="live",
                    initial_status="pending",
                )
                count += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "poll.connector_failed",
                connector=connector.name,
                error=str(exc),
            )
        by_connector[connector.name] = count
        ingested += count
    if ingested:
        await session.commit()
    return {"ingested": ingested, "by_connector": by_connector}


__all__ = ["enforce_budget_tick", "poll_connectors_tick"]
