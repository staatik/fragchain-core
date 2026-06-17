"""Celery tasks for M6 intel ingestion.

The task bodies here are deliberately thin — they wrap the async helpers in
``fragchain.ingest.service`` / ``fragchain.ingest.budget`` /
``fragchain.ingest.enrichment`` with ``asyncio.run`` so they can run inside
sync Celery worker processes.

Beat schedule (defined in ``fragchain/worker/celery.py``):

  * ``poll_connectors`` — every 15 minutes
  * ``enforce_budget`` — every 5 minutes
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any

import structlog

from fragchain.worker.celery import celery_app, run_async_task

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Per-CVE tasks
# ---------------------------------------------------------------------------


@celery_app.task(
    name="fragchain.worker.tasks.ingest_cve",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
)
def ingest_cve_task(
    self, cve_id: str | None = None, connector_name: str | None = None, **kwargs: Any
) -> dict[str, Any]:
    """Ingest one CVE from a named source connector.

    Used by the webhook receiver. If the live rate-limit is saturated, the
    task self-retries with a 60s countdown — CVEs queue, they never drop.
    """
    if not cve_id or not connector_name:
        return {"task": "ingest_cve", "status": "noop", "reason": "missing_args"}

    async def _run() -> dict[str, Any]:
        from fragchain.db.session import get_sessionmaker
        from fragchain.ingest.rate_limit import check_live_rate
        from fragchain.ingest.service import ingest_cve_from_source
        from fragchain.notifications import emit_event

        sm = get_sessionmaker()
        async with sm() as session:
            rate = await check_live_rate(session)
            if not rate.allowed:
                emit_event(
                    "rate_limit_warning",
                    {
                        "scope": "live",
                        "count_in_window": rate.count_in_window,
                        "limit": rate.limit,
                        "retry_after_seconds": rate.retry_after_seconds,
                        "cve_id": cve_id,
                    },
                )
                return {
                    "task": "ingest_cve",
                    "status": "rate_limited",
                    "retry_after": rate.retry_after_seconds,
                    "cve_id": cve_id,
                }
            cve = await ingest_cve_from_source(
                session, connector_name=connector_name, cve_id=cve_id
            )
            if cve is None:
                return {
                    "task": "ingest_cve",
                    "status": "not_found",
                    "cve_id": cve_id,
                }
            # Queue enrichment now — CVE is in `pending`.
            try:
                celery_app.send_task(
                    "fragchain.worker.tasks.enrich_cve",
                    kwargs={"cve_id": cve.cve_id},
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "ingest.queue_enrich_failed",
                    cve_id=cve.cve_id,
                    error=str(exc),
                )
            return {
                "task": "ingest_cve",
                "status": "ok",
                "cve_id": cve.cve_id,
                "id": str(cve.id),
            }

    try:
        result = run_async_task(lambda: _run())
    except Exception as exc:  # noqa: BLE001
        logger.exception("ingest_cve.failed", cve_id=cve_id, error=str(exc))
        raise self.retry(exc=exc) from exc

    if result.get("status") == "rate_limited":
        retry_after = result.get("retry_after") or 60
        raise self.retry(countdown=retry_after, exc=RuntimeError("rate limit"))
    return result


@celery_app.task(name="fragchain.worker.tasks.enrich_cve")
def enrich_cve(cve_id: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Run every enabled enrichment connector against a pending CVE.

    Transitions ``pending → enriching → synthesizing`` on success, ``→
    failed`` on any unhandled exception (rare — the orchestrator already
    isolates per-connector failures).
    """
    if not cve_id:
        return {"task": "enrich_cve", "status": "noop"}

    async def _run() -> dict[str, Any]:
        from fragchain.db.session import get_sessionmaker
        from fragchain.ingest.enrichment import enrich_cve_pending

        sm = get_sessionmaker()
        async with sm() as session:
            return await enrich_cve_pending(session, cve_id=cve_id)

    try:
        return run_async_task(lambda: _run())
    except Exception as exc:  # noqa: BLE001
        logger.exception("enrich_cve.failed", cve_id=cve_id, error=str(exc))
        return {"task": "enrich_cve", "status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# Job + scheduled tasks
# ---------------------------------------------------------------------------


@celery_app.task(name="fragchain.worker.tasks.stage_historical_cves")
def stage_historical_cves(
    job_id: str | None = None,
    filters_dict: dict[str, Any] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Stage a historical-import job. Looks up the job by id; ignores filters_dict.

    The ``filters_dict`` argument is preserved for compatibility with the
    kickoff signature but the canonical filters live in
    ``import_jobs.filters`` so a retry uses the same filter set.
    """
    if not job_id:
        return {"task": "stage_historical_cves", "status": "noop"}

    async def _run() -> dict[str, Any]:
        from fragchain.db.models import ImportJob
        from fragchain.db.session import get_sessionmaker
        from fragchain.ingest.service import stage_historical_job

        sm = get_sessionmaker()
        async with sm() as session:
            job = await session.get(ImportJob, uuid.UUID(job_id))
            if job is None:
                return {
                    "task": "stage_historical_cves",
                    "status": "error",
                    "error": f"import job {job_id} not found",
                }
            counts = await stage_historical_job(session, job)
            return {
                "task": "stage_historical_cves",
                "status": "ok",
                "job_id": job_id,
                **counts,
            }

    try:
        return run_async_task(lambda: _run())
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "stage_historical_cves.failed", job_id=job_id, error=str(exc)
        )
        return {
            "task": "stage_historical_cves",
            "status": "error",
            "job_id": job_id,
            "error": str(exc),
        }


@celery_app.task(name="fragchain.worker.tasks.poll_connectors")
def poll_connectors(**kwargs: Any) -> dict[str, Any]:
    """Pull new live CVEs from every installed source connector.

    Run from beat every 15 minutes.
    """

    async def _run() -> dict[str, Any]:
        from fragchain.db.session import get_sessionmaker
        from fragchain.ingest.budget import poll_connectors_tick

        sm = get_sessionmaker()
        async with sm() as session:
            return await poll_connectors_tick(session)

    try:
        result = run_async_task(lambda: _run())
        return {"task": "poll_connectors", "status": "ok", **result}
    except Exception as exc:  # noqa: BLE001
        logger.exception("poll_connectors.failed", error=str(exc))
        return {"task": "poll_connectors", "status": "error", "error": str(exc)}


@celery_app.task(name="fragchain.worker.tasks.enforce_budget")
def enforce_budget(**kwargs: Any) -> dict[str, Any]:
    """Drain pending CVEs into enrichment as budget allows.

    Run from beat every 5 minutes.
    """

    async def _run() -> dict[str, Any]:
        from fragchain.db.session import get_sessionmaker
        from fragchain.ingest.budget import enforce_budget_tick

        sm = get_sessionmaker()
        async with sm() as session:
            return await enforce_budget_tick(session)

    try:
        result = run_async_task(lambda: _run())
        return {"task": "enforce_budget", "status": "ok", **result}
    except Exception as exc:  # noqa: BLE001
        logger.exception("enforce_budget.failed", error=str(exc))
        return {"task": "enforce_budget", "status": "error", "error": str(exc)}


__all__ = [
    "enforce_budget",
    "enrich_cve",
    "ingest_cve_task",
    "poll_connectors",
    "stage_historical_cves",
]
