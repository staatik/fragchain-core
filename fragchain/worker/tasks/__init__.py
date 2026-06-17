"""Celery task registry.

Tasks land in submodules owned by their respective build modules:

  * ``fragchain.worker.tasks.ingest`` — M6 (ingest_cve, stage_historical_cves,
    enrich_cve, poll_connectors, enforce_budget).
  * Other module owners drop their tasks alongside as they ship.

Importing this package registers every task with the Celery app — the beat
schedule defined in ``fragchain.worker.celery`` references these names.

M8 embed_source_document / embed_sigma_rule, M11 synthesize_chain,
M12 sigma refresh, M14 map_coverage / refresh_matrix_cache, and
M15 generate_rules are real implementations in the named submodules.
"""
from __future__ import annotations

from typing import Any

import structlog

from fragchain.worker.celery import celery_app, run_async_task

# Side-effect import: registers the M6 ingestion tasks with the Celery app.
from fragchain.worker.tasks import ingest as _ingest_tasks  # noqa: F401

# Side-effect import: registers M8 vector tasks (embed_source_document,
# embed_sigma_rule). Replaces the stubs that lived in this module previously.
from fragchain.worker.tasks import vector as _vector_tasks  # noqa: F401

# Side-effect import: registers M11 synthesize_chain. Replaces the stub that
# previously lived in this module.
from fragchain.worker.tasks import synthesize as _synthesize_tasks  # noqa: F401

# Side-effect import: registers M12 sigma tasks (refresh_sigma_sources,
# submit_rule_to_target).
from fragchain.worker.tasks import sigma as _sigma_tasks  # noqa: F401

# Side-effect import: registers M14 coverage tasks (map_coverage,
# refresh_matrix_cache). Replaces the stubs that lived in this module.
from fragchain.worker.tasks import coverage as _coverage_tasks  # noqa: F401

# Side-effect import: registers M15 generate_rules. Replaces the stub that
# previously lived in this module.
from fragchain.worker.tasks import rules as _rules_tasks  # noqa: F401

# Side-effect imports: register the assessment-workspace tasks
# (assessment.embed_source, assessment.run_loop, assessment.generate_artifact).
# Without these the worker rejects the dispatched messages as unregistered
# and the pre-created DB rows stay in-flight forever (Phase 2b review C1).
from fragchain.worker.tasks import (  # noqa: F401
    embed_assessment_source as _embed_assessment_source_tasks,
)
from fragchain.worker.tasks import (  # noqa: F401
    generate_artifact as _generate_artifact_tasks,
)
from fragchain.worker.tasks import (  # noqa: F401
    run_assessment_loop as _run_assessment_loop_tasks,
)

# Side-effect import: registers the stale in-flight reaper
# (assessment.reap_stale_inflight) — the beat task that fails stuck
# 'running'/'generating' rows so a lost broker message can't 409-block an
# assessment forever (Wave 1a T6).
from fragchain.worker.tasks import reaper as _reaper_tasks  # noqa: F401

logger = structlog.get_logger(__name__)


def _stub(name: str, **kwargs: Any) -> dict[str, Any]:
    logger.info("task.stub.invoked", task=name, **kwargs)
    return {"task": name, "status": "stub", "kwargs": kwargs}


# ---------------------------------------------------------------------------
# Embargo release (M2)
# ---------------------------------------------------------------------------


@celery_app.task(name="fragchain.worker.tasks.release_embargoed_content")
def release_embargoed_content(**kwargs: Any) -> dict[str, Any]:
    """Auto-release every embargo whose timer has expired.

    Runs every 5 minutes from beat. Real implementation lives in
    ``fragchain.security.embargo.release_expired``.
    """
    import asyncio

    from fragchain.db.session import get_sessionmaker
    from fragchain.security.embargo import release_expired

    async def _run() -> dict[str, Any]:
        sm = get_sessionmaker()
        async with sm() as session:
            outcome = await release_expired(session)
        return {
            "task": "release_embargoed_content",
            "status": "ok",
            "released_count": outcome.count,
            "released": outcome.released,
        }

    try:
        return run_async_task(lambda: _run())
    except Exception as exc:  # noqa: BLE001
        logger.exception("task.release_embargoed_content.failed", error=str(exc))
        return {
            "task": "release_embargoed_content",
            "status": "error",
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Commons sync (M7)
# ---------------------------------------------------------------------------


@celery_app.task(name="fragchain.worker.tasks.sync_commons_source")
def sync_commons_source(source_id: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Sync one commons source (or every enabled source when ``source_id`` is None).

    Runs hourly from beat. With no ``source_id`` argument it walks every
    enabled source — the beat schedule fires it that way.
    """
    import asyncio
    import uuid as _uuid

    from fragchain.commons import CommonsClient
    from fragchain.db.session import get_sessionmaker

    async def _run() -> dict[str, Any]:
        sm = get_sessionmaker()
        async with sm() as session:
            client = CommonsClient(session)
            if source_id is None:
                result = await client.sync_all()
                return {
                    "task": "sync_commons_source",
                    "status": "ok",
                    "scope": "all",
                    "total_sources": result.total_sources,
                    "successes": result.successes,
                    "failures": result.failures,
                    "per_source": [
                        {
                            "source_id": r.source_id,
                            "source_name": r.source_name,
                            "status": r.status,
                            "previous_version": r.previous_version,
                            "new_version": r.new_version,
                            "chains_imported": r.chains_imported,
                            "chains_skipped": r.chains_skipped,
                            "message": r.message,
                        }
                        for r in result.per_source
                    ],
                }
            outcome = await client.sync_one(_uuid.UUID(source_id))
            if outcome is None:
                return {
                    "task": "sync_commons_source",
                    "status": "error",
                    "scope": "one",
                    "source_id": source_id,
                    "error": "source not found",
                }
            return {
                "task": "sync_commons_source",
                "status": outcome.status,
                "scope": "one",
                "source_id": outcome.source_id,
                "source_name": outcome.source_name,
                "previous_version": outcome.previous_version,
                "new_version": outcome.new_version,
                "chains_imported": outcome.chains_imported,
                "chains_skipped": outcome.chains_skipped,
                "message": outcome.message,
            }

    try:
        return run_async_task(lambda: _run())
    except Exception as exc:  # noqa: BLE001
        logger.exception("task.sync_commons_source.failed", error=str(exc))
        return {"task": "sync_commons_source", "status": "error", "error": str(exc)}


@celery_app.task(name="fragchain.worker.tasks.bootstrap_commons")
def bootstrap_commons(**kwargs: Any) -> dict[str, Any]:
    """First-run import of every enabled commons source."""
    import asyncio

    from fragchain.commons import CommonsClient
    from fragchain.db.session import get_sessionmaker

    async def _run() -> dict[str, Any]:
        sm = get_sessionmaker()
        async with sm() as session:
            client = CommonsClient(session)
            result = await client.bootstrap_all()
            return {
                "task": "bootstrap_commons",
                "status": "ok",
                "total_sources": result.total_sources,
                "successes": result.successes,
                "failures": result.failures,
                "per_source": [
                    {
                        "source_id": r.source_id,
                        "source_name": r.source_name,
                        "status": r.status,
                        "release_version": r.release_version,
                        "chains_imported": r.chains_imported,
                        "chains_skipped": r.chains_skipped,
                        "message": r.message,
                    }
                    for r in result.per_source
                ],
            }

    try:
        return run_async_task(lambda: _run())
    except Exception as exc:  # noqa: BLE001
        logger.exception("task.bootstrap_commons.failed", error=str(exc))
        return {"task": "bootstrap_commons", "status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# Rule evaluations (M17)
# ---------------------------------------------------------------------------


@celery_app.task(name="fragchain.worker.tasks.prompt_evaluations")
def prompt_evaluations(window_days: int = 7, **kwargs: Any) -> dict[str, Any]:
    """Daily sweep: surface rules that need a field evaluation.

    Picks up every M16-approved rule deployed ``window_days``+ days ago
    that still has zero rows in ``rule_evaluations``. For now the task
    just logs each pending rule — M36 will deliver these to the
    notifications channel (Slack / email / WS) once it lands.

    Beat fires this once per day. The window is configurable so
    operators in fast-iteration environments can drop it to ~3 days
    without rebuilding the image.
    """
    import asyncio

    from fragchain.db.session import get_sessionmaker
    from fragchain.evaluations import identify_rules_pending_evaluation

    async def _run() -> dict[str, Any]:
        sm = get_sessionmaker()
        async with sm() as session:
            pending = await identify_rules_pending_evaluation(
                session, window_days=window_days
            )
        for row in pending:
            # M36 will replace this with a structured notification
            # emission. For now, every pending rule lands as a single
            # structlog event so operators tailing logs can see the
            # backlog forming.
            logger.info(
                "evaluation.prompt",
                sigma_rule_id=str(row.sigma_rule_id),
                title=row.title,
                reviewed_at=row.reviewed_at.isoformat(),
                days_since_review=row.days_since_review,
            )
        return {
            "task": "prompt_evaluations",
            "status": "ok",
            "window_days": window_days,
            "pending_count": len(pending),
            "rules": [
                {
                    "sigma_rule_id": str(p.sigma_rule_id),
                    "title": p.title,
                    "reviewed_at": p.reviewed_at.isoformat(),
                    "days_since_review": p.days_since_review,
                }
                for p in pending
            ],
        }

    try:
        return run_async_task(lambda: _run())
    except Exception as exc:  # noqa: BLE001
        logger.exception("task.prompt_evaluations.failed", error=str(exc))
        return {
            "task": "prompt_evaluations",
            "status": "error",
            "error": str(exc),
        }
