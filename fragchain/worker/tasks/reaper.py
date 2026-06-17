"""Beat task: fail stale in-flight assessment rows (Wave 1a T6).

Both 202 endpoints commit their in-flight row (``assessment_loop_run``
``status='running'``, ``generated_artifacts`` ``status='generating'``)
and THEN dispatch the Celery task. If the broker message is lost (Redis
data loss, queue purge, ``.delay()`` raising after the commit), the row
stays in-flight forever: ``begin_run``'s already-running guard and
``ArtifactAlreadyGeneratingError`` then 409 every re-dispatch with no
operator-facing unstick path short of SQL.

This reaper runs every 5 minutes from beat and finalizes rows older than
``STALE_INFLIGHT_MAX_SECONDS`` to ``failed``. Each flip is an **atomic
conditional UPDATE** (``WHERE id = :id AND status = 'running'`` /
``'generating'``) so a worker finalizing the row between the reaper's
candidate SELECT and its COMMIT wins the race: the UPDATE matches zero
rows and the reaper skips it — only rows actually flipped are counted
and emitted for. Age basis: ``started_at`` for loop runs, ``created_at``
for artifacts. The respective completion events are emitted (payload
status ``failed``) so the workspace refetches instead of polling forever.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from sqlalchemy import select, update

from fragchain.config import get_settings
from fragchain.db.models import AssessmentLoopRun, GeneratedArtifactRow
from fragchain.db.session import get_sessionmaker
from fragchain.notifications import (
    EVENT_ASSESSMENT_ARTIFACT_GENERATED,
    EVENT_ASSESSMENT_LOOP_RUN_COMPLETED,
    emit_event,
)
from fragchain.worker.celery import celery_app, run_async_task

logger = structlog.get_logger(__name__)

REAP_ERROR = "reaped: stale in-flight row"


@asynccontextmanager
async def _sessionmaker():  # type: ignore[return]
    sm = get_sessionmaker()
    async with sm() as session:
        yield session


@celery_app.task(bind=True, name="assessment.reap_stale_inflight")
def reap_stale_inflight(self: Any) -> dict[str, Any]:
    return run_async_task(lambda: _reap())


async def _reap() -> dict[str, Any]:
    max_age = get_settings().STALE_INFLIGHT_MAX_SECONDS
    now = datetime.now(tz=timezone.utc)
    cutoff = now - timedelta(seconds=max_age)

    run_payloads: list[dict[str, Any]] = []
    artifact_payloads: list[dict[str, Any]] = []

    async with _sessionmaker() as session:
        result = await session.execute(
            select(AssessmentLoopRun).where(
                AssessmentLoopRun.status == "running",
                AssessmentLoopRun.started_at < cutoff,
            )
        )
        for run in result.scalars().all():
            # Atomic only-flip-if-still-running: a worker finalizing this
            # run between our SELECT and COMMIT makes the UPDATE match
            # zero rows — never clobber a concurrent terminal status.
            flip = await session.execute(
                update(AssessmentLoopRun)
                .where(
                    AssessmentLoopRun.id == run.id,
                    AssessmentLoopRun.status == "running",
                )
                .values(status="failed", error=REAP_ERROR, completed_at=now)
                .returning(AssessmentLoopRun.id)
                .execution_options(synchronize_session=False)
            )
            if flip.scalar_one_or_none() is None:
                logger.info(
                    "assessment.reaper.loop_run_finalized_concurrently",
                    run_id=str(run.id),
                    assessment_id=str(run.assessment_id),
                )
                continue
            run_payloads.append(
                {
                    "assessment_id": str(run.assessment_id),
                    "loop_number": run.loop_number,
                    "version": run.version,
                    "status": "failed",
                }
            )
            logger.warning(
                "assessment.reaper.loop_run_reaped",
                run_id=str(run.id),
                assessment_id=str(run.assessment_id),
                loop_number=run.loop_number,
                started_at=str(run.started_at),
            )

        result = await session.execute(
            select(GeneratedArtifactRow).where(
                GeneratedArtifactRow.status == "generating",
                GeneratedArtifactRow.created_at < cutoff,
            )
        )
        for row in result.scalars().all():
            # Atomic only-flip-if-still-generating (see loop-run twin).
            flip = await session.execute(
                update(GeneratedArtifactRow)
                .where(
                    GeneratedArtifactRow.id == row.id,
                    GeneratedArtifactRow.status == "generating",
                )
                .values(status="failed", error=REAP_ERROR, completed_at=now)
                .returning(GeneratedArtifactRow.id)
                .execution_options(synchronize_session=False)
            )
            if flip.scalar_one_or_none() is None:
                logger.info(
                    "assessment.reaper.artifact_finalized_concurrently",
                    artifact_id=str(row.id),
                    assessment_id=str(row.assessment_id),
                )
                continue
            artifact_payloads.append(
                {
                    "assessment_id": str(row.assessment_id),
                    "artifact_type": row.artifact_type,
                    "status": "failed",
                    "artifact_id": str(row.id),
                    "version": row.version,
                }
            )
            logger.warning(
                "assessment.reaper.artifact_reaped",
                artifact_id=str(row.id),
                assessment_id=str(row.assessment_id),
                artifact_type=row.artifact_type,
                created_at=str(row.created_at),
            )

        if run_payloads or artifact_payloads:
            await session.commit()

    # Emit AFTER the commit so subscribers refetch the terminal rows.
    for payload in run_payloads:
        try:
            emit_event(EVENT_ASSESSMENT_LOOP_RUN_COMPLETED, payload)
        except Exception as exc:  # noqa: BLE001 — best-effort
            logger.warning("assessment.reaper.emit_failed", error=str(exc))
    for payload in artifact_payloads:
        try:
            emit_event(EVENT_ASSESSMENT_ARTIFACT_GENERATED, payload)
        except Exception as exc:  # noqa: BLE001 — best-effort
            logger.warning("assessment.reaper.emit_failed", error=str(exc))

    return {
        "task": "assessment.reap_stale_inflight",
        "status": "ok",
        "reaped_loop_runs": len(run_payloads),
        "reaped_artifacts": len(artifact_payloads),
    }
