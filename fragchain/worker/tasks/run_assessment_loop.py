"""Celery task: execute one pre-created loop run for an assessment.

The API endpoint creates the ``assessment_loop_run`` row (``status='running'``)
via ``LoopOrchestrator.begin_run`` and dispatches this task with the run id;
the task calls ``LoopOrchestrator.execute_run`` to do the LLM work + post-loop
hooks and finalize the row. Wires the real :class:`Loop1` / :class:`Loop2` /
:class:`Loop3` plus the chain-synthesis, rule-supersession, detectability,
artifact-router, and coverage-dispatch collaborators so the post-loop hooks
run end-to-end.
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import structlog

from fragchain.assessments.loop_chain import advance_after_run
from fragchain.db.models import AssessmentLoopRun, CoverageAssessment
from fragchain.db.session import get_sessionmaker
from fragchain.notifications import (
    EVENT_ASSESSMENT_LOOP_RUN_COMPLETED,
    emit_event,
)
from fragchain.worker.celery import celery_app, run_async_task

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def _sessionmaker():  # type: ignore[return]
    sm = get_sessionmaker()
    async with sm() as session:
        yield session


def _make_orchestrator(session: Any) -> Any:
    from fragchain.assessments.orchestrator_factory import build_orchestrator

    return build_orchestrator(session)


@celery_app.task(bind=True, name="assessment.run_loop")
def run_assessment_loop(self: Any, run_id: str) -> dict[str, Any]:
    return run_async_task(lambda: _run(run_id))


def _completed_payload(run: Any) -> dict[str, Any]:
    return {
        "assessment_id": str(run.assessment_id),
        "loop_number": run.loop_number,
        "version": run.version,
        "status": run.status,
    }


async def _finalize_failed(run_id: uuid.UUID, error: str) -> Any | None:
    """Mark a stuck 'running' loop-run row 'failed' in a FRESH session.

    ``execute_run`` can raise after ``begin_run`` already committed the
    'running' row — e.g. a DB error in a post-loop hook (chain synthesis,
    the artifact-router FK) or the final commit. The worker's session is
    then rolled back, leaving the row at 'running', which hard-blocks
    re-dispatch (``begin_run``'s already-running guard → 409) and pins the
    UI to "Running…". Finalizing the row to 'failed' here restores the
    re-dispatch recovery path. A clean session is used because the original
    is poisoned after the error. Only a still-'running' row is flipped, so a
    duplicate/late call cannot clobber a terminal status.
    """
    try:
        async with _sessionmaker() as session:
            run = await session.get(AssessmentLoopRun, run_id)
            if run is None:
                return None
            if run.status == "running":
                run.status = "failed"
                run.error = error
                run.completed_at = datetime.now(tz=timezone.utc)
                await session.commit()
            return run
    except Exception as exc:  # noqa: BLE001 — best-effort recovery
        logger.warning(
            "assessment.run.finalize_failed_errored",
            run_id=str(run_id),
            error=str(exc),
        )
        return None


async def _load_auto_advance(assessment_id: uuid.UUID) -> bool:
    async with _sessionmaker() as session:
        asmt = await session.get(CoverageAssessment, assessment_id)
        return bool(asmt.auto_advance) if asmt is not None else False


async def _run(run_id: str) -> dict[str, Any]:
    rid = uuid.UUID(run_id)
    try:
        async with _sessionmaker() as session:
            orch = _make_orchestrator(session)
            run = await orch.execute_run(rid)
            payload = _completed_payload(run)
    except Exception as exc:  # noqa: BLE001 — never leave the row 'running'
        logger.exception("assessment.run.execute_failed", run_id=run_id)
        run = await _finalize_failed(rid, repr(exc))
        payload = _completed_payload(run) if run is not None else None

    if payload is None:
        return {"run_id": run_id, "status": "failed", "version": None}
    try:
        emit_event(EVENT_ASSESSMENT_LOOP_RUN_COMPLETED, payload)
    except Exception as exc:  # noqa: BLE001 — best-effort
        logger.warning("assessment.run.emit_completed_failed", error=str(exc))
    if payload is not None and run is not None:
        try:
            auto = await _load_auto_advance(run.assessment_id)
            await advance_after_run(
                sessionmaker=_sessionmaker, run=run, auto_advance=auto
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("assessment.chain.driver_failed", error=str(exc))
    return {
        "run_id": run_id,
        "status": payload["status"],
        "version": payload["version"],
    }
