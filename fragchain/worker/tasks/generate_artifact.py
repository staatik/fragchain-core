"""Celery task: generate one pre-created non-Sigma artifact (Phase 2b).

The API endpoint creates the ``generated_artifacts`` row
(``status='generating'``) via
``fragchain.assessments.artifact_generation.begin_generation`` and
dispatches this task with the row id; the task runs
``ArtifactGenerator.generate`` (context load + one structured LLM call) and
finalizes the row to ``generated``/``failed``, emitting
``assessment.artifact.generated``. A duplicate/late delivery no-ops on a
non-``generating`` row.
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import structlog

from fragchain.assessments.artifact_generation import ArtifactGenerator
from fragchain.assessments.detectability import ArtifactType
from fragchain.db.models import GeneratedArtifactRow
from fragchain.db.session import get_sessionmaker
from fragchain.notifications import (
    EVENT_ASSESSMENT_ARTIFACT_GENERATED,
    emit_event,
)
from fragchain.worker.celery import celery_app, run_async_task

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def _sessionmaker():  # type: ignore[return]
    sm = get_sessionmaker()
    async with sm() as session:
        yield session


def _make_generator(session: Any) -> ArtifactGenerator:
    from fragchain.prompts.store import PromptStore

    return ArtifactGenerator(session, prompt_store=PromptStore(session))


@celery_app.task(bind=True, name="assessment.generate_artifact")
def generate_artifact(self: Any, artifact_row_id: str) -> dict[str, Any]:
    return run_async_task(lambda: _run(artifact_row_id))


async def _finalize_failed(
    artifact_row_id: uuid.UUID, error: str
) -> GeneratedArtifactRow | None:
    """Mark a stuck 'generating' row 'failed' in a FRESH session.

    ``ArtifactGenerator.generate`` is advisory and finalizes its own
    failures — but if it escapes anyway (e.g. the session is poisoned
    before its failure-commit), the row would stay ``generating`` and the
    endpoint's already-generating guard would block re-dispatch forever.
    Only a still-``generating`` row is flipped, so a duplicate/late call
    cannot clobber a terminal status.
    """
    try:
        async with _sessionmaker() as session:
            row = await session.get(GeneratedArtifactRow, artifact_row_id)
            if row is None:
                return None
            if row.status == "generating":
                row.status = "failed"
                row.error = error
                row.completed_at = datetime.now(tz=timezone.utc)
                await session.commit()
            return row
    except Exception as exc:  # noqa: BLE001 — best-effort recovery
        logger.warning(
            "assessment.artifact.finalize_failed_errored",
            artifact_row_id=str(artifact_row_id),
            error=str(exc),
        )
        return None


def _event_payload(row: GeneratedArtifactRow) -> dict[str, Any]:
    return {
        "assessment_id": str(row.assessment_id),
        "artifact_type": row.artifact_type,
        "status": row.status,
        "artifact_id": str(row.id),
        "version": row.version,
    }


async def _run(artifact_row_id: str) -> dict[str, Any]:
    rid = uuid.UUID(artifact_row_id)
    try:
        async with _sessionmaker() as session:
            row = await session.get(GeneratedArtifactRow, rid)
            if row is None:
                logger.warning(
                    "assessment.artifact.row_missing", artifact_row_id=artifact_row_id
                )
                return {"artifact_id": artifact_row_id, "status": "missing"}
            if row.status != "generating":
                logger.info(
                    "assessment.artifact.not_generating_skip",
                    artifact_row_id=artifact_row_id,
                    status=row.status,
                )
                return {"artifact_id": artifact_row_id, "status": "skipped"}
            generator = _make_generator(session)
            row = await generator.generate(
                assessment_id=row.assessment_id,
                artifact_type=ArtifactType(row.artifact_type),
                artifact_row_id=rid,
            )
            if row is None or row.status == "generating":
                # generate() is advisory and finalizes its own failures, but
                # if even its _mark_failed died (poisoned session) the row is
                # still 'generating' and would block re-dispatch forever —
                # finalize in a fresh session.
                row = await _finalize_failed(
                    rid, "generator failed to finalize its row"
                )
    except Exception as exc:  # noqa: BLE001 — never leave the row 'generating'
        logger.exception(
            "assessment.artifact.generate_escaped", artifact_row_id=artifact_row_id
        )
        row = await _finalize_failed(rid, repr(exc))

    if row is None:
        return {"artifact_id": artifact_row_id, "status": "failed"}
    try:
        emit_event(EVENT_ASSESSMENT_ARTIFACT_GENERATED, _event_payload(row))
    except Exception as exc:  # noqa: BLE001 — best-effort
        logger.warning(
            "assessment.artifact.emit_generated_failed", error=str(exc)
        )
    return {"artifact_id": artifact_row_id, "status": row.status}
