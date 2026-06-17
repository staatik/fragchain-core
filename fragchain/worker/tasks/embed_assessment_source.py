"""Celery task: embed an analyst-pasted source into Qdrant ``source_chunks``.

Tagged with ``payload={assessment_id, source_id, kind: 'assessment_source',
tlp}`` so Loop 2 RAG can scope by ``assessment_id``. Re-running on a source
that has already been embedded re-runs the embedder and overwrites the
Qdrant point (the point id is the source id) — operators should treat the
task as costly to retry.
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from typing import Any

import structlog
from sqlalchemy import select

from fragchain.db.models import AssessmentSource
from fragchain.db.session import get_sessionmaker
from fragchain.notifications import (
    EVENT_ASSESSMENT_SOURCE_EMBEDDED,
    emit_event,
)
from fragchain.vector.collections import get_qdrant_client
from fragchain.worker.celery import celery_app, run_async_task

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Patchable indirections — kept as module-level callables so tests can patch
# them with unittest.mock.patch without touching the class internals.
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _sessionmaker():  # type: ignore[return]
    sm = get_sessionmaker()
    async with sm() as session:
        yield session


def _get_embedder() -> Any:
    """Return a lightweight embedder shim backed by VectorEmbedder."""
    from fragchain.vector.embedder import VectorEmbedder

    class _EmbedderShim:
        """Thin async wrapper that exposes ``.embed(texts)`` over VectorEmbedder."""

        async def embed(self, texts: list[str]) -> list[list[float]]:
            async with VectorEmbedder() as ve:
                return await ve._embed_texts(texts)  # noqa: SLF001

    return _EmbedderShim()


def _get_qdrant() -> Any:
    return get_qdrant_client()


# ---------------------------------------------------------------------------
# Celery entry point
# ---------------------------------------------------------------------------

@celery_app.task(bind=True, name="assessment.embed_source")
def embed_assessment_source(self: Any, source_id: str, **kwargs: Any) -> dict[str, Any]:
    """Celery entry point. Wraps the async ``_run``."""
    return run_async_task(lambda: _run(source_id))


# ---------------------------------------------------------------------------
# Async core — imported by tests and called by the task above.
# ---------------------------------------------------------------------------

async def _run(source_id: str) -> dict[str, Any]:
    async with _sessionmaker() as session:
        result = await session.execute(
            select(AssessmentSource).where(
                AssessmentSource.id == uuid.UUID(source_id)
            )
        )
        src = result.scalar_one_or_none()
        if src is None:
            logger.warning("embed.source.missing", source_id=source_id)
            return {"status": "missing"}
        if src.deleted_at is not None:
            logger.info("embed.source.deleted_skip", source_id=source_id)
            return {"status": "deleted_skip"}
        # F-013 (SAST S-018): idempotency on Celery retry. The previous
        # implementation re-ran the embedder + overwrote Qdrant on every
        # invocation, so a Redis blip → Celery retry → second LLM embed
        # call → operator billed twice. With this check, only rows in
        # the ``pending`` / ``failed`` states actually do work; rows
        # already in ``embedded`` short-circuit without an LLM call or
        # a Qdrant write. Status is set AFTER the Qdrant upsert succeeds
        # below, so a crash before the status flip correctly retriggers
        # work on the next retry.
        if src.embedding_status == "embedded":
            logger.info(
                "embed.source.already_embedded",
                source_id=source_id,
                status="already_embedded",
            )
            return {"status": "already_embedded"}

        embedder = _get_embedder()
        qdrant = _get_qdrant()
        try:
            # Chunk + embed so Loop 2 RAG retrieves the source prose, not just
            # IDs. Short pastes (< MIN_CHUNK_TOKENS) chunk to nothing, so fall
            # back to the whole content to keep them searchable. Per-chunk point
            # ids are deterministic (uuid5 over source:index) so a retry
            # overwrites the same points rather than duplicating.
            from fragchain.vector.embedder import _NS_SOURCE_CHUNK, chunk_text

            chunks = chunk_text(src.content) or [src.content]
            vectors = await embedder.embed(chunks)
            points = [
                {
                    "id": str(uuid.uuid5(_NS_SOURCE_CHUNK, f"{src.id}:{i}")),
                    "vector": vec,
                    "payload": {
                        "assessment_id": str(src.assessment_id),
                        "source_id": str(src.id),
                        "kind": "assessment_source",
                        "tlp": src.tlp,
                        "title": src.title,
                        "chunk_index": i,
                        "text": chunk,
                    },
                }
                for i, (chunk, vec) in enumerate(
                    zip(chunks, vectors, strict=True)
                )
            ]
            await qdrant.upsert(
                collection_name="source_chunks",
                points=points,
            )
        except Exception as exc:  # noqa: BLE001 - surface error to DB row
            src.embedding_status = "failed"
            src.embedding_error = repr(exc)
            await session.commit()
            logger.exception("embed.source.failed", source_id=source_id)
            try:
                emit_event(
                    EVENT_ASSESSMENT_SOURCE_EMBEDDED,
                    {
                        "assessment_id": str(src.assessment_id),
                        "source_id": str(src.id),
                        "status": "failed",
                    },
                )
            except Exception as emit_exc:  # noqa: BLE001
                logger.warning(
                    "assessment.source.emit_embedded_failed", error=str(emit_exc)
                )
            return {"status": "failed", "error": repr(exc)}

        src.embedding_status = "embedded"
        src.embedding_error = None
        await session.commit()
        logger.info("embed.source.completed", source_id=source_id)
        try:
            emit_event(
                EVENT_ASSESSMENT_SOURCE_EMBEDDED,
                {
                    "assessment_id": str(src.assessment_id),
                    "source_id": str(src.id),
                    "status": "embedded",
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("assessment.source.emit_embedded_failed", error=str(exc))
        return {"status": "embedded"}
