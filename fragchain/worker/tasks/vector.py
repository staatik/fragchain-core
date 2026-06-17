"""Celery tasks for M8 vector pipeline.

Two tasks land here:

  * ``embed_source_document(source_doc_id)`` — chunk + embed + upsert a
    source document into ``source_chunks`` and flip the row's ``embedded``
    flag. Dispatched from M6 ``enrich_cve`` for each new document.

  * ``embed_sigma_rule(rule_id)`` — embed one Sigma rule into ``sigma_rules``
    for semantic coverage matching. M12 dispatches this when a Sigma source
    pull lands a new rule.

Both wrap async helpers in ``fragchain.vector.embedder`` with ``asyncio.run``
so they run inside sync Celery worker processes. Errors are logged and
returned (never raised) so the task chain doesn't break — M14's coverage
mapper degrades gracefully when an embedding is missing.
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any

import structlog

from fragchain.worker.celery import celery_app, run_async_task

logger = structlog.get_logger(__name__)


@celery_app.task(name="fragchain.worker.tasks.embed_source_document")
def embed_source_document_task(
    document_id: str | None = None,
    source_doc_id: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Embed one source document. Returns ``{status, chunk_count}``.

    Accepts both ``document_id`` (the M1 stub kwarg name) and
    ``source_doc_id`` (M8 spec name) so existing callers keep working.
    """
    doc_id = source_doc_id or document_id
    if not doc_id:
        return {"task": "embed_source_document", "status": "noop"}

    async def _run() -> dict[str, Any]:
        from fragchain.db.session import get_sessionmaker
        from fragchain.vector.embedder import VectorEmbedder

        sm = get_sessionmaker()
        async with sm() as session:
            async with VectorEmbedder() as embedder:
                count = await embedder.embed_source_document(
                    session, uuid.UUID(str(doc_id))
                )
        return {
            "task": "embed_source_document",
            "status": "ok",
            "source_doc_id": str(doc_id),
            "chunk_count": int(count),
        }

    try:
        return run_async_task(lambda: _run())
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "task.embed_source_document.failed",
            source_doc_id=str(doc_id),
            error=str(exc),
        )
        return {
            "task": "embed_source_document",
            "status": "error",
            "source_doc_id": str(doc_id),
            "error": str(exc),
        }


@celery_app.task(name="fragchain.worker.tasks.embed_sigma_rule")
def embed_sigma_rule_task(
    rule_id: str | None = None,
    *,
    title: str | None = None,
    technique_ids: list[str] | None = None,
    yaml_body: str | None = None,
    sigma_uuid: str | None = None,
    status: str | None = None,
    logsource_product: str | None = None,
    logsource_service: str | None = None,
    origin: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Embed one Sigma rule into ``sigma_rules``.

    Caller (M12) hands over the rule fields explicitly — M8 has no Sigma
    rule ORM model. Keeping the contract input-only here means M12 can later
    swap to passing only ``rule_id`` once it ships the schema; this task
    will then load from the DB inline.
    """
    if not rule_id or not title or not yaml_body:
        return {
            "task": "embed_sigma_rule",
            "status": "noop",
            "reason": "missing_required_fields",
        }

    async def _run() -> dict[str, Any]:
        from fragchain.db.session import get_sessionmaker
        from fragchain.vector.embedder import VectorEmbedder

        sm = get_sessionmaker()
        async with sm() as session:
            async with VectorEmbedder() as embedder:
                ok = await embedder.embed_sigma_rule(
                    session,
                    uuid.UUID(str(rule_id)),
                    title=title,
                    technique_ids=list(technique_ids or []),
                    yaml_body=yaml_body,
                    sigma_uuid=sigma_uuid,
                    status=status,
                    logsource_product=logsource_product,
                    logsource_service=logsource_service,
                    origin=origin,
                )
        return {
            "task": "embed_sigma_rule",
            "status": "ok" if ok else "skipped",
            "rule_id": str(rule_id),
        }

    try:
        return run_async_task(lambda: _run())
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "task.embed_sigma_rule.failed", rule_id=str(rule_id), error=str(exc)
        )
        return {
            "task": "embed_sigma_rule",
            "status": "error",
            "rule_id": str(rule_id),
            "error": str(exc),
        }


__all__ = ["embed_sigma_rule_task", "embed_source_document_task"]
