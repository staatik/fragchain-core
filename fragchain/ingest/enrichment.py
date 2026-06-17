"""Enrichment task implementation (M6).

The Celery task ``enrich_cve`` advances a CVE from ``pending`` to
``enriching`` to ``synthesizing``. Heavy lifting (parallel fan-out, failure
isolation, rate limiting) is delegated to the M4 :class:`ConnectorOrchestrator`.
"""
from __future__ import annotations

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.connectors import (
    ConnectorOrchestrator,
    EnrichmentResult,
    get_orchestrator,
)
from fragchain.db.models import CVE
from fragchain.ingest.service import (
    _apply_merged_enrichment,
    _merge_enrichments,
    persist_documents,
)
from fragchain.ingest.state import (
    set_processing_failed,
    set_processing_stage,
)
from fragchain.notifications import emit_event

logger = structlog.get_logger(__name__)


async def enrich_cve_pending(
    session: AsyncSession,
    cve_id: str,
    *,
    orchestrator: ConnectorOrchestrator | None = None,
) -> dict[str, object]:
    """Enrich a CVE in ``pending`` status. Returns a status dict.

    Refuses to run on CVEs in any other status — this keeps the state
    machine deterministic. The caller (Celery task) is responsible for
    queueing this only after the CVE has reached ``pending`` (live ingest
    landed there directly; historical CVEs got there via approve).
    """
    orchestrator = orchestrator or get_orchestrator()
    result = await session.execute(select(CVE).where(CVE.cve_id == cve_id))
    cve = result.scalar_one_or_none()
    if cve is None:
        return {"status": "missing", "cve_id": cve_id}
    if cve.processing_status != "pending":
        return {
            "status": "skipped",
            "cve_id": cve_id,
            "reason": f"current status is {cve.processing_status}",
        }

    await set_processing_stage(
        session, cve, new_status="enriching", stage="enriching"
    )
    await session.commit()

    # Build a synthetic CVERecord-shaped dict for the connectors.
    cve_data = {
        "cve_id": cve.cve_id,
        "published": cve.published_at.isoformat() if cve.published_at else None,
        "modified": cve.modified_at.isoformat() if cve.modified_at else None,
        "cvss_v3": float(cve.cvss_score) if cve.cvss_score is not None else None,
        "cvss_vector": cve.cvss_vector,
        "affected_products": cve.affected_products,
        "raw": cve.raw_connector_data or {},
    }

    try:
        enrichments: dict[str, EnrichmentResult | None] = await orchestrator.enrich_cve(
            cve.cve_id, cve_data
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("enrich.failed", cve_id=cve.cve_id, error=str(exc))
        await set_processing_failed(
            session, cve, stage="enriching", error=str(exc)
        )
        await session.commit()
        return {"status": "error", "cve_id": cve_id, "error": str(exc)}

    # Use a CVERecord-shaped object for the merge helper. We don't have one
    # any more (the source connector ran earlier) — synthesize one from the
    # row so the merge code can stay shared with the staging path.
    from fragchain.connectors import CVERecord
    record = CVERecord(
        cve_id=cve.cve_id,
        published=cve.published_at,
        modified=cve.modified_at,
        cvss_v3=float(cve.cvss_score) if cve.cvss_score is not None else None,
        cvss_vector=cve.cvss_vector,
        affected_products=list(cve.affected_products) if isinstance(cve.affected_products, list) else [],
        raw=cve.raw_connector_data or {},
    )
    merged = _merge_enrichments(record, enrichments)
    _apply_merged_enrichment(cve, merged)
    new_doc_ids: list[str] = []
    if merged.get("documents"):
        await persist_documents(session, cve, merged["documents"])
        # Collect the documents that landed needing embedding so M8 can pick
        # them up. We query post-persist because persist_documents dedups by
        # content hash — the count of inserted rows isn't enough to know
        # which ones are new.
        from fragchain.db.models import SourceDocument
        result = await session.execute(
            select(SourceDocument.id).where(
                SourceDocument.cve_id == cve.id,
                SourceDocument.embedded.is_(False),
            )
        )
        new_doc_ids = [str(row[0]) for row in result.all()]

    # On success, advance to synthesizing so M11 can pick it up.
    await set_processing_stage(
        session, cve, new_status="synthesizing", stage="synthesizing"
    )
    await session.commit()

    # Queue M8 embedding for every pending document. Best-effort dispatch —
    # a missing worker mustn't fail the enrich step. The synthesis task can
    # tolerate un-embedded docs (just degrades RAG retrieval), and the
    # `embedded=false` flag means a re-trigger picks them up.
    if new_doc_ids:
        try:
            from fragchain.worker.celery import celery_app
            for doc_id in new_doc_ids:
                celery_app.send_task(
                    "fragchain.worker.tasks.embed_source_document",
                    kwargs={"source_doc_id": doc_id},
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "enrich.queue_embed_failed",
                cve_id=cve.cve_id,
                documents=len(new_doc_ids),
                error=str(exc),
            )

    emit_event(
        "enrichment_complete",
        {
            "cve_id": cve.cve_id,
            "id": str(cve.id),
            "connectors": sorted([k for k, v in enrichments.items() if v is not None]),
            "next_status": "synthesizing",
        },
    )

    # Queue the next stage (M11). The synthesize task name is a stub today —
    # M11 fills it in. Best-effort: a missing celery dispatch must not flip
    # this CVE to failed.
    try:
        from fragchain.worker.celery import celery_app
        celery_app.send_task(
            "fragchain.worker.tasks.synthesize_chain",
            kwargs={"cve_id": cve.cve_id},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "enrich.queue_synthesis_failed",
            cve_id=cve.cve_id,
            error=str(exc),
        )

    return {
        "status": "ok",
        "cve_id": cve_id,
        "connectors_run": len(enrichments),
        "connectors_succeeded": sum(1 for v in enrichments.values() if v is not None),
    }


__all__ = ["enrich_cve_pending"]
