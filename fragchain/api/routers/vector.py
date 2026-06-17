"""Vector store admin / debug API (M8).

Three endpoints under ``/api/v1/vector``:

  * ``GET  /vector/collections`` — list collection stats.
  * ``POST /vector/embed/{source_doc_id}`` — manual re-embed of one source
    document (used after a re-ingest, or to retry a failed embedding).
  * ``POST /vector/search`` — debug search interface. Body picks the
    collection + query + optional CVE filter.

All endpoints are maintainer-only — the search debug surface can return
amber/red excerpts that haven't been TLP-filtered for the caller and the
re-embed endpoint costs LLM tokens.
"""
from __future__ import annotations

import uuid
from typing import Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.middleware.tlp_filter import require_maintainer
from fragchain.db.models import SourceDocument
from fragchain.db.session import get_db
from fragchain.vector.collections import (
    COLLECTION_ATTACK_CHAINS,
    get_collections_info,
)
from fragchain.vector.embedder import VectorEmbedder

logger = structlog.get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class CollectionInfo(BaseModel):
    name: str
    status: str
    points_count: int | None = None
    vectors_size: int | None = None
    distance: str | None = None
    indexed_only_count: int | None = None
    error: str | None = None


class CollectionsResponse(BaseModel):
    collections: list[CollectionInfo]


class EmbedResponse(BaseModel):
    status: str
    source_doc_id: str
    chunk_count: int
    embedded: bool


class SearchRequest(BaseModel):
    query: str = Field(min_length=1)
    collection: Literal[
        "source_chunks", "sigma_rules", "attck_techniques", "attack_chains"
    ] = "source_chunks"
    cve_id: str | None = None
    limit: int = Field(default=10, ge=1, le=50)


class SearchHit(BaseModel):
    point_id: str
    score: float
    payload: dict


class SearchResponse(BaseModel):
    collection: str
    query: str
    hits: list[SearchHit]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/vector/collections", response_model=CollectionsResponse)
async def list_collections(
    request: Request,
    _user=Depends(require_maintainer),
) -> CollectionsResponse:
    info = await get_collections_info()
    out: list[CollectionInfo] = []
    for row in info:
        out.append(
            CollectionInfo(
                name=str(row.get("name", "")),
                status=str(row.get("status", "")),
                points_count=row.get("points_count"),
                vectors_size=row.get("vectors_size"),
                distance=row.get("distance"),
                indexed_only_count=row.get("indexed_only_count"),
                error=row.get("error"),
            )
        )
    return CollectionsResponse(collections=out)


@router.post("/vector/embed/{source_doc_id}", response_model=EmbedResponse)
async def embed_source_document(
    source_doc_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> EmbedResponse:
    """Force-embed one source document. Sync — returns when Qdrant upsert lands.

    This bypasses Celery so an operator gets an immediate result. The
    background pipeline (queued from ``enrich_cve``) is still the normal
    path; this endpoint is for debugging / retries / manual seeds.
    """
    doc = await db.get(SourceDocument, source_doc_id)
    if doc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Source document not found",
        )

    async with VectorEmbedder() as embedder:
        count = await embedder.embed_source_document(db, source_doc_id)
    return EmbedResponse(
        status="ok",
        source_doc_id=str(source_doc_id),
        chunk_count=int(count),
        embedded=True,
    )


@router.post("/vector/search", response_model=SearchResponse)
async def vector_search(
    body: SearchRequest,
    request: Request,
    _user=Depends(require_maintainer),
) -> SearchResponse:
    """Run a similarity search against one collection. Debug-only.

    Returns the top-K hits unfiltered by TLP — that's why the route is
    maintainer-gated. The UI surface (M21 matrix, M11 chain detail) consumes
    typed helpers on ``VectorEmbedder`` directly, not this endpoint.
    """
    async with VectorEmbedder() as embedder:
        hits_payload: list[SearchHit]
        if body.collection == "source_chunks":
            results = await embedder.search_source_chunks(
                body.query, cve_id=body.cve_id, limit=body.limit
            )
            hits_payload = [
                SearchHit(
                    point_id=r.point_id,
                    score=r.score,
                    payload={
                        "text": r.text,
                        "cve_id": r.cve_id,
                        "source_document_id": r.source_document_id,
                        "chunk_index": r.chunk_index,
                        "source_type": r.source_type,
                        "url": r.url,
                        "quality_score": r.quality_score,
                        "tlp": r.tlp,
                    },
                )
                for r in results
            ]
        elif body.collection == "sigma_rules":
            results = await embedder.search_sigma_rules(body.query, limit=body.limit)
            hits_payload = [
                SearchHit(
                    point_id=r.point_id,
                    score=r.score,
                    payload={
                        "rule_id": r.rule_id,
                        "sigma_uuid": r.sigma_uuid,
                        "title": r.title,
                        "technique_ids": r.technique_ids,
                        "status": r.status,
                        "logsource_product": r.logsource_product,
                        "logsource_service": r.logsource_service,
                        "origin": r.origin,
                    },
                )
                for r in results
            ]
        elif body.collection == "attck_techniques":
            results = await embedder.search_attck_techniques(body.query, limit=body.limit)
            hits_payload = [
                SearchHit(
                    point_id=r.point_id,
                    score=r.score,
                    payload={
                        "technique_id": r.technique_id,
                        "tactic_id": r.tactic_id,
                        "tactic_name": r.tactic_name,
                        "technique_name": r.technique_name,
                        "framework": r.framework,
                        "has_subtechniques": r.has_subtechniques,
                        "parent_technique_id": r.parent_technique_id,
                    },
                )
                for r in results
            ]
        elif body.collection == "attack_chains":
            # Raw Qdrant search — no typed helper exists yet (M11 ships it).
            vectors = await embedder._embed_texts([body.query])
            if not vectors:
                hits_payload = []
            else:
                client = embedder._qdrant()
                # query_points (not the removed .search()) — qdrant-client
                # >=1.18 dropped .search(); mirror embedder.py's typed helpers.
                response = await client.query_points(
                    collection_name=COLLECTION_ATTACK_CHAINS,
                    query=vectors[0],
                    limit=body.limit,
                    with_payload=True,
                )
                hits_payload = [
                    SearchHit(
                        point_id=str(h.id),
                        score=float(h.score),
                        payload=dict(h.payload or {}),
                    )
                    for h in response.points
                ]
        else:  # pragma: no cover — Literal validation forbids
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown collection {body.collection!r}",
            )

    return SearchResponse(
        collection=body.collection, query=body.query, hits=hits_payload
    )


__all__ = ["router"]
