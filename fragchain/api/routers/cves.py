"""CVE API — list, detail, and reprocess (M6).

Read endpoints honour TLP enforcement via the M2 middleware (``apply_tlp_filter``
and ``enforce_tlp_access``). Reprocess is maintainer-only because it bumps an
LLM budget item.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.middleware.tlp_filter import (
    apply_tlp_filter,
    enforce_tlp_access,
    get_request_user,
    require_authenticated,
    require_maintainer,
)
from fragchain.db.models import CVE, SourceDocument
from fragchain.db.session import get_db
from fragchain.assessments.cve_summary import (
    CveAssessmentSummary,
    rule_counts_for_cves,
    summarize_assessments_for_cves,
)
from fragchain.ingest.state import set_processing_stage

logger = structlog.get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CVEOut(BaseModel):
    id: str
    cve_id: str
    title: str | None
    description: str | None
    published_at: datetime | None
    modified_at: datetime | None
    cvss_score: float | None
    cvss_vector: str | None
    cisa_kev: bool
    cisa_kev_date: datetime | None
    epss_score: float | None
    epss_percentile: float | None
    attackerkb_score: float | None
    ctid_techniques: list[Any]
    affected_products: Any
    import_mode: str
    processing_status: str
    processing_stage: str | None
    processing_error: str | None
    approved_by: str | None
    approved_at: datetime | None
    import_job_id: str | None
    enrichment_sources: dict[str, Any]
    tlp: str
    embargo_until: datetime | None
    created_at: datetime
    updated_at: datetime
    # Badging spec (2026-06-10): populated by the list endpoint for the
    # returned page. ``assessment`` is None when the CVE has no assessment
    # OR the requester can't read it (F-002 uniform surface).
    rule_count: int | None = None
    assessment: CveAssessmentSummary | None = None


class CVEListResponse(BaseModel):
    total: int
    cves: list[CVEOut]


class SourceDocumentOut(BaseModel):
    id: str
    url: str
    source_type: str | None
    quality_score: float | None
    tlp: str
    embedded: bool
    processed: bool
    content_hash: str | None
    byte_size: int | None
    created_at: datetime


class CVEDetailOut(CVEOut):
    documents: list[SourceDocumentOut] = Field(default_factory=list)


class SuggestResponse(BaseModel):
    suggestions: list[str] = Field(default_factory=list)


_SUGGEST_FIELDS = {"vendor", "product"}
_SUGGEST_CACHE_TTL_SECONDS = 300


import re

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_MANUAL_DESCRIPTION_MIN = 40        # too short → LLM can't synthesize anything useful
_MANUAL_DESCRIPTION_MAX = 64_000    # bytes; matches the inline-doc ceiling in M6
_MANUAL_REF_MAX = 12                # cap reference list


class ManualSource(BaseModel):
    """An extra source document the operator wants attached to the CVE."""

    url: str = Field(min_length=1, max_length=2048)
    content: str = Field(min_length=1, max_length=_MANUAL_DESCRIPTION_MAX)
    source_type: str = Field(default="manual", max_length=40)
    quality_score: float | None = Field(default=None, ge=0.0, le=1.0)


class ManualCveCreate(BaseModel):
    cve_id: str = Field(min_length=8, max_length=20)
    description: str = Field(
        min_length=_MANUAL_DESCRIPTION_MIN, max_length=_MANUAL_DESCRIPTION_MAX
    )
    references: list[str] = Field(default_factory=list, max_length=_MANUAL_REF_MAX)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = Field(default=None, max_length=200)
    cisa_kev: bool = False
    affected_products: list[dict[str, Any]] = Field(default_factory=list, max_length=64)
    tlp: str = "tlp:clear"
    additional_sources: list[ManualSource] = Field(default_factory=list, max_length=16)


class ManualCveResponse(BaseModel):
    id: str
    cve_id: str
    status: str
    documents_inserted: int
    synthesis_queued: bool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_out(cve: CVE) -> CVEOut:
    return CVEOut(
        id=str(cve.id),
        cve_id=cve.cve_id,
        title=cve.title,
        description=cve.description,
        published_at=cve.published_at,
        modified_at=cve.modified_at,
        cvss_score=float(cve.cvss_score) if cve.cvss_score is not None else None,
        cvss_vector=cve.cvss_vector,
        cisa_kev=bool(cve.cisa_kev),
        cisa_kev_date=cve.cisa_kev_date,
        epss_score=float(cve.epss_score) if cve.epss_score is not None else None,
        epss_percentile=(
            float(cve.epss_percentile) if cve.epss_percentile is not None else None
        ),
        attackerkb_score=(
            float(cve.attackerkb_score) if cve.attackerkb_score is not None else None
        ),
        ctid_techniques=list(cve.ctid_techniques or []),
        affected_products=cve.affected_products,
        import_mode=cve.import_mode,
        processing_status=cve.processing_status,
        processing_stage=cve.processing_stage,
        processing_error=cve.processing_error,
        approved_by=cve.approved_by,
        approved_at=cve.approved_at,
        import_job_id=str(cve.import_job_id) if cve.import_job_id else None,
        enrichment_sources=dict(cve.enrichment_sources or {}),
        tlp=cve.tlp,
        embargo_until=cve.embargo_until,
        created_at=cve.created_at,
        updated_at=cve.updated_at,
    )


def _to_document_out(doc: SourceDocument) -> SourceDocumentOut:
    return SourceDocumentOut(
        id=str(doc.id),
        url=doc.url,
        source_type=doc.source_type,
        quality_score=float(doc.quality_score) if doc.quality_score is not None else None,
        tlp=doc.tlp,
        embedded=doc.embedded,
        processed=doc.processed,
        content_hash=doc.content_hash,
        byte_size=doc.byte_size,
        created_at=doc.created_at,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/cves", response_model=CVEListResponse)
async def list_cves(
    request: Request,
    kev: bool | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    import_mode: str | None = Query(default=None),
    cvss_min: float | None = Query(default=None, ge=0.0, le=10.0),
    published_after: datetime | None = Query(default=None),
    published_before: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> CVEListResponse:
    """List CVEs. Filters compose with AND.

    Responses are TLP-filtered: rows the caller can't read are stripped out
    before returning, and the total reflects only what they're allowed to see.
    """
    stmt = select(CVE).order_by(CVE.published_at.desc().nullslast())
    if kev is not None:
        stmt = stmt.where(CVE.cisa_kev.is_(kev))
    if status_filter:
        stmt = stmt.where(CVE.processing_status == status_filter)
    if import_mode:
        stmt = stmt.where(CVE.import_mode == import_mode)
    if cvss_min is not None:
        stmt = stmt.where(CVE.cvss_score >= cvss_min)
    if published_after:
        stmt = stmt.where(CVE.published_at >= published_after)
    if published_before:
        stmt = stmt.where(CVE.published_at <= published_before)

    # Apply TLP filter post-load (DB-side filtering would skip grant logic).
    rows = (await db.execute(stmt)).scalars().all()
    user = get_request_user(request)
    visible = await apply_tlp_filter(db, list(rows), user)
    sliced = visible[offset : offset + limit]
    outs = [_to_out(r) for r in sliced]
    # Badge data for the returned page only — constant number of batched
    # queries, advisory (failures degrade to no badges, never a 500).
    page_ids = [r.id for r in sliced]
    summaries = await summarize_assessments_for_cves(db, page_ids, user=user)
    rule_counts = await rule_counts_for_cves(db, page_ids)
    for row, out in zip(sliced, outs, strict=True):
        out.assessment = summaries.get(row.id)
        out.rule_count = rule_counts.get(row.id, 0)
    return CVEListResponse(total=len(visible), cves=outs)


@router.get("/cves/suggest", response_model=SuggestResponse)
async def suggest_cves(
    field: str = Query(..., description="Field to suggest: 'vendor' or 'product'"),
    q: str = Query(..., min_length=1, max_length=100),
    limit: int = Query(default=10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> SuggestResponse:
    """Autocomplete vendor/product names from ``cves.affected_products``.

    Backs the M23 Import Manager's vendor/product text inputs. Returns the
    distinct values present in the JSONB column, ordered by frequency
    (most-common first), with a 5-minute Redis cache. Names are not
    sensitive so this endpoint does not TLP-filter; gating is at the
    auth layer (any authenticated user).
    """
    if field not in _SUGGEST_FIELDS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="field must be 'vendor' or 'product'",
        )

    cache_key = f"suggest:{field}:{q.lower()}:{limit}"
    cached = await _suggest_cache_get(cache_key)
    if cached is not None:
        return SuggestResponse(suggestions=cached)

    sql = text(
        """
        SELECT v->>:field AS val, COUNT(*) AS cnt
        FROM (
            SELECT affected_products
            FROM cves
            WHERE jsonb_typeof(affected_products) = 'array'
        ) c
        CROSS JOIN LATERAL jsonb_array_elements(c.affected_products) AS v
        WHERE jsonb_typeof(v) = 'object'
          AND v ? :field
          AND v->>:field ILIKE :pat
        GROUP BY 1
        ORDER BY cnt DESC, val ASC
        LIMIT :limit
        """
    ).bindparams(field=field, pat=f"{q}%", limit=limit)

    try:
        rows = (await db.execute(sql)).all()
    except Exception as exc:  # noqa: BLE001 — defensive, e.g. SQLite in tests
        logger.warning("cves.suggest.query_failed", error=str(exc), field=field)
        return SuggestResponse(suggestions=[])

    suggestions = [r[0] for r in rows if r[0]]
    await _suggest_cache_set(cache_key, suggestions)
    return SuggestResponse(suggestions=suggestions)


@router.get("/cves/{cve_id}", response_model=CVEDetailOut)
async def get_cve(
    cve_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> CVEDetailOut:
    """Fetch one CVE with its attached source documents.

    Accepts either the textual ``CVE-2026-43284`` form or a UUID. Raises 403
    if the caller's clearance doesn't match the row's effective TLP.
    """
    cve = await _resolve_cve(db, cve_id)
    if cve is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="CVE not found",
        )
    user = get_request_user(request)
    await enforce_tlp_access(db, cve, user)

    docs = (
        await db.execute(select(SourceDocument).where(SourceDocument.cve_id == cve.id))
    ).scalars().all()
    visible_docs = await apply_tlp_filter(db, list(docs), user)
    out = CVEDetailOut(**_to_out(cve).model_dump())
    out.documents = [_to_document_out(d) for d in visible_docs]
    return out


@router.post(
    "/cves/manual",
    response_model=ManualCveResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_manual_cve(
    body: ManualCveCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> ManualCveResponse:
    """Manually create a CVE from operator-supplied text + references.

    Bypasses the connector ingest path. Use when:
      * The CVE isn't in OpenCTI / NVD yet (zero-day, internal advisory).
      * You want to evaluate the platform with a hand-crafted fixture.
      * A connector is offline and you have the advisory text in hand.

    Inserts a ``cves`` row plus one ``source_documents`` row carrying the
    pasted ``description`` (markdown OK; stays inline in
    ``document_metadata.content``). Each ``references`` URL becomes its own
    minimal source row so the LLM can cite them per the chain-generation
    prompt's Rule 4. Additional structured sources (``additional_sources``)
    are persisted with their full content.

    On success the synth task is dispatched immediately — the operator can
    open ``/chains/<cve_id>`` and watch the chain materialise.

    Rejects:
      * malformed CVE id (must match ``CVE-YYYY-NNNN+``)
      * description shorter than 40 chars (LLM can't produce a chain
        from a sentence fragment)
      * an existing CVE with this id (use ``/cves/{id}/resynthesize``
        to re-analyse instead)
    """
    cve_id_norm = body.cve_id.strip().upper()
    if not _CVE_ID_RE.match(cve_id_norm):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "cve_id must match the pattern 'CVE-YYYY-NNNN' "
                "(e.g. CVE-2026-43284); year ≥ 1999."
            ),
        )

    existing = await db.execute(select(CVE).where(CVE.cve_id == cve_id_norm))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"{cve_id_norm} already exists. To re-analyse, POST to "
                f"/api/v1/cves/{cve_id_norm}/resynthesize instead."
            ),
        )

    tlp = body.tlp or "tlp:clear"
    affected_products = body.affected_products or []

    cve = CVE(
        cve_id=cve_id_norm,
        import_mode="manual",
        processing_status="pending",
        cvss_score=body.cvss_score,
        cvss_vector=body.cvss_vector,
        cisa_kev=body.cisa_kev,
        affected_products=affected_products,
        description=body.description,
        tlp=tlp,
        raw_connector_data={
            "last_source": "manual",
            "submitted_by": user.username if user else None,
            "submitted_at": datetime.utcnow().isoformat() + "Z",
            "raw": {
                "manual": True,
            },
        },
    )
    db.add(cve)
    await db.flush()  # assign cve.id before we attach source_documents

    # Build the source-document set. The primary doc carries the operator's
    # pasted body; reference URLs become lightweight ref-only rows so the
    # LLM has something to cite per the chain prompt's source_refs contract.
    docs: list[dict[str, Any]] = [
        {
            "url": f"manual://{cve_id_norm}",
            "content": body.description,
            "source_type": "manual-advisory",
            "quality_score": 0.9,
            "connector": "manual",
            "tlp": tlp,
        }
    ]
    for ref_url in body.references:
        ref_url = ref_url.strip()
        if not ref_url:
            continue
        docs.append(
            {
                "url": ref_url,
                "content": "",  # ref-only; the LLM may have crawled this elsewhere
                "source_type": "reference",
                "quality_score": 0.5,
                "connector": "manual",
                "tlp": tlp,
            }
        )
    for extra in body.additional_sources:
        docs.append(
            {
                "url": extra.url,
                "content": extra.content,
                "source_type": extra.source_type or "manual",
                "quality_score": extra.quality_score,
                "connector": "manual",
                "tlp": tlp,
            }
        )

    from fragchain.ingest.service import persist_documents

    inserted = await persist_documents(db, cve, docs)

    # Manual entries skip the enrichment loop — the operator already
    # provided the description, references, and metadata. Flip the row
    # straight to ``synthesizing`` so the worker's synthesize_chain
    # task picks it up on next dispatch (the task refuses to run on a
    # ``pending`` row).
    actor_id = user.id if user else None
    await set_processing_stage(
        db,
        cve,
        new_status="synthesizing",
        stage="synthesizing",
        actor=actor_id,
        note="manual cve add",
    )
    await db.commit()

    logger.info(
        "cve.manual.created",
        cve_id=cve_id_norm,
        documents_inserted=inserted,
        actor=user.username if user else None,
    )

    synthesis_queued = False
    try:
        from fragchain.worker.celery import celery_app

        celery_app.send_task(
            "fragchain.worker.tasks.synthesize_chain",
            kwargs={"cve_id": cve_id_norm},
        )
        synthesis_queued = True
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "cve.manual.enqueue_failed", cve_id=cve_id_norm, error=str(exc)
        )

    return ManualCveResponse(
        id=str(cve.id),
        cve_id=cve_id_norm,
        status=cve.processing_status,
        documents_inserted=inserted,
        synthesis_queued=synthesis_queued,
    )


@router.post("/cves/{cve_id}/reprocess", status_code=status.HTTP_202_ACCEPTED)
async def reprocess_cve(
    cve_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> dict[str, Any]:
    """Force a CVE back through the enrichment + synthesis pipeline.

    Acceptable from any terminal status (complete / failed / skipped). The
    row drops to ``pending`` and the next ``enforce_budget`` tick (or an
    immediate ``enrich_cve`` task) picks it up.
    """
    cve = await _resolve_cve(db, cve_id)
    if cve is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="CVE not found",
        )
    await enforce_tlp_access(db, cve, get_request_user(request))
    actor_id = user.id if user else None
    await set_processing_stage(
        db, cve, new_status="pending", stage=None, actor=actor_id, note="reprocess"
    )
    await db.commit()
    # Best-effort: try to dispatch immediately; budget task is the safety net.
    try:
        from fragchain.worker.celery import celery_app

        celery_app.send_task(
            "fragchain.worker.tasks.enrich_cve",
            kwargs={"cve_id": cve.cve_id},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "cve.reprocess.enqueue_failed", cve_id=cve.cve_id, error=str(exc)
        )
    return {"status": "queued", "cve_id": cve.cve_id, "id": str(cve.id)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _resolve_cve(db: AsyncSession, ident: str) -> CVE | None:
    """Look up a CVE by either UUID or textual ID."""
    try:
        cve_uuid = uuid.UUID(ident)
        result = await db.execute(select(CVE).where(CVE.id == cve_uuid))
    except (ValueError, TypeError):
        result = await db.execute(select(CVE).where(CVE.cve_id == ident.upper()))
    return result.scalar_one_or_none()


# ---------------------------------------------------------------------------
# Redis cache for /cves/suggest
# ---------------------------------------------------------------------------


async def _suggest_redis_client() -> Any | None:
    try:
        import redis.asyncio as aioredis  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001
        logger.debug("cves.suggest.redis_unavailable", error=str(exc))
        return None
    from fragchain.config import get_settings

    try:
        return aioredis.from_url(
            get_settings().redis_url,
            socket_connect_timeout=2,
            socket_timeout=2,
            decode_responses=True,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("cves.suggest.redis_connect_failed", error=str(exc))
        return None


async def _suggest_cache_get(key: str) -> list[str] | None:
    client = await _suggest_redis_client()
    if client is None:
        return None
    try:
        raw = await client.get(key)
    except Exception as exc:  # noqa: BLE001
        logger.warning("cves.suggest.cache_get_failed", key=key, error=str(exc))
        return None
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return payload if isinstance(payload, list) else None


async def _suggest_cache_set(key: str, suggestions: list[str]) -> None:
    client = await _suggest_redis_client()
    if client is None:
        return
    try:
        await client.set(
            key, json.dumps(suggestions), ex=_SUGGEST_CACHE_TTL_SECONDS
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("cves.suggest.cache_set_failed", key=key, error=str(exc))


__all__ = ["router"]
