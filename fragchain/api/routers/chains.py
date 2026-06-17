"""Attack chains API (M11).

Endpoints under ``/api/v1``:

  * ``GET    /chains``                       — list with filters (TLP-filtered).
  * ``GET    /chains/{id}``                  — detail incl. flattened TTPs.
  * ``GET    /cves/{cve_id}/chain``          — newest chain for a CVE.
  * ``PATCH  /chains/{id}/validate``         — mark a chain validated.
  * ``PATCH  /chains/{id}/reject``           — reject with a reason.
  * ``POST   /chains/{id}/contribute``       — push to commons via M7.
  * ``POST   /cves/{cve_id}/resynthesize``   — force a re-generation.

Reads honour TLP enforcement via the M2 middleware. The PATCH + POST
endpoints are maintainer-only because they mutate review state or spend
LLM budget.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.middleware.tlp_filter import (
    apply_tlp_filter,
    enforce_tlp_access,
    get_request_user,
    require_authenticated,
    require_maintainer,
)
from fragchain.audit import audit_entity_state_change
from fragchain.db.models import (
    CVE,
    AttackChainRow,
    ChainTTPRow,
)
from fragchain.db.session import get_db
from fragchain.ingest.state import set_processing_stage

logger = structlog.get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ChainTTPOut(BaseModel):
    id: str
    seq_order: int
    tactic: str | None
    tactic_id: str | None
    technique_id: str | None
    technique_name: str | None
    sub_technique_id: str | None
    framework: str
    confidence: float | None
    preconditions: list[Any]
    detection_opportunity: str | None
    source_refs: list[Any]


class ChainSummaryOut(BaseModel):
    id: str
    cve_id: str
    cve_textual_id: str | None
    version: int
    model: str | None
    provider: str | None
    overall_confidence: float | None
    predicted_impact: str | None
    detection_gaps: list[Any]
    tlp: str
    status: str
    source_origin: str
    commons_chain_id: str | None
    validated_by: str | None
    validated_at: datetime | None
    rejection_reason: str | None
    created_at: datetime


class ChainListResponse(BaseModel):
    total: int
    chains: list[ChainSummaryOut]


class ChainDetailOut(ChainSummaryOut):
    chain: list[Any] = Field(default_factory=list)
    sources_used: list[Any] = Field(default_factory=list)
    prompt_template_id: str | None
    ttps: list[ChainTTPOut] = Field(default_factory=list)


class ChainValidateRequest(BaseModel):
    note: str | None = None


class ChainRejectRequest(BaseModel):
    reason: str = Field(min_length=1)


class ChainContributeRequest(BaseModel):
    source_ids: list[str] | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _resolve_chain(db: AsyncSession, chain_id: str) -> AttackChainRow | None:
    try:
        chain_uuid = uuid.UUID(chain_id)
    except (ValueError, TypeError):
        return None
    return await db.get(AttackChainRow, chain_uuid)


async def _resolve_cve(db: AsyncSession, ident: str) -> CVE | None:
    """Accept either UUID or textual ``CVE-YYYY-NNNN`` form."""
    try:
        cve_uuid = uuid.UUID(ident)
        result = await db.execute(select(CVE).where(CVE.id == cve_uuid))
    except (ValueError, TypeError):
        result = await db.execute(select(CVE).where(CVE.cve_id == ident.upper()))
    return result.scalar_one_or_none()


def _summary(row: AttackChainRow, cve_textual_id: str | None) -> ChainSummaryOut:
    return ChainSummaryOut(
        id=str(row.id),
        cve_id=str(row.cve_id),
        cve_textual_id=cve_textual_id,
        version=int(row.version),
        model=row.model,
        provider=row.provider,
        overall_confidence=(
            float(row.overall_confidence) if row.overall_confidence is not None else None
        ),
        predicted_impact=row.predicted_impact,
        detection_gaps=list(row.detection_gaps or []),
        tlp=row.tlp,
        status=row.status,
        source_origin=row.source_origin,
        commons_chain_id=row.commons_chain_id,
        validated_by=row.validated_by,
        validated_at=row.validated_at,
        rejection_reason=row.rejection_reason,
        created_at=row.created_at,
    )


def _ttp_out(row: ChainTTPRow) -> ChainTTPOut:
    return ChainTTPOut(
        id=str(row.id),
        seq_order=int(row.seq_order),
        tactic=row.tactic,
        tactic_id=row.tactic_id,
        technique_id=row.technique_id,
        technique_name=row.technique_name,
        sub_technique_id=row.sub_technique_id,
        framework=row.framework,
        confidence=float(row.confidence) if row.confidence is not None else None,
        preconditions=list(row.preconditions or []),
        detection_opportunity=row.detection_opportunity,
        source_refs=list(row.source_refs or []),
    )


def _detail(
    row: AttackChainRow,
    *,
    cve_textual_id: str | None,
    ttps: list[ChainTTPRow],
) -> ChainDetailOut:
    return ChainDetailOut(
        id=str(row.id),
        cve_id=str(row.cve_id),
        cve_textual_id=cve_textual_id,
        version=int(row.version),
        model=row.model,
        provider=row.provider,
        overall_confidence=(
            float(row.overall_confidence) if row.overall_confidence is not None else None
        ),
        predicted_impact=row.predicted_impact,
        detection_gaps=list(row.detection_gaps or []),
        tlp=row.tlp,
        status=row.status,
        source_origin=row.source_origin,
        commons_chain_id=row.commons_chain_id,
        validated_by=row.validated_by,
        validated_at=row.validated_at,
        rejection_reason=row.rejection_reason,
        created_at=row.created_at,
        chain=list(row.chain or []),
        sources_used=list(row.sources_used or []),
        prompt_template_id=(
            str(row.prompt_template_id) if row.prompt_template_id else None
        ),
        ttps=[_ttp_out(t) for t in sorted(ttps, key=lambda r: int(r.seq_order))],
    )


async def _cve_textual_id(db: AsyncSession, cve_pk: uuid.UUID) -> str | None:
    cve = await db.get(CVE, cve_pk)
    return cve.cve_id if cve is not None else None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/chains", response_model=ChainListResponse)
async def list_chains(
    request: Request,
    status_filter: str | None = Query(default=None, alias="status"),
    min_confidence: float | None = Query(default=None, ge=0.0, le=1.0),
    cve_id: str | None = Query(default=None),
    source_origin: str | None = Query(default=None, pattern=r"^(local|commons)$"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> ChainListResponse:
    """List attack chains with optional filters.

    ``cve_id`` accepts either the textual ``CVE-YYYY-NNNN`` form or the row's
    UUID. Responses are TLP-filtered post-load.
    """
    stmt = select(AttackChainRow).order_by(AttackChainRow.created_at.desc())
    if status_filter:
        stmt = stmt.where(AttackChainRow.status == status_filter)
    if min_confidence is not None:
        stmt = stmt.where(AttackChainRow.overall_confidence >= min_confidence)
    if source_origin:
        stmt = stmt.where(AttackChainRow.source_origin == source_origin)
    if cve_id:
        cve_row = await _resolve_cve(db, cve_id)
        if cve_row is None:
            return ChainListResponse(total=0, chains=[])
        stmt = stmt.where(AttackChainRow.cve_id == cve_row.id)
    rows = (await db.execute(stmt)).scalars().all()
    user = get_request_user(request)
    visible = await apply_tlp_filter(db, list(rows), user)
    sliced = visible[offset : offset + limit]
    # Resolve textual CVE ids in one round-trip rather than N.
    cve_ids = {r.cve_id for r in sliced}
    textual_map: dict[uuid.UUID, str] = {}
    if cve_ids:
        cve_rows = (
            await db.execute(select(CVE).where(CVE.id.in_(cve_ids)))
        ).scalars().all()
        textual_map = {c.id: c.cve_id for c in cve_rows}
    return ChainListResponse(
        total=len(visible),
        chains=[_summary(r, textual_map.get(r.cve_id)) for r in sliced],
    )


@router.get("/chains/{chain_id}", response_model=ChainDetailOut)
async def get_chain(
    chain_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> ChainDetailOut:
    chain = await _resolve_chain(db, chain_id)
    if chain is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Chain not found"
        )
    user = get_request_user(request)
    await enforce_tlp_access(db, chain, user)
    ttps = (
        await db.execute(
            select(ChainTTPRow).where(ChainTTPRow.chain_id == chain.id)
        )
    ).scalars().all()
    return _detail(
        chain,
        cve_textual_id=await _cve_textual_id(db, chain.cve_id),
        ttps=list(ttps),
    )


@router.get("/cves/{cve_id}/chain", response_model=ChainDetailOut)
async def get_chain_for_cve(
    cve_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> ChainDetailOut:
    """Return the newest chain for ``cve_id`` (textual or UUID).

    "Newest" = highest ``version``. Validated chains beat draft ones at the
    same version, but the typical flow never produces two same-version rows
    (UNIQUE(cve_id, version) at the DB layer).
    """
    cve = await _resolve_cve(db, cve_id)
    if cve is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="CVE not found"
        )
    await enforce_tlp_access(db, cve, get_request_user(request))
    chain = (
        await db.execute(
            select(AttackChainRow)
            .where(AttackChainRow.cve_id == cve.id)
            .order_by(AttackChainRow.version.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if chain is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="No chain for CVE"
        )
    await enforce_tlp_access(db, chain, get_request_user(request))
    ttps = (
        await db.execute(
            select(ChainTTPRow).where(ChainTTPRow.chain_id == chain.id)
        )
    ).scalars().all()
    return _detail(chain, cve_textual_id=cve.cve_id, ttps=list(ttps))


@router.patch("/chains/{chain_id}/validate", response_model=ChainDetailOut)
async def validate_chain(
    chain_id: str,
    payload: ChainValidateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> ChainDetailOut:
    chain = await _resolve_chain(db, chain_id)
    if chain is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Chain not found"
        )
    await enforce_tlp_access(db, chain, get_request_user(request))
    previous_status = chain.status
    chain.status = "validated"
    chain.validated_by = user.username if user else None
    chain.validated_at = datetime.now(tz=timezone.utc)
    chain.rejection_reason = None  # clear any prior rejection
    # Audit row before the commit so it lands in the same transaction as
    # the state change (Phase 4 audit Drift D2 / CLAUDE.md §19).
    await audit_entity_state_change(
        db,
        entity_type="chain",
        entity_id=chain.id,
        action="chain.validated",
        before={"status": previous_status},
        after={
            "status": "validated",
            "validated_by": chain.validated_by,
            "note": payload.note,
        },
        actor=user.id if user else None,
    )
    await db.commit()
    ttps = (
        await db.execute(
            select(ChainTTPRow).where(ChainTTPRow.chain_id == chain.id)
        )
    ).scalars().all()
    logger.info(
        "chain.validated",
        chain_id=str(chain.id),
        actor=user.username if user else None,
        note=payload.note,
    )
    return _detail(
        chain,
        cve_textual_id=await _cve_textual_id(db, chain.cve_id),
        ttps=list(ttps),
    )


@router.patch("/chains/{chain_id}/reject", response_model=ChainDetailOut)
async def reject_chain(
    chain_id: str,
    payload: ChainRejectRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> ChainDetailOut:
    chain = await _resolve_chain(db, chain_id)
    if chain is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Chain not found"
        )
    await enforce_tlp_access(db, chain, get_request_user(request))
    previous_status = chain.status
    chain.status = "rejected"
    chain.validated_by = user.username if user else None
    chain.validated_at = datetime.now(tz=timezone.utc)
    chain.rejection_reason = payload.reason
    # Audit row before the commit so it lands in the same transaction as
    # the state change (Phase 4 audit Drift D2 / CLAUDE.md §19).
    await audit_entity_state_change(
        db,
        entity_type="chain",
        entity_id=chain.id,
        action="chain.rejected",
        before={"status": previous_status},
        after={
            "status": "rejected",
            "validated_by": chain.validated_by,
        },
        actor=user.id if user else None,
        reason=payload.reason,
    )
    await db.commit()
    ttps = (
        await db.execute(
            select(ChainTTPRow).where(ChainTTPRow.chain_id == chain.id)
        )
    ).scalars().all()
    logger.info(
        "chain.rejected",
        chain_id=str(chain.id),
        actor=user.username if user else None,
        reason=payload.reason,
    )
    return _detail(
        chain,
        cve_textual_id=await _cve_textual_id(db, chain.cve_id),
        ttps=list(ttps),
    )


@router.post(
    "/chains/{chain_id}/contribute", status_code=status.HTTP_202_ACCEPTED
)
async def contribute_chain(
    chain_id: str,
    payload: ChainContributeRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> dict[str, Any]:
    """Push this chain to one or more commons sources via M7."""
    chain = await _resolve_chain(db, chain_id)
    if chain is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Chain not found"
        )
    await enforce_tlp_access(db, chain, get_request_user(request))
    cve_textual_id = await _cve_textual_id(db, chain.cve_id)
    if cve_textual_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="CVE row missing"
        )

    parsed_ids: list[uuid.UUID] | None = None
    if payload.source_ids:
        parsed_ids = []
        for raw in payload.source_ids:
            try:
                parsed_ids.append(uuid.UUID(raw))
            except (ValueError, TypeError) as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"invalid source_id {raw!r}",
                ) from exc

    chain_payload: dict[str, Any] = {
        "cve_id": cve_textual_id,
        "version": int(chain.version),
        "model": chain.model,
        "provider": chain.provider,
        "overall_confidence": (
            float(chain.overall_confidence) if chain.overall_confidence is not None else 0.0
        ),
        "predicted_impact": chain.predicted_impact or "",
        "detection_gaps": list(chain.detection_gaps or []),
        "tlp": chain.tlp,
        "source_origin": "local",
        "chain": list(chain.chain or []),
        "sources_used": list(chain.sources_used or []),
    }

    from fragchain.commons import CommonsClient

    client = CommonsClient(db)
    actor = user.username if user else None
    result = await client.contribute_chain(
        cve_id=cve_textual_id,
        chain_payload=chain_payload,
        actor_username=actor,
        source_ids=parsed_ids,
    )
    return {
        "status": "queued",
        "chain_id": str(chain.id),
        "cve_id": cve_textual_id,
        "submitted": result.submitted,
        "failed": result.failures,
        "per_source": [
            {
                "source_id": str(r.source_id),
                "source_name": r.source_name,
                "status": r.status,
                "pr_url": r.pr_url,
                "message": r.message,
            }
            for r in result.per_source
        ],
    }


@router.post(
    "/cves/{cve_id}/resynthesize", status_code=status.HTTP_202_ACCEPTED
)
async def resynthesize_cve(
    cve_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> dict[str, Any]:
    """Force a fresh chain synthesis for ``cve_id``.

    Pushes the CVE row to ``synthesizing`` (bypassing the enrichment loop —
    we assume the enrichment data is still fresh enough). The next worker
    cycle picks up ``synthesize_chain``.
    """
    cve = await _resolve_cve(db, cve_id)
    if cve is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="CVE not found"
        )
    await enforce_tlp_access(db, cve, get_request_user(request))
    actor_id = user.id if user else None
    await set_processing_stage(
        db,
        cve,
        new_status="synthesizing",
        stage="synthesizing",
        actor=actor_id,
        note="manual resynthesize",
    )
    await db.commit()
    try:
        from fragchain.worker.celery import celery_app

        celery_app.send_task(
            "fragchain.worker.tasks.synthesize_chain",
            kwargs={"cve_id": cve.cve_id},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "chain.resynthesize.enqueue_failed",
            cve_id=cve.cve_id,
            error=str(exc),
        )
    return {"status": "queued", "cve_id": cve.cve_id}


__all__ = ["router"]
