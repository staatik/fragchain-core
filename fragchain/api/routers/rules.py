"""Rule generator API (M15).

Endpoints under ``/api/v1``:

  * ``GET    /rules``                                   — list with filters.
  * ``GET    /rules/{id}``                              — detail incl. YAML.
  * ``POST   /rules/{id}/validate``                     — run pySigma.
  * ``POST   /cves/{cve_id}/regenerate-rules``          — force regenerate
                                                          (queues M15 task).
  * ``POST   /matrix/{technique_id}/generate-rule``     — manual trigger for
                                                          one technique.

Reads honour TLP enforcement via the M2 middleware. The POST endpoints are
maintainer-only because they mutate review state and spend LLM budget.
"""
from __future__ import annotations

import uuid
from datetime import datetime
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
from fragchain.db.models import (
    CVE,
    AttackChainRow,
    ChainTTPRow,
    CoverageMap,
    ReviewQueueItem,
    SigmaRule,
)
from fragchain.db.session import get_db
from fragchain.ingest.state import set_processing_stage
from fragchain.rules.validator import ValidationResult, validate_yaml

logger = structlog.get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class RuleSummaryOut(BaseModel):
    id: str
    sigma_uuid: str | None
    chain_id: str | None
    cve_id: str | None
    cve_textual_id: str | None
    title: str
    status: str
    origin: str
    technique_ids: list[str] = Field(default_factory=list)
    logsource_product: str | None
    logsource_service: str | None
    logsource_profile: str | None
    detection_level: str | None
    tags: list[str] = Field(default_factory=list)
    tlp: str
    review_notes: str | None
    prompt_template_id: str | None
    created_at: datetime


class RuleListResponse(BaseModel):
    total: int
    rules: list[RuleSummaryOut]


class RuleDetailOut(RuleSummaryOut):
    sigma_yaml: str
    content_hash: str | None
    queue_status: str | None = None
    priority: str | None = None
    priority_score: int | None = None


class ValidateResponse(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class RegenerateResponse(BaseModel):
    status: str
    cve_id: str
    chain_id: str | None = None
    queued: bool


class GenerateForTechniqueResponse(BaseModel):
    status: str
    technique_id: str
    queued_chains: list[str] = Field(default_factory=list)
    message: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_summary(row: SigmaRule, cve_textual_id: str | None) -> RuleSummaryOut:
    return RuleSummaryOut(
        id=str(row.id),
        sigma_uuid=str(row.sigma_uuid) if row.sigma_uuid else None,
        chain_id=str(row.chain_id) if row.chain_id else None,
        cve_id=str(row.cve_id) if row.cve_id else None,
        cve_textual_id=cve_textual_id,
        title=row.title,
        status=row.status,
        origin=row.origin,
        technique_ids=list(row.technique_ids or []),
        logsource_product=row.logsource_product,
        logsource_service=row.logsource_service,
        logsource_profile=row.logsource_profile,
        detection_level=row.detection_level,
        tags=list(row.tags or []),
        tlp=row.tlp,
        review_notes=row.review_notes,
        prompt_template_id=(
            str(row.prompt_template_id) if row.prompt_template_id else None
        ),
        created_at=row.created_at,
    )


async def _enrich_with_cve_id(
    db: AsyncSession, rows: list[SigmaRule]
) -> dict[uuid.UUID, str]:
    """Resolve the textual CVE id (CVE-YYYY-NNNN) for each rule's ``cve_id`` FK."""
    ids = sorted({r.cve_id for r in rows if r.cve_id is not None})
    if not ids:
        return {}
    cves = (await db.execute(select(CVE).where(CVE.id.in_(ids)))).scalars().all()
    return {c.id: c.cve_id for c in cves}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/rules",
    response_model=RuleListResponse,
    dependencies=[Depends(require_authenticated)],
)
async def list_rules(
    request: Request,
    status_filter: str | None = Query(None, alias="status", max_length=20),
    technique: str | None = Query(None, max_length=20),
    origin: str | None = Query(None, max_length=20),
    logsource_profile: str | None = Query(None, max_length=50),
    cve_id: str | None = Query(None, max_length=30),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> RuleListResponse:
    stmt = select(SigmaRule)
    if status_filter:
        stmt = stmt.where(SigmaRule.status == status_filter)
    if technique:
        stmt = stmt.where(SigmaRule.technique_ids.contains([technique.upper()]))
    if origin:
        stmt = stmt.where(SigmaRule.origin == origin)
    if logsource_profile:
        stmt = stmt.where(SigmaRule.logsource_profile == logsource_profile)
    if cve_id:
        # Resolve textual CVE id → UUID first.
        cve_row = (
            await db.execute(
                select(CVE).where(CVE.cve_id == cve_id.upper())
            )
        ).scalar_one_or_none()
        if cve_row is None:
            return RuleListResponse(total=0, rules=[])
        stmt = stmt.where(SigmaRule.cve_id == cve_row.id)
    stmt = stmt.order_by(SigmaRule.created_at.desc()).limit(limit).offset(offset)
    rows = list((await db.execute(stmt)).scalars().all())

    user = get_request_user(request)
    visible = await apply_tlp_filter(db, rows, user)
    cve_lookup = await _enrich_with_cve_id(db, visible)

    return RuleListResponse(
        total=len(visible),
        rules=[
            _row_to_summary(r, cve_lookup.get(r.cve_id) if r.cve_id else None)
            for r in visible
        ],
    )


@router.get(
    "/rules/{rule_id}",
    response_model=RuleDetailOut,
    dependencies=[Depends(require_authenticated)],
)
async def get_rule(
    rule_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> RuleDetailOut:
    try:
        ruid = uuid.UUID(rule_id)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="rule id must be a valid UUID",
        ) from exc
    row = await db.get(SigmaRule, ruid)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="rule not found"
        )

    user = get_request_user(request)
    await enforce_tlp_access(db, row, user)

    cve_textual_id: str | None = None
    if row.cve_id:
        cve_row = await db.get(CVE, row.cve_id)
        if cve_row is not None:
            cve_textual_id = cve_row.cve_id

    queue = (
        await db.execute(
            select(ReviewQueueItem)
            .where(ReviewQueueItem.sigma_rule_id == row.id)
            .order_by(ReviewQueueItem.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    base = _row_to_summary(row, cve_textual_id)
    return RuleDetailOut(
        **base.model_dump(),
        sigma_yaml=row.sigma_yaml,
        content_hash=row.content_hash,
        queue_status=queue.status if queue else None,
        priority=queue.priority if queue else None,
        priority_score=int(queue.priority_score) if queue else None,
    )


@router.post(
    "/rules/{rule_id}/validate",
    response_model=ValidateResponse,
    dependencies=[Depends(require_authenticated)],
)
async def validate_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
) -> ValidateResponse:
    try:
        ruid = uuid.UUID(rule_id)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="rule id must be a valid UUID",
        ) from exc
    row = await db.get(SigmaRule, ruid)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="rule not found"
        )
    result: ValidationResult = validate_yaml(row.sigma_yaml or "")
    return ValidateResponse(
        valid=result.valid,
        errors=list(result.errors),
        warnings=list(result.warnings),
    )


@router.post(
    "/cves/{cve_id}/regenerate-rules",
    response_model=RegenerateResponse,
    dependencies=[Depends(require_maintainer)],
)
async def regenerate_rules_for_cve(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
) -> RegenerateResponse:
    """Force regenerate rules for a CVE's newest chain.

    Drops the CVE row back to ``processing_status='generating'`` and queues
    ``generate_rules`` for the newest chain. The Celery task's state-machine
    guard accepts both ``generating`` and ``complete`` so re-runs work
    cleanly.
    """
    cve_upper = cve_id.upper().strip()
    cve = (
        await db.execute(select(CVE).where(CVE.cve_id == cve_upper))
    ).scalar_one_or_none()
    if cve is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="CVE not found"
        )
    newest = (
        await db.execute(
            select(AttackChainRow)
            .where(AttackChainRow.cve_id == cve.id)
            .order_by(AttackChainRow.version.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if newest is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CVE has no chains yet — run synthesis first",
        )

    if cve.processing_status != "generating":
        await set_processing_stage(
            db,
            cve,
            new_status="generating",
            stage="generating",
            note=f"regenerate-rules api chain_id={newest.id}",
        )
        await db.commit()

    queued = False
    try:
        from fragchain.worker.celery import celery_app

        celery_app.send_task(
            "fragchain.worker.tasks.generate_rules",
            kwargs={"chain_id": str(newest.id)},
        )
        queued = True
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "rules.regenerate.queue_failed",
            cve_id=cve.cve_id,
            chain_id=str(newest.id),
            error=str(exc),
        )

    return RegenerateResponse(
        status="ok",
        cve_id=cve.cve_id,
        chain_id=str(newest.id),
        queued=queued,
    )


@router.post(
    "/matrix/{technique_id}/generate-rule",
    response_model=GenerateForTechniqueResponse,
    dependencies=[Depends(require_maintainer)],
)
async def generate_rule_for_technique(
    technique_id: str,
    db: AsyncSession = Depends(get_db),
) -> GenerateForTechniqueResponse:
    """Manual trigger: queue rule generation for every chain that contains a TTP for this technique.

    The matrix UI uses this when an analyst clicks "Generate rule" on a
    technique cell. We fan out one ``generate_rules`` task per distinct chain
    that has a TTP for the technique — the generator's profile loop will then
    produce variants for each enabled profile.
    """
    tid = technique_id.strip().upper()
    if not tid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="technique_id is required",
        )

    # Confirm the technique exists in the coverage map (sanity check).
    coverage = (
        await db.execute(
            select(CoverageMap)
            .where(CoverageMap.technique_id == tid)
            .limit(1)
        )
    ).scalar_one_or_none()
    if coverage is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"technique {tid} not found in coverage map",
        )

    # Find every chain that has a TTP for this technique.
    rows = (
        await db.execute(
            select(ChainTTPRow.chain_id)
            .where(ChainTTPRow.technique_id == tid)
            .distinct()
        )
    ).scalars().all()
    chain_ids = [str(c) for c in rows]
    if not chain_ids:
        return GenerateForTechniqueResponse(
            status="ok",
            technique_id=tid,
            queued_chains=[],
            message=(
                "No chains contain this technique yet — synthesize a chain "
                "before generating rules."
            ),
        )

    queued: list[str] = []
    try:
        from fragchain.worker.celery import celery_app

        for cid in chain_ids:
            celery_app.send_task(
                "fragchain.worker.tasks.generate_rules",
                kwargs={"chain_id": cid},
            )
            queued.append(cid)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "rules.matrix_generate.queue_failed",
            technique_id=tid,
            error=str(exc),
        )

    return GenerateForTechniqueResponse(
        status="ok",
        technique_id=tid,
        queued_chains=queued,
    )


__all__ = ["router"]
