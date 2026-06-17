"""Coverage + ATT&CK Matrix API (M14).

Endpoints under ``/api/v1``:

  * ``GET /coverage``                — every technique with current coverage.
  * ``GET /coverage/{technique_id}`` — one technique, with CVE + rule lists.
  * ``GET /matrix``                  — full ATT&CK matrix (Redis-cached).
  * ``GET /matrix/{technique_id}``   — alias for ``/coverage/{technique_id}``.
  * ``POST /coverage/recompute``     — admin-only, re-runs the mapper on one
                                       chain (or every chain when omitted).

Reads are open to authenticated users — there are no TLP-bearing fields in
``coverage_map`` itself (the table holds aggregates). The detail endpoint
filters the CVE list per request using the standard TLP middleware.
"""
from __future__ import annotations

import uuid
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.middleware.tlp_filter import (
    apply_tlp_filter,
    get_request_user,
    require_authenticated,
    require_maintainer,
)
from fragchain.assessments.access import load_assessment_for_read
from fragchain.assessments.service import AssessmentNotFoundError
from fragchain.coverage import (
    CoverageMapper,
    CoverageMappingError,
    DEFAULT_FRAMEWORK,
    MatrixCache,
    MatrixFilters,
)
from fragchain.db.models import (
    CVE,
    AttackChainRow,
    CoverageMap,
    SigmaRule,
)
from fragchain.db.session import get_db

logger = structlog.get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CoverageRowOut(BaseModel):
    technique_id: str
    sub_technique_id: str | None
    parent_technique_id: str | None
    tactic_id: str | None
    tactic_name: str | None
    technique_name: str | None
    framework: str
    coverage_status: str
    covering_rule_count: int
    chain_cve_count: int
    kev_cve_count: int
    kev_exposed: bool
    has_subtechniques: bool


class CoverageListResponse(BaseModel):
    framework: str
    total: int
    rows: list[CoverageRowOut]


class CoverageDetailRule(BaseModel):
    id: str
    title: str
    status: str
    origin: str
    technique_ids: list[str] = Field(default_factory=list)
    logsource_product: str | None
    logsource_service: str | None


class CoverageDetailCve(BaseModel):
    id: str
    cve_id: str
    cvss_score: float | None
    cisa_kev: bool
    epss_score: float | None
    tlp: str


class CoverageDetailOut(CoverageRowOut):
    description: str | None = None
    covering_rules: list[CoverageDetailRule] = Field(default_factory=list)
    chain_cves: list[CoverageDetailCve] = Field(default_factory=list)


class RecomputeRequest(BaseModel):
    chain_id: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_out(row: CoverageMap) -> CoverageRowOut:
    return CoverageRowOut(
        technique_id=row.technique_id,
        sub_technique_id=row.sub_technique_id,
        parent_technique_id=row.parent_technique_id,
        tactic_id=row.tactic_id,
        tactic_name=row.tactic_name,
        technique_name=row.technique_name,
        framework=row.framework,
        coverage_status=row.coverage_status,
        covering_rule_count=len(list(row.covering_rule_ids or [])),
        chain_cve_count=int(row.chain_cve_count or 0),
        kev_cve_count=int(row.kev_cve_count or 0),
        kev_exposed=bool(row.kev_exposed),
        has_subtechniques=bool(row.has_subtechniques),
    )


def _parse_filters(
    framework: str,
    cve_id: str | None,
    date_from: str | None,
    date_to: str | None,
    cvss_min: float | None,
    kev_only: bool,
    tactic_id: str | None,
    assessment_id: uuid.UUID | None = None,
) -> MatrixFilters:
    return MatrixFilters(
        framework=framework or DEFAULT_FRAMEWORK,
        cve_id=cve_id,
        date_from=date_from,
        date_to=date_to,
        cvss_min=cvss_min,
        kev_only=kev_only,
        tactic_id=tactic_id,
        assessment_id=assessment_id,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/coverage",
    response_model=CoverageListResponse,
    dependencies=[Depends(require_authenticated)],
)
async def list_coverage(
    framework: str = Query(DEFAULT_FRAMEWORK, max_length=20),
    coverage_status: str | None = Query(None, max_length=20),
    tactic_id: str | None = Query(None, max_length=10),
    kev_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
) -> CoverageListResponse:
    stmt = select(CoverageMap).where(CoverageMap.framework == framework)
    if coverage_status:
        stmt = stmt.where(CoverageMap.coverage_status == coverage_status)
    if tactic_id:
        stmt = stmt.where(CoverageMap.tactic_id == tactic_id)
    if kev_only:
        stmt = stmt.where(CoverageMap.kev_exposed.is_(True))
    stmt = stmt.order_by(
        CoverageMap.tactic_id.asc().nullslast(),
        CoverageMap.technique_id.asc(),
    )
    rows = list((await db.execute(stmt)).scalars().all())
    return CoverageListResponse(
        framework=framework,
        total=len(rows),
        rows=[_row_to_out(r) for r in rows],
    )


@router.get(
    "/coverage/{technique_id}",
    response_model=CoverageDetailOut,
    dependencies=[Depends(require_authenticated)],
)
async def get_coverage_detail(
    technique_id: str,
    request: Request,
    framework: str = Query(DEFAULT_FRAMEWORK, max_length=20),
    db: AsyncSession = Depends(get_db),
) -> CoverageDetailOut:
    stmt = (
        select(CoverageMap)
        .where(CoverageMap.technique_id == technique_id)
        .where(CoverageMap.framework == framework)
        .limit(1)
    )
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"technique {technique_id} not found in framework {framework}",
        )

    rule_ids = [uuid.UUID(str(r)) for r in (row.covering_rule_ids or [])]
    cve_ids = [uuid.UUID(str(c)) for c in (row.chain_cve_ids or [])]

    rules: list[CoverageDetailRule] = []
    if rule_ids:
        rule_rows = (
            await db.execute(
                select(SigmaRule).where(SigmaRule.id.in_(rule_ids))
            )
        ).scalars().all()
        rules = [
            CoverageDetailRule(
                id=str(r.id),
                title=r.title,
                status=r.status,
                origin=r.origin,
                technique_ids=list(r.technique_ids or []),
                logsource_product=r.logsource_product,
                logsource_service=r.logsource_service,
            )
            for r in rule_rows
        ]

    user = get_request_user(request)
    cve_dtos: list[CoverageDetailCve] = []
    if cve_ids:
        cve_rows = (
            await db.execute(select(CVE).where(CVE.id.in_(cve_ids)))
        ).scalars().all()
        visible = await apply_tlp_filter(db, cve_rows, user)
        cve_dtos = [
            CoverageDetailCve(
                id=str(c.id),
                cve_id=c.cve_id,
                cvss_score=float(c.cvss_score) if c.cvss_score is not None else None,
                cisa_kev=bool(c.cisa_kev),
                epss_score=float(c.epss_score) if c.epss_score is not None else None,
                tlp=c.tlp,
            )
            for c in visible
        ]

    base = _row_to_out(row)
    return CoverageDetailOut(
        **base.model_dump(),
        description=row.description,
        covering_rules=rules,
        chain_cves=cve_dtos,
    )


@router.get("/matrix")
async def get_matrix(
    framework: str = Query(DEFAULT_FRAMEWORK, max_length=20),
    cve_id: str | None = Query(None, max_length=30),
    date_from: str | None = Query(None, max_length=32),
    date_to: str | None = Query(None, max_length=32),
    cvss_min: float | None = Query(None, ge=0.0, le=10.0),
    kev_only: bool = Query(False),
    tactic_id: str | None = Query(None, max_length=10),
    assessment_id: uuid.UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> dict[str, Any]:
    """Return the ATT&CK matrix scored by current coverage.

    F-009 (SAST S-003): when ``assessment_id`` is provided, the caller
    must pass the same ownership check used by ``GET /assessments/{id}``.
    Unauthorized callers receive an empty matrix payload (filter values
    preserved, zero techniques) rather than 404 — keeps the dict-shape
    contract uniform AND hides "exists but not yours" vs "doesn't exist".
    """
    if assessment_id is not None:
        try:
            await load_assessment_for_read(db, assessment_id, user=_user)
        except AssessmentNotFoundError:
            logger.info(
                "matrix.assessment_filter_denied",
                assessment_id=str(assessment_id),
                user_id=getattr(_user, "id", None),
            )
            return {
                "framework": framework,
                "techniques": [],
                "total_techniques": 0,
                "filters_applied": {
                    "framework": framework,
                    "assessment_id": str(assessment_id),
                },
            }

    filters = _parse_filters(
        framework=framework,
        cve_id=cve_id,
        date_from=date_from,
        date_to=date_to,
        cvss_min=cvss_min,
        kev_only=kev_only,
        tactic_id=tactic_id,
        assessment_id=assessment_id,
    )
    cache = MatrixCache()
    try:
        data = await cache.get_matrix_data(db, filters)
    finally:
        await cache.close()
    return data.to_dict()


@router.get(
    "/matrix/{technique_id}",
    response_model=CoverageDetailOut,
    dependencies=[Depends(require_authenticated)],
)
async def get_matrix_technique(
    technique_id: str,
    request: Request,
    framework: str = Query(DEFAULT_FRAMEWORK, max_length=20),
    db: AsyncSession = Depends(get_db),
) -> CoverageDetailOut:
    """Alias for /coverage/{technique_id} so the UI can use either base."""
    return await get_coverage_detail(
        technique_id=technique_id,
        request=request,
        framework=framework,
        db=db,
    )


@router.post(
    "/coverage/recompute",
    dependencies=[Depends(require_maintainer)],
)
async def recompute_coverage(
    payload: RecomputeRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Re-run the mapper on one chain (synchronous, returns the report).

    With ``chain_id=None`` this dispatches a Celery task per chain rather
    than blocking the request — the operator polls the matrix endpoint to
    see results.
    """
    if payload.chain_id:
        try:
            chain_uuid = uuid.UUID(payload.chain_id)
        except (ValueError, TypeError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="chain_id must be a valid UUID",
            ) from exc
        chain = await db.get(AttackChainRow, chain_uuid)
        if chain is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="chain not found",
            )
        mapper = CoverageMapper(db)
        try:
            report = await mapper.map_coverage(chain.id)
        except CoverageMappingError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{exc.stage}: {exc}",
            ) from exc
        return {
            "status": "ok",
            "chain_id": str(chain.id),
            "covered": report.covered_count,
            "partial": report.partial_count,
            "gap": report.gap_count,
            "llm_verify_calls": report.llm_verify_calls,
        }

    # No chain_id: queue one map_coverage task per chain in the system.
    chains = (
        await db.execute(select(AttackChainRow.id))
    ).scalars().all()
    queued = 0
    try:
        from fragchain.worker.celery import celery_app

        for cid in chains:
            celery_app.send_task(
                "fragchain.worker.tasks.map_coverage",
                kwargs={"chain_id": str(cid)},
            )
            queued += 1
    except Exception as exc:  # noqa: BLE001
        logger.warning("coverage.recompute_queue_failed", error=str(exc))
    return {"status": "ok", "queued": queued}


__all__ = ["router"]
