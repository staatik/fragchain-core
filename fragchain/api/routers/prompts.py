"""Prompts API (M9).

Endpoints under ``/api/v1/prompts``:

  * ``GET /prompts`` — list templates (filter by task_type, target_model).
  * ``GET /prompts/{id}`` — single template + recent evaluations.
  * ``POST /prompts`` — create a new version (auto-bumps the version int).
  * ``PATCH /prompts/{id}`` — clone-and-bump (NEVER mutates the source row).
  * ``POST /prompts/{id}/activate`` — make this version active for its key.
  * ``GET /prompts/{id}/diff/{other_id}`` — unified-diff between two versions.
  * ``POST /prompts/{id}/evaluate`` — run an evaluation against a benchmark set.
  * ``GET /prompts/benchmarks`` — list available benchmark JSON files.
  * ``POST /prompts/ab`` — start an A/B test.
  * ``GET /prompts/ab`` — list A/B tests.
  * ``POST /prompts/ab/{id}/conclude`` — mark a test concluded + record winner.

The kickoff lists the evaluation endpoint as ``/prompts/{id}/eval`` — we
expose ``/eval`` AND ``/evaluate`` (alias) so both spellings resolve. The
spec wording wins for client docs; the alias keeps the route discoverable
either way.

Authorization model in v1:
  * Authenticated reads (``GET``).
  * Maintainer-only writes (``POST``, ``PATCH``, activate, conclude). Prompt
    content controls every LLM call so the write surface is intentionally
    locked down until tier management lands in a later module.
"""
from __future__ import annotations

import uuid
from typing import Any

import structlog
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.middleware.tlp_filter import require_authenticated, require_maintainer
from fragchain.db.models import PromptABTest, PromptEvaluation, PromptTemplate
from fragchain.db.session import get_db
from fragchain.prompts import (
    ABTestRouter,
    BenchmarkLoadError,
    BenchmarkNotFoundError,
    EvaluationError,
    GroundTruthMissingError,
    PromptEvaluator,
    PromptNotFoundError,
    PromptStore,
    PromptTemplateView,
    WILDCARD,
    list_benchmarks,
)

logger = structlog.get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class TemplateOut(BaseModel):
    id: uuid.UUID
    name: str
    task_type: str
    target_model: str
    target_provider: str
    version: int
    system_prompt: str
    user_template: str
    is_active: bool
    notes: str | None = None
    created_by: str | None = None
    created_at: str

    @classmethod
    def from_row(cls, row: PromptTemplate) -> "TemplateOut":
        return cls(
            id=row.id,
            name=row.name,
            task_type=row.task_type,
            target_model=row.target_model,
            target_provider=row.target_provider,
            version=int(row.version),
            system_prompt=row.system_prompt or "",
            user_template=row.user_template or "",
            is_active=bool(row.is_active),
            notes=row.notes,
            created_by=row.created_by,
            created_at=row.created_at.isoformat() if row.created_at else "",
        )

    @classmethod
    def from_view(cls, view: PromptTemplateView, row: PromptTemplate) -> "TemplateOut":
        return cls(
            id=view.id,
            name=view.name,
            task_type=view.task_type,
            target_model=view.target_model,
            target_provider=view.target_provider,
            version=view.version,
            system_prompt=view.system_prompt,
            user_template=view.user_template,
            is_active=view.is_active,
            notes=view.notes,
            created_by=row.created_by,
            created_at=row.created_at.isoformat() if row.created_at else "",
        )


class TemplateListResponse(BaseModel):
    templates: list[TemplateOut]
    total: int


class EvaluationOut(BaseModel):
    id: uuid.UUID
    prompt_template_id: uuid.UUID
    benchmark_set: str
    technique_overlap: float | None
    ordering_consistency: float | None
    hallucination_count: int | None
    cost_per_run: float | None
    avg_latency_ms: int | None
    sample_outputs: Any | None = None
    evaluated_at: str
    evaluated_by: str | None = None

    @classmethod
    def from_row(cls, row: PromptEvaluation) -> "EvaluationOut":
        return cls(
            id=row.id,
            prompt_template_id=row.prompt_template_id,
            benchmark_set=row.benchmark_set,
            technique_overlap=(
                float(row.technique_overlap)
                if row.technique_overlap is not None
                else None
            ),
            ordering_consistency=(
                float(row.ordering_consistency)
                if row.ordering_consistency is not None
                else None
            ),
            hallucination_count=row.hallucination_count,
            cost_per_run=(
                float(row.cost_per_run) if row.cost_per_run is not None else None
            ),
            avg_latency_ms=row.avg_latency_ms,
            sample_outputs=row.sample_outputs,
            evaluated_at=row.evaluated_at.isoformat() if row.evaluated_at else "",
            evaluated_by=row.evaluated_by,
        )


class TemplateDetail(TemplateOut):
    evaluations: list[EvaluationOut] = Field(default_factory=list)


class CreateTemplateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    task_type: str = Field(..., min_length=1, max_length=50)
    system_prompt: str = Field(...)
    user_template: str = Field(...)
    target_model: str = Field(default=WILDCARD, max_length=100)
    target_provider: str = Field(default=WILDCARD, max_length=50)
    notes: str | None = None
    activate: bool = False


class PatchTemplateRequest(BaseModel):
    system_prompt: str | None = None
    user_template: str | None = None
    notes: str | None = None
    activate: bool = False


class DiffResponse(BaseModel):
    a: dict[str, Any]
    b: dict[str, Any]
    system_prompt_diff: list[str]
    user_template_diff: list[str]


class RunEvalRequest(BaseModel):
    benchmark_set: str = Field(..., min_length=1)
    model: str | None = None


class BenchmarkSummary(BaseModel):
    name: str
    description: str
    case_count: int
    iterations_per_case: int
    path: str
    error: str | None = None


class ABTestOut(BaseModel):
    id: uuid.UUID
    name: str
    task_type: str
    variant_a_template_id: uuid.UUID
    variant_b_template_id: uuid.UUID
    traffic_split: float
    status: str
    started_at: str
    concluded_at: str | None = None
    winner: str | None = None

    @classmethod
    def from_row(cls, row: PromptABTest) -> "ABTestOut":
        return cls(
            id=row.id,
            name=row.name,
            task_type=row.task_type,
            variant_a_template_id=row.variant_a_template_id,
            variant_b_template_id=row.variant_b_template_id,
            traffic_split=float(row.traffic_split or 0.0),
            status=row.status,
            started_at=row.started_at.isoformat() if row.started_at else "",
            concluded_at=row.concluded_at.isoformat() if row.concluded_at else None,
            winner=row.winner,
        )


class CreateABTestRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    task_type: str = Field(..., min_length=1, max_length=50)
    variant_a_template_id: uuid.UUID
    variant_b_template_id: uuid.UUID
    traffic_split: float = Field(default=0.50, ge=0.0, le=1.0)


class ConcludeABTestRequest(BaseModel):
    winner: str | None = Field(default=None, pattern="^[AB]$")


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------


@router.get("/prompts", response_model=TemplateListResponse)
async def list_templates(
    request: Request,
    db: AsyncSession = Depends(get_db),
    task_type: str | None = Query(default=None),
    target_model: str | None = Query(default=None),
    target_provider: str | None = Query(default=None),
    active_only: bool = Query(default=False),
    _user=Depends(require_authenticated),
) -> TemplateListResponse:
    stmt = select(PromptTemplate)
    if task_type is not None:
        stmt = stmt.where(PromptTemplate.task_type == task_type)
    if target_model is not None:
        stmt = stmt.where(PromptTemplate.target_model == target_model)
    if target_provider is not None:
        stmt = stmt.where(PromptTemplate.target_provider == target_provider)
    if active_only:
        stmt = stmt.where(PromptTemplate.is_active.is_(True))
    stmt = stmt.order_by(
        PromptTemplate.name,
        PromptTemplate.target_model,
        PromptTemplate.target_provider,
        PromptTemplate.version.desc(),
    )
    rows = (await db.execute(stmt)).scalars().all()
    out = [TemplateOut.from_row(r) for r in rows]
    return TemplateListResponse(templates=out, total=len(out))


@router.get("/prompts/benchmarks", response_model=list[BenchmarkSummary])
async def benchmarks(
    request: Request,
    _user=Depends(require_authenticated),
) -> list[BenchmarkSummary]:
    return [BenchmarkSummary(**b) for b in list_benchmarks()]


@router.get("/prompts/ab", response_model=list[ABTestOut])
async def list_ab_tests(
    request: Request,
    db: AsyncSession = Depends(get_db),
    status_filter: str | None = Query(default=None, alias="status"),
    _user=Depends(require_authenticated),
) -> list[ABTestOut]:
    router_obj = ABTestRouter(db)
    rows = await router_obj.list_tests(status=status_filter)
    return [ABTestOut.from_row(r) for r in rows]


@router.post("/prompts/ab", response_model=ABTestOut, status_code=status.HTTP_201_CREATED)
async def create_ab_test(
    request: Request,
    payload: CreateABTestRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> ABTestOut:
    router_obj = ABTestRouter(db)
    try:
        row = await router_obj.create_test(
            name=payload.name,
            task_type=payload.task_type,
            variant_a_id=payload.variant_a_template_id,
            variant_b_id=payload.variant_b_template_id,
            traffic_split=payload.traffic_split,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return ABTestOut.from_row(row)


@router.post(
    "/prompts/ab/{ab_test_id}/conclude",
    response_model=ABTestOut,
)
async def conclude_ab_test(
    ab_test_id: uuid.UUID,
    request: Request,
    payload: ConcludeABTestRequest = Body(default_factory=ConcludeABTestRequest),
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> ABTestOut:
    router_obj = ABTestRouter(db)
    try:
        row = await router_obj.conclude(ab_test_id, winner=payload.winner)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return ABTestOut.from_row(row)


@router.get("/prompts/{template_id}", response_model=TemplateDetail)
async def get_template(
    template_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> TemplateDetail:
    row = await db.get(PromptTemplate, template_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Template {template_id} not found"
        )
    evals = await PromptEvaluator.list_for_template(db, template_id)
    base = TemplateOut.from_row(row)
    return TemplateDetail(
        **base.model_dump(),
        evaluations=[EvaluationOut.from_row(e) for e in evals],
    )


@router.post("/prompts", response_model=TemplateOut, status_code=status.HTTP_201_CREATED)
async def create_template(
    request: Request,
    payload: CreateTemplateRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> TemplateOut:
    store = PromptStore(db)
    view = await store.create_version(
        name=payload.name,
        task_type=payload.task_type,
        target_model=payload.target_model,
        target_provider=payload.target_provider,
        system_prompt=payload.system_prompt,
        user_template=payload.user_template,
        created_by=user.username if user else None,
        notes=payload.notes,
        activate=payload.activate,
    )
    row = await db.get(PromptTemplate, view.id)
    assert row is not None
    return TemplateOut.from_view(view, row)


@router.patch("/prompts/{template_id}", response_model=TemplateOut)
async def patch_template(
    template_id: uuid.UUID,
    request: Request,
    payload: PatchTemplateRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> TemplateOut:
    store = PromptStore(db)
    try:
        view = await store.patch_as_new_version(
            template_id,
            system_prompt=payload.system_prompt,
            user_template=payload.user_template,
            notes=payload.notes,
            created_by=user.username if user else None,
            activate=payload.activate,
        )
    except PromptNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    row = await db.get(PromptTemplate, view.id)
    assert row is not None
    return TemplateOut.from_view(view, row)


@router.post("/prompts/{template_id}/activate", response_model=TemplateOut)
async def activate_template(
    template_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_maintainer),
) -> TemplateOut:
    store = PromptStore(db)
    try:
        view = await store.activate(template_id)
    except PromptNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    row = await db.get(PromptTemplate, view.id)
    assert row is not None
    return TemplateOut.from_view(view, row)


@router.get("/prompts/{template_id}/diff/{other_id}", response_model=DiffResponse)
async def diff_templates(
    template_id: uuid.UUID,
    other_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> DiffResponse:
    store = PromptStore(db)
    try:
        diff = await store.diff(template_id, other_id)
    except PromptNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return DiffResponse(**diff)


async def _run_evaluation(
    template_id: uuid.UUID,
    payload: "RunEvalRequest",
    db: AsyncSession,
    username: str | None,
) -> EvaluationOut:
    runner = PromptEvaluator(db)
    try:
        row = await runner.run(
            template_id,
            payload.benchmark_set,
            model=payload.model,
            evaluated_by=username,
        )
    except PromptNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except BenchmarkNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except (BenchmarkLoadError, GroundTruthMissingError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        )
    except EvaluationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        )
    return EvaluationOut.from_row(row)


@router.post("/prompts/{template_id}/eval", response_model=EvaluationOut)
async def trigger_eval(
    template_id: uuid.UUID,
    request: Request,
    payload: RunEvalRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> EvaluationOut:
    return await _run_evaluation(
        template_id, payload, db, user.username if user else None
    )


@router.post("/prompts/{template_id}/evaluate", response_model=EvaluationOut)
async def trigger_evaluate(
    template_id: uuid.UUID,
    request: Request,
    payload: RunEvalRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> EvaluationOut:
    return await _run_evaluation(
        template_id, payload, db, user.username if user else None
    )


__all__ = ["router"]
