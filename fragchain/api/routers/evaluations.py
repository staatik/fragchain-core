"""Rule efficacy evaluations API (M17).

Endpoints under ``/api/v1``:

  * ``POST /rules/{id}/evaluate``                — submit one evaluation.
  * ``GET  /rules/{id}/evaluations``             — list every evaluation.
  * ``GET  /rules/{id}/evaluations/aggregate``   — aggregate stats.
  * ``POST /evaluations/{id}/contribute``        — push to commons via M7.

Reads honour TLP enforcement on the underlying ``sigma_rules`` row.
Mutations are maintainer-only (analysts deploying rules and recording
field outcomes are operationally the same population as the M16
approvers). Once M3 hardens role assignment we can relax this to a
dedicated ``evaluator`` tier without changing the router.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.middleware.tlp_filter import (
    enforce_tlp_access,
    get_request_user,
    require_authenticated,
    require_maintainer,
)
from fragchain.commons import CommonsClient
from fragchain.db.models import RuleEvaluation, SigmaRule
from fragchain.db.session import get_db
from fragchain.evaluations import (
    AggregateStats,
    EvaluationError,
    EvaluationRecord,
    EvaluationStore,
)

logger = structlog.get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class EvaluationSubmitRequest(BaseModel):
    """Body for ``POST /rules/{id}/evaluate``.

    Every field is optional at the schema layer — the store enforces
    "must include at least one of TP / FP / notes" so a row carries
    something useful.
    """

    environment_platform: str | None = Field(default=None, max_length=50)
    environment_logsource: str | None = Field(default=None, max_length=100)
    environment_scale: str | None = Field(default=None, max_length=50)
    true_positives: int | None = Field(default=None, ge=0)
    false_positives_per_day: float | None = Field(default=None, ge=0.0)
    query_cost: str | None = Field(default=None, max_length=20)
    deployment_complexity: str | None = Field(default=None, max_length=20)
    notes: str | None = Field(default=None, max_length=8000)


class EvaluationOut(BaseModel):
    id: str
    sigma_rule_id: str
    evaluator_username: str | None
    evaluated_at: datetime
    environment_platform: str | None
    environment_logsource: str | None
    environment_scale: str | None
    true_positives: int | None
    false_positives_per_day: float | None
    query_cost: str | None
    deployment_complexity: str | None
    notes: str | None
    contributed_to_commons: bool


class EvaluationListResponse(BaseModel):
    sigma_rule_id: str
    total: int
    items: list[EvaluationOut] = Field(default_factory=list)


class AggregateOut(BaseModel):
    sigma_rule_id: str
    count: int
    avg_false_positives_per_day: float | None
    total_true_positives: int
    platforms_tested: list[str] = Field(default_factory=list)
    scales_tested: list[str] = Field(default_factory=list)
    contributed_count: int
    recommendation: str


class ContributeResponseItem(BaseModel):
    source_id: str
    source_name: str
    status: str
    pr_url: str | None
    pr_number: int | None
    branch: str | None
    message: str


class ContributeResponse(BaseModel):
    evaluation_id: str
    sigma_rule_id: str
    contributed_to_commons: bool
    submitted: int
    failures: int
    per_source: list[ContributeResponseItem] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Converters
# ---------------------------------------------------------------------------


def _record_to_out(record: EvaluationRecord) -> EvaluationOut:
    return EvaluationOut(
        id=str(record.id),
        sigma_rule_id=str(record.sigma_rule_id),
        evaluator_username=record.evaluator_username,
        evaluated_at=record.evaluated_at,
        environment_platform=record.environment_platform,
        environment_logsource=record.environment_logsource,
        environment_scale=record.environment_scale,
        true_positives=record.true_positives,
        false_positives_per_day=record.false_positives_per_day,
        query_cost=record.query_cost,
        deployment_complexity=record.deployment_complexity,
        notes=record.notes,
        contributed_to_commons=record.contributed_to_commons,
    )


def _aggregate_to_out(stats: AggregateStats) -> AggregateOut:
    return AggregateOut(
        sigma_rule_id=str(stats.sigma_rule_id),
        count=stats.count,
        avg_false_positives_per_day=stats.avg_false_positives_per_day,
        total_true_positives=stats.total_true_positives,
        platforms_tested=list(stats.platforms_tested),
        scales_tested=list(stats.scales_tested),
        contributed_count=stats.contributed_count,
        recommendation=stats.recommendation,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_uuid(value: str, *, field_name: str = "id") -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be a valid UUID",
        ) from exc


def _raise_for_eval_error(exc: EvaluationError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=str(exc))


async def _gate_rule_access(
    db: AsyncSession, request: Request, rule_id: uuid.UUID
) -> SigmaRule:
    rule = await db.get(SigmaRule, rule_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="sigma rule not found",
        )
    await enforce_tlp_access(db, rule, get_request_user(request))
    return rule


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/rules/{rule_id}/evaluate",
    response_model=EvaluationOut,
    status_code=status.HTTP_201_CREATED,
)
async def submit_evaluation(
    rule_id: str,
    payload: EvaluationSubmitRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> EvaluationOut:
    """Record one field evaluation for a Sigma rule.

    The body carries TP / FP rates plus environment-shape metadata. The
    store enforces that at least one of ``true_positives``,
    ``false_positives_per_day`` or ``notes`` is present — otherwise the
    row contributes nothing useful and is rejected with HTTP 400.
    """
    ruid = _coerce_uuid(rule_id, field_name="rule id")
    await _gate_rule_access(db, request, ruid)

    store = EvaluationStore(db)
    try:
        record = await store.record(
            ruid,
            evaluator=user.username if user else None,
            results=payload.model_dump(),
            actor_id=user.id if user else None,
        )
    except EvaluationError as exc:
        _raise_for_eval_error(exc)
    return _record_to_out(record)


@router.get(
    "/rules/{rule_id}/evaluations",
    response_model=EvaluationListResponse,
)
async def list_evaluations(
    rule_id: str,
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> EvaluationListResponse:
    """List every evaluation for ``rule_id``, newest first.

    Enforces TLP on the underlying rule — analysts without access to
    the rule's classification can't peek at its field outcomes either.
    """
    ruid = _coerce_uuid(rule_id, field_name="rule id")
    await _gate_rule_access(db, request, ruid)

    store = EvaluationStore(db)
    records = await store.list_for_rule(ruid, limit=limit, offset=offset)
    return EvaluationListResponse(
        sigma_rule_id=str(ruid),
        total=len(records),
        items=[_record_to_out(r) for r in records],
    )


@router.get(
    "/rules/{rule_id}/evaluations/aggregate",
    response_model=AggregateOut,
)
async def aggregate_evaluations(
    rule_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> AggregateOut:
    """Aggregated stats: avg FP/day, sample size, recommendation bucket.

    The dashboard reads ``recommendation`` directly to colour the rule
    badge (``production_ready`` / ``needs_tuning`` / ``problematic`` /
    ``insufficient_data``).
    """
    ruid = _coerce_uuid(rule_id, field_name="rule id")
    await _gate_rule_access(db, request, ruid)

    store = EvaluationStore(db)
    stats = await store.aggregate(ruid)
    return _aggregate_to_out(stats)


@router.post(
    "/evaluations/{evaluation_id}/contribute",
    response_model=ContributeResponse,
    status_code=status.HTTP_200_OK,
)
async def contribute_evaluation(
    evaluation_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> ContributeResponse:
    """Push the evaluation to every eligible commons source (via M7).

    The commons transport opens one PR per contribute-enabled source
    with the evaluation body + the rule's sigma_uuid as references.
    Multiple successful contributions across sources are recorded as a
    single ``contributed_to_commons=true`` flag — the per-source PR
    URLs are in the response body for the UI to surface.
    """
    eid = _coerce_uuid(evaluation_id, field_name="evaluation id")
    eval_row = await db.get(RuleEvaluation, eid)
    if eval_row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="evaluation not found",
        )
    # TLP gate on the underlying rule.
    await _gate_rule_access(db, request, eval_row.sigma_rule_id)
    rule = await db.get(SigmaRule, eval_row.sigma_rule_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="evaluation references missing sigma rule",
        )

    # The commons transport accepts an arbitrary "chain payload" today.
    # M17 piggybacks on the same plumbing — the payload carries an
    # ``evaluation`` block plus the rule reference. M35 (commons repo
    # schema) can split this into a dedicated evaluations directory
    # without changing the engine-side contract.
    payload: dict[str, Any] = {
        "type": "rule_evaluation",
        "sigma_rule_id": str(rule.id),
        "sigma_uuid": str(rule.sigma_uuid) if rule.sigma_uuid else None,
        "rule_title": rule.title,
        "technique_ids": list(rule.technique_ids or []),
        "tlp": rule.tlp,
        "evaluation": {
            "id": str(eval_row.id),
            "evaluator_username": eval_row.evaluator_username,
            "evaluated_at": (
                eval_row.evaluated_at.isoformat()
                if eval_row.evaluated_at
                else None
            ),
            "environment_platform": eval_row.environment_platform,
            "environment_logsource": eval_row.environment_logsource,
            "environment_scale": eval_row.environment_scale,
            "true_positives": eval_row.true_positives,
            "false_positives_per_day": (
                float(eval_row.false_positives_per_day)
                if eval_row.false_positives_per_day is not None
                else None
            ),
            "query_cost": eval_row.query_cost,
            "deployment_complexity": eval_row.deployment_complexity,
            "notes": eval_row.notes,
        },
    }

    client = CommonsClient(db)
    # ``contribute_chain`` is generic over the payload — passing the
    # sigma_uuid (or rule title hash) as the ``cve_id`` argument lets
    # the transport pick a deterministic branch / file name without
    # needing a dedicated commons API for evaluations in v1.
    branch_key = (
        f"eval-{str(rule.sigma_uuid)[:8]}"
        if rule.sigma_uuid
        else f"eval-{str(rule.id)[:8]}"
    )
    batch = await client.contribute_chain(
        cve_id=branch_key,
        chain_payload=payload,
        actor_username=user.username if user else None,
    )

    store = EvaluationStore(db)
    contributed = False
    if batch.submitted:
        try:
            await store.mark_contributed(
                eid,
                actor_id=user.id if user else None,
                actor_username=user.username if user else None,
            )
            contributed = True
        except EvaluationError as exc:
            _raise_for_eval_error(exc)

    return ContributeResponse(
        evaluation_id=str(eval_row.id),
        sigma_rule_id=str(rule.id),
        contributed_to_commons=contributed
        or bool(eval_row.contributed_to_commons),
        submitted=batch.submitted,
        failures=batch.failures,
        per_source=[
            ContributeResponseItem(
                source_id=r.source_id,
                source_name=r.source_name,
                status=r.status,
                pr_url=r.pr_url,
                pr_number=r.pr_number,
                branch=r.branch,
                message=r.message,
            )
            for r in batch.per_source
        ],
    )


__all__ = ["router"]
