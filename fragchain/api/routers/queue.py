"""Review queue API (M16).

Endpoints under ``/api/v1``:

  * ``GET    /queue``                       — list with filters.
  * ``GET    /queue/{id}``                  — detail incl. evidence bundle.
  * ``PATCH  /queue/{id}/assign``           — assign / clear assignee.
  * ``POST   /queue/{id}/approve``          — approve + create Git PR.
  * ``POST   /queue/{id}/reject``           — reject with reason.
  * ``POST   /queue/{id}/edit``             — edit YAML + validate + approve.

Reads honour TLP enforcement via the M2 middleware (rules carry a TLP
column propagated from chains + source documents). Writes are
maintainer-only — approve, reject and edit all mutate review state, can
spend Git host API budget, and create PRs visible to outside reviewers.
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
    apply_tlp_filter,
    enforce_tlp_access,
    get_request_user,
    require_authenticated,
    require_maintainer,
)
from fragchain.assessments.access import load_assessment_for_read
from fragchain.assessments.service import AssessmentNotFoundError
from fragchain.db.models import SigmaRule
from fragchain.db.session import get_db
from fragchain.queue import (
    ApproveOutcome,
    EditOutcome,
    QUEUE_STATUSES,
    QueueActionError,
    QueueItemDetail,
    QueueItemView,
    QueueManager,
    RejectOutcome,
    SimilarRuleHit,
    SourceDocSnippet,
    TTPContext,
)
from fragchain.queue.supersede import SupersedeError, SupersedeService

logger = structlog.get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class QueueItemOut(BaseModel):
    id: str
    sigma_rule_id: str
    priority: str
    priority_score: int
    priority_reason: str | None
    assigned_to: str | None
    status: str
    created_at: datetime
    completed_at: datetime | None
    title: str
    rule_status: str
    origin: str
    technique_ids: list[str] = Field(default_factory=list)
    logsource_profile: str | None
    detection_level: str | None
    tlp: str
    cve_id: str | None
    cve_textual_id: str | None
    chain_id: str | None
    review_notes: str | None
    git_pr_url: str | None
    # Plan C Phase 6: assessment-link projection.
    assessment_id: str | None = None
    low_detectability_override: bool = False
    superseded_by_assessment_id: str | None = None


class QueueListResponse(BaseModel):
    total: int
    items: list[QueueItemOut] = Field(default_factory=list)


class TTPContextOut(BaseModel):
    id: str
    seq_order: int
    tactic: str | None
    tactic_id: str | None
    technique_id: str | None
    technique_name: str | None
    confidence: float | None
    detection_opportunity: str | None
    is_focus: bool


class SourceDocSnippetOut(BaseModel):
    id: str
    url: str
    source_type: str | None
    quality_score: float | None
    tlp: str
    excerpt: str | None


class SimilarRuleHitOut(BaseModel):
    rule_id: str | None
    sigma_uuid: str | None
    title: str | None
    technique_ids: list[str] = Field(default_factory=list)
    score: float
    logsource_product: str | None
    logsource_service: str | None
    origin: str | None


class QueueDetailOut(BaseModel):
    item: QueueItemOut
    sigma_yaml: str
    parsed_yaml: dict[str, Any] | None
    cve: dict[str, Any] | None
    chain_context: list[TTPContextOut] = Field(default_factory=list)
    source_documents: list[SourceDocSnippetOut] = Field(default_factory=list)
    similar_rules: list[SimilarRuleHitOut] = Field(default_factory=list)
    priority_breakdown: dict[str, Any] = Field(default_factory=dict)


class AssignRequest(BaseModel):
    assigned_to: str | None = Field(default=None, max_length=255)


class ApproveRequest(BaseModel):
    target_id: str | None = None
    # When true, approve the rule locally without attempting a Git PR.
    # Useful for evaluation deployments that haven't configured a Sigma
    # target yet, or for rules an operator wants to mark approved but
    # ship out-of-band. The rule lands at ``status='approved'`` with
    # ``git_pr_url=None``; the queue item closes with ``status='approved'``.
    skip_pr: bool = False


class RejectRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=4000)


class EditRequest(BaseModel):
    # 200_000 chars is generous for any real Sigma rule — the SigmaHQ
    # corpus averages well under 4 KB per file. The cap is a denial-of-
    # service guard rather than a content rule (E-M3 in the Phase 5
    # security review).
    sigma_yaml: str = Field(min_length=1, max_length=200_000)
    target_id: str | None = None


class ApproveResponse(BaseModel):
    rule_id: str
    queue_id: str
    rule_status: str
    queue_status: str
    target_id: str | None
    target_name: str | None
    pr_submitted: bool
    pr_url: str | None
    pr_number: int | None
    commit_sha: str | None
    branch: str | None
    routing_reason: str
    message: str


class RejectResponse(BaseModel):
    rule_id: str
    queue_id: str
    rule_status: str
    queue_status: str
    reason: str


class EditResponse(BaseModel):
    rule_id: str
    queue_id: str
    approve: ApproveResponse
    warnings: list[str] = Field(default_factory=list)


class SupersedeRequest(BaseModel):
    rule_id: uuid.UUID
    rationale: str = Field(min_length=1, max_length=200)


class SupersedeResponse(BaseModel):
    review_id: uuid.UUID
    status: str
    supersede_rule_id: uuid.UUID


# ---------------------------------------------------------------------------
# Converters
# ---------------------------------------------------------------------------


def _view_to_out(view: QueueItemView) -> QueueItemOut:
    return QueueItemOut(
        id=str(view.id),
        sigma_rule_id=str(view.sigma_rule_id),
        priority=view.priority,
        priority_score=int(view.priority_score),
        priority_reason=view.priority_reason,
        assigned_to=view.assigned_to,
        status=view.status,
        created_at=view.created_at,
        completed_at=view.completed_at,
        title=view.title,
        rule_status=view.rule_status,
        origin=view.origin,
        technique_ids=list(view.technique_ids),
        logsource_profile=view.logsource_profile,
        detection_level=view.detection_level,
        tlp=view.tlp,
        cve_id=str(view.cve_id) if view.cve_id else None,
        cve_textual_id=view.cve_textual_id,
        chain_id=str(view.chain_id) if view.chain_id else None,
        review_notes=view.review_notes,
        git_pr_url=view.git_pr_url,
        assessment_id=str(view.assessment_id) if view.assessment_id else None,
        low_detectability_override=view.low_detectability_override,
        superseded_by_assessment_id=(
            str(view.superseded_by_assessment_id)
            if view.superseded_by_assessment_id
            else None
        ),
    )


def _ttp_to_out(ttp: TTPContext) -> TTPContextOut:
    return TTPContextOut(
        id=str(ttp.id),
        seq_order=ttp.seq_order,
        tactic=ttp.tactic,
        tactic_id=ttp.tactic_id,
        technique_id=ttp.technique_id,
        technique_name=ttp.technique_name,
        confidence=ttp.confidence,
        detection_opportunity=ttp.detection_opportunity,
        is_focus=ttp.is_focus,
    )


def _doc_to_out(doc: SourceDocSnippet) -> SourceDocSnippetOut:
    return SourceDocSnippetOut(
        id=str(doc.id),
        url=doc.url,
        source_type=doc.source_type,
        quality_score=doc.quality_score,
        tlp=doc.tlp,
        excerpt=doc.excerpt,
    )


def _similar_to_out(hit: SimilarRuleHit) -> SimilarRuleHitOut:
    return SimilarRuleHitOut(
        rule_id=hit.rule_id,
        sigma_uuid=hit.sigma_uuid,
        title=hit.title,
        technique_ids=list(hit.technique_ids),
        score=float(hit.score),
        logsource_product=hit.logsource_product,
        logsource_service=hit.logsource_service,
        origin=hit.origin,
    )


def _detail_to_out(detail: QueueItemDetail) -> QueueDetailOut:
    return QueueDetailOut(
        item=_view_to_out(detail.item),
        sigma_yaml=detail.sigma_yaml,
        parsed_yaml=detail.parsed_yaml,
        cve=detail.cve,
        chain_context=[_ttp_to_out(t) for t in detail.chain_context],
        source_documents=[_doc_to_out(d) for d in detail.source_documents],
        similar_rules=[_similar_to_out(h) for h in detail.similar_rules],
        priority_breakdown=dict(detail.priority_breakdown),
    )


def _approve_to_out(outcome: ApproveOutcome) -> ApproveResponse:
    return ApproveResponse(
        rule_id=str(outcome.rule_id),
        queue_id=str(outcome.queue_id),
        rule_status=outcome.rule_status,
        queue_status=outcome.queue_status,
        target_id=str(outcome.target_id) if outcome.target_id else None,
        target_name=outcome.target_name,
        pr_submitted=outcome.pr_submitted,
        pr_url=outcome.pr_url,
        pr_number=outcome.pr_number,
        commit_sha=outcome.commit_sha,
        branch=outcome.branch,
        routing_reason=outcome.routing_reason,
        message=outcome.message,
    )


def _reject_to_out(outcome: RejectOutcome) -> RejectResponse:
    return RejectResponse(
        rule_id=str(outcome.rule_id),
        queue_id=str(outcome.queue_id),
        rule_status=outcome.rule_status,
        queue_status=outcome.queue_status,
        reason=outcome.reason,
    )


def _edit_to_out(outcome: EditOutcome) -> EditResponse:
    return EditResponse(
        rule_id=str(outcome.rule_id),
        queue_id=str(outcome.queue_id),
        approve=_approve_to_out(outcome.approve),
        warnings=list(outcome.warnings),
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


def _coerce_optional_uuid(
    value: str | None, *, field_name: str
) -> uuid.UUID | None:
    if value is None:
        return None
    stripped = value.strip() if isinstance(value, str) else value
    if not stripped:
        return None
    return _coerce_uuid(stripped, field_name=field_name)


def _raise_for_action_error(exc: QueueActionError) -> None:
    detail: dict[str, Any] = {"detail": str(exc)}
    if exc.errors:
        detail["errors"] = exc.errors
    if exc.warnings:
        detail["warnings"] = exc.warnings
    # FastAPI accepts a dict body verbatim — frontends parse the same
    # structure they already use for /rules/{id}/validate.
    raise HTTPException(status_code=exc.status_code, detail=detail)


async def _filter_visible_views(
    request: Request,
    db: AsyncSession,
    views: list[QueueItemView],
) -> list[QueueItemView]:
    """Run TLP filtering over a list of detached views.

    The TLP middleware operates on objects with ``tlp`` + ``id`` +
    optional ``embargo_until``. Our :class:`QueueItemView` carries the
    first two (TLP is propagated from the underlying SigmaRule). Rule
    rows don't currently carry embargo, so we treat each view as
    embargo-free.
    """
    user = get_request_user(request)
    return await apply_tlp_filter(db, views, user)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/queue", response_model=QueueListResponse)
async def list_queue(
    request: Request,
    priority: str | None = Query(default=None, max_length=20),
    status_filter: str | None = Query(default=None, alias="status", max_length=20),
    assigned_to: str | None = Query(default=None, max_length=255),
    cve_id: str | None = Query(default=None, max_length=64),
    assessment_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> QueueListResponse:
    """List queue items ordered by priority_score DESC, created_at ASC.

    F-009 (SAST S-001): when ``assessment_id`` is provided, the caller must
    pass the same ownership check used by ``GET /assessments/{id}``.
    Unauthorized callers receive an empty list rather than 404 so the
    list-endpoint contract stays uniform AND existence is not disclosed
    (the same response is returned for "doesn't exist" and "exists but
    not yours"). The access check runs *before* the queue manager so no
    queue rows are emitted in error logs / metrics for an unauthorized
    probe.
    """
    if assessment_id is not None:
        try:
            await load_assessment_for_read(db, assessment_id, user=_user)
        except AssessmentNotFoundError:
            logger.info(
                "queue.list.assessment_filter_denied",
                assessment_id=str(assessment_id),
                user_id=getattr(_user, "id", None),
            )
            return QueueListResponse(total=0, items=[])

    manager = QueueManager(db)
    try:
        views = await manager.list_items(
            priority=priority,
            status_filter=status_filter,
            assigned_to=assigned_to,
            cve_id=cve_id,
            assessment_id=assessment_id,
            limit=limit,
            offset=offset,
        )
    except QueueActionError as exc:
        _raise_for_action_error(exc)
    visible = await _filter_visible_views(request, db, views)
    return QueueListResponse(
        total=len(visible),
        items=[_view_to_out(v) for v in visible],
    )


@router.get("/queue/{item_id}", response_model=QueueDetailOut)
async def get_queue_item(
    item_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_authenticated),
) -> QueueDetailOut:
    """Return one queue row plus the analyst evidence bundle.

    The detail payload carries the parsed YAML, CVE summary, chain
    context (focus TTP + 1 adjacent before/after), top 3 source
    documents, top 5 semantically-similar rules from Qdrant, and the
    priority breakdown carried over from M14.
    """
    uid = _coerce_uuid(item_id, field_name="queue id")
    manager = QueueManager(db)
    try:
        detail = await manager.get_item_with_evidence(uid)
    except QueueActionError as exc:
        _raise_for_action_error(exc)

    # TLP enforcement: gate on the underlying SigmaRule (the queue row
    # carries no TLP of its own; the rule's TLP is the source of truth).
    rule = await db.get(SigmaRule, detail.item.sigma_rule_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="queue item references missing sigma rule",
        )
    await enforce_tlp_access(db, rule, get_request_user(request))

    return _detail_to_out(detail)


@router.patch("/queue/{item_id}/assign", response_model=QueueItemOut)
async def assign_queue_item(
    item_id: str,
    payload: AssignRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> QueueItemOut:
    """Set / clear the queue row's assignee.

    Pass ``{"assigned_to": "<username>"}`` to assign; ``{"assigned_to": null}``
    or an empty string to clear. The queue item flips ``pending`` →
    ``in_review`` when first assigned.
    """
    uid = _coerce_uuid(item_id, field_name="queue id")
    manager = QueueManager(db)
    try:
        view = await manager.assign(
            uid,
            actor_username=user.username if user else None,
            actor_id=user.id if user else None,
            assigned_to=payload.assigned_to,
        )
    except QueueActionError as exc:
        _raise_for_action_error(exc)
    # TLP gate: the underlying rule's classification still applies.
    rule = await db.get(SigmaRule, view.sigma_rule_id)
    if rule is not None:
        await enforce_tlp_access(db, rule, get_request_user(request))
    return _view_to_out(view)


@router.post(
    "/queue/{item_id}/approve",
    response_model=ApproveResponse,
    status_code=status.HTTP_200_OK,
)
async def approve_queue_item(
    item_id: str,
    payload: ApproveRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> ApproveResponse:
    """Approve a pending rule and open a Git PR via M12.

    ``target_id`` is optional — when omitted, M12's RoutingEngine picks
    the right target based on the rule's tags / fields / level. Returns
    HTTP 409 if the rule is already approved/rejected, or no target is
    available. The rule is committed at ``status='approved'`` before the
    network call so a transport failure doesn't roll back the human
    decision.
    """
    uid = _coerce_uuid(item_id, field_name="queue id")
    target_uuid = _coerce_optional_uuid(payload.target_id, field_name="target_id")

    manager = QueueManager(db)
    try:
        outcome = await manager.approve(
            uid,
            actor_username=user.username if user else None,
            actor_id=user.id if user else None,
            target_id=target_uuid,
            skip_pr=payload.skip_pr,
        )
    except QueueActionError as exc:
        _raise_for_action_error(exc)
    return _approve_to_out(outcome)


@router.post(
    "/queue/{item_id}/reject",
    response_model=RejectResponse,
    status_code=status.HTTP_200_OK,
)
async def reject_queue_item(
    item_id: str,
    payload: RejectRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> RejectResponse:
    """Reject a pending rule with a reason. Reason lands in ``audit_log``."""
    uid = _coerce_uuid(item_id, field_name="queue id")
    manager = QueueManager(db)
    try:
        outcome = await manager.reject(
            uid,
            actor_username=user.username if user else None,
            actor_id=user.id if user else None,
            reason=payload.reason,
        )
    except QueueActionError as exc:
        _raise_for_action_error(exc)
    return _reject_to_out(outcome)


@router.post(
    "/queue/{item_id}/edit",
    response_model=EditResponse,
    status_code=status.HTTP_200_OK,
)
async def edit_queue_item(
    item_id: str,
    payload: EditRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> EditResponse:
    """Validate edited YAML through pySigma, then approve.

    On validation failure returns HTTP 400 with a JSON body of
    ``{"detail": "...", "errors": [...], "warnings": [...]}`` so the
    review UI can render field-level diagnostics. On success the rule
    is approved + a PR is created via the same flow as
    :func:`approve_queue_item`.
    """
    uid = _coerce_uuid(item_id, field_name="queue id")
    target_uuid = _coerce_optional_uuid(payload.target_id, field_name="target_id")
    manager = QueueManager(db)
    try:
        outcome = await manager.edit_and_approve(
            uid,
            actor_username=user.username if user else None,
            actor_id=user.id if user else None,
            new_yaml=payload.sigma_yaml,
            target_id=target_uuid,
        )
    except QueueActionError as exc:
        _raise_for_action_error(exc)
    return _edit_to_out(outcome)


@router.post(
    "/queue/{item_id}/supersede",
    response_model=SupersedeResponse,
    status_code=status.HTTP_200_OK,
)
async def supersede_queue_item(
    item_id: str,
    payload: SupersedeRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_maintainer),
) -> SupersedeResponse:
    """Close a pending rule with status='superseded' and label the analyst's choice.

    The chosen existing rule becomes the supersede target; the rationale is
    recorded on the queue item AND folded into a ``CoverageBenchmark`` row
    per technique (``source='supersede'``, ``expected_verdict='covered'``)
    so the analyst decision becomes ground-truth labeling for the benchmark
    runner.

    Unlike ``approve`` / ``reject`` / ``edit`` (which delegate commit to
    ``QueueManager`` internally), ``SupersedeService`` leaves the session
    uncommitted so the router can control transaction boundaries. The
    ``await db.commit()`` below is intentional and matches the service's
    documented contract.
    """
    uid = _coerce_uuid(item_id, field_name="queue id")
    svc = SupersedeService(db)
    try:
        result = await svc.supersede(
            review_id=uid,
            supersede_rule_id=payload.rule_id,
            rationale=payload.rationale,
            actor_username=user.username if user else None,
            actor_id=user.id if user else None,
        )
    except SupersedeError as exc:
        raise HTTPException(
            status_code=exc.status_code, detail=str(exc)
        ) from exc
    await db.commit()
    return SupersedeResponse(**result)


__all__ = ["router"]
