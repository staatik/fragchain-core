"""FastAPI router for the assessment workflow (spec §4 + §5 stubs).

Endpoints under ``/api/v1/assessments``:

* ``POST /assessments`` — create an assessment for a CVE, returning any
  existing chain candidate so the UI can offer "use as start".
* ``GET  /assessments`` — list (filter by state / creator).
* ``GET  /assessments/{id}`` — detail.
* ``POST /assessments/{id}/close`` — manual completion.
* ``POST /assessments/{id}/sources`` — paste a free-text source.
* ``DELETE /assessments/{id}/sources/{sid}`` — soft-delete with rationale.
* ``GET  /assessments/{id}/sources`` — list non-deleted sources.
* ``POST /assessments/{id}/loops/{n}/run`` — drive one loop via orchestrator.
* ``GET  /assessments/{id}/loops/{n}`` — list versions of one loop.
* ``POST /assessments/{id}/use-existing-chain`` — synth Loop 1 from existing chain.
* ``GET  /assessments/{id}/detectability`` — advisory classification (Phase 1).
* ``GET  /assessments/{id}/artifact-plan`` — compatibility-mode plan (Phase 2).
* ``POST /assessments/{id}/artifacts`` — dispatch non-Sigma artifact generation (Phase 2b).
* ``GET  /assessments/{id}/artifacts`` — list generated artifacts (Phase 2b).

Service factories are module-level callables so tests can monkeypatch them
without owning DI plumbing. The router holds no state.
"""
from __future__ import annotations

import uuid
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.middleware.tlp_filter import require_authenticated
from fragchain.assessments.access import (
    filter_assessments_for_user,
    load_assessment_for_read,
    load_assessment_for_write,
)
from fragchain.assessments.chain_reuse import (
    ChainNotFoundError,
    ChainReuseService,
)
from fragchain.assessments.content import ContentValidationError
from fragchain.assessments.artifact_generation import (
    ArtifactAlreadyGeneratingError,
    begin_generation,
)
from fragchain.assessments.artifact_router import active_plan_stmt
from fragchain.assessments.detectability import (
    ArtifactType,
    active_detectability_stmt,
)
from fragchain.assessments.orchestrator import (
    InvalidLoopTransitionError,
    LoopOrchestrator,
)
from fragchain.assessments.schemas import (
    ArtifactCreateRequest,
    ArtifactRejectRequest,
    ArtifactPlanRead,
    AssessmentCreateRequest,
    AssessmentCreateResponse,
    AssessmentExistingChain,
    AssessmentResponse,
    AssessmentState,
    CloseRequest,
    DetectabilityRead,
    GeneratedArtifactRead,
    LoopNumber,
    LoopRunOutput,
    LoopRunRequest,
    SourceCreateRequest,
    SourceDeleteRequest,
    SourceResponse,
    UseExistingChainRequest,
)
from fragchain.assessments.service import (
    AssessmentNotFoundError,
    AssessmentService,
    DuplicateAssessmentError,
)
from fragchain.assessments.source_service import (
    SourceNotFoundError,
    SourceService,
)
from fragchain.assessments.state_machine import StateTransitionError
from fragchain.assessments.trigger_resolver import InvalidTriggerError
from fragchain.db.models import (
    AssessmentLoopRun,
    GeneratedArtifactRow,
)
from fragchain.db.session import get_db

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/assessments", tags=["assessments"])


# ---------------------------------------------------------------------------
# Service factories — module-level so tests can monkeypatch them.
# ---------------------------------------------------------------------------

# F-002: access checks are exposed as module-level callables so router
# tests can rebind them to a no-op (`return MagicMock()`) without
# spinning up a real DB session. Production callers always hit the real
# implementations in ``fragchain.assessments.access``.
_load_assessment_for_read = load_assessment_for_read
_load_assessment_for_write = load_assessment_for_write
_filter_assessments_for_user = filter_assessments_for_user

# F-002-style indirection: tests rebind this to avoid real DB work.
_begin_generation = begin_generation


def _assessment_service_factory(session: AsyncSession) -> AssessmentService:
    return AssessmentService(session)


def _source_service_factory(session: AsyncSession) -> SourceService:
    return SourceService(session)


def _chain_reuse_factory(session: AsyncSession) -> ChainReuseService:
    return ChainReuseService(session)


def _orchestrator_factory(session: AsyncSession) -> LoopOrchestrator:
    from fragchain.assessments.orchestrator_factory import build_orchestrator

    return build_orchestrator(session)


# ---------------------------------------------------------------------------
# Helpers — map ORM rows to response models without leaking SQLAlchemy types.
# ---------------------------------------------------------------------------

def _to_assessment_response(row: Any) -> AssessmentResponse:
    return AssessmentResponse(
        id=row.id,
        cve_id=row.cve_id,
        creator_id=row.creator_id,
        initial_trigger=row.initial_trigger,
        context_note=row.context_note,
        state=AssessmentState(row.state),
        completed_at=row.completed_at,
        tlp=row.tlp,
        auto_advance=row.auto_advance,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _to_source_response(row: Any) -> SourceResponse:
    return SourceResponse(
        id=row.id,
        assessment_id=row.assessment_id,
        kind=row.kind,
        title=row.title,
        size_bytes=row.size_bytes,
        content_hash=row.content_hash,
        tlp=row.tlp,
        embedding_status=row.embedding_status,
        pasted_at=row.pasted_at,
    )


def _to_loop_run_output(row: Any) -> LoopRunOutput:
    return LoopRunOutput(
        id=row.id,
        assessment_id=row.assessment_id,
        loop_number=LoopNumber(int(row.loop_number)),
        version=row.version,
        status=row.status,
        is_active=row.is_active,
        output=row.output,
        gate_result=row.gate_result,
        override_rationale=row.override_rationale,
        embedding_warned=row.embedding_warned,
        model=row.model,
        cost_usd=float(row.cost_usd) if row.cost_usd is not None else None,
        latency_ms=row.latency_ms,
        error=row.error,
        started_at=row.started_at,
        completed_at=row.completed_at,
    )


def _to_artifact_read(row: Any) -> GeneratedArtifactRead:
    return GeneratedArtifactRead(
        id=row.id,
        assessment_id=row.assessment_id,
        artifact_plan_id=row.artifact_plan_id,
        artifact_type=row.artifact_type,
        version=row.version,
        is_active=row.is_active,
        plan_recommended=row.plan_recommended,
        status=row.status,
        validation_status=row.validation_status,
        content=row.content,
        model=row.model,
        cost_usd=float(row.cost_usd) if row.cost_usd is not None else None,
        error=row.error,
        created_at=row.created_at,
        completed_at=row.completed_at,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "",
    response_model=AssessmentCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_assessment(
    req: AssessmentCreateRequest,
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> AssessmentCreateResponse:
    try:
        asmt = await _assessment_service_factory(session).create(
            req, creator_id=user.id
        )
    except DuplicateAssessmentError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))
    except InvalidTriggerError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))

    existing_chain = await _chain_reuse_factory(session).find_existing_chain(
        req.cve_id
    )
    existing_payload: AssessmentExistingChain | None = None
    if existing_chain is not None:
        chain_data = existing_chain.chain if isinstance(existing_chain.chain, dict) else {}
        existing_payload = AssessmentExistingChain(
            chain_id=existing_chain.id,
            source_origin=existing_chain.source_origin,
            version=existing_chain.version,
            created_at=existing_chain.created_at,
            ttp_count=len(chain_data.get("chain", [])),
            overall_confidence=float(chain_data.get("overall_confidence", 0.0)),
        )

    return AssessmentCreateResponse(
        assessment=_to_assessment_response(asmt),
        existing_chain=existing_payload,
    )


@router.get("", response_model=list[AssessmentResponse])
async def list_assessments(
    state: AssessmentState | None = Query(default=None),
    creator_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> list[AssessmentResponse]:
    # F-002: every listed assessment passes through the per-row access
    # filter so an analyst cannot enumerate assessments belonging to
    # someone else.
    rows = await _assessment_service_factory(session).list(
        state=state, creator_id=creator_id, limit=limit, offset=offset
    )
    visible = await _filter_assessments_for_user(session, list(rows), user=user)
    return [_to_assessment_response(r) for r in visible]


@router.get("/{assessment_id}", response_model=AssessmentResponse)
async def get_assessment(
    assessment_id: uuid.UUID,
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> AssessmentResponse:
    try:
        row = await _load_assessment_for_read(session, assessment_id, user=user)
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    return _to_assessment_response(row)


@router.post("/{assessment_id}/close", response_model=AssessmentResponse)
async def close_assessment(
    assessment_id: uuid.UUID,
    req: CloseRequest,
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> AssessmentResponse:
    # F-002: load-with-access-check first so a non-owner gets 404, not 403.
    try:
        await _load_assessment_for_write(session, assessment_id, user=user)
        row = await _assessment_service_factory(session).close(
            assessment_id, closed_by=user.id
        )
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    except StateTransitionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))
    return _to_assessment_response(row)


@router.post(
    "/{assessment_id}/sources",
    response_model=SourceResponse,
    status_code=status.HTTP_201_CREATED,
)
async def add_source(
    assessment_id: uuid.UUID,
    req: SourceCreateRequest,
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> SourceResponse:
    try:
        await _load_assessment_for_write(session, assessment_id, user=user)
        row = await _source_service_factory(session).create(
            assessment_id, req, actor_id=user.id
        )
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    except ContentValidationError as exc:
        msg = str(exc)
        if "size" in msg or "cumulative" in msg or "token" in msg:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=msg,
            )
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=msg)
    return _to_source_response(row)


@router.get("/{assessment_id}/sources", response_model=list[SourceResponse])
async def list_sources(
    assessment_id: uuid.UUID,
    include_deleted: bool = Query(default=False),
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> list[SourceResponse]:
    try:
        await _load_assessment_for_read(session, assessment_id, user=user)
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    rows = await _source_service_factory(session).list(
        assessment_id, include_deleted=include_deleted
    )
    return [_to_source_response(r) for r in rows]


@router.delete(
    "/{assessment_id}/sources/{source_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_source(
    assessment_id: uuid.UUID,
    source_id: uuid.UUID,
    req: SourceDeleteRequest,
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> Response:
    try:
        await _load_assessment_for_write(session, assessment_id, user=user)
        await _source_service_factory(session).delete(
            source_id, actor_id=user.id, rationale=req.rationale
        )
    except (AssessmentNotFoundError, SourceNotFoundError):
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{assessment_id}/loops/{loop_number}/run",
    response_model=LoopRunOutput,
    status_code=status.HTTP_202_ACCEPTED,
)
async def run_loop(
    assessment_id: uuid.UUID,
    loop_number: int = Path(..., ge=1, le=3),
    req: LoopRunRequest = LoopRunRequest(),
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> LoopRunOutput:
    """Dispatch a loop run to the worker. Returns 202 + the 'running' row.

    The synchronous part is only the cheap precheck + row creation; the LLM
    work runs in the Celery task so the request never blocks on the model.
    """
    from fragchain.notifications import EVENT_ASSESSMENT_LOOP_RUN_STARTED, emit_event
    from fragchain.worker.tasks.run_assessment_loop import run_assessment_loop

    try:
        await _load_assessment_for_write(session, assessment_id, user=user)
        run = await _orchestrator_factory(session).begin_run(
            assessment_id,
            LoopNumber(loop_number),
            override_rationale=req.override_rationale,
        )
        await session.commit()
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    except InvalidLoopTransitionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))

    run_assessment_loop.delay(str(run.id))
    try:
        emit_event(
            EVENT_ASSESSMENT_LOOP_RUN_STARTED,
            {"assessment_id": str(assessment_id), "loop_number": loop_number},
        )
    except Exception:  # noqa: BLE001 — best-effort
        pass
    return _to_loop_run_output(run)


@router.get(
    "/{assessment_id}/loops/{loop_number}",
    response_model=list[LoopRunOutput],
)
async def list_loop_versions(
    assessment_id: uuid.UUID,
    loop_number: int = Path(..., ge=1, le=3),
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> list[LoopRunOutput]:
    try:
        await _load_assessment_for_read(session, assessment_id, user=user)
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    result = await session.execute(
        select(AssessmentLoopRun)
        .where(AssessmentLoopRun.assessment_id == assessment_id)
        .where(AssessmentLoopRun.loop_number == loop_number)
        .order_by(AssessmentLoopRun.version.desc())
    )
    return [_to_loop_run_output(r) for r in result.scalars().all()]


@router.get(
    "/{assessment_id}/detectability",
    response_model=DetectabilityRead,
)
async def get_detectability(
    assessment_id: uuid.UUID,
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> DetectabilityRead:
    """Detectability classification for the ACTIVE Loop 2 run (Phase 1).

    Advisory output — it never gates Loop 3. 404 when no classification
    exists yet (Loop 2 not run, or classifier unavailable for that run).
    """
    try:
        await _load_assessment_for_read(session, assessment_id, user=user)
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    result = await session.execute(active_detectability_stmt(assessment_id))
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail="no detectability classification",
        )
    return DetectabilityRead(
        id=row.id,
        assessment_id=row.assessment_id,
        loop_run_id=row.loop_run_id,
        detectability_class=row.detectability_class,
        confidence=float(row.confidence),
        gate_passed=row.gate_passed,
        payload=row.payload,
        model=row.model,
        created_at=row.created_at,
    )


@router.get(
    "/{assessment_id}/artifact-plan",
    response_model=ArtifactPlanRead,
)
async def get_artifact_plan(
    assessment_id: uuid.UUID,
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> ArtifactPlanRead:
    """Artifact plan for the ACTIVE Loop 2 run (Phase 2, compatibility).

    Advisory output — generation is not gated by it. 404 when no plan
    exists yet (Loop 2 not run, or classifier/router unavailable).
    """
    try:
        await _load_assessment_for_read(session, assessment_id, user=user)
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    result = await session.execute(active_plan_stmt(assessment_id))
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail="no artifact plan",
        )
    return ArtifactPlanRead(
        id=row.id,
        assessment_id=row.assessment_id,
        detectability_assessment_id=row.detectability_assessment_id,
        loop_run_id=row.loop_run_id,
        mode=row.mode,
        sigma_planned=row.sigma_planned,
        plan=row.plan,
        observed=row.observed,
        policy_version=row.policy_version,
        created_at=row.created_at,
    )


@router.post(
    "/{assessment_id}/artifacts",
    response_model=GeneratedArtifactRead,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_artifact(
    assessment_id: uuid.UUID,
    req: ArtifactCreateRequest,
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> GeneratedArtifactRead:
    """Dispatch non-Sigma artifact generation. Returns 202 + the 'generating' row.

    The synchronous part is only the supersede-and-insert precheck; the LLM
    work runs in the Celery task so the request never blocks on the model.
    Generation is allowed for any of the three types on demand (spec
    decision 6) — ``plan_recommended`` records the advisory signal.
    """
    from fragchain.worker.tasks.generate_artifact import generate_artifact

    try:
        await _load_assessment_for_write(session, assessment_id, user=user)
        row = await _begin_generation(
            session,
            assessment_id=assessment_id,
            artifact_type=ArtifactType(req.artifact_type),
        )
        await session.commit()
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    except ArtifactAlreadyGeneratingError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))

    generate_artifact.delay(str(row.id))
    return _to_artifact_read(row)


@router.get(
    "/{assessment_id}/artifacts",
    response_model=list[GeneratedArtifactRead],
)
async def list_artifacts(
    assessment_id: uuid.UUID,
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> list[GeneratedArtifactRead]:
    """All generated artifacts for the assessment (active + historical),
    newest first. Empty list (not 404) when none exist yet."""
    try:
        await _load_assessment_for_read(session, assessment_id, user=user)
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    result = await session.execute(
        select(GeneratedArtifactRow)
        .where(GeneratedArtifactRow.assessment_id == assessment_id)
        .order_by(GeneratedArtifactRow.created_at.desc())
    )
    return [_to_artifact_read(r) for r in result.scalars().all()]


async def _validation_action(
    session: AsyncSession,
    assessment_id: uuid.UUID,
    artifact_id: uuid.UUID,
    user: Any,
    action,
) -> GeneratedArtifactRead:
    """Shared wiring for the Phase 3 (W3b) validate/approve/reject endpoints."""
    from fragchain.assessments.artifact_validation import (
        ArtifactNotFoundError,
        ArtifactValidator,
        InvalidValidationTransitionError,
    )

    try:
        await _load_assessment_for_write(session, assessment_id, user=user)
        validator = ArtifactValidator(session)
        row = await action(validator, artifact_id, assessment_id)
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    except ArtifactNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="artifact not found")
    except InvalidValidationTransitionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))
    return _to_artifact_read(row)


@router.post(
    "/{assessment_id}/artifacts/{artifact_id}/validate",
    response_model=GeneratedArtifactRead,
)
async def validate_artifact(
    assessment_id: uuid.UUID,
    artifact_id: uuid.UUID,
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> GeneratedArtifactRead:
    """Run the deterministic lints (advisory) — moves the artifact to
    needs_review / validation_failed. Never gates anything."""
    return await _validation_action(
        session, assessment_id, artifact_id, user,
        lambda v, aid, asid: v.validate(aid, assessment_id=asid),
    )


@router.post(
    "/{assessment_id}/artifacts/{artifact_id}/approve",
    response_model=GeneratedArtifactRead,
)
async def approve_artifact(
    assessment_id: uuid.UUID,
    artifact_id: uuid.UUID,
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> GeneratedArtifactRead:
    """Human sign-off — moves the artifact to analyst_approved (terminal)."""
    return await _validation_action(
        session, assessment_id, artifact_id, user,
        lambda v, aid, asid: v.approve(
            aid, reviewer=getattr(user, "id", None), assessment_id=asid
        ),
    )


@router.post(
    "/{assessment_id}/artifacts/{artifact_id}/reject",
    response_model=GeneratedArtifactRead,
)
async def reject_artifact(
    assessment_id: uuid.UUID,
    artifact_id: uuid.UUID,
    req: ArtifactRejectRequest,
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> GeneratedArtifactRead:
    """Human rejection — moves the artifact to rejected (terminal)."""
    return await _validation_action(
        session, assessment_id, artifact_id, user,
        lambda v, aid, asid: v.reject(
            aid, reason=req.reason, reviewer=getattr(user, "id", None),
            assessment_id=asid,
        ),
    )


@router.post(
    "/{assessment_id}/use-existing-chain",
    response_model=LoopRunOutput,
)
async def use_existing_chain(
    assessment_id: uuid.UUID,
    req: UseExistingChainRequest,
    user: Any = Depends(require_authenticated),
    session: AsyncSession = Depends(get_db),
) -> LoopRunOutput:
    try:
        await _load_assessment_for_write(session, assessment_id, user=user)
        run = await _chain_reuse_factory(session).use_as_start(
            assessment_id, req.chain_id
        )
    except AssessmentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    except ChainNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
    return _to_loop_run_output(run)
