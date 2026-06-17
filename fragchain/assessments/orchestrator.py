"""LoopOrchestrator — drives one loop, handles versioning + downstream invalidation.

Reads the assessment + prior loop runs, calls the appropriate Loop implementation,
attaches the detectability gate result for Loop 2, and persists a new
``assessment_loop_run`` row. Supersession is **at-success** (Wave 1a T5):
``begin_run`` creates the new row ``is_active=false`` and leaves the prior
active row + downstream runs untouched; only when the run finalizes with
real output (``succeeded`` or ``gate_failed``) does ``execute_run`` demote
the prior active row to ``status='superseded', is_active=false``, flip the
new row active, and invalidate downstream loops (numbered higher). A
``failed`` run therefore never orphans the prior good output or its
detectability/plan rows.

For Loop 3, refuses to run if the latest Loop 2 row has ``gate_result.passed=False``
unless ``override_rationale`` is provided. The orchestrator does NOT make LLM
calls itself — it depends on injected Loop instances.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.chain_synthesis import (
    ChainSynthesizer,
)
from fragchain.assessments.loops.base import Loop, LoopContext
from fragchain.assessments.rule_supersession import RuleSuperseder
from fragchain.assessments.schemas import AssessmentState, LoopNumber
from fragchain.assessments.service import AssessmentNotFoundError
from fragchain.assessments.state_machine import (
    can_run_loop,
    next_state_after_loop,
    states_invalidated_by_rerun,
)
from fragchain.audit import audit_entity_state_change
from fragchain.db.models import (
    AssessmentLoopRun,
    AssessmentSource,
    CoverageAssessment,
)

logger = structlog.get_logger(__name__)


class InvalidLoopTransitionError(ValueError):
    """Requested loop run is not legal from the current assessment state."""


class LoopOrchestrator:
    def __init__(
        self,
        session: AsyncSession,
        *,
        loop1: Loop,
        loop2: Loop,
        loop3: Loop,
        chain_synthesizer: ChainSynthesizer | None = None,
        rule_superseder: RuleSuperseder | None = None,
        coverage_dispatcher: Callable[[str], None] | None = None,
        detectability_classifier: Any | None = None,
        artifact_router: Any | None = None,
        gate_min_categories: int = 3,
    ) -> None:
        self._session = session
        self._loops: dict[LoopNumber, Loop] = {
            LoopNumber.ONE: loop1,
            LoopNumber.TWO: loop2,
            LoopNumber.THREE: loop3,
        }
        self._chain_synthesizer = chain_synthesizer
        self._rule_superseder = rule_superseder
        self._coverage_dispatcher = coverage_dispatcher
        self._detectability_classifier = detectability_classifier
        self._artifact_router = artifact_router
        self._gate_min = gate_min_categories

        from fragchain.assessments.loops.post_loop import (
            GateHook,
            ChainSynthesisHook,
            RuleSupersessionHook,
            ObserveLoop3Hook,
            CoverageDispatchHook,
            DetectabilityHook,
        )

        self._pre_finalize_hooks = [
            GateHook(gate_min=self._gate_min),
            ChainSynthesisHook(synthesizer=self._chain_synthesizer),
            RuleSupersessionHook(superseder=self._rule_superseder),
            ObserveLoop3Hook(router=self._artifact_router),
            CoverageDispatchHook(dispatcher=self._coverage_dispatcher),
        ]
        self._post_finalize_hooks = [
            DetectabilityHook(
                classifier=self._detectability_classifier,
                router=self._artifact_router,
            ),
        ]

    async def begin_run(
        self,
        assessment_id: uuid.UUID,
        loop_number: LoopNumber,
        *,
        override_rationale: str | None = None,
    ) -> AssessmentLoopRun:
        """Synchronous precheck + create a 'running' row. No LLM work.

        The slow execution happens later in :meth:`execute_run`, dispatched
        to the worker. State is NOT advanced here — the assessment stays at
        its current state while the row is 'running'.
        """
        asmt = await self._load_assessment(assessment_id)
        current = AssessmentState(asmt.state)

        if not can_run_loop(current, loop_number):
            raise InvalidLoopTransitionError(
                f"cannot run loop {loop_number.value} from state {current.value}"
            )

        # Running rows are created INACTIVE (supersede-at-success), so the
        # already-running guard must look at status, not the active flag.
        if await self._running_run(assessment_id, loop_number) is not None:
            raise InvalidLoopTransitionError(
                f"loop {loop_number.value} is already running for this assessment"
            )

        if loop_number == LoopNumber.THREE:
            latest_loop2 = await self._latest_active_run(
                assessment_id, LoopNumber.TWO
            )
            if (
                latest_loop2 is not None
                and latest_loop2.status == "gate_failed"
                and not override_rationale
            ):
                raise InvalidLoopTransitionError(
                    "Loop 2 gate failed; supply override_rationale to proceed"
                )

        # Supersede-at-success (Wave 1a T5): the new row starts INACTIVE and
        # the prior active row + downstream runs stay untouched here. If the
        # worker run fails transiently, the previous good output (and the
        # detectability/plan rows that join on the active Loop 2 run) remain
        # reachable; demotion + downstream invalidation happen in
        # execute_run's successful finalize.
        next_version = await self._next_version(assessment_id, loop_number)
        run = AssessmentLoopRun(
            assessment_id=assessment_id,
            loop_number=loop_number.value,
            version=next_version,
            status="running",
            is_active=False,
            override_rationale=override_rationale,
            started_at=datetime.now(tz=timezone.utc),
        )
        self._session.add(run)
        await self._session.flush()
        return run

    async def run_loop(
        self,
        assessment_id: uuid.UUID,
        loop_number: LoopNumber,
        *,
        override_rationale: str | None = None,
    ) -> AssessmentLoopRun:
        """Convenience: begin + execute inline. Used by tests and the
        deterministic in-process path; the API + worker use begin_run /
        execute_run separately so the LLM work runs off the request."""
        run = await self.begin_run(
            assessment_id, loop_number, override_rationale=override_rationale
        )
        return await self.execute_run(run.id)

    async def execute_run(self, run_id: uuid.UUID) -> AssessmentLoopRun:
        run = await self._session.get(AssessmentLoopRun, run_id)
        if run is None:
            raise AssessmentNotFoundError(f"loop run {run_id} not found")
        # Idempotency: a duplicate Celery delivery must not re-run a finished
        # loop. Only a 'running' row is executable.
        if run.status != "running":
            return run
        assessment_id = run.assessment_id
        loop_number = LoopNumber(run.loop_number)
        override_rationale = run.override_rationale
        asmt = await self._load_assessment(assessment_id)
        current = AssessmentState(asmt.state)

        sources = await self._load_sources(assessment_id)
        any_embedding_pending = any(
            s.embedding_status == "pending" for s in sources
        )

        prior_outputs = await self._collect_prior_outputs(assessment_id)
        ctx = LoopContext(
            assessment_id=assessment_id,
            cve_id=asmt.cve_id,
            cve_textual_id=str(asmt.initial_trigger.get("value", "")),
            source_contents=[s.content for s in sources],
            prior_outputs=prior_outputs,
        )

        loop_impl = self._loops[loop_number]
        started = time.perf_counter()
        try:
            if loop_number == LoopNumber.THREE:
                # Loop 3 needs to know whether the analyst is overriding a
                # gate-failed Loop 2 result. The override is supplied as the
                # Loop 3 call's ``override_rationale`` (the same value the gate
                # check above consumes) — not a field on the Loop 2 row, which
                # is never written on the gate-fail path. Reading it here so
                # the rule generator flips low_detectability_override on each
                # review-queue row it inserts.
                override_value = bool((override_rationale or "").strip())
                # Phase 2c gate (ADR-0004): skip Sigma generation for the
                # precision-1.0 decline classes. Keyed on the detectability
                # CLASS, never on plan.sigma_planned (which folds in the
                # anti-predictive confidence-floor demotion). An analyst
                # override bypasses the skip (they explicitly asked for rules);
                # those rules carry low_detectability_override so the review
                # queue flags them for scrutiny — appropriate even when the
                # deterministic gate passed, since they were force-generated
                # against the "no reliable detection" recommendation.
                gated_class = None
                if not override_value:
                    from fragchain.assessments.gating import sigma_generation_gated
                    from fragchain.config import get_settings

                    det_class = await self._active_detectability_class(
                        assessment_id
                    )
                    if det_class is None:
                        # Fail-open by design (the classifier is advisory and
                        # swallows its own failures). Log it so an operator can
                        # tell "class generates" from "gate could not evaluate".
                        logger.info(
                            "assessment.loop3.gate_no_classification",
                            assessment_id=str(assessment_id),
                        )
                    elif sigma_generation_gated(
                        det_class,
                        enabled_skip_classes=get_settings().router_gating_skip_classes,
                    ):
                        gated_class = det_class
                output = await loop_impl.run(
                    ctx,
                    low_detectability_override=override_value,
                    gated_class=gated_class,
                )
            else:
                output = await loop_impl.run(ctx)
            status = "succeeded"
            error = None
        except Exception as exc:  # noqa: BLE001
            output = None
            status = "failed"
            error = repr(exc)
            logger.exception(
                "assessment.loop.failed",
                assessment_id=str(assessment_id),
                loop_number=loop_number.value,
            )
        latency_ms = int((time.perf_counter() - started) * 1000)

        from fragchain.assessments.loops.post_loop import (
            LoopExecution,
            run_pipeline,
        )

        ex = LoopExecution(
            ctx=ctx,
            run=run,
            assessment=asmt,
            loop_number=loop_number,
            status=status,
            output=output,
            gate_result=None,
            prior_outputs=prior_outputs,
        )
        if error is not None:
            run.error = error  # loop-impl exception captured in the try/except above

        await run_pipeline(self._pre_finalize_hooks, ex)

        await self._finalize_run(ex, any_embedding_pending, latency_ms, current)

        await run_pipeline(self._post_finalize_hooks, ex)

        await self._session.commit()
        await self._session.refresh(run)
        logger.info(
            "assessment.loop.completed",
            assessment_id=str(assessment_id),
            loop_number=loop_number.value,
            version=run.version,
            status=ex.status,
            latency_ms=latency_ms,
        )
        return run

    # -- internal helpers --------------------------------------------------

    async def _finalize_run(
        self,
        ex: Any,  # LoopExecution
        any_embedding_pending: bool,
        latency_ms: int,
        current: AssessmentState,
    ) -> None:
        run = ex.run
        status = ex.status
        output = ex.output
        loop_number = ex.loop_number
        assessment_id = ex.assessment.id

        persisted_output = output
        if ex.synth_meta and output is not None:
            persisted_output = {**output, "_chain": ex.synth_meta}

        run.status = status
        run.output = persisted_output
        run.gate_result = ex.gate_result
        run.embedding_warned = any_embedding_pending
        run.latency_ms = latency_ms
        # run.error may already be set by the loop-impl failure or a hook — do
        # NOT overwrite it here.
        run.completed_at = datetime.now(tz=timezone.utc)

        llm_meta = output.get("_llm") if isinstance(output, dict) else None
        if isinstance(llm_meta, dict):
            meta_model = llm_meta.get("model")
            if isinstance(meta_model, str):
                run.model = meta_model
            meta_cost = llm_meta.get("cost_usd")
            if isinstance(meta_cost, (int, float)) and not isinstance(meta_cost, bool):
                run.cost_usd = Decimal(str(round(float(meta_cost), 4)))

        if status in ("succeeded", "gate_failed"):
            await self._supersede_prior_active_rows(assessment_id, loop_number)
            await self._session.flush()
            run.is_active = True
            await self._invalidate_downstream(assessment_id, loop_number)
            new_state = next_state_after_loop(current, loop_number)
            ex.assessment.state = new_state.value
        else:
            new_state = current

        if status in ("succeeded", "gate_failed"):
            await self._session.flush()  # ensure run.id for post-finalize hooks

        await audit_entity_state_change(
            self._session,
            entity_type="coverage_assessment",
            entity_id=assessment_id,
            action=f"run_loop_{loop_number.value}",
            before={"state": current.value},
            after={
                "state": new_state.value,
                "loop_number": loop_number.value,
                "version": run.version,
                "status": status,
            },
            actor=ex.assessment.creator_id,
        )

    async def _load_assessment(
        self, assessment_id: uuid.UUID
    ) -> CoverageAssessment:
        result = await self._session.execute(
            select(CoverageAssessment).where(
                CoverageAssessment.id == assessment_id
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            raise AssessmentNotFoundError(str(assessment_id))
        return row

    async def _load_sources(
        self, assessment_id: uuid.UUID
    ) -> list[AssessmentSource]:
        result = await self._session.execute(
            select(AssessmentSource)
            .where(AssessmentSource.assessment_id == assessment_id)
            .where(AssessmentSource.deleted_at.is_(None))
        )
        return list(result.scalars().all())

    async def _collect_prior_outputs(
        self, assessment_id: uuid.UUID
    ) -> dict[int, dict[str, Any]]:
        result = await self._session.execute(
            select(AssessmentLoopRun)
            .where(AssessmentLoopRun.assessment_id == assessment_id)
            .where(AssessmentLoopRun.is_active.is_(True))
        )
        out: dict[int, dict[str, Any]] = {}
        for run in result.scalars().all():
            if run.output is not None:
                out[int(run.loop_number)] = run.output
        return out

    async def _active_detectability_class(
        self, assessment_id: uuid.UUID
    ) -> str | None:
        """The detectability class on the assessment's active Loop 2 run, or
        None. This is the Phase 2c gate's only input — never the artifact plan's
        ``sigma_planned`` (which folds in the anti-predictive confidence floor).

        Uses the shared ``active_detectability_stmt`` so the definition of
        "current classification" can't drift from the API / artifact-generator
        readers.
        """
        from fragchain.assessments.detectability import active_detectability_stmt

        result = await self._session.execute(
            active_detectability_stmt(assessment_id)
        )
        row = result.scalar_one_or_none()
        return row.detectability_class if row is not None else None

    async def _next_version(
        self, assessment_id: uuid.UUID, loop_number: LoopNumber
    ) -> int:
        from fragchain.assessments.active_rows import next_version

        return await next_version(
            self._session,
            AssessmentLoopRun,
            AssessmentLoopRun.assessment_id == assessment_id,
            AssessmentLoopRun.loop_number == loop_number.value,
        )

    async def _latest_active_run(
        self, assessment_id: uuid.UUID, loop_number: LoopNumber
    ) -> AssessmentLoopRun | None:
        result = await self._session.execute(
            select(AssessmentLoopRun)
            .where(AssessmentLoopRun.assessment_id == assessment_id)
            .where(AssessmentLoopRun.loop_number == loop_number.value)
            .where(AssessmentLoopRun.is_active.is_(True))
        )
        return result.scalar_one_or_none()

    async def _running_run(
        self, assessment_id: uuid.UUID, loop_number: LoopNumber
    ) -> AssessmentLoopRun | None:
        """The in-flight row for this loop, if any.

        Deliberately NOT filtered on ``is_active`` — running rows are
        created inactive under supersede-at-success, so the active flag
        says nothing about whether a run is in flight.
        """
        result = await self._session.execute(
            select(AssessmentLoopRun)
            .where(AssessmentLoopRun.assessment_id == assessment_id)
            .where(AssessmentLoopRun.loop_number == loop_number.value)
            .where(AssessmentLoopRun.status == "running")
        )
        return result.scalars().first()

    async def _supersede_prior_active_rows(
        self, assessment_id: uuid.UUID, loop_number: LoopNumber
    ) -> None:
        result = await self._session.execute(
            select(AssessmentLoopRun)
            .where(AssessmentLoopRun.assessment_id == assessment_id)
            .where(AssessmentLoopRun.loop_number == loop_number.value)
            .where(AssessmentLoopRun.is_active.is_(True))
        )
        for row in result.scalars().all():
            row.is_active = False
            row.status = "superseded"

    async def _invalidate_downstream(
        self, assessment_id: uuid.UUID, loop_number: LoopNumber
    ) -> None:
        for downstream in states_invalidated_by_rerun(loop_number):
            result = await self._session.execute(
                select(AssessmentLoopRun)
                .where(AssessmentLoopRun.assessment_id == assessment_id)
                .where(AssessmentLoopRun.loop_number == downstream.value)
                .where(AssessmentLoopRun.is_active.is_(True))
            )
            for row in result.scalars().all():
                row.is_active = False
                row.status = "superseded"
