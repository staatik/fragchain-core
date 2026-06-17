"""Phase 2 artifact router — schemas, deterministic policy, service (ADR-0004 §3).

Compatibility mode: the router consumes the Phase 1 detectability
classification, applies deterministic guardrails, and persists an
``ArtifactPlanRow`` — it does NOT gate Loop 3. A post-Loop-3 observation
records whether generation diverged from the plan, building the evidence
needed before the router is flipped to active gating (Phase 2c).

The policy is intentionally a pure function (``build_plan``): the LLM
reasoned once in the classifier; the router never re-asks. Every guardrail
override of the classifier's opinion is appended to
``RouterPlan.policy_adjustments`` so conflicts are visible, not silent.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.detectability import (
    ArtifactType,
    DetectabilityAssessment,
    DetectabilityClass,
)
from fragchain.assessments.loops.base import LoopContext
from fragchain.config import get_settings
from fragchain.db.models import (
    ArtifactPlanRow,
    AssessmentLoopRun,
    DetectabilityAssessmentRow,
)
from fragchain.notifications import emit_event
from fragchain.notifications.events import (
    EVENT_ASSESSMENT_PLAN_CREATED,
    EVENT_ASSESSMENT_PLAN_DIVERGED,
)

logger = structlog.get_logger(__name__)

POLICY_VERSION = "v1"


def active_plan_stmt(assessment_id: uuid.UUID):
    """Select the plan keyed to the ACTIVE Loop 2 run of an assessment.

    Shared by the API endpoint and the post-Loop-3 observation so the
    definition of "current plan" cannot drift between readers.
    """
    return (
        select(ArtifactPlanRow)
        .join(
            AssessmentLoopRun,
            ArtifactPlanRow.loop_run_id == AssessmentLoopRun.id,
        )
        .where(
            ArtifactPlanRow.assessment_id == assessment_id,
            AssessmentLoopRun.is_active.is_(True),
            AssessmentLoopRun.loop_number == 2,
        )
        .order_by(ArtifactPlanRow.created_at.desc())
        .limit(1)
    )


class PlannedArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: ArtifactType
    reason: str = Field(min_length=1)
    priority: int = Field(ge=1, le=5)
    prerequisites: list[str] = Field(default_factory=list)


class SkippedPlanArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: ArtifactType
    reason: str = Field(min_length=1)


class RouterPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recommended: list[PlannedArtifact] = Field(default_factory=list)
    skipped: list[SkippedPlanArtifact] = Field(default_factory=list)
    required_inputs: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    policy_version: str
    policy_adjustments: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _sigma_explicit(self) -> "RouterPlan":
        rec = {a.type for a in self.recommended}
        skp = {a.type for a in self.skipped}
        if ArtifactType.SIGMA_RULE not in (rec | skp):
            raise ValueError(
                "sigma_rule must appear in recommended or skipped "
                "(explicit justification required)"
            )
        if rec & skp:
            raise ValueError("an artifact type cannot be both recommended and skipped")
        return self

    @property
    def sigma_planned(self) -> bool:
        return ArtifactType.SIGMA_RULE in {a.type for a in self.recommended}


class _PlanBuilder:
    """Mutable working state for one ``build_plan`` invocation.

    ``adjustments`` is an **append-only trace** of every policy action, in
    application order — it documents how the plan was derived, not the
    final plan state (e.g. a prerequisite may be recorded on an artifact a
    later guardrail demotes; the final lists are authoritative).
    """

    def __init__(self, classification: DetectabilityAssessment) -> None:
        self.recommended: dict[ArtifactType, PlannedArtifact] = {}
        self.skipped: dict[ArtifactType, SkippedPlanArtifact] = {}
        self.adjustments: list[str] = []
        for rec in classification.recommended_artifacts:
            self.recommended[rec.type] = PlannedArtifact(
                type=rec.type, reason=rec.reason, priority=rec.priority
            )
        for skp in classification.skipped_artifacts:
            self.skipped[skp.type] = SkippedPlanArtifact(
                type=skp.type, reason=skp.reason
            )
        # The Phase 1 schema only forbids sigma_rule from appearing in both
        # classifier lists; any other type may legally be dual-listed.
        # RouterPlan is stricter (no type in both lists), so reconcile here
        # — skip wins, conservatively — instead of letting the validator
        # reject an otherwise valid classification.
        for dual in set(self.recommended) & set(self.skipped):
            del self.recommended[dual]
            self.adjustments.append(
                f"reconciled {dual.value}: classifier listed it as both "
                "recommended and skipped — keeping the skip"
            )

    def demote(self, artifact: ArtifactType, reason: str) -> None:
        """Move an artifact from recommended to skipped, recording the override."""
        if artifact in self.recommended:
            del self.recommended[artifact]
            self.adjustments.append(
                f"demoted {artifact.value}: {reason} (classifier had recommended it)"
            )
        if artifact not in self.skipped:
            self.skipped[artifact] = SkippedPlanArtifact(type=artifact, reason=reason)

    def ensure_recommended(
        self, artifact: ArtifactType, reason: str, priority: int
    ) -> None:
        """Add an artifact unless it is already recommended **or skipped**.

        A classifier skip-with-reason wins over a policy default — e.g. an
        ``insufficient_information`` plan may legitimately end with zero
        recommended artifacts if the classifier explicitly skipped the
        research task too.
        """
        if artifact in self.recommended or artifact in self.skipped:
            return
        self.recommended[artifact] = PlannedArtifact(
            type=artifact, reason=reason, priority=priority
        )
        self.adjustments.append(f"added {artifact.value}: {reason}")

    def add_prerequisite(self, artifact: ArtifactType, prerequisite: str) -> None:
        planned = self.recommended.get(artifact)
        if planned is not None and prerequisite not in planned.prerequisites:
            planned.prerequisites.append(prerequisite)
            self.adjustments.append(
                f"prerequisite on {artifact.value}: {prerequisite}"
            )


def build_plan(
    classification: DetectabilityAssessment,
    *,
    classifier_confidence: float,
    gate_result: dict[str, Any],
    min_confidence: float,
) -> RouterPlan:
    """Pure routing policy v1 — same inputs always produce the same plan."""
    b = _PlanBuilder(classification)
    cls = classification.detectability_class

    if cls is DetectabilityClass.INSUFFICIENT_INFORMATION:
        b.demote(
            ArtifactType.SIGMA_RULE,
            "policy: insufficient evidence for reliable detection",
        )
        b.ensure_recommended(
            ArtifactType.ANALYST_RESEARCH_TASK,
            "policy: gather evidence before attempting detection",
            priority=1,
        )
    elif cls is DetectabilityClass.CONTROL_ONLY:
        b.demote(
            ArtifactType.SIGMA_RULE,
            "policy: control-only class — prevention preferred over detection",
        )
        b.ensure_recommended(
            ArtifactType.MITIGATION_PLAN,
            "policy: default deliverable for control-only vulnerabilities",
            priority=1,
        )
    elif cls is DetectabilityClass.ENVIRONMENT_DEPENDENT:
        b.add_prerequisite(
            ArtifactType.SIGMA_RULE,
            "verify required telemetry exists in the target environment",
        )
        b.ensure_recommended(
            ArtifactType.TELEMETRY_CONTRACT,
            "policy: document the telemetry this detection depends on",
            priority=2,
        )
    # directly_detectable / indirectly_detectable: classifier plan passes through.

    if classifier_confidence < min_confidence:
        b.demote(
            ArtifactType.SIGMA_RULE,
            f"policy: classifier confidence {classifier_confidence:.2f} below "
            f"floor {min_confidence:.2f}",
        )
        b.ensure_recommended(
            ArtifactType.ANALYST_RESEARCH_TASK,
            "policy: low classification confidence — needs human research",
            priority=1,
        )

    if not gate_result.get("passed", False):
        b.add_prerequisite(
            ArtifactType.SIGMA_RULE,
            "Loop 2 gate failed — analyst override required before generation",
        )

    recommended = sorted(b.recommended.values(), key=lambda a: (a.priority, a.type.value))
    skipped = sorted(b.skipped.values(), key=lambda a: a.type.value)
    return RouterPlan(
        recommended=recommended,
        skipped=skipped,
        required_inputs=list(classification.required_telemetry),
        confidence=classifier_confidence,
        policy_version=POLICY_VERSION,
        policy_adjustments=b.adjustments,
    )


class ArtifactRouter:
    """Compatibility-mode router (Phase 2, ADR-0004 §3).

    Advisory like the classifier: both public methods swallow their own
    failures so the assessment flow is never blocked by planning.
    """

    def __init__(
        self,
        session: AsyncSession,
        *,
        min_confidence: float | None = None,
    ) -> None:
        self._session = session
        self._min_confidence = (
            get_settings().ROUTER_MIN_CONFIDENCE
            if min_confidence is None
            else min_confidence
        )

    async def plan(
        self,
        *,
        ctx: LoopContext,
        detectability_row: DetectabilityAssessmentRow,
        gate_result: dict[str, Any],
    ) -> ArtifactPlanRow | None:
        try:
            return await self._plan(
                ctx=ctx,
                detectability_row=detectability_row,
                gate_result=gate_result,
            )
        except Exception as exc:  # noqa: BLE001 — advisory stage, never blocks
            logger.warning(
                "assessment.artifact_plan.failed",
                assessment_id=str(ctx.assessment_id),
                error=repr(exc),
            )
            return None

    async def _plan(
        self,
        *,
        ctx: LoopContext,
        detectability_row: DetectabilityAssessmentRow,
        gate_result: dict[str, Any],
    ) -> ArtifactPlanRow:
        # The classifier adds its row without flushing; ``id`` is a
        # flush-time default, so it is still None here. Flush (inside the
        # advisory wrapper) before keying the plan to it — otherwise the
        # NOT NULL FK fails at commit, outside our try/except, and takes
        # the whole loop run down with it.
        await self._session.flush()
        classification = DetectabilityAssessment.model_validate(
            detectability_row.payload
        )
        plan = build_plan(
            classification,
            classifier_confidence=float(detectability_row.confidence),
            gate_result=gate_result,
            min_confidence=self._min_confidence,
        )
        row = ArtifactPlanRow(
            assessment_id=ctx.assessment_id,
            detectability_assessment_id=detectability_row.id,
            loop_run_id=detectability_row.loop_run_id,
            sigma_planned=plan.sigma_planned,
            plan=plan.model_dump(mode="json"),
            policy_version=plan.policy_version,
        )
        self._session.add(row)
        logger.info(
            "assessment.artifact_plan.created",
            assessment_id=str(ctx.assessment_id),
            sigma_planned=row.sigma_planned,
            adjustments=len(plan.policy_adjustments),
        )
        try:
            emit_event(
                EVENT_ASSESSMENT_PLAN_CREATED,
                {
                    "assessment_id": str(ctx.assessment_id),
                    "sigma_planned": row.sigma_planned,
                },
            )
        except Exception as emit_exc:  # noqa: BLE001
            logger.warning(
                "assessment.artifact_plan.emit_failed", error=str(emit_exc)
            )
        return row

    async def observe_loop3(
        self,
        *,
        assessment_id: uuid.UUID,
        rules_generated: int,
        gaps_processed: int | None = None,
    ) -> None:
        try:
            await self._observe_loop3(
                assessment_id=assessment_id,
                rules_generated=rules_generated,
                gaps_processed=gaps_processed,
            )
        except Exception as exc:  # noqa: BLE001 — advisory stage, never blocks
            logger.warning(
                "assessment.artifact_plan.observe_failed",
                assessment_id=str(assessment_id),
                error=repr(exc),
            )

    async def _observe_loop3(
        self,
        *,
        assessment_id: uuid.UUID,
        rules_generated: int,
        gaps_processed: int | None,
    ) -> None:
        result = await self._session.execute(
            active_plan_stmt(assessment_id)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return

        sigma_generated = rules_generated > 0
        # Divergence is a *disagreement* between plan and outcome, not any
        # mismatch: planning Sigma and generating none is legitimate when
        # the coverage mapper found zero gaps (everything already covered)
        # — only count it as divergence when gaps existed and generation
        # still produced nothing, or when the plan said skip but rules
        # were generated anyway.
        if sigma_generated:
            diverged = not row.sigma_planned
        else:
            diverged = row.sigma_planned and (
                gaps_processed is None or gaps_processed > 0
            )
        row.observed = {
            "rules_generated": rules_generated,
            "gaps_processed": gaps_processed,
            "sigma_generated": sigma_generated,
            "diverged": diverged,
            "observed_at": datetime.now(tz=timezone.utc).isoformat(),
        }
        if diverged:
            logger.info(
                "assessment.artifact_plan.diverged",
                assessment_id=str(assessment_id),
                sigma_planned=row.sigma_planned,
                rules_generated=rules_generated,
            )
            try:
                emit_event(
                    EVENT_ASSESSMENT_PLAN_DIVERGED,
                    {
                        "assessment_id": str(assessment_id),
                        "sigma_planned": row.sigma_planned,
                        "rules_generated": rules_generated,
                    },
                )
            except Exception as emit_exc:  # noqa: BLE001
                logger.warning(
                    "assessment.artifact_plan.emit_failed", error=str(emit_exc)
                )
