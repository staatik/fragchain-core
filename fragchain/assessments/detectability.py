"""Phase 1 detectability classifier — schemas + service (ADR-0004).

Advisory stage: classifies what a defender can realistically detect for the
assessed vulnerability. Runs after Loop 2; never gates the assessment flow
in Phase 1 (the deterministic category gate remains the flow-controller).
Schema strictness mirrors CLAUDE.md §11: ``extra='forbid'`` so prompt drift
fails loudly instead of silently dropping fields.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.loops.base import (
    LoopContext,
    resolve_chat_model,
    resolve_chat_provider,
)
from fragchain.config import get_settings
from fragchain.db.models import AssessmentLoopRun, DetectabilityAssessmentRow
from fragchain.llm.base import InteractionType, LLMProvider
from fragchain.llm.structured import structured_complete

logger = structlog.get_logger(__name__)


class DetectabilityClass(str, Enum):
    DIRECTLY_DETECTABLE = "directly_detectable"
    INDIRECTLY_DETECTABLE = "indirectly_detectable"
    ENVIRONMENT_DEPENDENT = "environment_dependent"
    CONTROL_ONLY = "control_only"
    INSUFFICIENT_INFORMATION = "insufficient_information"


class ArtifactType(str, Enum):
    """v1 artifact vocabulary (ADR-0004 §4)."""

    SIGMA_RULE = "sigma_rule"
    ANALYST_RESEARCH_TASK = "analyst_research_task"
    MITIGATION_PLAN = "mitigation_plan"
    TELEMETRY_CONTRACT = "telemetry_contract"


class RecommendedArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: ArtifactType
    reason: str = Field(min_length=1)
    priority: int = Field(ge=1, le=5)


class SkippedArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: ArtifactType
    reason: str = Field(min_length=1)


class DetectabilityAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detectability_class: DetectabilityClass
    rationale: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    observable_behaviors: list[str] = Field(default_factory=list)
    required_telemetry: list[str] = Field(default_factory=list)
    optional_telemetry: list[str] = Field(default_factory=list)
    blind_spots: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    recommended_artifacts: list[RecommendedArtifact] = Field(default_factory=list)
    skipped_artifacts: list[SkippedArtifact] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _sigma_explicitly_justified(self) -> "DetectabilityAssessment":
        # AGENTS.md / 005-artifact-router: Sigma generation must be explicitly
        # justified — recommended with a reason OR skipped with a reason.
        rec = {a.type for a in self.recommended_artifacts}
        skp = {a.type for a in self.skipped_artifacts}
        if ArtifactType.SIGMA_RULE not in (rec | skp):
            raise ValueError(
                "sigma_rule must appear in recommended_artifacts or "
                "skipped_artifacts (explicit justification required)"
            )
        if ArtifactType.SIGMA_RULE in (rec & skp):
            raise ValueError("sigma_rule cannot be both recommended and skipped")
        return self


_MAX_SAMPLES_PER_CATEGORY = 5


@dataclass
class PredictResult:
    assessment: DetectabilityAssessment
    model: str
    cost_usd: float
    prompt_template_id: uuid.UUID


def active_detectability_stmt(assessment_id: uuid.UUID):
    """Select the classification keyed to the ACTIVE Loop 2 run of an assessment.

    Shared by the API endpoint and the artifact generator so the definition of
    'current classification' cannot drift between readers.
    """
    return (
        select(DetectabilityAssessmentRow)
        .join(
            AssessmentLoopRun,
            DetectabilityAssessmentRow.loop_run_id == AssessmentLoopRun.id,
        )
        .where(
            DetectabilityAssessmentRow.assessment_id == assessment_id,
            AssessmentLoopRun.is_active.is_(True),
            AssessmentLoopRun.loop_number == 2,
        )
        .order_by(DetectabilityAssessmentRow.created_at.desc())
        .limit(1)
    )


def _summarize_indicators(indicators: dict[str, list[Any]]) -> str:
    """Compact per-category summary so the prompt stays token-bounded."""
    lines: list[str] = []
    for category in sorted(indicators):
        items = indicators.get(category) or []
        line = f"- {category}: {len(items)} indicator(s)"
        samples = []
        for item in items[:_MAX_SAMPLES_PER_CATEGORY]:
            value = item.get("value", "") if isinstance(item, dict) else str(item)
            kind = item.get("kind", "?") if isinstance(item, dict) else "?"
            samples.append(f"{value!r} ({kind})")
        if samples:
            line += ": " + ", ".join(samples)
        lines.append(line)
    return "\n".join(lines) if lines else "(none)"


class DetectabilityClassifier:
    """Advisory post-Loop-2 classifier (Phase 1, ADR-0004).

    Never raises out of :meth:`classify` — a classification failure is
    logged and swallowed so the assessment flow is unaffected.
    """

    def __init__(
        self,
        session: AsyncSession,
        *,
        prompt_store: Any,
        model: str | None = None,
        provider: LLMProvider | None = None,
    ) -> None:
        self._session = session
        self._prompt_store = prompt_store
        self._model_override = model
        self._provider = provider

    async def classify(
        self,
        *,
        ctx: LoopContext,
        loop_run_id: uuid.UUID,
        loop2_output: dict[str, Any],
        gate_result: dict[str, Any],
    ) -> DetectabilityAssessmentRow | None:
        try:
            return await self._classify(
                ctx=ctx,
                loop_run_id=loop_run_id,
                loop2_output=loop2_output,
                gate_result=gate_result,
            )
        except Exception as exc:  # noqa: BLE001 — advisory stage, never blocks
            logger.warning(
                "assessment.detectability.failed",
                assessment_id=str(ctx.assessment_id),
                error=repr(exc),
            )
            return None

    async def predict(
        self,
        *,
        ctx: LoopContext,
        loop2_output: dict[str, Any],
        gate_result: dict[str, Any],
    ) -> PredictResult:
        selection = await self._prompt_store.get_active(
            task_type="detectability_classification",
            target_model=self._model_override or "*",
            target_provider="*",
        )

        loop1_out = ctx.prior_outputs.get(1) or {}
        vuln_profile = loop1_out.get("vuln_profile") or {}
        indicators = loop2_output.get("indicators") or {}
        unanswered = loop2_output.get("unanswered_questions") or []

        gate_summary = (
            f"passed={gate_result.get('passed')}, "
            f"filled={gate_result.get('filled_categories')}, "
            f"empty={gate_result.get('empty_categories')}, "
            f"threshold={gate_result.get('threshold')}"
        )
        user_text = selection.user_template.format(
            cve_id=ctx.cve_textual_id,
            vuln_profile=json.dumps(vuln_profile, indent=2, sort_keys=True),
            indicators_summary=_summarize_indicators(indicators),
            gate_summary=gate_summary,
            unanswered="\n".join(f"- {q}" for q in unanswered) or "(none)",
        )

        model = resolve_chat_model(self._model_override, selection.target_model)
        provider = resolve_chat_provider(self._provider)

        result = await structured_complete(
            provider=provider,
            system=selection.system_prompt,
            user=user_text,
            model=model,
            schema=DetectabilityAssessment,
            interaction_type=InteractionType.DETECTABILITY_CLASSIFICATION,
            entity_type="coverage_assessment",
            entity_id=ctx.assessment_id,
            prompt_template_id=selection.id,
            prompt_version=selection.version,
            timeout_seconds=get_settings().LLM_STRUCTURED_TIMEOUT_SECONDS,
        )
        return PredictResult(
            assessment=result.value,
            model=model,
            cost_usd=float(result.cost_usd),
            prompt_template_id=selection.id,
        )

    async def _classify(
        self,
        *,
        ctx: LoopContext,
        loop_run_id: uuid.UUID,
        loop2_output: dict[str, Any],
        gate_result: dict[str, Any],
    ) -> DetectabilityAssessmentRow:
        pr = await self.predict(
            ctx=ctx,
            loop2_output=loop2_output,
            gate_result=gate_result,
        )

        row = DetectabilityAssessmentRow(
            assessment_id=ctx.assessment_id,
            loop_run_id=loop_run_id,
            detectability_class=pr.assessment.detectability_class.value,
            confidence=Decimal(str(round(pr.assessment.confidence, 3))),
            gate_passed=bool(gate_result.get("passed")),
            payload=pr.assessment.model_dump(mode="json"),
            model=pr.model,
            prompt_template_id=pr.prompt_template_id,
            cost_usd=Decimal(str(round(pr.cost_usd, 4))),
        )
        self._session.add(row)
        logger.info(
            "assessment.detectability.classified",
            assessment_id=str(ctx.assessment_id),
            detectability_class=row.detectability_class,
        )
        return row
