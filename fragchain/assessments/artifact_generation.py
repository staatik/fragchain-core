"""Phase 2b non-Sigma artifact generation — schemas + service (ADR-0004).

Generates the three non-Sigma defensive artifacts the artifact router can
recommend (``mitigation_plan`` / ``analyst_research_task`` /
``telemetry_contract``) as structured, schema-validated documents. On-demand
and advisory: a generation failure marks its own row ``failed`` and never
raises into the caller. Schema strictness mirrors CLAUDE.md §11:
``extra='forbid'`` so prompt drift fails loudly.

Spec: docs/superpowers/specs/2026-06-10-phase-2b-artifact-generation-design.md
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.artifact_router import active_plan_stmt
from fragchain.assessments.detectability import (
    ArtifactType,
    _summarize_indicators,  # noqa: PLC2701
    active_detectability_stmt,
)
from fragchain.assessments.loops.base import (
    resolve_chat_model,
    resolve_chat_provider,
)
from fragchain.config import get_settings
from fragchain.db.models import (
    AssessmentLoopRun,
    CoverageAssessment,
    DetectabilityAssessmentRow,
    GeneratedArtifactRow,
)
from fragchain.llm.base import InteractionType, LLMProvider
from fragchain.llm.structured import structured_complete

logger = structlog.get_logger(__name__)

# The three artifact types this module can generate. sigma_rule stays on the
# Loop 3 path and is never generated here.
GENERATABLE_TYPES: frozenset[ArtifactType] = frozenset(
    {
        ArtifactType.MITIGATION_PLAN,
        ArtifactType.ANALYST_RESEARCH_TASK,
        ArtifactType.TELEMETRY_CONTRACT,
    }
)


class ArtifactSection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    heading: str = Field(min_length=1)
    items: list[str] = Field(min_length=1)


class GeneratedArtifactContent(BaseModel):
    """Generic structured body shared by all three artifact types.

    ``sections`` carries the per-type substance (mitigation steps, research
    questions, telemetry requirements) as headed string lists — no free
    markdown, so the frontend renders plain text nodes only. The
    assumptions/limitations/references/confidence metadata is mandated on
    every generated artifact by AGENTS.md.
    """

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    sections: list[ArtifactSection] = Field(min_length=1)
    assumptions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class ArtifactGenerationError(Exception):
    """Base error for the artifact-generation service."""


class ArtifactAlreadyGeneratingError(ArtifactGenerationError):
    """An active row for this (assessment, type) is still 'generating'."""


async def begin_generation(
    session: AsyncSession,
    *,
    assessment_id: uuid.UUID,
    artifact_type: ArtifactType,
) -> GeneratedArtifactRow:
    """Sync precheck + row creation (the Plan A ``begin_run`` idiom).

    Deactivates the prior active row for ``(assessment_id, artifact_type)``,
    inserts a fresh ``status='generating'`` row with ``version = max+1``,
    and records plan provenance (``artifact_plan_id`` +
    ``plan_recommended``) from the current active plan when one exists.
    The caller commits and dispatches the Celery task.

    Raises :class:`ArtifactAlreadyGeneratingError` when the active row is
    still ``generating`` — re-dispatching mid-flight would double-bill the
    LLM call for no benefit.
    """
    if artifact_type not in GENERATABLE_TYPES:
        raise ValueError(
            f"artifact_type {artifact_type.value!r} is not generatable here "
            "(sigma_rule stays on the Loop 3 path)"
        )

    result = await session.execute(
        select(GeneratedArtifactRow)
        .where(
            GeneratedArtifactRow.assessment_id == assessment_id,
            GeneratedArtifactRow.artifact_type == artifact_type.value,
        )
        .order_by(GeneratedArtifactRow.version.desc())
    )
    prior_rows = result.scalars().all()
    active = [r for r in prior_rows if r.is_active]
    for row in active:
        if row.status == "generating":
            raise ArtifactAlreadyGeneratingError(
                f"{artifact_type.value} is already generating for this assessment"
            )

    plan_result = await session.execute(active_plan_stmt(assessment_id))
    plan_row = plan_result.scalar_one_or_none()
    plan_id = plan_row.id if plan_row is not None else None
    plan_recommended = False
    if plan_row is not None:
        recommended_types = {
            a.get("type") for a in (plan_row.plan or {}).get("recommended", [])
        }
        plan_recommended = artifact_type.value in recommended_types

    # Deactivate-then-flush BEFORE inserting the replacement: the partial
    # unique index (one active row per assessment+type) is checked per
    # statement, so the INSERT must not reach the DB while the old row is
    # still active.
    for row in active:
        row.is_active = False
    await session.flush()

    new_row = GeneratedArtifactRow(
        assessment_id=assessment_id,
        artifact_plan_id=plan_id,
        artifact_type=artifact_type.value,
        version=(prior_rows[0].version + 1) if prior_rows else 1,
        is_active=True,
        plan_recommended=plan_recommended,
        status="generating",
    )
    session.add(new_row)
    await session.flush()
    logger.info(
        "assessment.artifact.generation_begun",
        assessment_id=str(assessment_id),
        artifact_type=artifact_type.value,
        version=new_row.version,
        plan_recommended=plan_recommended,
    )
    return new_row


# task_type doubles as the prompt_templates key and the InteractionType value.
_INTERACTION_BY_ARTIFACT: dict[ArtifactType, InteractionType] = {
    ArtifactType.MITIGATION_PLAN: InteractionType.MITIGATION_PLAN,
    ArtifactType.ANALYST_RESEARCH_TASK: InteractionType.ANALYST_RESEARCH_TASK,
    ArtifactType.TELEMETRY_CONTRACT: InteractionType.TELEMETRY_CONTRACT,
}


def _summarize_detectability(row: DetectabilityAssessmentRow | None) -> str:
    if row is None:
        return "(no detectability classification available)"
    payload = row.payload or {}
    lines = [
        f"class: {row.detectability_class} "
        f"(confidence {float(row.confidence):.2f})",
        f"rationale: {payload.get('rationale', '')}",
    ]
    for key in ("required_telemetry", "blind_spots", "assumptions"):
        items = payload.get(key) or []
        if items:
            lines.append(f"{key}: " + "; ".join(str(i) for i in items))
    return "\n".join(lines)


def _summarize_plan(row: Any | None) -> str:
    if row is None:
        return "(no artifact plan available)"
    plan = row.plan or {}
    lines = [
        f"- recommended {a.get('type')}: {a.get('reason')}"
        for a in plan.get("recommended") or []
    ] + [
        f"- skipped {a.get('type')}: {a.get('reason')}"
        for a in plan.get("skipped") or []
    ]
    return "\n".join(lines) or "(empty plan)"


class ArtifactGenerator:
    """Headless-callable non-Sigma artifact generator (Phase 2b).

    Advisory at the service boundary: :meth:`generate` catches its own
    exceptions, marks the pre-inserted row ``failed``, and never raises —
    the worker task adds a fresh-session backstop for the case where even
    the failure-commit dies (Plan A's ``_finalize_failed`` idiom).
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

    async def generate(
        self,
        *,
        assessment_id: uuid.UUID,
        artifact_type: ArtifactType,
        artifact_row_id: uuid.UUID,
    ) -> GeneratedArtifactRow | None:
        try:
            return await self._generate(
                assessment_id=assessment_id,
                artifact_type=artifact_type,
                artifact_row_id=artifact_row_id,
            )
        except Exception as exc:  # noqa: BLE001 — advisory stage, never raises
            logger.warning(
                "assessment.artifact.generate_failed",
                assessment_id=str(assessment_id),
                artifact_type=artifact_type.value,
                error=repr(exc),
            )
            return await self._mark_failed(artifact_row_id, repr(exc))

    async def _generate(
        self,
        *,
        assessment_id: uuid.UUID,
        artifact_type: ArtifactType,
        artifact_row_id: uuid.UUID,
    ) -> GeneratedArtifactRow | None:
        row = await self._session.get(GeneratedArtifactRow, artifact_row_id)
        if row is None:
            logger.warning(
                "assessment.artifact.row_missing",
                artifact_row_id=str(artifact_row_id),
            )
            return None
        if row.status != "generating":
            # Celery-delivery idempotency: a duplicate/late task must not
            # re-bill the LLM call or clobber a terminal status.
            logger.info(
                "assessment.artifact.not_generating_skip",
                artifact_row_id=str(artifact_row_id),
                status=row.status,
            )
            return row

        task_type = artifact_type.value
        selection = await self._prompt_store.get_active(
            task_type=task_type,
            target_model=self._model_override or "*",
            target_provider="*",
        )
        if selection is None:
            raise RuntimeError(
                f"no active prompt template for task_type={task_type!r}"
            )

        ctx = await self._load_context(assessment_id)
        user_text = selection.user_template.format(
            cve_id=ctx["cve_id"],
            vuln_profile=ctx["vuln_profile"],
            indicators_summary=ctx["indicators_summary"],
            detectability_summary=ctx["detectability_summary"],
            plan_summary=ctx["plan_summary"],
        )

        model = resolve_chat_model(self._model_override, selection.target_model)
        provider = resolve_chat_provider(self._provider)

        result = await structured_complete(
            provider=provider,
            system=selection.system_prompt,
            user=user_text,
            model=model,
            schema=GeneratedArtifactContent,
            interaction_type=_INTERACTION_BY_ARTIFACT[artifact_type],
            entity_type="coverage_assessment",
            entity_id=assessment_id,
            prompt_template_id=selection.id,
            prompt_version=selection.version,
            timeout_seconds=get_settings().LLM_STRUCTURED_TIMEOUT_SECONDS,
        )
        content = result.value

        row.status = "generated"
        row.content = content.model_dump(mode="json")
        row.model = model
        row.prompt_template_id = selection.id
        row.cost_usd = Decimal(str(round(result.cost_usd, 4)))
        row.error = None
        row.completed_at = datetime.now(tz=timezone.utc)
        await self._session.commit()
        logger.info(
            "assessment.artifact.generated",
            assessment_id=str(assessment_id),
            artifact_type=task_type,
            version=row.version,
        )
        return row

    async def _load_context(self, assessment_id: uuid.UUID) -> dict[str, str]:
        """Bounded prompt context from whatever rows exist.

        Every piece degrades to an explicit "(none)" marker — on-demand
        generation must work even before Loop 1/2 have run (the prompt
        tells the model to fill limitations honestly).
        """
        asmt = await self._session.get(CoverageAssessment, assessment_id)
        trigger = (asmt.initial_trigger or {}) if asmt is not None else {}
        cve_id = str(trigger.get("value", "")) or "(unknown)"

        async def _active_output(loop_number: int) -> dict[str, Any]:
            result = await self._session.execute(
                select(AssessmentLoopRun)
                .where(
                    AssessmentLoopRun.assessment_id == assessment_id,
                    AssessmentLoopRun.loop_number == loop_number,
                    AssessmentLoopRun.is_active.is_(True),
                )
                .order_by(AssessmentLoopRun.version.desc())
                .limit(1)
            )
            run = result.scalar_one_or_none()
            return (run.output or {}) if run is not None else {}

        loop1_out = await _active_output(1)
        loop2_out = await _active_output(2)
        vuln_profile = loop1_out.get("vuln_profile") or {}
        indicators = loop2_out.get("indicators") or {}

        det_result = await self._session.execute(
            active_detectability_stmt(assessment_id)
        )
        det_row = det_result.scalar_one_or_none()
        plan_result = await self._session.execute(active_plan_stmt(assessment_id))
        plan_row = plan_result.scalar_one_or_none()

        return {
            "cve_id": cve_id,
            "vuln_profile": (
                json.dumps(vuln_profile, indent=2, sort_keys=True)
                if vuln_profile
                else "(none)"
            ),
            "indicators_summary": _summarize_indicators(indicators),
            "detectability_summary": _summarize_detectability(det_row),
            "plan_summary": _summarize_plan(plan_row),
        }

    async def _mark_failed(
        self, artifact_row_id: uuid.UUID, error: str
    ) -> GeneratedArtifactRow | None:
        try:
            # The session may hold a failed transaction (that's typically why
            # we're here) — roll back so the recovery UPDATE can run. On a
            # clean session this is a harmless no-op transaction end.
            await self._session.rollback()
            row = await self._session.get(GeneratedArtifactRow, artifact_row_id)
            if row is None:
                return None
            if row.status == "generating":
                row.status = "failed"
                row.error = error
                row.completed_at = datetime.now(tz=timezone.utc)
                await self._session.commit()
            return row
        except Exception as exc:  # noqa: BLE001 — best-effort; worker backstops
            logger.warning(
                "assessment.artifact.mark_failed_errored",
                artifact_row_id=str(artifact_row_id),
                error=repr(exc),
            )
            return None
