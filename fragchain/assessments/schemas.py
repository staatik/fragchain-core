"""Pydantic schemas for the assessment workflow.

Request/response shapes for the FastAPI router. Field validators enforce
the v1 constraints (free_text-only kind, trigger-kind allowlist) so the
router doesn't have to repeat the rules.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class TriggerKind(str, Enum):
    CVE_ID = "cve_id"
    TICKET = "ticket"
    PSIRT_URL = "psirt_url"


class AssessmentState(str, Enum):
    CREATED = "created"
    LOOP1_DONE = "loop1_done"
    LOOP2_DONE = "loop2_done"
    LOOP3_DONE = "loop3_done"
    COMPLETED = "completed"


class LoopNumber(int, Enum):
    ONE = 1
    TWO = 2
    THREE = 3


class Trigger(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: TriggerKind
    value: str = Field(min_length=1, max_length=500)


class AssessmentCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trigger: Trigger
    cve_id: uuid.UUID
    context_note: str | None = Field(default=None, max_length=2000)


class AssessmentResponse(BaseModel):
    id: uuid.UUID
    cve_id: uuid.UUID
    creator_id: uuid.UUID
    initial_trigger: dict[str, Any]
    context_note: str | None
    state: AssessmentState
    completed_at: datetime | None
    tlp: str
    auto_advance: bool = False
    created_at: datetime
    updated_at: datetime


class AssessmentExistingChain(BaseModel):
    chain_id: uuid.UUID
    source_origin: str
    version: int
    created_at: datetime
    ttp_count: int
    overall_confidence: float


class AssessmentCreateResponse(BaseModel):
    assessment: AssessmentResponse
    existing_chain: AssessmentExistingChain | None = None


class SourceCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["free_text"]
    title: str | None = Field(default=None, max_length=200)
    content: str = Field(min_length=1)
    tlp: str | None = None

    @field_validator("title")
    @classmethod
    def _empty_title_is_none(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        return stripped or None


class SourceResponse(BaseModel):
    id: uuid.UUID
    assessment_id: uuid.UUID
    kind: str
    title: str | None
    size_bytes: int
    content_hash: str
    tlp: str
    embedding_status: str
    pasted_at: datetime


class SourceDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rationale: str = Field(min_length=1, max_length=500)


class LoopRunOutput(BaseModel):
    id: uuid.UUID
    assessment_id: uuid.UUID
    loop_number: LoopNumber
    version: int
    status: str
    is_active: bool
    output: dict[str, Any] | None
    gate_result: dict[str, Any] | None
    override_rationale: str | None
    embedding_warned: bool
    model: str | None
    cost_usd: float | None
    latency_ms: int | None
    error: str | None
    started_at: datetime
    completed_at: datetime | None


class DetectabilityRead(BaseModel):
    """Read projection of a persisted detectability classification (Phase 1).

    Advisory output of the post-Loop-2 classifier — never gates Loop 3.
    ``payload`` is the full ``DetectabilityAssessment`` schema round-trip.
    """

    id: uuid.UUID
    assessment_id: uuid.UUID
    loop_run_id: uuid.UUID
    detectability_class: str
    confidence: float
    gate_passed: bool
    payload: dict[str, Any]
    model: str | None
    created_at: datetime


class ArtifactPlanRead(BaseModel):
    """Read projection of a persisted artifact plan (Phase 2, compatibility).

    ``plan`` is the full ``RouterPlan`` round-trip; ``observed`` is filled
    after Loop 3 runs and records whether generation diverged from the plan.
    """

    id: uuid.UUID
    assessment_id: uuid.UUID
    detectability_assessment_id: uuid.UUID
    loop_run_id: uuid.UUID
    mode: str
    sigma_planned: bool
    plan: dict[str, Any]
    observed: dict[str, Any] | None
    policy_version: str
    created_at: datetime


class LoopRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    override_rationale: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _validate_override(self) -> LoopRunRequest:
        # Override rationale is only meaningful for Loop 2 gate-fail paths;
        # the orchestrator validates it in context. Schema-level we just
        # cap length.
        return self


class UseExistingChainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    chain_id: uuid.UUID


class CloseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str | None = Field(default=None, max_length=500)


class ArtifactCreateRequest(BaseModel):
    """Request body for on-demand non-Sigma artifact generation (Phase 2b)."""

    model_config = ConfigDict(extra="forbid")

    artifact_type: Literal[
        "mitigation_plan", "analyst_research_task", "telemetry_contract"
    ]


class ArtifactRejectRequest(BaseModel):
    """Request body for rejecting a generated artifact (Phase 3 / W3b)."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1)


class GeneratedArtifactRead(BaseModel):
    """Read projection of a generated_artifacts row (Phase 2b).

    ``content`` is the validated ``GeneratedArtifactContent`` round-trip;
    null while ``status='generating'`` or after a failure.
    """

    id: uuid.UUID
    assessment_id: uuid.UUID
    artifact_plan_id: uuid.UUID | None
    artifact_type: str
    version: int
    is_active: bool
    plan_recommended: bool
    status: str
    validation_status: str
    content: dict[str, Any] | None
    model: str | None
    cost_usd: float | None
    error: str | None
    created_at: datetime
    completed_at: datetime | None
