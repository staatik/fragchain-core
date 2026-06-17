"""Pydantic schemas for Loop 1 + Loop 2 outputs.

The schemas use ``extra='forbid'`` to surface prompt drift; if a model
emits an unknown field we'd rather fail the loop than silently drop data
(matches CLAUDE.md §11 strictness rules).
"""
from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ObservableCategory(str, Enum):
    PROCESS = "process"
    COMMAND_LINE = "command_line"
    FILE = "file"
    NETWORK = "network"
    REGISTRY = "registry"
    PARENT_CHILD = "parent_child"
    API_CALL = "api_call"


class VulnProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vuln_class: str
    affected_component: str
    trigger_conditions: list[str] = Field(min_length=1)
    attacker_preconditions: list[str] = Field(min_length=1)
    expected_impact: str
    exploitation_surface: str


class DetectionQuestion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=8)
    category: ObservableCategory
    question: str = Field(min_length=1)
    why_it_matters: str = Field(min_length=1)


class Loop1Output(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vuln_profile: VulnProfile
    detection_questions: list[DetectionQuestion] = Field(
        min_length=3, max_length=20
    )


class BehavioralIndicator(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1)
    kind: Literal["literal", "regex", "substring"]
    source_ref: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    answers_question_id: str | None = None


class Loop2Output(BaseModel):
    # ``indicators`` uses the enum's *string value* as the key so the dict
    # round-trips cleanly through JSON (LLM I/O, MinIO archive, Pydantic
    # ``model_dump``). The ``_fill_missing_categories`` validator guarantees
    # every ``ObservableCategory.value`` is present after construction so
    # downstream Phase 4 code can iterate categories without ``KeyError``.
    model_config = ConfigDict(extra="forbid")

    indicators: dict[str, list[BehavioralIndicator]] = Field(
        default_factory=dict
    )
    unanswered_questions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _fill_missing_categories(self) -> "Loop2Output":
        # Downstream consumers iterate over all categories — guarantee
        # presence to keep gate evaluation + chain synthesis null-free.
        # Normalize any enum-typed keys callers may have passed in.
        filled: dict[str, list[BehavioralIndicator]] = {}
        for key, value in self.indicators.items():
            normalized = key.value if isinstance(key, ObservableCategory) else key
            filled[normalized] = value
        for cat in ObservableCategory:
            filled.setdefault(cat.value, [])
        # ``ConfigDict`` is not frozen — direct assignment is allowed, but
        # ``object.__setattr__`` sidesteps Pydantic's re-coercion of the
        # dict keys back into ``ObservableCategory`` members.
        object.__setattr__(self, "indicators", filled)
        return self
