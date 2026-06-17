"""Phase 2b content schemas — strict, extra='forbid' (spec §Content schema)."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from fragchain.assessments.artifact_generation import (
    GENERATABLE_TYPES,
    ArtifactSection,
    GeneratedArtifactContent,
)
from fragchain.assessments.detectability import ArtifactType


def _valid_payload(**extra) -> dict:
    payload = {
        "title": "Mitigation plan for CVE-2026-1234",
        "summary": "Patch and reduce exposure.",
        "sections": [
            {"heading": "Patching", "items": ["Upgrade to 2.4.1"]},
        ],
        "assumptions": ["Vendor advisory is accurate"],
        "limitations": ["No exploit telemetry available"],
        "references": ["https://example.com/advisory"],
        "confidence": 0.7,
    }
    payload.update(extra)
    return payload


def test_valid_payload_parses() -> None:
    content = GeneratedArtifactContent.model_validate(_valid_payload())
    assert content.title.startswith("Mitigation")
    assert content.sections[0].heading == "Patching"


def test_metadata_lists_default_empty() -> None:
    payload = _valid_payload()
    for key in ("assumptions", "limitations", "references"):
        payload.pop(key)
    content = GeneratedArtifactContent.model_validate(payload)
    assert content.assumptions == []
    assert content.limitations == []
    assert content.references == []


def test_extra_fields_rejected() -> None:
    with pytest.raises(ValidationError):
        GeneratedArtifactContent.model_validate(_valid_payload(surprise="x"))


def test_section_extra_fields_rejected() -> None:
    with pytest.raises(ValidationError):
        ArtifactSection.model_validate(
            {"heading": "H", "items": ["a"], "surprise": "x"}
        )


def test_empty_sections_rejected() -> None:
    with pytest.raises(ValidationError):
        GeneratedArtifactContent.model_validate(_valid_payload(sections=[]))


def test_section_with_empty_items_rejected() -> None:
    with pytest.raises(ValidationError):
        GeneratedArtifactContent.model_validate(
            _valid_payload(sections=[{"heading": "H", "items": []}])
        )


def test_confidence_bounds() -> None:
    with pytest.raises(ValidationError):
        GeneratedArtifactContent.model_validate(_valid_payload(confidence=1.5))
    with pytest.raises(ValidationError):
        GeneratedArtifactContent.model_validate(_valid_payload(confidence=-0.1))


def test_generatable_types_exclude_sigma() -> None:
    assert ArtifactType.SIGMA_RULE not in GENERATABLE_TYPES
    assert GENERATABLE_TYPES == frozenset(
        {
            ArtifactType.MITIGATION_PLAN,
            ArtifactType.ANALYST_RESEARCH_TASK,
            ArtifactType.TELEMETRY_CONTRACT,
        }
    )


def test_interaction_types_for_artifact_generation() -> None:
    from fragchain.llm.base import InteractionType

    assert InteractionType.MITIGATION_PLAN.value == "mitigation_plan"
    assert InteractionType.ANALYST_RESEARCH_TASK.value == "analyst_research_task"
    assert InteractionType.TELEMETRY_CONTRACT.value == "telemetry_contract"
