"""Schema tests for the Phase 1 detectability classifier (ADR-0004)."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from fragchain.assessments.detectability import (
    ArtifactType,
    DetectabilityAssessment,
    DetectabilityClass,
    SkippedArtifact,
)


def _valid_payload(**overrides):
    base = {
        "detectability_class": "directly_detectable",
        "rationale": "Exploit spawns a child shell from the service binary.",
        "confidence": 0.8,
        "observable_behaviors": ["httpd spawning /bin/sh"],
        "required_telemetry": ["process creation with parent-child linkage"],
        "optional_telemetry": ["command-line auditing"],
        "blind_spots": ["fileless variants"],
        "assumptions": ["auditd or sysmon-equivalent is deployed"],
        "recommended_artifacts": [
            {
                "type": "sigma_rule",
                "reason": "stable parent-child observable",
                "priority": 1,
            }
        ],
        "skipped_artifacts": [],
        "references": ["https://example.org/advisory"],
    }
    base.update(overrides)
    return base


@pytest.mark.parametrize(
    "cls",
    [
        "directly_detectable",
        "indirectly_detectable",
        "environment_dependent",
        "control_only",
        "insufficient_information",
    ],
)
def test_all_five_classes_round_trip(cls: str) -> None:
    a = DetectabilityAssessment.model_validate(
        _valid_payload(detectability_class=cls)
    )
    assert a.detectability_class == DetectabilityClass(cls)


def test_extra_fields_rejected() -> None:
    with pytest.raises(ValidationError):
        DetectabilityAssessment.model_validate(_valid_payload(surprise="x"))


def test_confidence_bounds() -> None:
    with pytest.raises(ValidationError):
        DetectabilityAssessment.model_validate(_valid_payload(confidence=1.5))


def test_sigma_must_be_explicitly_recommended_or_skipped() -> None:
    # sigma_rule absent from both lists → invalid (must be justified either way)
    with pytest.raises(ValidationError):
        DetectabilityAssessment.model_validate(
            _valid_payload(recommended_artifacts=[], skipped_artifacts=[])
        )


def test_sigma_cannot_be_both_recommended_and_skipped() -> None:
    with pytest.raises(ValidationError):
        DetectabilityAssessment.model_validate(
            _valid_payload(
                skipped_artifacts=[{"type": "sigma_rule", "reason": "too noisy"}]
            )
        )


def test_sigma_skip_with_reason_is_valid_no_detection_outcome() -> None:
    # control_only: no Sigma, mitigation plan instead — a valid successful output.
    a = DetectabilityAssessment.model_validate(
        _valid_payload(
            detectability_class="control_only",
            recommended_artifacts=[
                {
                    "type": "mitigation_plan",
                    "reason": "patch + config change suffice",
                    "priority": 1,
                }
            ],
            skipped_artifacts=[
                {
                    "type": "sigma_rule",
                    "reason": "no stable exploit observable in common telemetry",
                }
            ],
        )
    )
    assert a.skipped_artifacts[0].reason
    assert ArtifactType.SIGMA_RULE not in {r.type for r in a.recommended_artifacts}


def test_skip_reason_required() -> None:
    with pytest.raises(ValidationError):
        SkippedArtifact.model_validate({"type": "sigma_rule", "reason": ""})


def test_missing_telemetry_representable() -> None:
    # environment_dependent with required telemetry the env may lack.
    a = DetectabilityAssessment.model_validate(
        _valid_payload(
            detectability_class="environment_dependent",
            required_telemetry=["application-level audit log (module X)"],
            recommended_artifacts=[
                {
                    "type": "telemetry_contract",
                    "reason": "telemetry must exist first",
                    "priority": 1,
                }
            ],
            skipped_artifacts=[
                {
                    "type": "sigma_rule",
                    "reason": "required telemetry not commonly enabled",
                }
            ],
        )
    )
    assert a.required_telemetry
