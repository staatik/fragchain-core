"""Deterministic routing-policy tests (Phase 2, ADR-0004 §3).

The policy is a pure function: same classification + context in, same plan
out. Each test pins one guardrail of policy v1.
"""
from __future__ import annotations

import pytest

from fragchain.assessments.artifact_router import (
    POLICY_VERSION,
    RouterPlan,
    build_plan,
)
from fragchain.assessments.detectability import (
    ArtifactType,
    DetectabilityAssessment,
)


def _classification(**overrides) -> DetectabilityAssessment:
    base = {
        "detectability_class": "directly_detectable",
        "rationale": "stable child-process observable",
        "confidence": 0.8,
        "required_telemetry": ["process creation"],
        "recommended_artifacts": [
            {"type": "sigma_rule", "reason": "stable observable", "priority": 1}
        ],
        "skipped_artifacts": [],
    }
    base.update(overrides)
    return DetectabilityAssessment.model_validate(base)


_GATE_PASS = {"passed": True, "filled_categories": ["process", "file", "network"],
              "empty_categories": [], "threshold": 3}
_GATE_FAIL = {"passed": False, "filled_categories": ["process"],
              "empty_categories": ["file"], "threshold": 3}


def _plan(classification=None, *, confidence=0.8, gate=None, floor=0.4) -> RouterPlan:
    return build_plan(
        classification or _classification(),
        classifier_confidence=confidence,
        gate_result=gate or _GATE_PASS,
        min_confidence=floor,
    )


def _types(items) -> set[ArtifactType]:
    return {a.type for a in items}


# ---------------------------------------------------------------------------
# Pass-through classes
# ---------------------------------------------------------------------------


def test_directly_detectable_passes_classifier_plan_through() -> None:
    plan = _plan()
    assert ArtifactType.SIGMA_RULE in _types(plan.recommended)
    assert plan.recommended[0].reason == "stable observable"
    assert plan.policy_adjustments == []
    assert plan.policy_version == POLICY_VERSION
    assert plan.required_inputs == ["process creation"]


def test_indirectly_detectable_passes_through() -> None:
    plan = _plan(_classification(detectability_class="indirectly_detectable"))
    assert ArtifactType.SIGMA_RULE in _types(plan.recommended)
    assert plan.policy_adjustments == []


# ---------------------------------------------------------------------------
# Class guardrails
# ---------------------------------------------------------------------------


def test_insufficient_information_forces_sigma_skip_and_research_task() -> None:
    plan = _plan(_classification(detectability_class="insufficient_information"))
    assert ArtifactType.SIGMA_RULE in _types(plan.skipped)
    assert ArtifactType.SIGMA_RULE not in _types(plan.recommended)
    assert ArtifactType.ANALYST_RESEARCH_TASK in _types(plan.recommended)
    assert plan.policy_adjustments  # the override is recorded, not silent


def test_control_only_forces_sigma_skip_and_mitigation_plan() -> None:
    plan = _plan(_classification(detectability_class="control_only"))
    assert ArtifactType.SIGMA_RULE in _types(plan.skipped)
    assert ArtifactType.MITIGATION_PLAN in _types(plan.recommended)
    # the demoted skip carries a policy reason
    skip = next(s for s in plan.skipped if s.type == ArtifactType.SIGMA_RULE)
    assert "control-only" in skip.reason


def test_control_only_conflict_with_classifier_is_recorded() -> None:
    # classifier said "generate sigma" for a control_only class — guardrail
    # wins but the conflict must be visible.
    plan = _plan(_classification(detectability_class="control_only"))
    assert any("sigma_rule" in adj for adj in plan.policy_adjustments)


def test_environment_dependent_adds_prerequisite_and_telemetry_contract() -> None:
    plan = _plan(_classification(detectability_class="environment_dependent"))
    sigma = next(a for a in plan.recommended if a.type == ArtifactType.SIGMA_RULE)
    assert any("telemetry" in p for p in sigma.prerequisites)
    assert ArtifactType.TELEMETRY_CONTRACT in _types(plan.recommended)


def test_environment_dependent_respects_existing_telemetry_contract() -> None:
    c = _classification(
        detectability_class="environment_dependent",
        recommended_artifacts=[
            {"type": "sigma_rule", "reason": "r", "priority": 1},
            {"type": "telemetry_contract", "reason": "classifier said so", "priority": 1},
        ],
    )
    plan = _plan(c)
    contracts = [a for a in plan.recommended if a.type == ArtifactType.TELEMETRY_CONTRACT]
    assert len(contracts) == 1
    assert contracts[0].reason == "classifier said so"  # not overwritten


# ---------------------------------------------------------------------------
# Confidence floor + gate
# ---------------------------------------------------------------------------


def test_low_confidence_demotes_sigma_to_skip() -> None:
    plan = _plan(confidence=0.2, floor=0.4)
    assert ArtifactType.SIGMA_RULE in _types(plan.skipped)
    assert ArtifactType.ANALYST_RESEARCH_TASK in _types(plan.recommended)
    skip = next(s for s in plan.skipped if s.type == ArtifactType.SIGMA_RULE)
    assert "confidence" in skip.reason


def test_confidence_at_floor_is_not_demoted() -> None:
    plan = _plan(confidence=0.4, floor=0.4)
    assert ArtifactType.SIGMA_RULE in _types(plan.recommended)


def test_gate_failed_adds_override_prerequisite() -> None:
    plan = _plan(gate=_GATE_FAIL)
    sigma = next(a for a in plan.recommended if a.type == ArtifactType.SIGMA_RULE)
    assert any("override" in p for p in sigma.prerequisites)


# ---------------------------------------------------------------------------
# Structural invariants
# ---------------------------------------------------------------------------


def test_sigma_never_in_both_lists_after_demotion() -> None:
    plan = _plan(_classification(detectability_class="control_only"))
    assert _types(plan.recommended) & _types(plan.skipped) == set()


def test_classifier_skip_with_reason_survives() -> None:
    c = _classification(
        recommended_artifacts=[
            {"type": "mitigation_plan", "reason": "patch available", "priority": 1}
        ],
        skipped_artifacts=[
            {"type": "sigma_rule", "reason": "no stable observable"}
        ],
    )
    plan = _plan(c)
    skip = next(s for s in plan.skipped if s.type == ArtifactType.SIGMA_RULE)
    assert skip.reason == "no stable observable"
    assert plan.policy_adjustments == []


def test_plan_is_deterministic() -> None:
    c = _classification(detectability_class="environment_dependent")
    a = build_plan(c, classifier_confidence=0.3, gate_result=_GATE_FAIL, min_confidence=0.4)
    b = build_plan(c, classifier_confidence=0.3, gate_result=_GATE_FAIL, min_confidence=0.4)
    assert a.model_dump() == b.model_dump()


def test_every_skip_has_a_reason() -> None:
    for cls in ("insufficient_information", "control_only"):
        plan = _plan(_classification(detectability_class=cls))
        assert all(s.reason for s in plan.skipped)


def test_plan_schema_rejects_sigma_in_neither_list() -> None:
    with pytest.raises(Exception):
        RouterPlan.model_validate(
            {
                "recommended": [],
                "skipped": [],
                "required_inputs": [],
                "confidence": 0.5,
                "policy_version": POLICY_VERSION,
                "policy_adjustments": [],
            }
        )


def test_dual_listed_non_sigma_artifact_reconciled_to_skip() -> None:
    # Phase 1 schema permits a non-sigma type in BOTH classifier lists;
    # RouterPlan is stricter — reconcile (skip wins) instead of rejecting.
    c = _classification(
        recommended_artifacts=[
            {"type": "sigma_rule", "reason": "stable", "priority": 1},
            {"type": "telemetry_contract", "reason": "useful", "priority": 2},
        ],
        skipped_artifacts=[
            {"type": "telemetry_contract", "reason": "env owns telemetry docs"}
        ],
    )
    plan = _plan(c)
    assert ArtifactType.TELEMETRY_CONTRACT in _types(plan.skipped)
    assert ArtifactType.TELEMETRY_CONTRACT not in _types(plan.recommended)
    assert any("reconciled telemetry_contract" in a for a in plan.policy_adjustments)


def test_environment_dependent_plus_low_confidence_final_state() -> None:
    # Guardrail interaction: env_dependent adds a prerequisite to Sigma,
    # then the confidence floor demotes Sigma. Final plan must be
    # consistent (Sigma skipped only); the adjustments list is an
    # append-only derivation trace and may still mention the prerequisite.
    plan = _plan(
        _classification(detectability_class="environment_dependent"),
        confidence=0.2,
        floor=0.4,
    )
    assert ArtifactType.SIGMA_RULE in _types(plan.skipped)
    assert ArtifactType.SIGMA_RULE not in _types(plan.recommended)
    assert ArtifactType.TELEMETRY_CONTRACT in _types(plan.recommended)
    assert ArtifactType.ANALYST_RESEARCH_TASK in _types(plan.recommended)
    assert _types(plan.recommended) & _types(plan.skipped) == set()
