"""Phase 2c class-derived Sigma-generation gate (pure policy).

The gate keys on the detectability CLASS, never on plan.sigma_planned (which
folds in the anti-predictive confidence-floor demotion — see
docs/architecture/2026-06-14-phase-2c-revisited-decision.md).
"""
from __future__ import annotations

import uuid

from fragchain.assessments.gating import (
    SIGMA_SKIP_CLASSES,
    gated_loop3_output,
    sigma_generation_gated,
)

_BOTH = frozenset({"insufficient_information", "control_only"})


def test_skip_classes_are_the_two_decline_classes():
    assert SIGMA_SKIP_CLASSES == frozenset(
        {"insufficient_information", "control_only"}
    )


def test_gates_the_two_decline_classes_when_enabled():
    assert sigma_generation_gated("insufficient_information", enabled_skip_classes=_BOTH)
    assert sigma_generation_gated("control_only", enabled_skip_classes=_BOTH)


def test_never_gates_generate_or_prerequisite_classes():
    for cls in ("directly_detectable", "indirectly_detectable", "environment_dependent"):
        assert not sigma_generation_gated(cls, enabled_skip_classes=_BOTH)


def test_empty_config_disables_the_gate():
    assert not sigma_generation_gated("control_only", enabled_skip_classes=frozenset())
    assert not sigma_generation_gated(
        "insufficient_information", enabled_skip_classes=frozenset()
    )


def test_config_can_narrow_to_one_class():
    only = frozenset({"insufficient_information"})
    assert sigma_generation_gated("insufficient_information", enabled_skip_classes=only)
    assert not sigma_generation_gated("control_only", enabled_skip_classes=only)


def test_none_or_unknown_class_never_gates():
    assert not sigma_generation_gated(None, enabled_skip_classes=_BOTH)
    assert not sigma_generation_gated("", enabled_skip_classes=_BOTH)
    assert not sigma_generation_gated("made_up_class", enabled_skip_classes=_BOTH)


def test_gated_output_carries_fallback_and_no_rules():
    cid = uuid.uuid4()
    out = gated_loop3_output("control_only", chain_id=cid)
    assert out["rules"] == []
    assert out["gated"] is True
    assert out["gated_class"] == "control_only"
    assert out["recommended_fallback"] == "mitigation_plan"
    assert out["chain_id"] == str(cid)
    assert out["_llm"] == {"model": None, "cost_usd": 0.0}
    assert "no reliable detection" in out["gated_reason"].lower()


def test_settings_property_parses_skip_classes(monkeypatch):
    from fragchain.config import Settings

    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv(
        "ROUTER_GATING_SKIP_CLASSES", "insufficient_information, control_only"
    )
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.router_gating_skip_classes == frozenset(
        {"insufficient_information", "control_only"}
    )

    monkeypatch.setenv("ROUTER_GATING_SKIP_CLASSES", "")
    assert Settings(_env_file=None).router_gating_skip_classes == frozenset()  # type: ignore[call-arg]


def test_gated_output_fallback_per_class():
    assert (
        gated_loop3_output("insufficient_information", chain_id=uuid.uuid4())[
            "recommended_fallback"
        ]
        == "analyst_research_task"
    )
    assert (
        gated_loop3_output("control_only", chain_id=uuid.uuid4())[
            "recommended_fallback"
        ]
        == "mitigation_plan"
    )
