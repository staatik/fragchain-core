from __future__ import annotations

import pytest
from pydantic import ValidationError

from fragchain.assessments.loops.schemas import (
    BehavioralIndicator,
    DetectionQuestion,
    Loop1Output,
    Loop2Output,
    ObservableCategory,
    VulnProfile,
)


def test_vuln_profile_requires_all_fields():
    vp = VulnProfile(
        vuln_class="deserialization rce",
        affected_component="log4j JNDI lookup",
        trigger_conditions=["lookups enabled"],
        attacker_preconditions=["network reachable"],
        expected_impact="rce",
        exploitation_surface="public http",
    )
    assert vp.vuln_class == "deserialization rce"


def test_vuln_profile_rejects_unknown_field():
    with pytest.raises(ValidationError):
        VulnProfile(
            vuln_class="x", affected_component="y",
            trigger_conditions=["a"], attacker_preconditions=["b"],
            expected_impact="c", exploitation_surface="d",
            future_unknown_field="boom",
        )


def test_loop1_output_min_three_questions():
    qs = [
        DetectionQuestion(
            id=f"q{i}", category=ObservableCategory.PROCESS,
            question="?", why_it_matters="?",
        )
        for i in range(2)
    ]
    vp = VulnProfile(
        vuln_class="x", affected_component="y",
        trigger_conditions=["a"], attacker_preconditions=["b"],
        expected_impact="c", exploitation_surface="d",
    )
    with pytest.raises(ValidationError):
        Loop1Output(vuln_profile=vp, detection_questions=qs)


def test_behavioral_indicator_kinds_constrained():
    BehavioralIndicator(
        value="java.exe", kind="literal", source_ref="src1",
        confidence=0.8, answers_question_id="q1",
    )
    with pytest.raises(ValidationError):
        BehavioralIndicator(
            value="x", kind="unknown_kind", source_ref="s",
            confidence=0.5, answers_question_id=None,
        )


def test_loop2_output_has_full_category_map_after_validation():
    out = Loop2Output(indicators={}, unanswered_questions=[])
    # the schema fills missing categories with empty lists so downstream code
    # can iterate ObservableCategory without KeyError.
    assert set(out.indicators.keys()) == {c.value for c in ObservableCategory}
