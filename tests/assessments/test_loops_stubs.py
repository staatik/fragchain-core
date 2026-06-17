"""Stub loop unit tests.

Stubs return deterministic canned outputs so the workflow can be
end-to-end testable without an LLM. The Loop 2 stub deliberately
emits a thin indicator map that fails the default category-coverage
gate, so the gate-failure path is exercised in integration tests.
"""
from __future__ import annotations

import uuid

import pytest

from fragchain.assessments.loops.base import LoopContext
from fragchain.assessments.loops.stubs import (
    StubLoop1,
    StubLoop2,
    StubLoop3,
    evaluate_detectability_gate,
)


@pytest.fixture
def ctx() -> LoopContext:
    return LoopContext(
        assessment_id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        cve_textual_id="CVE-2026-1234",
        source_contents=["analyst pasted intel content"],
        prior_outputs={},
    )


@pytest.mark.asyncio
async def test_loop1_stub_emits_vuln_profile_and_questions(ctx: LoopContext) -> None:
    out = await StubLoop1().run(ctx)
    assert out["vuln_profile"]["vuln_class"]
    assert isinstance(out["detection_questions"], list)
    assert len(out["detection_questions"]) >= 3


@pytest.mark.asyncio
async def test_loop2_stub_returns_indicators_below_gate(ctx: LoopContext) -> None:
    out = await StubLoop2().run(ctx)
    assert "indicators" in out
    # Stub emits indicators in 1 or 2 categories; gate threshold is 3.
    filled = [k for k, v in out["indicators"].items() if v]
    assert 1 <= len(filled) <= 2


@pytest.mark.asyncio
async def test_loop3_stub_returns_rule_drafts(ctx: LoopContext) -> None:
    out = await StubLoop3().run(ctx)
    assert "rules" in out
    assert isinstance(out["rules"], list)


def test_evaluate_detectability_gate_passes_at_or_above_threshold() -> None:
    result = evaluate_detectability_gate(
        {
            "process": [{"value": "java.exe"}],
            "command_line": [{"value": "-jar"}],
            "network": [{"value": "ldap://"}],
            "file": [],
            "registry": [],
            "parent_child": [],
            "api_call": [],
        },
        min_categories=3,
    )
    assert result["passed"] is True
    assert sorted(result["filled_categories"]) == [
        "command_line",
        "network",
        "process",
    ]


def test_evaluate_detectability_gate_fails_below_threshold() -> None:
    result = evaluate_detectability_gate(
        {
            "process": [{"value": "java.exe"}],
            "command_line": [],
            "network": [],
            "file": [],
            "registry": [],
            "parent_child": [],
            "api_call": [],
        },
        min_categories=3,
    )
    assert result["passed"] is False
    assert result["filled_categories"] == ["process"]
    assert result["threshold"] == 3
