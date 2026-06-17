"""Behavior tests for the concrete post-loop hooks."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.loops.post_loop import (
    GateHook,
    ChainSynthesisHook,
    LoopExecution,
)
from fragchain.assessments.chain_synthesis import ChainSynthesisError
from fragchain.assessments.schemas import LoopNumber


def _ex(loop_number, status, output, gate_result=None, prior_outputs=None):
    asmt = MagicMock()
    asmt.id = uuid.uuid4()
    asmt.cve_id = uuid.uuid4()
    asmt.initial_trigger = {"value": "CVE-2024-0001"}
    ex = LoopExecution(
        ctx=MagicMock(assessment_id=uuid.uuid4()),
        run=MagicMock(),
        assessment=asmt,
        loop_number=loop_number,
        status=status,
        output=output,
        gate_result=gate_result,
        prior_outputs=prior_outputs or {},
    )
    return ex


@pytest.mark.asyncio
async def test_gate_hook_flips_status_when_gate_fails():
    ex = _ex(
        LoopNumber.TWO, "succeeded",
        output={"indicators": {"process": [], "file": [], "network": [],
                "command_line": [], "registry": [], "parent_child": [],
                "api_call": []}},
    )
    hook = GateHook(gate_min=3)
    assert hook.should_run(ex)
    await hook.run(ex)
    assert ex.status == "gate_failed"
    assert ex.gate_result is not None and ex.gate_result["passed"] is False


@pytest.mark.asyncio
async def test_gate_hook_passes_with_enough_categories():
    ex = _ex(
        LoopNumber.TWO, "succeeded",
        output={"indicators": {"process": [{"value": "p"}],
                "command_line": [{"value": "c"}], "network": [{"value": "n"}],
                "file": [], "registry": [], "parent_child": [], "api_call": []}},
    )
    hook = GateHook(gate_min=3)
    await hook.run(ex)
    assert ex.status == "succeeded"
    assert ex.gate_result["passed"] is True


@pytest.mark.asyncio
async def test_gate_hook_skips_non_loop2():
    ex = _ex(LoopNumber.ONE, "succeeded", output={})
    assert GateHook(gate_min=3).should_run(ex) is False


@pytest.mark.asyncio
async def test_chain_synthesis_hook_flips_status_to_failed_on_error():
    synth = MagicMock()
    synth.synthesize = AsyncMock(side_effect=ChainSynthesisError("boom"))
    ex = _ex(
        LoopNumber.TWO, "succeeded",
        output={"indicators": {}},
        gate_result={"passed": True},
        prior_outputs={1: {"vuln_profile": {"vuln_class": "x"}}},
    )
    hook = ChainSynthesisHook(synthesizer=synth)
    assert hook.should_run(ex)
    await hook.run(ex)
    assert ex.status == "failed"


@pytest.mark.asyncio
async def test_chain_synthesis_hook_skips_when_gate_failed():
    ex = _ex(
        LoopNumber.TWO, "gate_failed",
        output={"indicators": {}},
        gate_result={"passed": False},
    )
    hook = ChainSynthesisHook(synthesizer=MagicMock())
    assert hook.should_run(ex) is False
