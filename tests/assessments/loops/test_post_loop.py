"""Tests for the post-loop hook pipeline scaffolding."""
from __future__ import annotations

import uuid

import pytest

from fragchain.assessments.loops.post_loop import (
    LoopExecution,
    run_pipeline,
)
from fragchain.assessments.schemas import LoopNumber


class _RecordingHook:
    def __init__(self, name, applies, marker):
        self.name = name
        self._applies = applies
        self._marker = marker

    def should_run(self, ex):
        return self._applies

    async def run(self, ex):
        ex.trace.append(self._marker)


@pytest.mark.asyncio
async def test_run_pipeline_runs_only_applicable_hooks_in_order():
    ex = LoopExecution(
        ctx=None,
        run=None,
        assessment=None,
        loop_number=LoopNumber.TWO,
        status="succeeded",
        output={},
        gate_result=None,
        prior_outputs={},
    )
    ex.trace = []
    hooks = [
        _RecordingHook("a", True, "A"),
        _RecordingHook("skip", False, "SKIP"),
        _RecordingHook("b", True, "B"),
    ]
    await run_pipeline(hooks, ex)
    assert ex.trace == ["A", "B"]


def test_loop_execution_is_mutable_dataclass():
    ex = LoopExecution(
        ctx=None, run=None, assessment=None,
        loop_number=LoopNumber.ONE, status="succeeded",
        output=None, gate_result=None, prior_outputs={},
    )
    ex.status = "failed"
    assert ex.status == "failed"
    assert ex.synth_meta is None
    assert ex.supersession_totals == {"pending_superseded": 0, "approved_deprecated": 0}
