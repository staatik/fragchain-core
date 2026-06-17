"""State transition unit tests.

Pure-function module — no DB, no async. The orchestrator calls these
helpers to determine whether a transition is legal before mutating
the row.
"""
from __future__ import annotations

import pytest

from fragchain.assessments.schemas import AssessmentState, LoopNumber
from fragchain.assessments.state_machine import (
    StateTransitionError,
    can_close,
    can_run_loop,
    next_state_after_loop,
    states_invalidated_by_rerun,
)


@pytest.mark.parametrize(
    "current,loop,expected",
    [
        (AssessmentState.CREATED, LoopNumber.ONE, True),
        (AssessmentState.CREATED, LoopNumber.TWO, False),
        (AssessmentState.LOOP1_DONE, LoopNumber.ONE, True),  # re-run
        (AssessmentState.LOOP1_DONE, LoopNumber.TWO, True),
        (AssessmentState.LOOP1_DONE, LoopNumber.THREE, False),
        (AssessmentState.LOOP2_DONE, LoopNumber.ONE, True),  # re-run, invalidates 2+3
        (AssessmentState.LOOP2_DONE, LoopNumber.TWO, True),  # re-run
        (AssessmentState.LOOP2_DONE, LoopNumber.THREE, True),
        (AssessmentState.LOOP3_DONE, LoopNumber.ONE, True),  # re-run, invalidates 2+3
        (AssessmentState.LOOP3_DONE, LoopNumber.TWO, True),  # re-run, invalidates 3
        (AssessmentState.LOOP3_DONE, LoopNumber.THREE, True),  # re-run
        (AssessmentState.COMPLETED, LoopNumber.ONE, False),
        (AssessmentState.COMPLETED, LoopNumber.TWO, False),
        (AssessmentState.COMPLETED, LoopNumber.THREE, False),
    ],
)
def test_can_run_loop(current, loop, expected) -> None:
    assert can_run_loop(current, loop) is expected


def test_next_state_after_loop_progresses_or_returns_same() -> None:
    assert next_state_after_loop(AssessmentState.CREATED, LoopNumber.ONE) == \
        AssessmentState.LOOP1_DONE
    assert next_state_after_loop(AssessmentState.LOOP1_DONE, LoopNumber.TWO) == \
        AssessmentState.LOOP2_DONE
    assert next_state_after_loop(AssessmentState.LOOP2_DONE, LoopNumber.THREE) == \
        AssessmentState.LOOP3_DONE
    # Re-running a loop keeps state at that loop's done.
    assert next_state_after_loop(AssessmentState.LOOP3_DONE, LoopNumber.THREE) == \
        AssessmentState.LOOP3_DONE
    assert next_state_after_loop(AssessmentState.LOOP2_DONE, LoopNumber.TWO) == \
        AssessmentState.LOOP2_DONE


def test_states_invalidated_by_rerun_returns_downstream_only() -> None:
    assert states_invalidated_by_rerun(LoopNumber.ONE) == [LoopNumber.TWO, LoopNumber.THREE]
    assert states_invalidated_by_rerun(LoopNumber.TWO) == [LoopNumber.THREE]
    assert states_invalidated_by_rerun(LoopNumber.THREE) == []


def test_can_close_only_in_loop3_done_or_loop2_done() -> None:
    assert can_close(AssessmentState.LOOP3_DONE) is True
    # loop2_done OK because gate failure + analyst override path may produce
    # no rules and still want to close.
    assert can_close(AssessmentState.LOOP2_DONE) is True
    assert can_close(AssessmentState.CREATED) is False
    assert can_close(AssessmentState.LOOP1_DONE) is False
    assert can_close(AssessmentState.COMPLETED) is False


def test_state_transition_error_is_subclass_of_value_error() -> None:
    assert issubclass(StateTransitionError, ValueError)
