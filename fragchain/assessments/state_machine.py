"""Pure state-transition functions.

The state machine is documented in spec §4.2. This module exposes
predicates the orchestrator uses to gate transitions; it does not
touch the DB and is fully synchronous so it's trivially testable.
"""
from __future__ import annotations

from fragchain.assessments.schemas import AssessmentState, LoopNumber


class StateTransitionError(ValueError):
    """Raised when a requested transition violates the state machine."""


# Map of which loops can run from which current states. Loop N is runnable
# once its prerequisite (loop N-1 done) is met, from any later non-terminal
# state — re-running from a later state supersedes downstream runs and
# reverts state to loop(N)_done (spec §4.2).
_RUNNABLE: dict[AssessmentState, set[LoopNumber]] = {
    AssessmentState.CREATED: {LoopNumber.ONE},
    AssessmentState.LOOP1_DONE: {LoopNumber.ONE, LoopNumber.TWO},
    AssessmentState.LOOP2_DONE: {LoopNumber.ONE, LoopNumber.TWO, LoopNumber.THREE},
    AssessmentState.LOOP3_DONE: {LoopNumber.ONE, LoopNumber.TWO, LoopNumber.THREE},
    AssessmentState.COMPLETED: set(),
}


def can_run_loop(current: AssessmentState, loop: LoopNumber) -> bool:
    """True if ``loop`` is a legal next action from ``current``."""
    return loop in _RUNNABLE.get(current, set())


def next_state_after_loop(
    current: AssessmentState, loop: LoopNumber
) -> AssessmentState:
    """Compute the state after a successful run of ``loop``.

    Re-running a loop keeps state at that loop's done. Forward progress
    advances state.
    """
    target = {
        LoopNumber.ONE: AssessmentState.LOOP1_DONE,
        LoopNumber.TWO: AssessmentState.LOOP2_DONE,
        LoopNumber.THREE: AssessmentState.LOOP3_DONE,
    }[loop]
    return target


def states_invalidated_by_rerun(loop: LoopNumber) -> list[LoopNumber]:
    """Loop numbers whose active rows must be marked superseded when
    ``loop`` is re-run.
    """
    return [
        n for n in (LoopNumber.ONE, LoopNumber.TWO, LoopNumber.THREE)
        if n.value > loop.value
    ]


def can_close(current: AssessmentState) -> bool:
    """An assessment can be closed once Loop 2 has produced output (gate
    fail or pass) or Loop 3 is done. CREATED / LOOP1_DONE cannot close —
    nothing yet to record. COMPLETED is terminal.
    """
    return current in (AssessmentState.LOOP2_DONE, AssessmentState.LOOP3_DONE)
