from __future__ import annotations

from unittest.mock import MagicMock

import pytest


def test_make_orchestrator_uses_real_loops():
    """Phase 8: _make_orchestrator wires Loop1/2/3 (not stubs)."""
    from fragchain.assessments.loops.loop1 import Loop1
    from fragchain.assessments.loops.loop2 import Loop2
    from fragchain.assessments.loops.loop3 import Loop3
    from fragchain.worker.tasks.run_assessment_loop import _make_orchestrator

    session = MagicMock()
    orch = _make_orchestrator(session)

    # Orchestrator stores loops in self._loops keyed by LoopNumber enum.
    # Walk the dict and find each by type.
    loops = list(orch._loops.values())  # noqa: SLF001
    assert any(isinstance(l, Loop1) for l in loops), "Loop1 not wired"
    assert any(isinstance(l, Loop2) for l in loops), "Loop2 not wired"
    assert any(isinstance(l, Loop3) for l in loops), "Loop3 not wired"
