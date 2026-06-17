from __future__ import annotations

from unittest.mock import MagicMock

import pytest


def test_assessments_router_factory_uses_real_loops():
    """Phase 8: API _orchestrator_factory wires real Loop1/2/3, not stubs."""
    from fragchain.api.routers.assessments import _orchestrator_factory
    from fragchain.assessments.loops.loop1 import Loop1
    from fragchain.assessments.loops.loop2 import Loop2
    from fragchain.assessments.loops.loop3 import Loop3

    session = MagicMock()
    orch = _orchestrator_factory(session)

    loops = list(orch._loops.values())  # noqa: SLF001
    assert any(isinstance(l, Loop1) for l in loops), "Loop1 not wired"
    assert any(isinstance(l, Loop2) for l in loops), "Loop2 not wired"
    assert any(isinstance(l, Loop3) for l in loops), "Loop3 not wired"
