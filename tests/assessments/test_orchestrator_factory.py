"""The shared orchestrator factory wires all collaborators."""
from __future__ import annotations

from unittest.mock import MagicMock

from fragchain.assessments.orchestrator import LoopOrchestrator
from fragchain.assessments.orchestrator_factory import build_orchestrator


def test_build_orchestrator_wires_all_collaborators(monkeypatch):
    monkeypatch.setattr(
        "fragchain.assessments.orchestrator_factory.get_qdrant_client",
        lambda: MagicMock(),
    )
    orch = build_orchestrator(MagicMock())
    assert isinstance(orch, LoopOrchestrator)
    assert orch._chain_synthesizer is not None
    assert orch._rule_superseder is not None
    assert orch._detectability_classifier is not None
    assert orch._artifact_router is not None
    assert orch._coverage_dispatcher is not None
    assert set(orch._loops.keys())
