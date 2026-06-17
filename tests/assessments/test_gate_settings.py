"""GATE_MIN_CATEGORIES is a real setting that reaches the gate (Wave 1a T1).

CLAUDE.md §12.1 documents ``GATE_MIN_CATEGORIES`` as the detectability-gate
threshold, but until this change it was a hardcoded ``=3`` constructor
default on ``LoopOrchestrator`` and ``Loop2`` that neither factory passed.
These tests pin: (a) the setting exists with the documented default, and
(b) an env override propagates through BOTH orchestrator factories (API +
worker) to the orchestrator gate threshold and Loop 2's gap-pass threshold.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from fragchain.config import Settings, get_settings


@pytest.fixture
def gate_override(monkeypatch: pytest.MonkeyPatch):
    """Set GATE_MIN_CATEGORIES=5 in the env and clear the settings cache.

    Cache is cleared again on teardown so other tests see pristine settings.
    """
    monkeypatch.setenv("GATE_MIN_CATEGORIES", "5")
    get_settings.cache_clear()
    yield 5
    monkeypatch.delenv("GATE_MIN_CATEGORIES", raising=False)
    get_settings.cache_clear()


def test_setting_exists_with_documented_default() -> None:
    assert Settings().GATE_MIN_CATEGORIES == 3


def test_env_override_reaches_settings(gate_override: int) -> None:
    assert get_settings().GATE_MIN_CATEGORIES == gate_override


def test_worker_factory_passes_gate_threshold(gate_override: int) -> None:
    from fragchain.worker.tasks.run_assessment_loop import _make_orchestrator

    orch = _make_orchestrator(MagicMock())
    assert orch._gate_min == gate_override  # noqa: SLF001
    # Loop 2's gap-pass threshold must match the orchestrator's gate.
    loop2 = orch._loops[2]  # noqa: SLF001
    assert loop2._gate_min == gate_override  # noqa: SLF001


def test_api_factory_passes_gate_threshold(gate_override: int) -> None:
    from fragchain.api.routers.assessments import _orchestrator_factory

    orch = _orchestrator_factory(MagicMock())
    assert orch._gate_min == gate_override  # noqa: SLF001
    loop2 = orch._loops[2]  # noqa: SLF001
    assert loop2._gate_min == gate_override  # noqa: SLF001


def test_env_example_documents_the_setting() -> None:
    from pathlib import Path

    env_example = (
        Path(__file__).resolve().parents[2] / ".env.example"
    ).read_text()
    assert "GATE_MIN_CATEGORIES=3" in env_example
