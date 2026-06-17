"""The benchmark runner's --dry-run path validates fixtures with no LLM/DB."""
from __future__ import annotations

import importlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

runner = importlib.import_module("scripts.run_detectability_benchmark")


class _ACM:
    """Minimal async-context-manager yielding a stub session."""

    def __init__(self, session):
        self._s = session

    async def __aenter__(self):
        return self._s

    async def __aexit__(self, *exc):
        return False


def test_load_fixture_returns_30_cases():
    cases = runner.load_fixture(runner.DEFAULT_FIXTURE)
    assert len(cases) == 30
    assert cases[0].expected_class in {
        "directly_detectable", "indirectly_detectable", "environment_dependent",
        "control_only", "insufficient_information",
    }


def test_dry_run_reports_label_distribution_without_llm():
    # dry-run scores the EXPECTED labels against themselves (sanity) -> accuracy 1.0,
    # exercising the fixture-load + metrics wiring with zero LLM calls.
    report = runner.dry_run(runner.DEFAULT_FIXTURE)
    assert report["n"] == 30
    assert report["accuracy"] == 1.0  # expected vs expected
    assert set(report["confusion_matrix"]["classes"]) == {
        "directly_detectable", "indirectly_detectable", "environment_dependent",
        "control_only", "insufficient_information",
    }


def test_emit_review_doc_lists_all_cases():
    doc = runner.emit_review_doc(runner.DEFAULT_FIXTURE)
    assert doc.count("\n| case-") == 30  # one table row per case
    assert "Proposed class" in doc


@pytest.mark.asyncio
async def test_run_scored_bootstraps_providers_before_classifying():
    """The scored path must register the LLM provider — a standalone script
    doesn't inherit the API lifespan, so without this the classifier raises
    'No chat-capable LLM provider registered' (Phase 3 was never run, so this
    gap shipped latent)."""
    boot = AsyncMock()
    session = MagicMock()
    session.commit = AsyncMock()
    sm = MagicMock(return_value=_ACM(session))
    fake_outcome = runner.CaseOutcome(
        case_id="c", expected="control_only", predicted="control_only", confidence=0.5
    )
    with patch("fragchain.llm.bootstrap_providers_for_scripts", boot), \
         patch("fragchain.db.session.get_sessionmaker", return_value=sm), \
         patch("fragchain.assessments.detectability.DetectabilityClassifier"), \
         patch("fragchain.prompts.store.PromptStore"), \
         patch.object(runner, "_score_case", AsyncMock(return_value=(fake_outcome, 0.0, 0.0))):
        report = await runner.run_scored(
            runner.DEFAULT_FIXTURE, store=False, evaluated_by="test"
        )
    boot.assert_awaited_once()
    assert report["n"] == 30
