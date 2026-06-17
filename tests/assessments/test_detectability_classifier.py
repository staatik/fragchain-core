"""DetectabilityClassifier service tests (Phase 1).

Mirrors the Loop 1 test pattern: patch ``structured_complete`` inside the
module under test; fake session records added rows.
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fragchain.assessments.detectability import (
    DetectabilityAssessment,
    DetectabilityClassifier,
    _summarize_indicators,
)
from fragchain.assessments.loops.base import LoopContext
from fragchain.llm.structured import StructuredResult


def _ctx(prior: dict | None = None) -> LoopContext:
    return LoopContext(
        assessment_id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        cve_textual_id="CVE-2026-0001",
        source_contents=[],
        prior_outputs=prior
        or {1: {"vuln_profile": {"vuln_class": "command injection"}}},
    )


def _selection() -> MagicMock:
    sel = MagicMock()
    sel.id = uuid.uuid4()
    sel.version = 1
    sel.system_prompt = "system"
    sel.user_template = (
        "CVE: {cve_id}\n{vuln_profile}\n{indicators_summary}\n"
        "{gate_summary}\n{unanswered}"
    )
    sel.target_model = "*"
    return sel


def _assessment_value() -> DetectabilityAssessment:
    return DetectabilityAssessment.model_validate(
        {
            "detectability_class": "directly_detectable",
            "rationale": "r",
            "confidence": 0.7,
            "recommended_artifacts": [
                {
                    "type": "sigma_rule",
                    "reason": "stable observable",
                    "priority": 1,
                }
            ],
            "skipped_artifacts": [],
        }
    )


@pytest.mark.asyncio
async def test_classify_persists_row() -> None:
    session = MagicMock()
    session.add = MagicMock()
    prompt_store = MagicMock()
    prompt_store.get_active = AsyncMock(return_value=_selection())
    fake = StructuredResult(value=_assessment_value(), confidence=1.0)

    with patch(
        "fragchain.assessments.detectability.structured_complete",
        new=AsyncMock(return_value=fake),
    ) as sc, patch(
        "fragchain.assessments.detectability.resolve_chat_provider",
        new=MagicMock(return_value=MagicMock()),
    ):
        clf = DetectabilityClassifier(
            session, prompt_store=prompt_store, provider=MagicMock()
        )
        loop_run_id = uuid.uuid4()
        row = await clf.classify(
            ctx=_ctx(),
            loop_run_id=loop_run_id,
            loop2_output={
                "indicators": {
                    "process": [
                        {
                            "value": "sh",
                            "kind": "literal",
                            "source_ref": "s",
                            "confidence": 0.9,
                        }
                    ]
                },
                "unanswered_questions": [],
            },
            gate_result={
                "passed": True,
                "filled_categories": ["process"],
                "empty_categories": [],
                "threshold": 3,
            },
        )

    assert row is not None
    assert row.detectability_class == "directly_detectable"
    assert row.loop_run_id == loop_run_id
    assert row.gate_passed is True
    assert row.payload["rationale"] == "r"
    session.add.assert_called_once()
    kwargs = sc.await_args.kwargs
    assert kwargs["schema"] is DetectabilityAssessment
    assert kwargs["entity_type"] == "coverage_assessment"


@pytest.mark.asyncio
async def test_classify_failure_returns_none_never_raises() -> None:
    session = MagicMock()
    prompt_store = MagicMock()
    prompt_store.get_active = AsyncMock(side_effect=RuntimeError("llm down"))

    clf = DetectabilityClassifier(
        session, prompt_store=prompt_store, provider=MagicMock()
    )
    row = await clf.classify(
        ctx=_ctx(),
        loop_run_id=uuid.uuid4(),
        loop2_output={"indicators": {}},
        gate_result={
            "passed": False,
            "filled_categories": [],
            "empty_categories": [],
            "threshold": 3,
        },
    )
    assert row is None
    session.add.assert_not_called()


@pytest.mark.asyncio
async def test_predict_returns_assessment_and_does_not_persist() -> None:
    session = MagicMock()
    session.add = MagicMock()
    prompt_store = MagicMock()
    prompt_store.get_active = AsyncMock(return_value=_selection())
    fake = StructuredResult(value=_assessment_value(), confidence=1.0, cost_usd=0.01)

    with patch(
        "fragchain.assessments.detectability.structured_complete",
        new=AsyncMock(return_value=fake),
    ), patch(
        "fragchain.assessments.detectability.resolve_chat_provider",
        new=MagicMock(return_value=MagicMock()),
    ):
        clf = DetectabilityClassifier(
            session, prompt_store=prompt_store, provider=MagicMock()
        )
        result = await clf.predict(
            ctx=_ctx(),
            loop2_output={
                "indicators": {"network": [{"value": "x"}]},
                "unanswered_questions": [],
            },
            gate_result={
                "passed": True,
                "filled_categories": ["network"],
                "empty_categories": [],
                "threshold": 3,
            },
        )

    assert result.assessment.detectability_class is not None
    assert isinstance(result.cost_usd, float)
    session.add.assert_not_called()


def test_indicator_summary_caps_samples() -> None:
    many = {
        "process": [
            {
                "value": f"v{i}",
                "kind": "literal",
                "source_ref": "s",
                "confidence": 0.5,
            }
            for i in range(20)
        ],
        "network": [],
    }
    text = _summarize_indicators(many)
    assert "process: 20 indicator(s)" in text
    assert "v4" in text and "v9" not in text  # max 5 samples per category
    assert "network: 0" in text
