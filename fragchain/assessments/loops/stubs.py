"""Stub loop implementations for Plan A.

These return canned outputs so the workflow + orchestrator + state
machine are exercisable without an LLM. The real implementations land
in Plan C and live in ``fragchain/assessments/loops/loop1.py``,
``loop2.py``, ``loop3.py`` next to this file.
"""
from __future__ import annotations

from typing import Any

from fragchain.assessments.loops.base import LoopContext


_DEFAULT_GATE_THRESHOLD = 3
_ALL_CATEGORIES = (
    "process",
    "command_line",
    "file",
    "network",
    "registry",
    "parent_child",
    "api_call",
)


class StubLoop1:
    """Returns a canned vuln profile + 3 detection questions."""

    async def run(self, ctx: LoopContext) -> dict[str, Any]:
        return {
            "vuln_profile": {
                "vuln_class": "stub vuln class",
                "affected_component": "stub component",
                "trigger_conditions": ["stub-condition-1"],
                "attacker_preconditions": ["stub-precondition-1"],
                "expected_impact": "stub impact",
                "exploitation_surface": "stub surface",
            },
            "detection_questions": [
                {
                    "id": "q1",
                    "category": "process",
                    "question": "what process is spawned?",
                    "why_it_matters": "stub",
                },
                {
                    "id": "q2",
                    "category": "command_line",
                    "question": "what command-line is unique?",
                    "why_it_matters": "stub",
                },
                {
                    "id": "q3",
                    "category": "network",
                    "question": "what outbound signature?",
                    "why_it_matters": "stub",
                },
            ],
        }


class StubLoop2:
    """Returns a thin indicator map (1–2 categories filled).

    Deliberately below the default gate threshold so the gate-failure
    path is exercised. Integration tests that want the gate to pass can
    monkeypatch this stub.
    """

    async def run(self, ctx: LoopContext) -> dict[str, Any]:
        indicators: dict[str, list[dict[str, Any]]] = {
            cat: [] for cat in _ALL_CATEGORIES
        }
        indicators["process"] = [
            {
                "value": "stub.exe",
                "kind": "literal",
                "source_ref": "stub",
                "confidence": 0.5,
                "answers_question_id": "q1",
            }
        ]
        return {
            "indicators": indicators,
            "unanswered_questions": ["q2", "q3"],
        }


class StubLoop3:
    """Returns one canned Sigma-shaped rule per profile (stubbed: 1 rule)."""

    async def run(
        self,
        ctx: LoopContext,
        *,
        low_detectability_override: bool = False,
        gated_class: str | None = None,
    ) -> dict[str, Any]:
        if gated_class is not None:
            from fragchain.assessments.gating import gated_loop3_output

            return gated_loop3_output(gated_class, chain_id=None)
        return {
            "rules": [
                {
                    "title": f"Stub rule for {ctx.cve_textual_id}",
                    "logsource": {"product": "linux", "service": "auditd"},
                    "detection": {"selection": {}, "condition": "selection"},
                    "level": "medium",
                }
            ]
        }


def evaluate_detectability_gate(
    indicators: dict[str, list[Any]],
    *,
    min_categories: int = _DEFAULT_GATE_THRESHOLD,
) -> dict[str, Any]:
    """Compute gate result from a Loop 2 indicator map.

    The threshold is the count of non-empty categories. Returns a JSON
    payload suitable for the ``assessment_loop_run.gate_result`` column.
    """
    filled = sorted([cat for cat, vals in indicators.items() if vals])
    empty = sorted([cat for cat in _ALL_CATEGORIES if cat not in filled])
    return {
        "passed": len(filled) >= min_categories,
        "filled_categories": filled,
        "empty_categories": empty,
        "threshold": min_categories,
    }
