"""Structural validation of the detectability pilot fixture."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from fragchain.assessments.detectability import DetectabilityClass
from fragchain.assessments.loops.schemas import ObservableCategory

FIXTURE = Path(__file__).resolve().parents[2] / "benchmarks" / "detectability_pilot_v1.json"
VALID_CLASSES = {c.value for c in DetectabilityClass}
VALID_CATEGORIES = {c.value for c in ObservableCategory}


def _load():
    return json.loads(FIXTURE.read_text())


def test_fixture_has_30_cases_spanning_all_classes():
    data = _load()
    cases = data["cases"]
    assert len(cases) == 30
    classes = Counter(c["expected"]["detectability_class"] for c in cases)
    # all 5 classes represented, >=5 each (so the confusion matrix is populated)
    assert set(classes) == VALID_CLASSES
    assert min(classes.values()) >= 5


def test_every_case_is_structurally_valid():
    for c in _load()["cases"]:
        assert isinstance(c["id"], str) and c["id"]
        assert c["expected"]["detectability_class"] in VALID_CLASSES
        cve = c["cve"]
        assert cve["cve_id"] and cve["description"]
        lo = c["loop2_output"]
        assert set(lo["indicators"].keys()) <= VALID_CATEGORIES
        assert isinstance(lo["unanswered_questions"], list)
        gr = c["gate_result"]
        assert isinstance(gr["passed"], bool)
        assert isinstance(c["vuln_profile"], dict)


def test_case_ids_unique():
    ids = [c["id"] for c in _load()["cases"]]
    assert len(ids) == len(set(ids))
