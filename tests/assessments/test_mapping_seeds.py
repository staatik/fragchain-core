from __future__ import annotations

import re

import pytest

from fragchain.assessments.mapping_seeds import (
    CATEGORY_RELEVANCE_SEED,
    VULN_CLASS_SEED,
    ObservableCategoryLiteral,
)


TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
TACTIC_RE = re.compile(r"^TA\d{4}$")
ALLOWED_CATEGORIES = {
    "process", "command_line", "file", "network",
    "registry", "parent_child", "api_call",
}


def test_vuln_class_seed_shape():
    assert len(VULN_CLASS_SEED) >= 10
    seen = set()
    for row in VULN_CLASS_SEED:
        key = (row["vuln_class"], row["technique_id"])
        assert key not in seen, f"duplicate {key}"
        seen.add(key)
        assert TECH_RE.match(row["technique_id"]), row
        assert TACTIC_RE.match(row["tactic_id"]), row
        assert row["seq_order"] >= 1
        assert 0.0 <= float(row["base_confidence"]) <= 1.0


def test_each_vuln_class_has_at_least_two_ttps():
    by_class: dict[str, list[dict]] = {}
    for row in VULN_CLASS_SEED:
        by_class.setdefault(row["vuln_class"], []).append(row)
    for cls, rows in by_class.items():
        assert len(rows) >= 2, f"{cls} has only {len(rows)} TTPs"


def test_category_relevance_seed_shape():
    assert len(CATEGORY_RELEVANCE_SEED) >= 10
    for row in CATEGORY_RELEVANCE_SEED:
        assert TECH_RE.match(row["technique_id"])
        assert row["category"] in ALLOWED_CATEGORIES
        assert 0.0 <= float(row["weight"]) <= 1.0


def test_every_seeded_ttp_has_relevance_rows():
    seeded_tech = {r["technique_id"] for r in VULN_CLASS_SEED}
    relevance_tech = {r["technique_id"] for r in CATEGORY_RELEVANCE_SEED}
    missing = seeded_tech - relevance_tech
    assert not missing, f"TTPs lacking relevance entries: {missing}"
