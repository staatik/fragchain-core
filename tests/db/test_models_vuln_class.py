from __future__ import annotations

import pytest

from fragchain.db.models import (
    ChainTTPRow,
    TTPCategoryRelevanceRow,
    VulnClassToTTPRow,
)


def test_vuln_class_row_has_required_columns():
    cols = {c.name for c in VulnClassToTTPRow.__table__.columns}
    assert {"vuln_class", "technique_id", "tactic_id", "tactic",
            "technique_name", "seq_order", "base_confidence"} <= cols


def test_ttp_category_relevance_row_has_required_columns():
    cols = {c.name for c in TTPCategoryRelevanceRow.__table__.columns}
    assert {"technique_id", "category", "weight"} <= cols


def test_chain_ttp_row_has_behavioral_indicators():
    assert "behavioral_indicators" in {
        c.name for c in ChainTTPRow.__table__.columns
    }
