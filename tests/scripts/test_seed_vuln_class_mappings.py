from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scripts.seed_vuln_class_mappings import run as seed_run


@pytest.mark.asyncio
async def test_seed_inserts_all_rows_on_empty_db():
    session = AsyncMock()
    scalars = MagicMock()
    scalars.all.return_value = []
    fetch = MagicMock()
    fetch.scalars.return_value = scalars
    session.execute.return_value = fetch

    counts = await seed_run(session)

    assert counts["vuln_class_to_ttps_inserted"] >= 20
    assert counts["ttp_category_relevance_inserted"] >= 18
    session.commit.assert_awaited()


@pytest.mark.asyncio
async def test_seed_is_idempotent():
    """Running seed twice does not duplicate rows."""
    from fragchain.assessments.mapping_seeds import (
        CATEGORY_RELEVANCE_SEED,
        VULN_CLASS_SEED,
    )

    existing_vuln_keys = {
        (r["vuln_class"], r["technique_id"]) for r in VULN_CLASS_SEED
    }
    existing_cat_keys = {
        (r["technique_id"], r["category"]) for r in CATEGORY_RELEVANCE_SEED
    }

    session = AsyncMock()

    class _FakeRow:
        def __init__(self, key):
            self.key = key

    def _execute_side_effect(stmt):
        from fragchain.db.models import (
            TTPCategoryRelevanceRow, VulnClassToTTPRow,
        )
        table = stmt.froms[0] if hasattr(stmt, "froms") and stmt.froms else None
        scalars = MagicMock()
        # Return existing rows so the seeder skips inserts.
        if table is VulnClassToTTPRow.__table__:
            scalars.all.return_value = [
                MagicMock(vuln_class=v, technique_id=t)
                for v, t in existing_vuln_keys
            ]
        elif table is TTPCategoryRelevanceRow.__table__:
            scalars.all.return_value = [
                MagicMock(technique_id=t, category=c)
                for t, c in existing_cat_keys
            ]
        else:
            scalars.all.return_value = []
        fetch = MagicMock()
        fetch.scalars.return_value = scalars
        return fetch

    session.execute.side_effect = _execute_side_effect

    counts = await seed_run(session)

    assert counts["vuln_class_to_ttps_inserted"] == 0
    assert counts["ttp_category_relevance_inserted"] == 0
