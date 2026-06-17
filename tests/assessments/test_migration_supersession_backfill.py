"""Regression test for migration 0017 supersession backfill.

The 0017 migration adds ``attack_chains.superseded_at`` (nullable) and a
partial unique index ``uq_attack_chains_active_per_cve ON attack_chains
(cve_id) WHERE superseded_at IS NULL``. Without a backfill step, any
deployment with more than one chain row per CVE (which is normal — the
generator persists ``AttackChain.version`` bumps) fails the upgrade with
``UniqueViolationError`` on the index creation.

This test covers two angles:

1.  **Source check** — the migration file contains the backfill
    ``UPDATE`` between the ``add_column("superseded_at", ...)`` call and
    the ``create_index("uq_attack_chains_active_per_cve", ...)`` call.
    A future refactor that drops or reorders the statement will fail
    here, which is cheap and dialect-agnostic.

2.  **Semantic check** — we replay the equivalent SQL against an
    in-memory SQLite DB seeded with two rows for one CVE. We then
    create the partial unique index and confirm the older row picked up
    ``superseded_at`` while the newest row stayed NULL. SQLite supports
    partial unique indexes via ``CREATE UNIQUE INDEX ... WHERE ...``,
    so the index-creation step exercises the same protection the
    production index gives us.

SQLite cannot run the real Alembic migration (JSONB, ``NOW()``, etc.)
and the project has no Postgres test infra, so this is the pragmatic
coverage available. Combined with the source check, it pins the
behavior the design doc requires: "one active chain per CVE".
"""
from __future__ import annotations

import pathlib
import re
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

MIGRATION_PATH = pathlib.Path(
    "fragchain/db/migrations/versions/0017_assessment_centric.py"
)


# ---------------------------------------------------------------------------
# Source-level guard: the backfill UPDATE must appear between the add_column
# for superseded_at and the create_index for uq_attack_chains_active_per_cve.
# ---------------------------------------------------------------------------


def test_migration_0017_has_supersession_backfill_before_index() -> None:
    src = MIGRATION_PATH.read_text()

    add_col_marker = 'sa.Column("superseded_at"'
    update_marker = "UPDATE attack_chains"
    index_marker = '"uq_attack_chains_active_per_cve"'

    add_col_pos = src.find(add_col_marker)
    update_pos = src.find(update_marker)
    index_pos = src.find(index_marker)

    assert add_col_pos != -1, "add_column for superseded_at missing"
    assert update_pos != -1, "supersession backfill UPDATE missing"
    assert index_pos != -1, "uq_attack_chains_active_per_cve missing"
    assert add_col_pos < update_pos < index_pos, (
        "backfill UPDATE must run after add_column(superseded_at) and "
        "before create_index(uq_attack_chains_active_per_cve)"
    )

    # The UPDATE must mark every non-latest row per CVE as superseded.
    assert "b.version > a.version" in src
    assert "superseded_at = NOW()" in src


# ---------------------------------------------------------------------------
# Semantic guard: replay the backfill SQL against SQLite and confirm the
# partial unique index can be created.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_supersession_backfill_keeps_one_active_per_cve() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    """
                    CREATE TABLE attack_chains (
                        id TEXT PRIMARY KEY,
                        cve_id TEXT NOT NULL,
                        version INTEGER NOT NULL DEFAULT 1,
                        created_at TIMESTAMP NOT NULL,
                        superseded_at TIMESTAMP NULL,
                        UNIQUE(cve_id, version)
                    )
                    """
                )
            )

            cve_a = str(uuid.uuid4())
            cve_b = str(uuid.uuid4())
            older = str(uuid.uuid4())
            newer = str(uuid.uuid4())
            solo = str(uuid.uuid4())

            # Two rows for cve_a — older v1, newer v2. Both pre-migration
            # have superseded_at = NULL, which is what the failing scenario
            # described in the bug looked like.
            await conn.execute(
                text(
                    "INSERT INTO attack_chains (id, cve_id, version, "
                    "created_at) VALUES (:id, :cve_id, 1, "
                    "'2026-01-01 00:00:00')"
                ),
                {"id": older, "cve_id": cve_a},
            )
            await conn.execute(
                text(
                    "INSERT INTO attack_chains (id, cve_id, version, "
                    "created_at) VALUES (:id, :cve_id, 2, "
                    "'2026-02-01 00:00:00')"
                ),
                {"id": newer, "cve_id": cve_a},
            )
            # One row for cve_b — should stay active (NULL superseded_at).
            await conn.execute(
                text(
                    "INSERT INTO attack_chains (id, cve_id, version, "
                    "created_at) VALUES (:id, :cve_id, 1, "
                    "'2026-01-01 00:00:00')"
                ),
                {"id": solo, "cve_id": cve_b},
            )

            # Equivalent of the migration's backfill (NOW() → SQLite's
            # CURRENT_TIMESTAMP). Same predicate.
            await conn.execute(
                text(
                    """
                    UPDATE attack_chains
                    SET superseded_at = CURRENT_TIMESTAMP
                    WHERE EXISTS (
                        SELECT 1 FROM attack_chains b
                        WHERE b.cve_id = attack_chains.cve_id
                          AND (b.version > attack_chains.version
                               OR (b.version = attack_chains.version
                                   AND b.created_at > attack_chains.created_at))
                    )
                    """
                )
            )

            # Now the partial unique index must succeed.
            await conn.execute(
                text(
                    "CREATE UNIQUE INDEX uq_attack_chains_active_per_cve "
                    "ON attack_chains (cve_id) WHERE superseded_at IS NULL"
                )
            )

            # Assertions.
            rows = (
                await conn.execute(
                    text(
                        "SELECT id, superseded_at FROM attack_chains "
                        "ORDER BY cve_id, version"
                    )
                )
            ).all()
            by_id = {r[0]: r[1] for r in rows}

            assert by_id[older] is not None, "older v1 must be superseded"
            assert by_id[newer] is None, "newest v2 must stay active"
            assert by_id[solo] is None, "single-row CVE must stay active"

            # Index exists.
            idx_row = (
                await conn.execute(
                    text(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='index' AND "
                        "name='uq_attack_chains_active_per_cve'"
                    )
                )
            ).first()
            assert idx_row is not None

            # And the index actually enforces "one active per cve_id" —
            # inserting a fresh active row for cve_a must fail.
            with pytest.raises(Exception) as excinfo:
                await conn.execute(
                    text(
                        "INSERT INTO attack_chains (id, cve_id, version, "
                        "created_at) VALUES (:id, :cve_id, 3, "
                        "'2026-03-01 00:00:00')"
                    ),
                    {"id": str(uuid.uuid4()), "cve_id": cve_a},
                )
            assert re.search(r"unique", str(excinfo.value), re.IGNORECASE)
    finally:
        await engine.dispose()
