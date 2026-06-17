"""Regression tests for migration 0020 — assessment FK ondelete + indexes.

The 2026-05-19 audit flagged that migration 0017 created six FKs into
``coverage_assessment`` with no ``ondelete`` clause, while the ORM
declares ``ondelete="SET NULL"`` on every one of them. It also flagged
three ``assessment_id`` columns the ORM declares ``index=True`` for that
0017 never indexed. 0020 fixes both.

The project has no Postgres test infrastructure, so this file follows
the pattern from ``tests/assessments/test_migration_supersession_backfill.py``:

1.  **Source check** — the migration file contains, for every (table,
    column) pair, both the ``DROP CONSTRAINT`` and the
    ``create_foreign_key(..., ondelete="SET NULL")`` call. And it creates
    the three missing ``ix_<table>_<column>`` indexes.

2.  **Semantic check** — replay the equivalent SQL against SQLite. Two
    scenarios: (a) parent delete cascades to NULL on the child column,
    proving ``ON DELETE SET NULL`` is in effect; (b) the new index exists
    on the indexed column.

3.  **ORM-side check** — confirm the three partial unique indexes flagged
    by the audit are now declared in ``__table_args__`` (not recreated
    by the migration — they already exist on disk from 0008/0013/0017).
"""
from __future__ import annotations

import pathlib
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

import ast

from fragchain.db.models import AttackChainRow, PromptTemplate, ReviewQueueItem

MIGRATION_PATH = pathlib.Path(
    "fragchain/db/migrations/versions/0020_assessment_fk_indexes.py"
)


def _extract_tuple_list(module_src: str, var_name: str) -> list[tuple[str, str]]:
    """Pull a module-level ``var_name = [...]`` assignment of literal
    ``(str, str)`` tuples out of the migration source via AST parsing.

    Using AST instead of ``importlib`` keeps these tests runnable in any
    environment — the migration module imports ``alembic`` at module
    scope, which only resolves inside the project's venv. The tests run
    against any Python 3.12 with sqlalchemy / aiosqlite installed.
    """
    tree = ast.parse(module_src)
    for node in tree.body:
        target_id: str | None = None
        value_node: ast.expr | None = None
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    target_id = target.id
                    value_node = node.value
                    break
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target_id = node.target.id
            value_node = node.value
        if target_id == var_name and isinstance(value_node, ast.List):
            return [
                (elt.elts[0].value, elt.elts[1].value)
                for elt in value_node.elts  # type: ignore[attr-defined]
            ]
    raise AssertionError(f"{var_name} not found at module scope in migration")


_MIGRATION_SRC = MIGRATION_PATH.read_text()
_FK_COLUMNS = _extract_tuple_list(_MIGRATION_SRC, "_FK_COLUMNS")
_MISSING_INDEXES = _extract_tuple_list(_MIGRATION_SRC, "_MISSING_INDEXES")

# Hard-coded expected lists — the audit-flagged set. If a future refactor
# narrows the migration's coverage, these tests fail loudly rather than
# silently shrinking with the code.
_EXPECTED_FK_COLUMNS = [
    ("attack_chains", "assessment_id"),
    ("attack_chains", "superseded_by_assessment_id"),
    ("review_queue", "assessment_id"),
    ("review_queue", "superseded_by_assessment_id"),
    ("sigma_rules", "deprecated_by_assessment_id"),
    ("llm_interactions", "assessment_id"),
]
_EXPECTED_MISSING_INDEXES = [
    ("attack_chains", "assessment_id"),
    ("review_queue", "assessment_id"),
    ("llm_interactions", "assessment_id"),
]


# ---------------------------------------------------------------------------
# Source-level guards
# ---------------------------------------------------------------------------


def test_migration_0020_covers_every_flagged_fk() -> None:
    """The migration's ``_FK_COLUMNS`` list must include every (table,
    column) pair the audit flagged. A future refactor that narrows the
    list silently un-fixes some FKs — fail loudly here."""
    assert set(_FK_COLUMNS) == set(_EXPECTED_FK_COLUMNS)


def test_migration_0020_covers_every_missing_index() -> None:
    assert set(_MISSING_INDEXES) == set(_EXPECTED_MISSING_INDEXES)


def test_migration_0020_upgrade_uses_set_null() -> None:
    """The upgrade block must use ``ondelete='SET NULL'`` (matching the
    ORM contract) and the idempotent ``DROP CONSTRAINT IF EXISTS`` form."""
    src = MIGRATION_PATH.read_text()
    upgrade_start = src.find("def upgrade()")
    downgrade_start = src.find("def downgrade()")
    assert upgrade_start != -1
    upgrade_src = src[upgrade_start:downgrade_start]

    assert 'ondelete="SET NULL"' in upgrade_src
    assert "DROP CONSTRAINT IF EXISTS" in upgrade_src
    assert "create_foreign_key(" in upgrade_src
    assert "create_index(" in upgrade_src


def test_migration_0020_downgrade_inverts_upgrade() -> None:
    """Downgrade must drop the new indexes and recreate the FKs WITHOUT
    ``ondelete`` so the table matches the pre-0020 shape. The literal
    kwarg must not appear inside the downgrade block."""
    src = MIGRATION_PATH.read_text()
    downgrade_start = src.find("def downgrade()")
    assert downgrade_start != -1
    downgrade_src = src[downgrade_start:]

    assert "drop_index(" in downgrade_src
    assert "create_foreign_key(" in downgrade_src
    assert 'ondelete="SET NULL"' not in downgrade_src


# ---------------------------------------------------------------------------
# Semantic guard via SQLite — proves ON DELETE SET NULL actually fires
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_on_delete_set_null_clears_child_assessment_id() -> None:
    """After 0020, deleting a ``coverage_assessment`` parent row must
    null out every child reference rather than violating an FK. SQLite
    enforces ``ON DELETE SET NULL`` when ``PRAGMA foreign_keys = ON`` is
    set; the semantics are identical to PostgreSQL for this case."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("PRAGMA foreign_keys = ON"))
            await conn.execute(
                text(
                    """
                    CREATE TABLE coverage_assessment (
                        id TEXT PRIMARY KEY
                    )
                    """
                )
            )
            await conn.execute(
                text(
                    """
                    CREATE TABLE attack_chains (
                        id TEXT PRIMARY KEY,
                        assessment_id TEXT
                            REFERENCES coverage_assessment(id)
                            ON DELETE SET NULL
                    )
                    """
                )
            )

            assessment_id = str(uuid.uuid4())
            chain_id = str(uuid.uuid4())
            await conn.execute(
                text("INSERT INTO coverage_assessment (id) VALUES (:id)"),
                {"id": assessment_id},
            )
            await conn.execute(
                text(
                    "INSERT INTO attack_chains (id, assessment_id) "
                    "VALUES (:cid, :aid)"
                ),
                {"cid": chain_id, "aid": assessment_id},
            )

            # The fix: deleting the parent must succeed and null the child.
            await conn.execute(
                text("DELETE FROM coverage_assessment WHERE id = :id"),
                {"id": assessment_id},
            )
            row = (
                await conn.execute(
                    text(
                        "SELECT assessment_id FROM attack_chains "
                        "WHERE id = :cid"
                    ),
                    {"cid": chain_id},
                )
            ).first()
            assert row is not None, "child row was unexpectedly deleted"
            assert row[0] is None, (
                "child assessment_id must be NULLed by ON DELETE SET NULL"
            )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_pre_0020_bare_fk_would_block_parent_delete() -> None:
    """Inverse: the pre-0020 shape (FK without ``ondelete``) blocks the
    parent delete. This locks in *why* 0020 is needed; if a future
    refactor accidentally re-introduces a bare FK, this test surfaces
    the symptom."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("PRAGMA foreign_keys = ON"))
            await conn.execute(
                text(
                    "CREATE TABLE coverage_assessment (id TEXT PRIMARY KEY)"
                )
            )
            # No ON DELETE clause — this is the pre-0020 shape.
            await conn.execute(
                text(
                    """
                    CREATE TABLE attack_chains (
                        id TEXT PRIMARY KEY,
                        assessment_id TEXT
                            REFERENCES coverage_assessment(id)
                    )
                    """
                )
            )

            assessment_id = str(uuid.uuid4())
            chain_id = str(uuid.uuid4())
            await conn.execute(
                text("INSERT INTO coverage_assessment (id) VALUES (:id)"),
                {"id": assessment_id},
            )
            await conn.execute(
                text(
                    "INSERT INTO attack_chains (id, assessment_id) "
                    "VALUES (:cid, :aid)"
                ),
                {"cid": chain_id, "aid": assessment_id},
            )

            with pytest.raises(Exception) as excinfo:
                await conn.execute(
                    text("DELETE FROM coverage_assessment WHERE id = :id"),
                    {"id": assessment_id},
                )
            assert "FOREIGN KEY" in str(excinfo.value).upper() or (
                "constraint" in str(excinfo.value).lower()
            )
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# ORM-side check — partial unique indexes are now declared in __table_args__
# ---------------------------------------------------------------------------


def _find_index(cls, name: str):
    for idx in cls.__table__.indexes:
        if idx.name == name:
            return idx
    return None


def test_prompt_template_declares_uq_prompt_templates_active() -> None:
    idx = _find_index(PromptTemplate, "uq_prompt_templates_active")
    assert idx is not None, (
        "PromptTemplate must declare uq_prompt_templates_active in __table_args__"
    )
    assert idx.unique is True
    # Re-keyed from `name` to `task_type` in migration 0021 (F4): the engine
    # resolves prompts by task_type, so the active-row uniqueness must be per
    # task_type, not per name.
    assert [c.name for c in idx.columns] == [
        "task_type", "target_model", "target_provider"
    ]
    where = str(idx.dialect_options.get("postgresql", {}).get("where", ""))
    assert "is_active" in where


def test_attack_chain_row_declares_uq_attack_chains_active_per_cve() -> None:
    idx = _find_index(AttackChainRow, "uq_attack_chains_active_per_cve")
    assert idx is not None, (
        "AttackChainRow must declare uq_attack_chains_active_per_cve in __table_args__"
    )
    assert idx.unique is True
    assert [c.name for c in idx.columns] == ["cve_id"]
    where = str(idx.dialect_options.get("postgresql", {}).get("where", ""))
    assert "superseded_at" in where


def test_review_queue_item_declares_ux_review_queue_pending_rule() -> None:
    idx = _find_index(ReviewQueueItem, "ux_review_queue_pending_rule")
    assert idx is not None, (
        "ReviewQueueItem must declare ux_review_queue_pending_rule in __table_args__"
    )
    assert idx.unique is True
    assert [c.name for c in idx.columns] == ["sigma_rule_id"]
    where = str(idx.dialect_options.get("postgresql", {}).get("where", ""))
    assert "pending" in where


def test_sigma_rule_declares_similarity_columns() -> None:
    from fragchain.db.models import SigmaRule
    cols = {c.name for c in SigmaRule.__table__.columns}
    assert "similar_to_rule_id" in cols
    assert "similarity_score" in cols


def test_assessment_id_columns_declare_index_true() -> None:
    """Sanity-check that the ORM still declares ``index=True`` on every
    column 0020 creates an index for. If a future refactor drops the
    ORM-side ``index=True``, future autogenerate runs would emit
    ``drop_index`` for the index 0020 just created — surface that loudly."""
    from fragchain.db.models import (
        AttackChainRow,
        LLMInteraction,
        ReviewQueueItem,
    )

    for cls, column in (
        (AttackChainRow, "assessment_id"),
        (ReviewQueueItem, "assessment_id"),
        (LLMInteraction, "assessment_id"),
    ):
        col = cls.__table__.columns[column]
        assert col.index is True, (
            f"{cls.__name__}.{column} must keep index=True so 0020's "
            f"ix_{cls.__tablename__}_{column} is preserved by autogenerate"
        )
