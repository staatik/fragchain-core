"""Fix assessment FK ondelete drift + create missing assessment_id indexes.

Revision ID: 0020_assessment_fk_indexes
Revises: 0019_cve_title_description
Create Date: 2026-05-19

The 2026-05-19 platform-wide audit (`docs/AUDIT_2026-05-19.md`) flagged
two schema drifts in migration 0017's assessment-centric work:

1.  **FK ondelete drift on 6 columns.** The ORM declares
    ``ondelete="SET NULL"`` on every FK into ``coverage_assessment``, but
    0017 added the FKs with bare ``sa.ForeignKey("coverage_assessment.id")``
    (no ondelete). Today, deleting an assessment row raises
    ``ForeignKeyViolationError`` even though the model contract promises
    silent set-null. This migration drops each bare FK and recreates it
    with ``ON DELETE SET NULL`` so the on-disk behaviour matches the ORM.

2.  **Missing indexes on ``assessment_id`` columns.** The ORM declares
    ``index=True`` on the three child ``assessment_id`` columns
    (``attack_chains``, ``review_queue``, ``llm_interactions``), but 0017
    never called ``op.create_index`` for any of them. The active-flow
    filters ``GET /chains?assessment_id=…``, ``GET /queue?assessment_id=…``
    and per-assessment LLM-cost roll-ups do full table scans today.

Both fixes are pure DDL and idempotent (``DROP CONSTRAINT IF EXISTS``,
``CREATE INDEX IF NOT EXISTS``). Safe to re-run after a partial failure.

The three partial unique indexes that were also flagged
(`uq_prompt_templates_active`, `ux_review_queue_pending_rule`,
`uq_attack_chains_active_per_cve`) already exist on disk from earlier
migrations — they are surfaced into the ORM via ``__table_args__`` in
`fragchain/db/models.py` rather than recreated here.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0020_assessment_fk_indexes"
down_revision: Union[str, Sequence[str], None] = "0019_cve_title_description"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Each tuple: (child_table, child_column). PostgreSQL's default name for
# an inline-declared FK is ``<table>_<column>_fkey``; if that name isn't
# present (e.g. the database was renamed manually), the IF EXISTS clause
# lets the migration no-op instead of crashing.
_FK_COLUMNS: list[tuple[str, str]] = [
    ("attack_chains", "assessment_id"),
    ("attack_chains", "superseded_by_assessment_id"),
    ("review_queue", "assessment_id"),
    ("review_queue", "superseded_by_assessment_id"),
    ("sigma_rules", "deprecated_by_assessment_id"),
    ("llm_interactions", "assessment_id"),
]

# (child_table, child_column) — every column the ORM declares ``index=True``
# but 0017 never created an index for. Names follow the project's
# ``ix_<table>_<column>`` convention (matches the index Alembic would emit
# from ORM autogenerate).
_MISSING_INDEXES: list[tuple[str, str]] = [
    ("attack_chains", "assessment_id"),
    ("review_queue", "assessment_id"),
    ("llm_interactions", "assessment_id"),
]


def upgrade() -> None:
    for table, column in _FK_COLUMNS:
        constraint_name = f"{table}_{column}_fkey"
        op.execute(
            f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {constraint_name}"
        )
        op.create_foreign_key(
            constraint_name,
            table,
            "coverage_assessment",
            [column],
            ["id"],
            ondelete="SET NULL",
        )

    for table, column in _MISSING_INDEXES:
        op.create_index(
            f"ix_{table}_{column}",
            table,
            [column],
            if_not_exists=True,
        )


def downgrade() -> None:
    for table, column in _MISSING_INDEXES:
        op.drop_index(f"ix_{table}_{column}", table_name=table, if_exists=True)

    for table, column in _FK_COLUMNS:
        constraint_name = f"{table}_{column}_fkey"
        op.execute(
            f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {constraint_name}"
        )
        op.create_foreign_key(
            constraint_name,
            table,
            "coverage_assessment",
            [column],
            ["id"],
        )
