"""Make the loop-run active index UNIQUE (Wave 1a T3).

The one-active-per-(assessment_id, loop_number) invariant documented on
``AssessmentLoopRun`` was backed only by a NON-unique partial index
(``idx_assessment_loop_run_active``, migration 0017) plus ``begin_run``'s
app-level guard — a concurrent double-dispatch race could mint two active
rows. This migration resolves any existing duplicates (keep the
highest-version row active, demote the rest — the supersession semantics
the orchestrator applies), drops the old non-unique index, and creates a
UNIQUE partial index, matching the ``uq_generated_artifacts_active`` idiom.

Revision ID: 0026_loop_run_active_unique
Revises: 0025_generated_artifacts
Create Date: 2026-06-11
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0026_loop_run_active_unique"
down_revision: Union[str, Sequence[str], None] = "0025_generated_artifacts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Resolve existing duplicates FIRST or the unique index creation
    #    fails on any non-fresh DB that hit the race (same class of bug as
    #    the 0017 superseded_at backfill). For each (assessment_id,
    #    loop_number) with more than one active row, keep the
    #    highest-version row active and demote the others to the
    #    orchestrator's supersession state.
    op.execute(
        sa.text(
            """
            UPDATE assessment_loop_run AS r
            SET is_active = false,
                status = 'superseded'
            WHERE r.is_active
              AND EXISTS (
                  SELECT 1
                  FROM assessment_loop_run AS newer
                  WHERE newer.assessment_id = r.assessment_id
                    AND newer.loop_number = r.loop_number
                    AND newer.is_active
                    AND newer.version > r.version
              )
            """
        )
    )

    # 2. Replace the non-unique partial index with a UNIQUE one.
    op.drop_index(
        "idx_assessment_loop_run_active",
        table_name="assessment_loop_run",
    )
    op.create_index(
        "uq_assessment_loop_run_active",
        "assessment_loop_run",
        ["assessment_id", "loop_number"],
        unique=True,
        postgresql_where=sa.text("is_active"),
    )


def downgrade() -> None:
    # The demotion of duplicate active rows is a data fix and is not
    # reversed — the demoted rows keep status='superseded', which is a
    # state the pre-0026 engine already produced and handles.
    op.drop_index(
        "uq_assessment_loop_run_active",
        table_name="assessment_loop_run",
    )
    op.create_index(
        "idx_assessment_loop_run_active",
        "assessment_loop_run",
        ["assessment_id", "loop_number"],
        postgresql_where=sa.text("is_active = true"),
    )
