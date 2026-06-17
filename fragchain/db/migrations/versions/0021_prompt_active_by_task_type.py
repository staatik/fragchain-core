"""Re-key uq_prompt_templates_active from name to task_type.

Revision ID: 0021_prompt_active_by_task_type
Revises: 0020_assessment_fk_indexes
Create Date: 2026-05-28

CLAUDE.md §15/§19 state the invariant "at most one active prompt per
(task_type, target_model, target_provider)", but migration 0008 created
``uq_prompt_templates_active`` on ``(name, target_model, target_provider)``.
Since the engine resolves prompts by ``task_type`` (PromptStore.get_active),
an operator-cloned template with ``name != task_type`` was either invisible
to the resolver or could sit active alongside the default — the documented
guarantee was never enforced at the DB level.

This migration aligns the index with the contract:

1.  Backfill: where two or more active rows share the same
    ``(task_type, target_model, target_provider)``, keep the highest
    ``(version, created_at)`` active and deactivate the rest. Without this,
    ``CREATE UNIQUE INDEX`` would fail on any DB that already has such a
    pair (mirrors the 0017 backfill pattern).
2.  Drop the old name-keyed index, create the task_type-keyed one.

Pure DDL/DML, idempotent (DROP ... IF EXISTS, guarded backfill). Safe to
re-run after a partial failure.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0021_prompt_active_by_task_type"
down_revision: Union[str, Sequence[str], None] = "0020_assessment_fk_indexes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Deactivate duplicate actives, keeping the newest per task identity.
    op.execute(
        """
        UPDATE prompt_templates p
        SET is_active = false
        WHERE p.is_active = true
          AND EXISTS (
              SELECT 1 FROM prompt_templates q
              WHERE q.is_active = true
                AND q.task_type = p.task_type
                AND q.target_model = p.target_model
                AND q.target_provider = p.target_provider
                AND q.id <> p.id
                AND (q.version, q.created_at) > (p.version, p.created_at)
          )
        """
    )
    # 2. Swap the index from name-keyed to task_type-keyed.
    op.execute("DROP INDEX IF EXISTS uq_prompt_templates_active")
    op.create_index(
        "uq_prompt_templates_active",
        "prompt_templates",
        ["task_type", "target_model", "target_provider"],
        unique=True,
        postgresql_where=sa.text("is_active = true"),
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_prompt_templates_active")
    op.create_index(
        "uq_prompt_templates_active",
        "prompt_templates",
        ["name", "target_model", "target_provider"],
        unique=True,
        postgresql_where=sa.text("is_active = true"),
    )
