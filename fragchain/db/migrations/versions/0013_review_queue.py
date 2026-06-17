"""review_queue + sigma_rules extensions (M15 — Rule generator + review)

Revision ID: 0013_review_queue
Revises: 0012_logsource_profiles
Create Date: 2026-05-13

Adds the queue table M16 will own (we create it in M15 so the rule generator
can insert pending items the moment a draft lands) and extends ``sigma_rules``
with two columns the generator needs to record per-row metadata:

* ``review_notes`` — free-text notes from the generator (validation warnings,
  pySigma feedback, fallback after retry exhaustion). Surfaced in the review
  queue UI so analysts see why a row landed under review.
* ``prompt_template_id`` — the active prompt version that produced this rule.
  Mirrors ``attack_chains.prompt_template_id`` so per-version regression
  analytics can correlate generation prompts with downstream review outcomes.

The ``review_queue`` schema mirrors CLAUDE.md §M16 exactly. Spec carries the
table under M16, but the generator (M15) is the only writer at generation
time — M16 owns the lifecycle transitions (pending → in_review → approved /
rejected). Splitting "create table" from "add lifecycle endpoints" would
force M15 to drop drafts into thin air; we ship the table here and let M16
layer the endpoints on top.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013_review_queue"
down_revision: Union[str, Sequence[str], None] = "0012_logsource_profiles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ---- sigma_rules extensions ---------------------------------------
    op.add_column(
        "sigma_rules",
        sa.Column("review_notes", sa.Text(), nullable=True),
    )
    op.add_column(
        "sigma_rules",
        sa.Column(
            "prompt_template_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("prompt_templates.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_sigma_rules_prompt_template_id",
        "sigma_rules",
        ["prompt_template_id"],
    )

    # ---- review_queue ------------------------------------------------
    op.create_table(
        "review_queue",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "sigma_rule_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sigma_rules.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "priority",
            sa.String(20),
            nullable=False,
            server_default="medium",
        ),
        sa.Column(
            "priority_score",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("priority_reason", sa.Text(), nullable=True),
        sa.Column("assigned_to", sa.String(255), nullable=True),
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            server_default="pending",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "completed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_review_queue_sigma_rule_id", "review_queue", ["sigma_rule_id"]
    )
    op.create_index("ix_review_queue_status", "review_queue", ["status"])
    op.create_index(
        "ix_review_queue_priority_score", "review_queue", ["priority_score"]
    )
    # One pending item per rule — re-running M15 on the same chain should
    # update the existing row, not duplicate it. Allows multiple historical
    # rows (status='approved' / 'rejected') for the same rule.
    op.create_index(
        "ux_review_queue_pending_rule",
        "review_queue",
        ["sigma_rule_id"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
    )


def downgrade() -> None:
    op.drop_index(
        "ux_review_queue_pending_rule", table_name="review_queue"
    )
    op.drop_index(
        "ix_review_queue_priority_score", table_name="review_queue"
    )
    op.drop_index("ix_review_queue_status", table_name="review_queue")
    op.drop_index(
        "ix_review_queue_sigma_rule_id", table_name="review_queue"
    )
    op.drop_table("review_queue")

    op.drop_index(
        "ix_sigma_rules_prompt_template_id", table_name="sigma_rules"
    )
    op.drop_column("sigma_rules", "prompt_template_id")
    op.drop_column("sigma_rules", "review_notes")
