"""rule_evaluations (M17 — field efficacy capture)

Revision ID: 0014_rule_evaluations
Revises: 0013_review_queue
Create Date: 2026-05-13

One table, ``rule_evaluations``: after a rule lands in a target environment
analysts record TP/FP rates, query cost, deployment complexity etc.
Aggregated stats expose which rules actually work in practice.

Schema mirrors CLAUDE.md / FragChain_Module_Specifications M17 exactly. We
add three index helpers on top of the spec table:

* ``ix_rule_evaluations_sigma_rule_id`` — every aggregate / list call filters
  by the rule id; this is the hot path.
* ``ix_rule_evaluations_evaluated_at`` — the daily ``prompt_evaluations``
  Celery task scans rules that have been deployed for 7+ days without an
  evaluation; a covering index on the evaluation timestamp keeps the join
  to ``sigma_rules.reviewed_at`` cheap.
* ``ix_rule_evaluations_contributed`` — partial index on
  ``contributed_to_commons=true`` so the commons sync / status endpoint can
  count contributions without a full scan.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014_rule_evaluations"
down_revision: Union[str, Sequence[str], None] = "0013_review_queue"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "rule_evaluations",
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
        sa.Column("evaluator_username", sa.String(255), nullable=True),
        sa.Column(
            "evaluated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("environment_platform", sa.String(50), nullable=True),
        sa.Column("environment_logsource", sa.String(100), nullable=True),
        # 'small' | 'medium' | 'enterprise'
        sa.Column("environment_scale", sa.String(50), nullable=True),
        sa.Column("true_positives", sa.Integer(), nullable=True),
        sa.Column(
            "false_positives_per_day",
            sa.Numeric(6, 2),
            nullable=True,
        ),
        # 'low' | 'medium' | 'high' — informational; not enforced at the DB.
        sa.Column("query_cost", sa.String(20), nullable=True),
        # 'trivial' | 'moderate' | 'complex' — informational; not enforced.
        sa.Column("deployment_complexity", sa.String(20), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "contributed_to_commons",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.create_index(
        "ix_rule_evaluations_sigma_rule_id",
        "rule_evaluations",
        ["sigma_rule_id"],
    )
    op.create_index(
        "ix_rule_evaluations_evaluated_at",
        "rule_evaluations",
        ["evaluated_at"],
    )
    op.create_index(
        "ix_rule_evaluations_contributed",
        "rule_evaluations",
        ["sigma_rule_id"],
        postgresql_where=sa.text("contributed_to_commons = TRUE"),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_rule_evaluations_contributed", table_name="rule_evaluations"
    )
    op.drop_index(
        "ix_rule_evaluations_evaluated_at", table_name="rule_evaluations"
    )
    op.drop_index(
        "ix_rule_evaluations_sigma_rule_id", table_name="rule_evaluations"
    )
    op.drop_table("rule_evaluations")
