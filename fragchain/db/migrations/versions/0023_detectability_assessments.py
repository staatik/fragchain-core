"""Add detectability_assessments table (Phase 1, ADR-0004).

Revision ID: 0023_detectability_assessments
Revises: 0022_rule_similarity
Create Date: 2026-06-09
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "0023_detectability_assessments"
down_revision: Union[str, Sequence[str], None] = "0022_rule_similarity"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "detectability_assessments",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "assessment_id",
            UUID(as_uuid=True),
            sa.ForeignKey(
                "coverage_assessment.id",
                ondelete="CASCADE",
                name="fk_detectability_assessments_assessment_id",
            ),
            nullable=False,
        ),
        sa.Column(
            "loop_run_id",
            UUID(as_uuid=True),
            sa.ForeignKey(
                "assessment_loop_run.id",
                ondelete="CASCADE",
                name="fk_detectability_assessments_loop_run_id",
            ),
            nullable=False,
            unique=True,
        ),
        sa.Column("detectability_class", sa.String(32), nullable=False),
        sa.Column("confidence", sa.Numeric(4, 3), nullable=False),
        sa.Column("gate_passed", sa.Boolean(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("model", sa.String(100), nullable=True),
        sa.Column(
            "prompt_template_id",
            UUID(as_uuid=True),
            sa.ForeignKey(
                "prompt_templates.id",
                ondelete="SET NULL",
                name="fk_detectability_assessments_prompt_template_id",
            ),
            nullable=True,
        ),
        sa.Column("cost_usd", sa.Numeric(8, 4), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_detectability_assessments_assessment_id",
        "detectability_assessments",
        ["assessment_id"],
    )
    op.create_index(
        "ix_detectability_assessments_detectability_class",
        "detectability_assessments",
        ["detectability_class"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_detectability_assessments_detectability_class",
        table_name="detectability_assessments",
    )
    op.drop_index(
        "ix_detectability_assessments_assessment_id",
        table_name="detectability_assessments",
    )
    op.drop_table("detectability_assessments")
