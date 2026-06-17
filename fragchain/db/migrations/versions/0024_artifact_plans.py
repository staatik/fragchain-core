"""Add artifact_plans table (Phase 2, ADR-0004 §3 — compatibility mode).

Revision ID: 0024_artifact_plans
Revises: 0023_detectability_assessments
Create Date: 2026-06-09
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "0024_artifact_plans"
down_revision: Union[str, Sequence[str], None] = "0023_detectability_assessments"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "artifact_plans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "assessment_id",
            UUID(as_uuid=True),
            sa.ForeignKey(
                "coverage_assessment.id",
                ondelete="CASCADE",
                name="fk_artifact_plans_assessment_id",
            ),
            nullable=False,
        ),
        sa.Column(
            "detectability_assessment_id",
            UUID(as_uuid=True),
            sa.ForeignKey(
                "detectability_assessments.id",
                ondelete="CASCADE",
                name="fk_artifact_plans_detectability_assessment_id",
            ),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "loop_run_id",
            UUID(as_uuid=True),
            sa.ForeignKey(
                "assessment_loop_run.id",
                ondelete="CASCADE",
                name="fk_artifact_plans_loop_run_id",
            ),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "mode",
            sa.String(20),
            nullable=False,
            server_default="compatibility",
        ),
        sa.Column("sigma_planned", sa.Boolean(), nullable=False),
        sa.Column("plan", JSONB(), nullable=False),
        sa.Column("policy_version", sa.String(16), nullable=False),
        sa.Column("observed", JSONB(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_artifact_plans_assessment_id",
        "artifact_plans",
        ["assessment_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_artifact_plans_assessment_id", table_name="artifact_plans")
    op.drop_table("artifact_plans")
