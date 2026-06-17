"""Add generated_artifacts table (Phase 2b, ADR-0004 §4 — non-Sigma artifacts).

Revision ID: 0025_generated_artifacts
Revises: 0024_artifact_plans
Create Date: 2026-06-10
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "0025_generated_artifacts"
down_revision: Union[str, Sequence[str], None] = "0024_artifact_plans"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "generated_artifacts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "assessment_id",
            UUID(as_uuid=True),
            sa.ForeignKey(
                "coverage_assessment.id",
                ondelete="CASCADE",
                name="fk_generated_artifacts_assessment_id",
            ),
            nullable=False,
        ),
        sa.Column(
            "artifact_plan_id",
            UUID(as_uuid=True),
            sa.ForeignKey(
                "artifact_plans.id",
                ondelete="SET NULL",
                name="fk_generated_artifacts_artifact_plan_id",
            ),
            nullable=True,
        ),
        sa.Column("artifact_type", sa.String(32), nullable=False),
        sa.Column(
            "version", sa.Integer(), nullable=False, server_default=sa.text("1")
        ),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "plan_recommended",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "status", sa.String(20), nullable=False, server_default="generating"
        ),
        sa.Column(
            "validation_status",
            sa.String(24),
            nullable=False,
            server_default="not_validated",
        ),
        sa.Column("content", JSONB(), nullable=True),
        sa.Column("model", sa.String(100), nullable=True),
        sa.Column(
            "prompt_template_id",
            UUID(as_uuid=True),
            sa.ForeignKey(
                "prompt_templates.id",
                ondelete="SET NULL",
                name="fk_generated_artifacts_prompt_template_id",
            ),
            nullable=True,
        ),
        sa.Column("cost_usd", sa.Numeric(8, 4), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_generated_artifacts_assessment_id",
        "generated_artifacts",
        ["assessment_id"],
    )
    op.create_index(
        "uq_generated_artifacts_active",
        "generated_artifacts",
        ["assessment_id", "artifact_type"],
        unique=True,
        postgresql_where=sa.text("is_active"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_generated_artifacts_active", table_name="generated_artifacts"
    )
    op.drop_index(
        "ix_generated_artifacts_assessment_id", table_name="generated_artifacts"
    )
    op.drop_table("generated_artifacts")
