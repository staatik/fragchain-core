"""Vuln-class -> TTP and TTP -> observable-category mapping tables.

Revision ID: 0018_vuln_class_mappings
Revises: 0017_assessment_centric
Create Date: 2026-05-19

Plan C Phase 1. The two tables back :class:`fragchain.assessments.mapping.VulnClassMapper`,
which the assessment chain-synthesis bridge consults to turn Loop 1's
``vuln_class`` and Loop 2's indicators into TTPs with confidence.

Also adds ``chain_ttps.behavioral_indicators`` (JSONB, nullable) so the
synthesis bridge can persist per-TTP indicator lists alongside the existing
``attack_chains.behavioral_indicators`` whole-chain column added in 0017.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0018_vuln_class_mappings"
down_revision: Union[str, Sequence[str], None] = "0017_assessment_centric"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "vuln_class_to_ttps",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("vuln_class", sa.String(120), nullable=False),
        sa.Column("technique_id", sa.String(20), nullable=False),
        sa.Column("tactic_id", sa.String(10), nullable=False),
        sa.Column("tactic", sa.String(50), nullable=False),
        sa.Column("technique_name", sa.String(200), nullable=False),
        sa.Column("seq_order", sa.Integer, nullable=False),
        sa.Column(
            "base_confidence",
            sa.Numeric(3, 2),
            nullable=False,
            server_default="0.50",
        ),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "vuln_class",
            "technique_id",
            name="uq_vuln_class_to_ttps_class_tech",
        ),
    )
    op.create_index(
        "ix_vuln_class_to_ttps_class",
        "vuln_class_to_ttps",
        ["vuln_class"],
    )

    op.create_table(
        "ttp_category_relevance",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("technique_id", sa.String(20), nullable=False),
        sa.Column("category", sa.String(20), nullable=False),
        sa.Column(
            "weight",
            sa.Numeric(3, 2),
            nullable=False,
            server_default="1.00",
        ),
        sa.UniqueConstraint(
            "technique_id",
            "category",
            name="uq_ttp_category_relevance_tech_cat",
        ),
    )
    op.create_index(
        "ix_ttp_category_relevance_tech",
        "ttp_category_relevance",
        ["technique_id"],
    )

    op.add_column(
        "chain_ttps",
        sa.Column("behavioral_indicators", postgresql.JSONB, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("chain_ttps", "behavioral_indicators")
    op.drop_index(
        "ix_ttp_category_relevance_tech",
        table_name="ttp_category_relevance",
    )
    op.drop_table("ttp_category_relevance")
    op.drop_index(
        "ix_vuln_class_to_ttps_class",
        table_name="vuln_class_to_ttps",
    )
    op.drop_table("vuln_class_to_ttps")
