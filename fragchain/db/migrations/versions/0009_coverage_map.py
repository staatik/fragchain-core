"""coverage_map table (M8 seeds, M14 mutates)

Revision ID: 0009_coverage_map
Revises: 0008_prompts
Create Date: 2026-05-12

Creates the ``coverage_map`` table early so the M8 ATT&CK seed can populate
one row per technique with ``coverage_status='no_data'``. M14 (Coverage
Mapper) is the canonical owner of this table — it flips rows to ``covered`` /
``partial`` / ``gap`` once chains and Sigma rules exist. M8 just gets the
rows on disk so the ATT&CK Matrix screen has a full grid from day one.

Schema matches FragChain_Module_Specifications.md §M14 verbatim, with
``description``, ``has_subtechniques`` and ``parent_technique_id`` added so
the matrix UI can render rows without an extra join against
``attck_techniques`` (which is in Qdrant, not Postgres).
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009_coverage_map"
down_revision: Union[str, None] = "0008_prompts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "coverage_map",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("technique_id", sa.String(20), nullable=False),
        sa.Column("sub_technique_id", sa.String(20), nullable=True),
        sa.Column("tactic_id", sa.String(10), nullable=True),
        sa.Column("tactic_name", sa.String(50), nullable=True),
        sa.Column("technique_name", sa.String(200), nullable=True),
        sa.Column(
            "framework",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'attck'"),
        ),
        sa.Column(
            "coverage_status",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'no_data'"),
        ),
        sa.Column(
            "covering_rule_ids",
            postgresql.ARRAY(postgresql.UUID(as_uuid=True)),
            nullable=False,
            server_default=sa.text("ARRAY[]::UUID[]"),
        ),
        sa.Column(
            "chain_cve_ids",
            postgresql.ARRAY(postgresql.UUID(as_uuid=True)),
            nullable=False,
            server_default=sa.text("ARRAY[]::UUID[]"),
        ),
        sa.Column(
            "chain_cve_count", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column(
            "kev_cve_count", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column(
            "kev_exposed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "last_refreshed",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "has_subtechniques",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("parent_technique_id", sa.String(20), nullable=True),
        sa.UniqueConstraint(
            "technique_id", "framework", name="uq_coverage_map_technique_framework"
        ),
    )
    op.create_index("ix_coverage_map_tactic_id", "coverage_map", ["tactic_id"])
    op.create_index(
        "ix_coverage_map_coverage_status", "coverage_map", ["coverage_status"]
    )
    op.create_index("ix_coverage_map_framework", "coverage_map", ["framework"])
    op.create_index("ix_coverage_map_kev_exposed", "coverage_map", ["kev_exposed"])


def downgrade() -> None:
    op.drop_index("ix_coverage_map_kev_exposed", table_name="coverage_map")
    op.drop_index("ix_coverage_map_framework", table_name="coverage_map")
    op.drop_index("ix_coverage_map_coverage_status", table_name="coverage_map")
    op.drop_index("ix_coverage_map_tactic_id", table_name="coverage_map")
    op.drop_table("coverage_map")
