"""connector_state (M4 — connector framework)

Revision ID: 0004_connector_state
Revises: 0003_identity
Create Date: 2026-05-12

Adds the `connector_state` table — the persistent mirror of every installed
connector's runtime state. Schema is exactly the one in CLAUDE.md §M4 /
FragChain_Module_Specifications.md M4. Rows are written by the orchestrator
on app startup (after discovery) and on every config-mutation API call.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_connector_state"
down_revision: Union[str, None] = "0003_identity"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "connector_state",
        sa.Column("name", sa.String(50), primary_key=True),
        sa.Column("version", sa.String(20), nullable=True),
        sa.Column("type", sa.String(20), nullable=True),
        sa.Column(
            "enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")
        ),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("max_output_tlp", sa.String(20), nullable=True),
        sa.Column(
            "default_output_tlp",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'tlp:clear'"),
        ),
        sa.Column("last_health_check", sa.DateTime(timezone=True), nullable=True),
        sa.Column("health_status", sa.String(20), nullable=True),
        sa.Column(
            "error_count", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "rate_limit_config",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_connector_state_type", "connector_state", ["type"]
    )
    op.create_index(
        "ix_connector_state_enabled", "connector_state", ["enabled"]
    )


def downgrade() -> None:
    op.drop_index("ix_connector_state_enabled", table_name="connector_state")
    op.drop_index("ix_connector_state_type", table_name="connector_state")
    op.drop_table("connector_state")
