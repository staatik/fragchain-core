"""llm_interactions (M5 — LLM provider framework)

Revision ID: 0005_llm_interactions
Revises: 0004_connector_state
Create Date: 2026-05-12

Adds the `llm_interactions` table — exactly the schema from CLAUDE.md §M5
and FragChain_Module_Specifications.md M5. Every chat completion and every
embedding batch writes one row here; full prompt + response JSON lives in
MinIO at the `storage_path` column.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_llm_interactions"
down_revision: Union[str, None] = "0004_connector_state"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "llm_interactions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("entity_type", sa.String(50), nullable=True),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("interaction_type", sa.String(50), nullable=True),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("model", sa.String(100), nullable=True),
        sa.Column("prompt_template_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("prompt_version", sa.Integer(), nullable=True),
        sa.Column("prompt_tokens", sa.Integer(), nullable=True),
        sa.Column("completion_tokens", sa.Integer(), nullable=True),
        sa.Column("total_cost_usd", sa.Numeric(10, 6), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column(
            "success", sa.Boolean(), nullable=False, server_default=sa.text("true")
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("storage_path", sa.String(500), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )
    op.create_index(
        "ix_llm_interactions_provider", "llm_interactions", ["provider"]
    )
    op.create_index(
        "ix_llm_interactions_interaction_type",
        "llm_interactions",
        ["interaction_type"],
    )
    op.create_index(
        "ix_llm_interactions_entity_type", "llm_interactions", ["entity_type"]
    )
    op.create_index(
        "ix_llm_interactions_entity_id", "llm_interactions", ["entity_id"]
    )
    op.create_index(
        "ix_llm_interactions_created_at", "llm_interactions", ["created_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_llm_interactions_created_at", table_name="llm_interactions")
    op.drop_index("ix_llm_interactions_entity_id", table_name="llm_interactions")
    op.drop_index("ix_llm_interactions_entity_type", table_name="llm_interactions")
    op.drop_index(
        "ix_llm_interactions_interaction_type", table_name="llm_interactions"
    )
    op.drop_index("ix_llm_interactions_provider", table_name="llm_interactions")
    op.drop_table("llm_interactions")
