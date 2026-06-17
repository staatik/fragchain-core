"""commons_sources + commons_chains (M7 — intelligence commons)

Revision ID: 0006_commons_sources
Revises: 0005_llm_interactions
Create Date: 2026-05-12

Creates the two tables that own commons state:
  * `commons_sources` — operator-configured commons feeds (multi-source).
    Seeds one row pointing at the public fragchain-intelligence repo so a
    fresh deployment has somewhere to sync from with zero configuration.
  * `commons_chains` — chains imported from each source. The lookup table
    that `CommonsClient.check_chain_exists(cve_id)` reads.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_commons_sources"
down_revision: Union[str, None] = "0005_llm_interactions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "commons_sources",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column(
            "auth_type", sa.String(20), nullable=False, server_default=sa.text("'none'")
        ),
        sa.Column("auth_credentials_ref", sa.String(255), nullable=True),
        sa.Column(
            "sync_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")
        ),
        sa.Column(
            "contribute_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("priority", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "trust_level",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'community'"),
        ),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_release_version", sa.String(50), nullable=True),
        sa.Column("last_sync_status", sa.String(20), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "chains_imported", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.UniqueConstraint("name", name="uq_commons_sources_name"),
    )
    op.create_index(
        "ix_commons_sources_priority", "commons_sources", ["priority"]
    )

    op.create_table(
        "commons_chains",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "source_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("commons_sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("content_hash", sa.String(64), nullable=True),
        sa.Column(
            "tlp",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'tlp:clear'"),
        ),
        sa.Column("data", postgresql.JSONB(), nullable=False),
        sa.Column(
            "imported_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.UniqueConstraint(
            "source_id",
            "cve_id",
            "version",
            name="uq_commons_chains_source_cve_ver",
        ),
    )
    op.create_index("ix_commons_chains_source_id", "commons_chains", ["source_id"])
    op.create_index("ix_commons_chains_cve_id", "commons_chains", ["cve_id"])

    # Seed the default public commons source. Operators can disable, edit,
    # or delete it via PATCH/DELETE — but on a fresh install it gives the
    # deployment a working bootstrap target with zero config.
    op.execute(
        """
        INSERT INTO commons_sources (
            name, url, auth_type, sync_enabled, contribute_enabled,
            priority, trust_level
        ) VALUES (
            'Public Commons',
            'https://github.com/fragchain/fragchain-intelligence',
            'none',
            true,
            false,
            0,
            'community'
        )
        """
    )


def downgrade() -> None:
    op.drop_index("ix_commons_chains_cve_id", table_name="commons_chains")
    op.drop_index("ix_commons_chains_source_id", table_name="commons_chains")
    op.drop_table("commons_chains")
    op.drop_index("ix_commons_sources_priority", table_name="commons_sources")
    op.drop_table("commons_sources")
