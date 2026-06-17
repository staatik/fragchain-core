"""sigma_sources + sigma_targets + sigma_rules (M12 — Sigma integration)

Revision ID: 0011_sigma
Revises: 0010_attack_chains
Create Date: 2026-05-12

Three tables back the Sigma integration:

  * ``sigma_sources`` — operator-configured read repos. Seeded with one row
    pointing at SigmaHQ so a fresh deployment can pull existing rules with
    zero configuration.
  * ``sigma_targets`` — operator-configured write repos. Routing rules pick
    a target per generated rule; the ``is_default`` target catches anything
    that doesn't match an explicit rule.
  * ``sigma_rules`` — every rule the engine knows about, either imported
    from a source or generated locally. Carries enough metadata for M14
    (coverage mapper) and M16 (review queue) to operate without touching
    Qdrant for filterable fields.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011_sigma"
down_revision: Union[str, None] = "0010_attack_chains"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ---- sigma_sources --------------------------------------------------
    op.create_table(
        "sigma_sources",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("git_url", sa.Text(), nullable=False),
        sa.Column(
            "branch", sa.String(100), nullable=False, server_default=sa.text("'main'")
        ),
        sa.Column(
            "auth_type", sa.String(20), nullable=False, server_default=sa.text("'none'")
        ),
        sa.Column("auth_credentials_ref", sa.String(255), nullable=True),
        sa.Column("path_filter", sa.String(255), nullable=True),
        sa.Column(
            "enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")
        ),
        sa.Column("last_pull_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_pull_status", sa.String(20), nullable=True),
        sa.Column("last_pull_commit", sa.String(64), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "rules_imported",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
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
        sa.UniqueConstraint("name", name="uq_sigma_sources_name"),
    )

    # ---- sigma_targets --------------------------------------------------
    op.create_table(
        "sigma_targets",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("git_url", sa.Text(), nullable=False),
        sa.Column(
            "branch", sa.String(100), nullable=False, server_default=sa.text("'main'")
        ),
        sa.Column(
            "auth_type",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'token'"),
        ),
        sa.Column("auth_credentials_ref", sa.String(255), nullable=True),
        sa.Column("target_path", sa.String(255), nullable=True),
        sa.Column(
            "is_default",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "auto_pr", sa.Boolean(), nullable=False, server_default=sa.text("true")
        ),
        sa.Column("routing_rules", postgresql.JSONB(), nullable=True),
        sa.Column(
            "enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")
        ),
        sa.Column("last_pr_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.UniqueConstraint("name", name="uq_sigma_targets_name"),
    )
    op.create_index(
        "ix_sigma_targets_is_default", "sigma_targets", ["is_default"]
    )

    # ---- sigma_rules ----------------------------------------------------
    op.create_table(
        "sigma_rules",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "sigma_uuid", postgresql.UUID(as_uuid=True), unique=True, nullable=True
        ),
        sa.Column(
            "chain_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("attack_chains.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "cve_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cves.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("technique_ids", postgresql.ARRAY(sa.String(20)), nullable=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("sigma_yaml", sa.Text(), nullable=False),
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'generated'"),
        ),
        sa.Column(
            "origin",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'fragchain'"),
        ),
        sa.Column(
            "source_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sigma_sources.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "target_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sigma_targets.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("source_rel_path", sa.String(500), nullable=True),
        sa.Column("logsource_product", sa.String(100), nullable=True),
        sa.Column("logsource_service", sa.String(100), nullable=True),
        sa.Column("logsource_profile", sa.String(50), nullable=True),
        sa.Column("detection_level", sa.String(20), nullable=True),
        sa.Column("tags", postgresql.ARRAY(sa.String(255)), nullable=True),
        sa.Column(
            "tlp",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'tlp:clear'"),
        ),
        sa.Column("reviewed_by", sa.String(255), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("merged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("git_pr_url", sa.String(500), nullable=True),
        sa.Column("git_commit_sha", sa.String(64), nullable=True),
        sa.Column("content_hash", sa.String(64), nullable=True),
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
    )
    op.create_index("ix_sigma_rules_sigma_uuid", "sigma_rules", ["sigma_uuid"])
    op.create_index("ix_sigma_rules_chain_id", "sigma_rules", ["chain_id"])
    op.create_index("ix_sigma_rules_cve_id", "sigma_rules", ["cve_id"])
    op.create_index("ix_sigma_rules_status", "sigma_rules", ["status"])
    op.create_index("ix_sigma_rules_origin", "sigma_rules", ["origin"])
    op.create_index("ix_sigma_rules_source_id", "sigma_rules", ["source_id"])
    op.create_index("ix_sigma_rules_target_id", "sigma_rules", ["target_id"])
    op.create_index("ix_sigma_rules_content_hash", "sigma_rules", ["content_hash"])

    # Seed the default SigmaHQ public source. Operators can disable or
    # delete it via PATCH/DELETE — but on a fresh install it gives the
    # deployment a working rule library with zero configuration.
    op.execute(
        """
        INSERT INTO sigma_sources (
            name, git_url, branch, auth_type, path_filter, enabled
        ) VALUES (
            'SigmaHQ',
            'https://github.com/SigmaHQ/sigma',
            'master',
            'none',
            'rules',
            true
        )
        """
    )


def downgrade() -> None:
    op.drop_index("ix_sigma_rules_content_hash", table_name="sigma_rules")
    op.drop_index("ix_sigma_rules_target_id", table_name="sigma_rules")
    op.drop_index("ix_sigma_rules_source_id", table_name="sigma_rules")
    op.drop_index("ix_sigma_rules_origin", table_name="sigma_rules")
    op.drop_index("ix_sigma_rules_status", table_name="sigma_rules")
    op.drop_index("ix_sigma_rules_cve_id", table_name="sigma_rules")
    op.drop_index("ix_sigma_rules_chain_id", table_name="sigma_rules")
    op.drop_index("ix_sigma_rules_sigma_uuid", table_name="sigma_rules")
    op.drop_table("sigma_rules")
    op.drop_index("ix_sigma_targets_is_default", table_name="sigma_targets")
    op.drop_table("sigma_targets")
    op.drop_table("sigma_sources")
