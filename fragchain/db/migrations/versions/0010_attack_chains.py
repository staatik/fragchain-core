"""attack_chains + chain_ttps (M10 — chain schema)

Revision ID: 0010_attack_chains
Revises: 0009_coverage_map
Create Date: 2026-05-12

Two tables back the relational projection of the M10 Pydantic schema:

  * ``attack_chains`` — one row per ``(cve_id, version)`` chain. The full
    chain JSON is also persisted in ``chain`` (JSONB) so a consumer can
    rehydrate the Pydantic ``AttackChain`` model with one read, while
    relational consumers (M14 coverage mapper, queue priority scorer) can
    query the flattened ``chain_ttps`` rows.
  * ``chain_ttps`` — one row per TTP in a chain, ordered by ``seq_order``.
    ``source_refs`` is persisted as JSONB (the M10 schema enforces
    non-emptiness in Python; the DB default is the empty array so the
    column is never NULL).

FK choices:
  * ``attack_chains.cve_id`` -> ``cves.id`` (``ON DELETE CASCADE``) — drop
    the chain when the CVE is deleted.
  * ``attack_chains.prompt_template_id`` -> ``prompt_templates.id``
    (``ON DELETE SET NULL``) — keep the chain even if the originating
    prompt template is removed; the FK is nullable on purpose so
    hand-validated chains can exist without a prompt.
  * ``chain_ttps.chain_id`` -> ``attack_chains.id`` (``ON DELETE CASCADE``)
    — TTPs have no meaning outside their chain.

Status state machine on ``attack_chains.status``: ``draft`` (LLM output)
-> ``validated`` (analyst approved) -> ``rejected`` (analyst rejected).
M11 writes the row in ``draft``; M18+ analyst workflow flips it forward.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010_attack_chains"
down_revision: Union[str, None] = "0009_coverage_map"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ---- attack_chains --------------------------------------------------
    op.create_table(
        "attack_chains",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "cve_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cves.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "version", sa.Integer(), nullable=False, server_default=sa.text("1")
        ),
        sa.Column("model", sa.String(100), nullable=True),
        sa.Column("provider", sa.String(50), nullable=True),
        sa.Column(
            "prompt_template_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("prompt_templates.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("overall_confidence", sa.Numeric(3, 2), nullable=True),
        sa.Column("chain", postgresql.JSONB(), nullable=False),
        sa.Column(
            "sources_used",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("predicted_impact", sa.Text(), nullable=True),
        sa.Column(
            "detection_gaps",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "tlp",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'tlp:clear'"),
        ),
        sa.Column("embargo_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'draft'"),
        ),
        sa.Column("validated_by", sa.String(255), nullable=True),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column(
            "source_origin",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'local'"),
        ),
        sa.Column("commons_chain_id", sa.String(100), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.UniqueConstraint(
            "cve_id", "version", name="uq_attack_chains_cve_version"
        ),
    )
    op.create_index("ix_attack_chains_cve_id", "attack_chains", ["cve_id"])
    op.create_index("ix_attack_chains_status", "attack_chains", ["status"])
    op.create_index("ix_attack_chains_tlp", "attack_chains", ["tlp"])
    op.create_index(
        "ix_attack_chains_source_origin", "attack_chains", ["source_origin"]
    )
    op.create_index(
        "ix_attack_chains_created_at", "attack_chains", ["created_at"]
    )

    # ---- chain_ttps -----------------------------------------------------
    op.create_table(
        "chain_ttps",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "chain_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("attack_chains.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("seq_order", sa.Integer(), nullable=False),
        sa.Column("tactic", sa.String(50), nullable=True),
        sa.Column("tactic_id", sa.String(10), nullable=True),
        sa.Column("technique_id", sa.String(20), nullable=True),
        sa.Column("technique_name", sa.String(200), nullable=True),
        sa.Column("sub_technique_id", sa.String(20), nullable=True),
        sa.Column(
            "framework",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'attck'"),
        ),
        sa.Column("confidence", sa.Numeric(3, 2), nullable=True),
        sa.Column(
            "preconditions",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("detection_opportunity", sa.Text(), nullable=True),
        sa.Column(
            "source_refs",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.UniqueConstraint(
            "chain_id", "seq_order", name="uq_chain_ttps_chain_seq"
        ),
    )
    op.create_index("ix_chain_ttps_chain_id", "chain_ttps", ["chain_id"])
    op.create_index(
        "ix_chain_ttps_technique_id", "chain_ttps", ["technique_id"]
    )
    op.create_index("ix_chain_ttps_tactic_id", "chain_ttps", ["tactic_id"])
    op.create_index("ix_chain_ttps_framework", "chain_ttps", ["framework"])


def downgrade() -> None:
    op.drop_index("ix_chain_ttps_framework", table_name="chain_ttps")
    op.drop_index("ix_chain_ttps_tactic_id", table_name="chain_ttps")
    op.drop_index("ix_chain_ttps_technique_id", table_name="chain_ttps")
    op.drop_index("ix_chain_ttps_chain_id", table_name="chain_ttps")
    op.drop_table("chain_ttps")
    op.drop_index("ix_attack_chains_created_at", table_name="attack_chains")
    op.drop_index("ix_attack_chains_source_origin", table_name="attack_chains")
    op.drop_index("ix_attack_chains_tlp", table_name="attack_chains")
    op.drop_index("ix_attack_chains_status", table_name="attack_chains")
    op.drop_index("ix_attack_chains_cve_id", table_name="attack_chains")
    op.drop_table("attack_chains")
