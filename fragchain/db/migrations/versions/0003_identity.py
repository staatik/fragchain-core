"""user_identities + trust_attestations + contribution_signatures (M3)

Revision ID: 0003_identity
Revises: 0002_tlp_embargo
Create Date: 2026-05-12

Placeholder schema for the post-v1 identity workflow. Tables exist so other
modules can reference them; no rows are written in v1. The columns track
CLAUDE.md §9 (and FragChain_TLP_and_Identity.md §3.2).

`users.tier` and `users.clearance_level` already shipped in 0001_initial — this
migration only adds the three identity tables.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_identity"
down_revision: Union[str, None] = "0002_tlp_embargo"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "user_identities",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("identity_type", sa.String(20), nullable=True),
        sa.Column("public_key", sa.Text(), nullable=True),
        sa.Column("fingerprint", sa.String(128), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verification_challenge", sa.Text(), nullable=True),
        sa.Column("verification_signature", sa.Text(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.Text(), nullable=True),
    )
    op.create_index("ix_user_identities_user_id", "user_identities", ["user_id"])
    op.create_index(
        "ix_user_identities_fingerprint", "user_identities", ["fingerprint"]
    )

    op.create_table(
        "trust_attestations",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "attestor_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "subject_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("attestation_type", sa.String(50), nullable=True),
        sa.Column("attestation_text", sa.Text(), nullable=True),
        sa.Column("signed_attestation", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_trust_attestations_attestor",
        "trust_attestations",
        ["attestor_user_id"],
    )
    op.create_index(
        "ix_trust_attestations_subject",
        "trust_attestations",
        ["subject_user_id"],
    )

    op.create_table(
        "contribution_signatures",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("entity_type", sa.String(50), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "signer_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("signer_fingerprint", sa.String(128), nullable=True),
        sa.Column("content_hash", sa.String(64), nullable=True),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column(
            "signed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "verified",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.UniqueConstraint(
            "entity_type",
            "entity_id",
            "signer_user_id",
            name="uq_contribution_signatures_entity_signer",
        ),
    )
    op.create_index(
        "ix_contribution_signatures_entity",
        "contribution_signatures",
        ["entity_type", "entity_id"],
    )
    op.create_index(
        "ix_contribution_signatures_signer",
        "contribution_signatures",
        ["signer_user_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_contribution_signatures_signer", table_name="contribution_signatures"
    )
    op.drop_index(
        "ix_contribution_signatures_entity", table_name="contribution_signatures"
    )
    op.drop_table("contribution_signatures")

    op.drop_index("ix_trust_attestations_subject", table_name="trust_attestations")
    op.drop_index("ix_trust_attestations_attestor", table_name="trust_attestations")
    op.drop_table("trust_attestations")

    op.drop_index("ix_user_identities_fingerprint", table_name="user_identities")
    op.drop_index("ix_user_identities_user_id", table_name="user_identities")
    op.drop_table("user_identities")
