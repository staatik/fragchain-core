"""tlp_access_grants + embargo_participants (M2)

Revision ID: 0002_tlp_embargo
Revises: 0001_initial
Create Date: 2026-05-12

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_tlp_embargo"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tlp_access_grants",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("entity_type", sa.String(50), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "granted_to_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "granted_to_deployment_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "granted_by_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_tlp_access_grants_entity",
        "tlp_access_grants",
        ["entity_type", "entity_id"],
    )
    op.create_index(
        "ix_tlp_access_grants_user",
        "tlp_access_grants",
        ["granted_to_user_id"],
    )

    op.create_table(
        "embargo_participants",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("entity_type", sa.String(50), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "granted_by_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.UniqueConstraint(
            "entity_type",
            "entity_id",
            "user_id",
            name="uq_embargo_participants_entity_user",
        ),
    )
    op.create_index(
        "ix_embargo_participants_entity",
        "embargo_participants",
        ["entity_type", "entity_id"],
    )
    op.create_index(
        "ix_embargo_participants_user",
        "embargo_participants",
        ["user_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_embargo_participants_user", table_name="embargo_participants")
    op.drop_index("ix_embargo_participants_entity", table_name="embargo_participants")
    op.drop_table("embargo_participants")

    op.drop_index("ix_tlp_access_grants_user", table_name="tlp_access_grants")
    op.drop_index("ix_tlp_access_grants_entity", table_name="tlp_access_grants")
    op.drop_table("tlp_access_grants")
