"""logsource_profiles (M13 — per-platform rule generation profiles)

Revision ID: 0012_logsource_profiles
Revises: 0011_sigma, 0011_cisa_kev_date_to_date
Create Date: 2026-05-12

One table, ``logsource_profiles``: a profile encodes how the M15 rule
generator should write detection logic for a specific environment —
product/service mapping, common field names, and a few hand-written
example rules used as few-shot context in the LLM prompt.

Operators see one row per environment they care about. The seven
built-in profiles are seeded by ``scripts/seed_profiles.py`` (also
runnable as a one-shot at first boot). Built-in rows carry
``is_builtin=true``; operator-created profiles default to ``false`` and
can be freely edited via PATCH. Modifying a built-in row is rejected at
the API boundary.

Two of the seven built-ins start ``enabled=true`` (the most common
Linux + Windows EDR signals) — everything else ships disabled so a
fresh deployment doesn't generate redundant rule variants nobody is
ingesting.

Note: this revision is a **merge** of two parallel 0011 heads —
``0011_sigma`` (M12, Sigma integration tables) and
``0011_cisa_kev_date_to_date`` (Phase 4 cleanup that re-typed the
``cves.cisa_kev_date`` column). Both branched off ``0010_attack_chains``
and neither rewrote the other's schema, so the merge is purely
graph-level: 0012 is the single head from this point forward.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012_logsource_profiles"
down_revision: Union[str, Sequence[str], None] = (
    "0011_sigma",
    "0011_cisa_kev_date_to_date",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "logsource_profiles",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(50), nullable=False),
        sa.Column("display_name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("platform", sa.String(20), nullable=False),
        sa.Column("sigma_product", sa.String(50), nullable=True),
        sa.Column("sigma_service", sa.String(50), nullable=True),
        sa.Column(
            "field_conventions",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "example_rules",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "is_builtin",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
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
        sa.UniqueConstraint("name", name="uq_logsource_profiles_name"),
    )
    op.create_index(
        "ix_logsource_profiles_enabled", "logsource_profiles", ["enabled"]
    )
    op.create_index(
        "ix_logsource_profiles_platform", "logsource_profiles", ["platform"]
    )
    op.create_index(
        "ix_logsource_profiles_is_builtin",
        "logsource_profiles",
        ["is_builtin"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_logsource_profiles_is_builtin", table_name="logsource_profiles"
    )
    op.drop_index(
        "ix_logsource_profiles_platform", table_name="logsource_profiles"
    )
    op.drop_index(
        "ix_logsource_profiles_enabled", table_name="logsource_profiles"
    )
    op.drop_table("logsource_profiles")
