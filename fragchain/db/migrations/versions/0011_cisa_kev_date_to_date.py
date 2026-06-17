"""cisa_kev_date: TIMESTAMP WITH TIME ZONE -> DATE (Phase 4 cleanup C0b)

Revision ID: 0011_cisa_kev_date_to_date
Revises: 0010_attack_chains
Create Date: 2026-05-13

M6 spec (FragChain_Module_Specifications.md §M6 schema) lists ``cisa_kev_date``
as ``DATE``. Migration 0007 created it as ``TIMESTAMP WITH TIME ZONE``, which
caused ``upsert_cve_from_record`` to crash with ``DataError: invalid input for
query argument: '2026-04-22' (expected datetime, got str)`` whenever a
connector emitted the KEV date as the natural ISO calendar string.

This migration aligns the column with the spec: a calendar date for when CISA
listed the CVE in the Known Exploited Vulnerabilities catalogue. No timezone
component is meaningful here. The ``USING`` clause coerces any existing
timestamp rows (live deployments mid-migration) to the underlying date.

Pair with the ``_coerce_date`` helper in ``fragchain/ingest/service.py``.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0011_cisa_kev_date_to_date"
down_revision: Union[str, None] = "0010_attack_chains"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "cves",
        "cisa_kev_date",
        existing_type=sa.DateTime(timezone=True),
        type_=sa.Date(),
        postgresql_using="cisa_kev_date::date",
        existing_nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "cves",
        "cisa_kev_date",
        existing_type=sa.Date(),
        type_=sa.DateTime(timezone=True),
        postgresql_using="cisa_kev_date::timestamptz",
        existing_nullable=True,
    )
