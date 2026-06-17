"""Add ``title`` and ``description`` columns to ``cves``.

Revision ID: 0019_cve_title_description
Revises: 0018_vuln_class_mappings
Create Date: 2026-05-19

The connector layer (`CVERecord`) and the manual-CVE submission body both
carry a CVE description, and the coverage mapper's Phase 1.5 / Phase 2
verify prompts read both ``title`` and ``description`` off the CVE row to
ground the LLM in what the vulnerability actually does. Those columns
never existed on the ORM model — the AttributeError was masked in CI
because the prompt tests used ``MagicMock`` CVE objects. First real
coverage-mapping run on a live deployment surfaced
``'CVE' object has no attribute 'title'``.

This migration adds both columns nullable. Backfill is not attempted:
``description`` was previously stuffed into ``raw_connector_data.raw.description``
for manual CVEs only, and the call sites that need it (mapper prompts) are
fine with NULL. Operators who want to backfill from raw_connector_data can
do so with a one-shot SQL update; we don't run it automatically because
connector-sourced CVEs don't carry the value in raw_connector_data anyway.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0019_cve_title_description"
down_revision: Union[str, Sequence[str], None] = "0018_vuln_class_mappings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "cves",
        sa.Column("title", sa.String(length=500), nullable=True),
    )
    op.add_column(
        "cves",
        sa.Column("description", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("cves", "description")
    op.drop_column("cves", "title")
