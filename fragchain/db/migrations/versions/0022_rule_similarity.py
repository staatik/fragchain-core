"""Add generated-rule similarity flagging columns.

Revision ID: 0022_rule_similarity
Revises: 0021_prompt_active_by_task_type
Create Date: 2026-05-28
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0022_rule_similarity"
down_revision: Union[str, Sequence[str], None] = "0021_prompt_active_by_task_type"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "sigma_rules",
        sa.Column("similar_to_rule_id", sa.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "sigma_rules",
        sa.Column("similarity_score", sa.Numeric(4, 3), nullable=True),
    )
    # NOTE: similar_to_rule_id is a soft cross-store pointer (the matched rule
    # comes from Qdrant and may be an external library rule or a point whose
    # PG row was pruned). Intentionally NO foreign key — a hard FK would reject
    # the insert on that benign drift.


def downgrade() -> None:
    op.drop_column("sigma_rules", "similarity_score")
    op.drop_column("sigma_rules", "similar_to_rule_id")
