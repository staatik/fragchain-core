"""Add ``auto_advance`` to ``coverage_assessment`` for the loop-chaining driver.

Revision ID: 0027_assessment_auto_advance
Revises: 0026_loop_run_active_unique
Create Date: 2026-06-12

W2a loop-chaining: when ``auto_advance`` is true, a successful loop run
dispatches the next loop automatically (gate-fail / failure / loop-3-done
stop the chain). Default false preserves the manual step-by-step flow; W3a
headless mode creates assessments with the flag on.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0027_assessment_auto_advance"
down_revision: Union[str, Sequence[str], None] = "0026_loop_run_active_unique"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "coverage_assessment",
        sa.Column(
            "auto_advance",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("coverage_assessment", "auto_advance")
