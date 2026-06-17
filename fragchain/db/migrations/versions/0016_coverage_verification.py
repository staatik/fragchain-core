"""coverage_verification (Phase A Day 1 — schema scaffolding)

Revision ID: 0016_coverage_verification
Revises: 0015_cleanup_mock_commons_chains
Create Date: 2026-05-16

Phase A of the coverage-verification work (see
``docs/architecture/COVERAGE_VERIFICATION_DESIGN.md``). This migration only
lays down schema; the mapper / generator / CLI changes that consume it land
in Days 3–5.

Adds:

* ``coverage_benchmark`` — hand-labeled (cve, technique, rule) → verdict
  pairs used as ground truth for the verify path. Includes a mandatory
  rationale so labels stay reviewable.
* ``coverage_benchmark_runs`` — one row per benchmark run with the
  confusion matrix + precision / recall / F1 so prompt-version A/B is
  observable from a single SELECT.
* ``coverage_map.mapper_version`` (default ``v0-baseline``) and
  ``coverage_map.last_verified_at`` — lets the Phase A mapper write
  ``phase-a`` rows alongside the existing baseline without silently
  re-mapping it. The design doc resolved open question #2 here: keep
  historical rows so we have a comparable benchmark baseline; provide a
  ``scripts/clear_coverage_map.py`` opt-in for fresh starts.
* ``review_queue.supersede_rule_id`` (FK to ``sigma_rules``) and
  ``review_queue.supersede_rationale`` (mandatory at the application
  layer when the analyst supersedes a candidate). The new
  ``status='superseded'`` value reuses the existing varchar column —
  no enum constraint to add.

The supersede path writes a ``coverage_benchmark`` row directly with
``expected_verdict='covered'`` (Day 5). This deviates slightly from the
design doc — which mentioned ``rule_evaluations`` — because that table is
purpose-built for field-efficacy capture (TP/FP rates, environment
shape) and adding a free-form ``action`` column would muddy its
semantics. ``coverage_benchmark`` already has exactly the shape we need
(``cve_id``, ``technique_id``, ``rule_id``, ``expected_verdict``,
``rationale``, ``labeled_by``), so analyst judgments auto-feed the
labeled set without a parallel data path.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0016_coverage_verification"
down_revision: Union[str, Sequence[str], None] = "0015_cleanup_mock_commons_chains"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # coverage_benchmark — labeled (cve, technique, rule) ground-truth
    # ------------------------------------------------------------------
    op.create_table(
        "coverage_benchmark",
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
        sa.Column("technique_id", sa.String(20), nullable=False),
        sa.Column(
            "rule_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sigma_rules.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # 'covered' | 'partial' | 'no_match' — informational, not enforced
        sa.Column("expected_verdict", sa.String(20), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("labeled_by", sa.String(255), nullable=False),
        sa.Column(
            "labeled_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        # Commons treatment — matches §4 decision #1 in the design doc.
        sa.Column(
            "tlp",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'tlp:clear'"),
        ),
        sa.Column(
            "contributed_to_commons",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        # Provenance — distinguishes manual labels from supersede-derived ones.
        # 'manual' (default) | 'supersede' (Day-5 supersede action) | 'commons'
        sa.Column(
            "source",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'manual'"),
        ),
        sa.UniqueConstraint(
            "cve_id",
            "technique_id",
            "rule_id",
            name="uq_coverage_benchmark_cve_technique_rule",
        ),
    )
    op.create_index(
        "ix_coverage_benchmark_cve_id",
        "coverage_benchmark",
        ["cve_id"],
    )
    op.create_index(
        "ix_coverage_benchmark_technique_id",
        "coverage_benchmark",
        ["technique_id"],
    )
    op.create_index(
        "ix_coverage_benchmark_rule_id",
        "coverage_benchmark",
        ["rule_id"],
    )

    # ------------------------------------------------------------------
    # coverage_benchmark_runs — confusion matrix + P/R/F1 per run
    # ------------------------------------------------------------------
    op.create_table(
        "coverage_benchmark_runs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        # Free-form label like 'baseline', 'phase-a', 'phase-a-v2' — used
        # as the human-readable axis when comparing runs in the eventual
        # Prompts Management panel (Phase B).
        sa.Column("run_label", sa.String(100), nullable=False),
        sa.Column(
            "prompt_template_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("prompt_templates.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("semantic_threshold", sa.Numeric(3, 2), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "completed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("total_pairs", sa.Integer(), nullable=False),
        sa.Column("true_positives", sa.Integer(), nullable=False),
        sa.Column("false_positives", sa.Integer(), nullable=False),
        sa.Column("true_negatives", sa.Integer(), nullable=False),
        sa.Column("false_negatives", sa.Integer(), nullable=False),
        sa.Column("precision_score", sa.Numeric(5, 4), nullable=True),
        sa.Column("recall_score", sa.Numeric(5, 4), nullable=True),
        sa.Column("f1_score", sa.Numeric(5, 4), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_coverage_benchmark_runs_run_label",
        "coverage_benchmark_runs",
        ["run_label"],
    )
    op.create_index(
        "ix_coverage_benchmark_runs_started_at",
        "coverage_benchmark_runs",
        ["started_at"],
    )

    # ------------------------------------------------------------------
    # coverage_map — version + last-verified columns
    # ------------------------------------------------------------------
    # Existing rows backfill to 'v0-baseline' via server_default. New rows
    # written by the Phase A mapper (Day 4) explicitly set 'phase-a'.
    op.add_column(
        "coverage_map",
        sa.Column(
            "mapper_version",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'v0-baseline'"),
        ),
    )
    op.add_column(
        "coverage_map",
        sa.Column(
            "last_verified_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_coverage_map_mapper_version",
        "coverage_map",
        ["mapper_version"],
    )

    # ------------------------------------------------------------------
    # review_queue — supersede metadata
    # ------------------------------------------------------------------
    op.add_column(
        "review_queue",
        sa.Column(
            "supersede_rule_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sigma_rules.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "review_queue",
        sa.Column(
            "supersede_rationale",
            sa.Text(),
            nullable=True,
        ),
    )
    # Index supersede_rule_id since the eventual "show me rules other
    # analysts have superseded with" join filters on it.
    op.create_index(
        "ix_review_queue_supersede_rule_id",
        "review_queue",
        ["supersede_rule_id"],
        postgresql_where=sa.text("supersede_rule_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_review_queue_supersede_rule_id", table_name="review_queue"
    )
    op.drop_column("review_queue", "supersede_rationale")
    op.drop_column("review_queue", "supersede_rule_id")

    op.drop_index("ix_coverage_map_mapper_version", table_name="coverage_map")
    op.drop_column("coverage_map", "last_verified_at")
    op.drop_column("coverage_map", "mapper_version")

    op.drop_index(
        "ix_coverage_benchmark_runs_started_at",
        table_name="coverage_benchmark_runs",
    )
    op.drop_index(
        "ix_coverage_benchmark_runs_run_label",
        table_name="coverage_benchmark_runs",
    )
    op.drop_table("coverage_benchmark_runs")

    op.drop_index(
        "ix_coverage_benchmark_rule_id", table_name="coverage_benchmark"
    )
    op.drop_index(
        "ix_coverage_benchmark_technique_id", table_name="coverage_benchmark"
    )
    op.drop_index(
        "ix_coverage_benchmark_cve_id", table_name="coverage_benchmark"
    )
    op.drop_table("coverage_benchmark")
