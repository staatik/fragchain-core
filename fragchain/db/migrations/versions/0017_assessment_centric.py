"""assessment-centric workflow (Plan A — foundation)

Revision ID: 0017_assessment_centric
Revises: 0016_coverage_verification
Create Date: 2026-05-17

Adds:

* ``coverage_assessment`` — 1:1 per CVE, owned by an analyst.
* ``assessment_source`` — free-text-paste sources attached to an assessment.
* ``assessment_loop_run`` — versioned loop outputs (Loop 1/2/3).
* ``attack_chains.assessment_id``, ``attack_chains.superseded_by_assessment_id``,
  ``attack_chains.superseded_at``, ``attack_chains.behavioral_indicators``.
* Partial unique index ``uq_attack_chains_active_per_cve`` enforcing one
  active chain per CVE (active = ``superseded_at IS NULL``).
* ``review_queue.assessment_id``, ``review_queue.low_detectability_override``,
  ``review_queue.superseded_by_assessment_id``.
* ``sigma_rules.deprecated_by_rule_id``, ``sigma_rules.deprecated_at``,
  ``sigma_rules.deprecated_by_assessment_id``.
* ``llm_interactions.assessment_id`` (optional FK for direct cost joins).

All new columns are nullable / defaulted so existing rows survive the
migration without backfill. The ``source_origin`` enum on ``attack_chains``
is widened by the application layer (the DB stores it as varchar); no DB
constraint changes are needed for that.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0017_assessment_centric"
down_revision: Union[str, Sequence[str], None] = "0016_coverage_verification"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # coverage_assessment
    # ------------------------------------------------------------------
    op.create_table(
        "coverage_assessment",
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
        sa.Column("creator_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("initial_trigger", postgresql.JSONB, nullable=False),
        sa.Column("context_note", sa.Text, nullable=True),
        sa.Column("state", sa.String(32), nullable=False, server_default="created"),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "tlp", sa.String(20), nullable=False, server_default="tlp:clear"
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("cve_id", name="uq_coverage_assessment_cve"),
    )

    # ------------------------------------------------------------------
    # assessment_source
    # ------------------------------------------------------------------
    op.create_table(
        "assessment_source",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("coverage_assessment.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("title", sa.String(200), nullable=True),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer, nullable=False),
        sa.Column(
            "tlp", sa.String(20), nullable=False, server_default="tlp:clear"
        ),
        sa.Column(
            "embedding_status",
            sa.String(20),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("embedding_error", sa.Text, nullable=True),
        sa.Column("injection_risk_score", sa.Numeric(3, 2), nullable=True),
        sa.Column("pasted_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "pasted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("delete_rationale", sa.Text, nullable=True),
        sa.UniqueConstraint(
            "assessment_id",
            "content_hash",
            name="uq_assessment_source_hash",
        ),
    )

    op.create_index(
        "idx_assessment_source_emb_status",
        "assessment_source",
        ["assessment_id", "embedding_status"],
        postgresql_where=sa.text("deleted_at IS NULL"),
    )

    # ------------------------------------------------------------------
    # assessment_loop_run
    # ------------------------------------------------------------------
    op.create_table(
        "assessment_loop_run",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("coverage_assessment.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("loop_number", sa.SmallInteger, nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column(
            "is_active",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("output", postgresql.JSONB, nullable=True),
        sa.Column("gate_result", postgresql.JSONB, nullable=True),
        sa.Column("override_rationale", sa.Text, nullable=True),
        sa.Column(
            "embedding_warned",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "prompt_template_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("prompt_templates.id"),
            nullable=True,
        ),
        sa.Column("model", sa.String(100), nullable=True),
        sa.Column("cost_usd", sa.Numeric(8, 4), nullable=True),
        sa.Column("latency_ms", sa.Integer, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "loop_number IN (1, 2, 3)", name="ck_assessment_loop_run_loop_number"
        ),
        sa.UniqueConstraint(
            "assessment_id",
            "loop_number",
            "version",
            name="uq_assessment_loop_run_version",
        ),
    )

    op.create_index(
        "idx_assessment_loop_run_active",
        "assessment_loop_run",
        ["assessment_id", "loop_number"],
        postgresql_where=sa.text("is_active = true"),
    )

    # ------------------------------------------------------------------
    # attack_chains: assessment linkage + supersession + indicators
    # ------------------------------------------------------------------
    op.add_column(
        "attack_chains",
        sa.Column(
            "assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("coverage_assessment.id"),
            nullable=True,
        ),
    )
    op.add_column(
        "attack_chains",
        sa.Column(
            "superseded_by_assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("coverage_assessment.id"),
            nullable=True,
        ),
    )
    op.add_column(
        "attack_chains",
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "attack_chains",
        sa.Column("behavioral_indicators", postgresql.JSONB, nullable=True),
    )

    # Backfill supersession before creating the partial unique index. The
    # generator persists a new row per regeneration (UNIQUE(cve_id, version)
    # already exists from M10), so deployments with non-fresh data have N>1
    # chain rows per CVE. Without this UPDATE, the index below would fail
    # with UniqueViolationError on `docker compose up`. Keep only the
    # latest-version (tie-break by created_at) row per CVE active.
    op.execute(
        """
        UPDATE attack_chains a
        SET superseded_at = NOW()
        WHERE EXISTS (
            SELECT 1 FROM attack_chains b
            WHERE b.cve_id = a.cve_id
              AND (b.version > a.version
                   OR (b.version = a.version AND b.created_at > a.created_at))
        )
        """
    )

    op.create_index(
        "uq_attack_chains_active_per_cve",
        "attack_chains",
        ["cve_id"],
        unique=True,
        postgresql_where=sa.text("superseded_at IS NULL"),
    )

    # ------------------------------------------------------------------
    # review_queue: assessment linkage + low-detectability flag + supersession
    # ------------------------------------------------------------------
    op.add_column(
        "review_queue",
        sa.Column(
            "assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("coverage_assessment.id"),
            nullable=True,
        ),
    )
    op.add_column(
        "review_queue",
        sa.Column(
            "low_detectability_override",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "review_queue",
        sa.Column(
            "superseded_by_assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("coverage_assessment.id"),
            nullable=True,
        ),
    )

    # ------------------------------------------------------------------
    # sigma_rules: deprecation by assessment-produced replacement
    # ------------------------------------------------------------------
    op.add_column(
        "sigma_rules",
        sa.Column(
            "deprecated_by_rule_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sigma_rules.id"),
            nullable=True,
        ),
    )
    op.add_column(
        "sigma_rules",
        sa.Column("deprecated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "sigma_rules",
        sa.Column(
            "deprecated_by_assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("coverage_assessment.id"),
            nullable=True,
        ),
    )

    # ------------------------------------------------------------------
    # llm_interactions: optional assessment FK for direct cost joins
    # ------------------------------------------------------------------
    op.add_column(
        "llm_interactions",
        sa.Column(
            "assessment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("coverage_assessment.id"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("llm_interactions", "assessment_id")
    op.drop_column("sigma_rules", "deprecated_by_assessment_id")
    op.drop_column("sigma_rules", "deprecated_at")
    op.drop_column("sigma_rules", "deprecated_by_rule_id")
    op.drop_column("review_queue", "superseded_by_assessment_id")
    op.drop_column("review_queue", "low_detectability_override")
    op.drop_column("review_queue", "assessment_id")
    op.drop_index("uq_attack_chains_active_per_cve", table_name="attack_chains")
    op.drop_column("attack_chains", "behavioral_indicators")
    op.drop_column("attack_chains", "superseded_at")
    op.drop_column("attack_chains", "superseded_by_assessment_id")
    op.drop_column("attack_chains", "assessment_id")
    op.drop_index("idx_assessment_loop_run_active", table_name="assessment_loop_run")
    op.drop_table("assessment_loop_run")
    op.drop_index(
        "idx_assessment_source_emb_status", table_name="assessment_source"
    )
    op.drop_table("assessment_source")
    op.drop_table("coverage_assessment")
