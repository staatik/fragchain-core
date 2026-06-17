"""prompt_templates + prompt_evaluations + prompt_ab_tests (M9 — prompt management)

Revision ID: 0008_prompts
Revises: 0007_cves_imports
Create Date: 2026-05-12

Three tables back the runtime-managed prompt layer:

  * ``prompt_templates`` — every version of every named prompt. Only one row
    per ``(name, target_model, target_provider)`` is allowed to be active at a
    time; enforcement lives in the application + a partial unique index.
  * ``prompt_evaluations`` — one row per benchmark run against a template.
  * ``prompt_ab_tests`` — A/B traffic-split definitions; the router picks A
    or B per request based on ``traffic_split``.

The FK from ``llm_interactions.prompt_template_id`` is *not* added here on
purpose — it stays nullable + un-FKed because providers can write rows that
predate any template (e.g. ad-hoc embeddings) and adding the FK would force a
template-id on every interaction. The application is responsible for
populating it when a real template was used.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_prompts"
down_revision: Union[str, None] = "0007_cves_imports"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ---- prompt_templates ------------------------------------------------
    op.create_table(
        "prompt_templates",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("task_type", sa.String(50), nullable=False),
        sa.Column(
            "target_model",
            sa.String(100),
            nullable=False,
            server_default=sa.text("'*'"),
        ),
        sa.Column(
            "target_provider",
            sa.String(50),
            nullable=False,
            server_default=sa.text("'*'"),
        ),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("system_prompt", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("user_template", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column(
            "is_active", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.UniqueConstraint(
            "name",
            "target_model",
            "target_provider",
            "version",
            name="uq_prompt_templates_name_model_provider_version",
        ),
    )
    op.create_index(
        "ix_prompt_templates_name", "prompt_templates", ["name"]
    )
    op.create_index(
        "ix_prompt_templates_task_type", "prompt_templates", ["task_type"]
    )
    op.create_index(
        "ix_prompt_templates_target_model", "prompt_templates", ["target_model"]
    )
    # Partial unique index: at most one active row per (name, target_model,
    # target_provider). Lets the activate endpoint flip rows transactionally
    # without a global lock.
    op.create_index(
        "uq_prompt_templates_active",
        "prompt_templates",
        ["name", "target_model", "target_provider"],
        unique=True,
        postgresql_where=sa.text("is_active = true"),
    )

    # ---- prompt_evaluations ----------------------------------------------
    op.create_table(
        "prompt_evaluations",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "prompt_template_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("prompt_templates.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("benchmark_set", sa.String(100), nullable=False),
        sa.Column("technique_overlap", sa.Numeric(3, 2), nullable=True),
        sa.Column("ordering_consistency", sa.Numeric(3, 2), nullable=True),
        sa.Column("hallucination_count", sa.Integer(), nullable=True),
        sa.Column("cost_per_run", sa.Numeric(8, 4), nullable=True),
        sa.Column("avg_latency_ms", sa.Integer(), nullable=True),
        sa.Column("sample_outputs", postgresql.JSONB(), nullable=True),
        sa.Column(
            "evaluated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("evaluated_by", sa.String(255), nullable=True),
    )
    op.create_index(
        "ix_prompt_evaluations_template", "prompt_evaluations", ["prompt_template_id"]
    )
    op.create_index(
        "ix_prompt_evaluations_benchmark", "prompt_evaluations", ["benchmark_set"]
    )
    op.create_index(
        "ix_prompt_evaluations_evaluated_at", "prompt_evaluations", ["evaluated_at"]
    )

    # ---- prompt_ab_tests -------------------------------------------------
    op.create_table(
        "prompt_ab_tests",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("task_type", sa.String(50), nullable=False),
        sa.Column(
            "variant_a_template_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("prompt_templates.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "variant_b_template_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("prompt_templates.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "traffic_split",
            sa.Numeric(3, 2),
            nullable=False,
            server_default=sa.text("0.50"),
        ),
        sa.Column(
            "status", sa.String(20), nullable=False, server_default=sa.text("'active'")
        ),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("concluded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("winner", sa.String(1), nullable=True),
    )
    op.create_index(
        "ix_prompt_ab_tests_task_type", "prompt_ab_tests", ["task_type"]
    )
    op.create_index(
        "ix_prompt_ab_tests_status", "prompt_ab_tests", ["status"]
    )


def downgrade() -> None:
    op.drop_index("ix_prompt_ab_tests_status", table_name="prompt_ab_tests")
    op.drop_index("ix_prompt_ab_tests_task_type", table_name="prompt_ab_tests")
    op.drop_table("prompt_ab_tests")

    op.drop_index(
        "ix_prompt_evaluations_evaluated_at", table_name="prompt_evaluations"
    )
    op.drop_index(
        "ix_prompt_evaluations_benchmark", table_name="prompt_evaluations"
    )
    op.drop_index(
        "ix_prompt_evaluations_template", table_name="prompt_evaluations"
    )
    op.drop_table("prompt_evaluations")

    op.drop_index("uq_prompt_templates_active", table_name="prompt_templates")
    op.drop_index(
        "ix_prompt_templates_target_model", table_name="prompt_templates"
    )
    op.drop_index("ix_prompt_templates_task_type", table_name="prompt_templates")
    op.drop_index("ix_prompt_templates_name", table_name="prompt_templates")
    op.drop_table("prompt_templates")
