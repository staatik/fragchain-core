"""cves + source_documents + import_jobs + import_filter_presets (M6 — intel ingestion)

Revision ID: 0007_cves_imports
Revises: 0006_commons_sources
Create Date: 2026-05-12

Creates the four tables that own the CVE state machine and the historical
import workflow:

  * ``import_jobs`` — operator-initiated batch jobs (filters + counts).
  * ``cves`` — one row per CVE; the state machine is rooted here.
  * ``source_documents`` — RAG snippets attached to a CVE.
  * ``import_filter_presets`` — saved analyst filter combinations.

``cves`` carries a soft FK to ``import_jobs`` (SET NULL on delete) so deleting
a job doesn't cascade into the CVE rows it staged.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_cves_imports"
down_revision: Union[str, None] = "0006_commons_sources"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ---- import_jobs ----------------------------------------------------
    op.create_table(
        "import_jobs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'staging'"),
        ),
        sa.Column("filters", postgresql.JSONB(), nullable=False),
        sa.Column("preview_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("staged_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("approved_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("processed_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("skipped_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("error_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_import_jobs_status", "import_jobs", ["status"])
    op.create_index("ix_import_jobs_created_at", "import_jobs", ["created_at"])

    # ---- cves -----------------------------------------------------------
    op.create_table(
        "cves",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("cve_id", sa.String(20), nullable=False),
        sa.Column("provisional_id", sa.String(20), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cvss_score", sa.Numeric(3, 1), nullable=True),
        sa.Column("cvss_vector", sa.String(100), nullable=True),
        sa.Column(
            "cisa_kev",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("cisa_kev_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("epss_score", sa.Numeric(6, 5), nullable=True),
        sa.Column("epss_percentile", sa.Numeric(6, 5), nullable=True),
        sa.Column("epss_fetched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "ctid_techniques",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("attackerkb_score", sa.Numeric(3, 2), nullable=True),
        sa.Column("attackerkb_data", postgresql.JSONB(), nullable=True),
        sa.Column("affected_products", postgresql.JSONB(), nullable=True),
        sa.Column(
            "import_mode",
            sa.String(10),
            nullable=False,
            server_default=sa.text("'live'"),
        ),
        sa.Column(
            "processing_status",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column("processing_stage", sa.String(20), nullable=True),
        sa.Column("processing_error", sa.Text(), nullable=True),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "import_job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("import_jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "enrichment_sources",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "tlp",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'tlp:clear'"),
        ),
        sa.Column("embargo_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("raw_connector_data", postgresql.JSONB(), nullable=True),
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
        sa.UniqueConstraint("cve_id", name="uq_cves_cve_id"),
    )
    op.create_index("ix_cves_cve_id", "cves", ["cve_id"])
    op.create_index("ix_cves_processing_status", "cves", ["processing_status"])
    op.create_index("ix_cves_import_mode", "cves", ["import_mode"])
    op.create_index("ix_cves_cisa_kev", "cves", ["cisa_kev"])
    op.create_index("ix_cves_published_at", "cves", ["published_at"])
    op.create_index("ix_cves_import_job_id", "cves", ["import_job_id"])

    # ---- source_documents ----------------------------------------------
    op.create_table(
        "source_documents",
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
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("source_type", sa.String(30), nullable=True),
        sa.Column("quality_score", sa.Numeric(3, 2), nullable=True),
        sa.Column(
            "tlp",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'tlp:clear'"),
        ),
        sa.Column("embargo_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("content_hash", sa.String(64), nullable=True),
        sa.Column("storage_path", sa.String(500), nullable=True),
        sa.Column("byte_size", sa.Integer(), nullable=True),
        sa.Column(
            "processed", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "embedded", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column("metadata", postgresql.JSONB(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )
    op.create_index("ix_source_documents_cve_id", "source_documents", ["cve_id"])
    op.create_index(
        "ix_source_documents_content_hash", "source_documents", ["content_hash"]
    )

    # ---- import_filter_presets -----------------------------------------
    op.create_table(
        "import_filter_presets",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("filters", postgresql.JSONB(), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column(
            "is_builtin",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("use_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
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
    )
    op.create_index(
        "ix_import_filter_presets_is_builtin",
        "import_filter_presets",
        ["is_builtin"],
    )
    op.create_index(
        "ix_import_filter_presets_use_count",
        "import_filter_presets",
        ["use_count"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_import_filter_presets_use_count", table_name="import_filter_presets"
    )
    op.drop_index(
        "ix_import_filter_presets_is_builtin", table_name="import_filter_presets"
    )
    op.drop_table("import_filter_presets")
    op.drop_index("ix_source_documents_content_hash", table_name="source_documents")
    op.drop_index("ix_source_documents_cve_id", table_name="source_documents")
    op.drop_table("source_documents")
    op.drop_index("ix_cves_import_job_id", table_name="cves")
    op.drop_index("ix_cves_published_at", table_name="cves")
    op.drop_index("ix_cves_cisa_kev", table_name="cves")
    op.drop_index("ix_cves_import_mode", table_name="cves")
    op.drop_index("ix_cves_processing_status", table_name="cves")
    op.drop_index("ix_cves_cve_id", table_name="cves")
    op.drop_table("cves")
    op.drop_index("ix_import_jobs_created_at", table_name="import_jobs")
    op.drop_index("ix_import_jobs_status", table_name="import_jobs")
    op.drop_table("import_jobs")
