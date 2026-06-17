from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for all FragChain ORM models."""


class SystemConfig(Base):
    __tablename__ = "system_config"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[dict[str, Any] | list[Any] | str | int | float | bool | None] = mapped_column(
        JSONB, nullable=False
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entity_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    before: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    after: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    tier: Mapped[str] = mapped_column(String(20), nullable=False, server_default="authenticated")
    clearance_level: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="tlp:green"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TLPAccessGrant(Base):
    __tablename__ = "tlp_access_grants"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    granted_to_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    granted_to_deployment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    granted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class UserIdentity(Base):
    """Public-key identity binding for a user (M3 placeholder schema).

    Populated by post-v1 identity provider modules (M38+). All columns nullable
    except `id`/`user_id` so a register-now / verify-later workflow is possible.
    """

    __tablename__ = "user_identities"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    identity_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_challenge: Mapped[str | None] = mapped_column(Text, nullable=True)
    verification_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class TrustAttestation(Base):
    """One trusted user vouching for another (M3 placeholder schema)."""

    __tablename__ = "trust_attestations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    attestor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    subject_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    attestation_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    attestation_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    signed_attestation: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ContributionSignature(Base):
    """Signature record over a contributable entity (M3 placeholder schema)."""

    __tablename__ = "contribution_signatures"
    __table_args__ = (
        UniqueConstraint(
            "entity_type",
            "entity_id",
            "signer_user_id",
            name="uq_contribution_signatures_entity_signer",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    signer_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    signer_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    signed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")


class ConnectorState(Base):
    """Persistent state for an installed connector (M4).

    Mirrors what `ConnectorOrchestrator` holds in memory, plus operator-set
    config. The row is keyed by connector `name` (uniqueness across the whole
    deployment). Rows are created/updated by the orchestrator on every
    discovery / config change.
    """

    __tablename__ = "connector_state"

    name: Mapped[str] = mapped_column(String(50), primary_key=True)
    version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    max_output_tlp: Mapped[str | None] = mapped_column(String(20), nullable=True)
    default_output_tlp: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="tlp:clear"
    )
    last_health_check: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    health_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    error_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    rate_limit_config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)


class LLMInteraction(Base):
    """One LLM call (chat or embedding) — every call writes one row (M5).

    The row is cheap; the full prompt + response JSON lives in MinIO at
    `storage_path` so an analyst can replay or diff prompts without bloating
    Postgres. `entity_type` / `entity_id` are nullable because the interaction
    may pre-date the row it ends up attached to (e.g. embedding a snippet
    before the chain is persisted).
    """

    __tablename__ = "llm_interactions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    entity_type: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    entity_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    interaction_type: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    provider: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    prompt_template_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    prompt_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_cost_usd: Mapped[Any] = mapped_column(Numeric(10, 6), nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    storage_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("coverage_assessment.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )


class EmbargoParticipant(Base):
    __tablename__ = "embargo_participants"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    granted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )


class CommonsSource(Base):
    """Configurable intelligence commons source (M7).

    Operators can configure one or more git-hosted commons repos. The
    default deployment seeds the public `fragchain-intelligence` repo. Additional
    rows represent internal/partner commons feeds. Conflict resolution uses
    `priority` (higher wins) with `trust_level` as a tiebreaker
    (internal > partner > community).
    """

    __tablename__ = "commons_sources"
    __table_args__ = (
        UniqueConstraint("name", name="uq_commons_sources_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    auth_type: Mapped[str] = mapped_column(String(20), nullable=False, server_default="none")
    auth_credentials_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sync_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )
    contribute_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    priority: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    trust_level: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="community"
    )
    last_sync_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_release_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    last_sync_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    chains_imported: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class CVE(Base):
    """CVE record produced by source connectors or imported by analysts (M6).

    Holds the latest known facts about one vulnerability. Enrichment results
    are merged into the typed columns (``epss_score``, ``cisa_kev``, etc.) and
    ``enrichment_sources`` records which connector contributed which slice so
    a re-run can selectively refresh stale fields.

    ``processing_status`` is the state machine governing whether the
    synthesis pipeline (M11) is allowed to advance the row. The default
    ``pending`` matches the live-feed flow; historical imports land in
    ``staged`` until an analyst approves them.
    """

    __tablename__ = "cves"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cve_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False, index=True)
    provisional_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    title: Mapped[str | None] = mapped_column(String(500), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cvss_score: Mapped[Any] = mapped_column(Numeric(3, 1), nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cisa_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false", index=True)
    cisa_kev_date: Mapped[date | None] = mapped_column(Date(), nullable=True)
    epss_score: Mapped[Any] = mapped_column(Numeric(6, 5), nullable=True)
    epss_percentile: Mapped[Any] = mapped_column(Numeric(6, 5), nullable=True)
    epss_fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ctid_techniques: Mapped[list[Any] | None] = mapped_column(
        JSONB, nullable=False, server_default="'[]'::jsonb"
    )
    attackerkb_score: Mapped[Any] = mapped_column(Numeric(3, 2), nullable=True)
    attackerkb_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    affected_products: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(
        JSONB, nullable=True
    )
    import_mode: Mapped[str] = mapped_column(
        String(10), nullable=False, server_default="live", index=True
    )
    processing_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="pending", index=True
    )
    processing_stage: Mapped[str | None] = mapped_column(String(20), nullable=True)
    processing_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    import_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("import_jobs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    enrichment_sources: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=False, server_default="'{}'::jsonb"
    )
    tlp: Mapped[str] = mapped_column(String(20), nullable=False, server_default="tlp:clear")
    embargo_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    raw_connector_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class SourceDocument(Base):
    """A primary-source text snippet attached to a CVE (M6).

    Anything destined for the RAG pipeline lands here: advisories, blog posts,
    PoC writeups, vendor security bulletins. ``storage_path`` points at the
    full byte payload in MinIO; the row carries indexing/metadata only. M8
    flips ``embedded=True`` once the chunks are in Qdrant.
    """

    __tablename__ = "source_documents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cve_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cves.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str | None] = mapped_column(String(30), nullable=True)
    quality_score: Mapped[Any] = mapped_column(Numeric(3, 2), nullable=True)
    tlp: Mapped[str] = mapped_column(String(20), nullable=False, server_default="tlp:clear")
    embargo_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    storage_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    byte_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    processed: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    embedded: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    document_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        "metadata", JSONB, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ImportJob(Base):
    """A historical-import batch (M6).

    Lifecycle: ``staging`` → ``approved`` (operator clicks approve) → ``processing``
    (workers draining) → ``complete`` (all CVEs reached complete/skipped/failed).
    Counts are bumped by the staging worker and the approval endpoints; the
    UI reads them straight off the row.
    """

    __tablename__ = "import_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="staging", index=True
    )
    filters: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    preview_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    staged_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    approved_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    processed_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    skipped_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    error_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ImportFilterPreset(Base):
    """Saved analyst filter preset for the historical Import Manager (M6).

    Six built-in presets ship via ``scripts/seed_filter_presets.py``
    (``is_builtin=True``); custom presets created via the API live alongside
    them. ``use_count`` is bumped from the API so the UI can sort by
    "popular".
    """

    __tablename__ = "import_filter_presets"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    filters: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    use_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class PromptTemplate(Base):
    """Runtime-managed prompt template (M9).

    Every prompt the engine sends to an LLM is sourced from one of these
    rows. New versions are *additions* — old rows are never mutated — so the
    full history is always reconstructible. ``is_active`` is the toggle the
    engine reads at runtime; a partial unique index in the migration
    guarantees at most one active row per ``(name, target_model,
    target_provider)``.

    ``target_model`` and ``target_provider`` accept the wildcard ``'*'`` so
    a single template can apply to any model/provider unless a more specific
    template exists (the resolver in ``fragchain.prompts.store`` walks the
    specificity hierarchy).
    """

    __tablename__ = "prompt_templates"
    __table_args__ = (
        UniqueConstraint(
            "name",
            "target_model",
            "target_provider",
            "version",
            name="uq_prompt_templates_name_model_provider_version",
        ),
        # Partial unique index: at most one active row per
        # (task_type, target_model, target_provider). Keyed on task_type
        # (not name) because the engine resolves prompts by task_type — a
        # cloned/renamed template must not create a second active row for the
        # same task. Re-keyed from `name` in migration 0021.
        Index(
            "uq_prompt_templates_active",
            "task_type",
            "target_model",
            "target_provider",
            unique=True,
            postgresql_where=text("is_active = true"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    task_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    target_model: Mapped[str] = mapped_column(
        String(100), nullable=False, server_default="*", index=True
    )
    target_provider: Mapped[str] = mapped_column(
        String(50), nullable=False, server_default="*"
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    system_prompt: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    user_template: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class PromptEvaluation(Base):
    """Benchmark run against a prompt template (M9).

    One row per ``(template, benchmark_set)`` evaluation. Scores live as
    decimals in ``[0, 1]`` (``technique_overlap`` / ``ordering_consistency``);
    ``hallucination_count`` is the raw count of fabricated TTPs.
    ``sample_outputs`` carries a handful of model outputs for inspection — the
    full prompt + response of every call lives in the linked
    ``llm_interactions`` rows.
    """

    __tablename__ = "prompt_evaluations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    prompt_template_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("prompt_templates.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    benchmark_set: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    technique_overlap: Mapped[Any] = mapped_column(Numeric(3, 2), nullable=True)
    ordering_consistency: Mapped[Any] = mapped_column(Numeric(3, 2), nullable=True)
    hallucination_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_per_run: Mapped[Any] = mapped_column(Numeric(8, 4), nullable=True)
    avg_latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sample_outputs: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(
        JSONB, nullable=True
    )
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    evaluated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class PromptABTest(Base):
    """A/B traffic-split between two prompt templates (M9).

    The router consults this row at request time. ``traffic_split`` is the
    probability of picking variant A (so 0.50 means 50/50). ``status``
    transitions ``active`` → ``paused`` (router falls back to the regular
    active prompt) → ``concluded`` (with a ``winner`` recorded).
    """

    __tablename__ = "prompt_ab_tests"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    task_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    variant_a_template_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("prompt_templates.id", ondelete="RESTRICT"),
        nullable=False,
    )
    variant_b_template_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("prompt_templates.id", ondelete="RESTRICT"),
        nullable=False,
    )
    traffic_split: Mapped[Any] = mapped_column(
        Numeric(3, 2), nullable=False, server_default="0.50"
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="active", index=True
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    concluded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    winner: Mapped[str | None] = mapped_column(String(1), nullable=True)


class CommonsChain(Base):
    """A chain imported from a commons source (M7).

    Stores the chain JSON verbatim plus enough indexing to answer
    `check_chain_exists(cve_id)` and run conflict resolution between sources.
    The full chain (with provenance) lives in `data`. When M10/M11 land they
    project this into `attack_chains` rows whenever a deployment elects to
    use a commons chain directly. Until then this is the only persisted form.
    """

    __tablename__ = "commons_chains"
    __table_args__ = (
        UniqueConstraint(
            "source_id", "cve_id", "version", name="uq_commons_chains_source_cve_ver"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("commons_sources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tlp: Mapped[str] = mapped_column(String(20), nullable=False, server_default="tlp:clear")
    data: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class CoverageMap(Base):
    """One row per ATT&CK technique, populated by M8 seed + mutated by M14.

    The ATT&CK Matrix screen reads straight off this table. M8 (this module)
    seeds every technique with ``coverage_status='no_data'`` so the UI has a
    full grid from day one. M14's coverage mapper later flips rows to
    ``covered`` / ``partial`` / ``gap`` and back-fills the array columns
    (``covering_rule_ids``, ``chain_cve_ids``) once chains and Sigma rules
    exist.

    ``description``, ``has_subtechniques`` and ``parent_technique_id`` are
    additions on top of the M14 spec — they let the matrix UI render rows
    without an extra join against the Qdrant ``attck_techniques``
    collection (which holds the same fields but isn't a relational store).
    """

    __tablename__ = "coverage_map"
    __table_args__ = (
        UniqueConstraint(
            "technique_id", "framework", name="uq_coverage_map_technique_framework"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    sub_technique_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    tactic_id: Mapped[str | None] = mapped_column(String(10), nullable=True, index=True)
    tactic_name: Mapped[str | None] = mapped_column(String(50), nullable=True)
    technique_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    framework: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="attck", index=True
    )
    coverage_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="no_data", index=True
    )
    covering_rule_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)),
        nullable=False,
        server_default=text("ARRAY[]::UUID[]"),
    )
    chain_cve_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)),
        nullable=False,
        server_default=text("ARRAY[]::UUID[]"),
    )
    chain_cve_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )
    kev_cve_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )
    kev_exposed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false", index=True
    )
    last_refreshed: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    has_subtechniques: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    parent_technique_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Migration 0016 — Phase A. Existing rows backfill to 'v0-baseline' via
    # server_default so the eventual benchmark runner can diff Phase A's
    # output against the legacy mapper's output without ambiguity.
    mapper_version: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        server_default="v0-baseline",
        index=True,
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class AttackChainRow(Base):
    """One attack chain for a CVE (M10).

    Stores the full chain JSON in ``chain`` (Pydantic round-trip) plus
    flattened metadata for relational queries. The flattened per-TTP rows
    live in ``chain_ttps``. The DB enforces ``UNIQUE(cve_id, version)`` so
    versioning is observable -- M11 bumps the version on a regeneration
    rather than mutating the row.

    ``status`` runs ``draft`` (LLM output, awaiting review) ->
    ``validated`` (analyst approved) -> ``rejected`` (analyst rejected).
    Hand-validated ground truth ingested via M11 import lands in
    ``validated`` directly.
    """

    __tablename__ = "attack_chains"
    __table_args__ = (
        UniqueConstraint("cve_id", "version", name="uq_attack_chains_cve_version"),
        # Partial unique index from migration 0017 — enforces the §12.1
        # invariant "one active chain per CVE" (active = ``superseded_at
        # IS NULL``). Declared here so the invariant is visible without
        # reading the migration and so autogenerate doesn't drop it.
        Index(
            "uq_attack_chains_active_per_cve",
            "cve_id",
            unique=True,
            postgresql_where=text("superseded_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cve_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cves.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(50), nullable=True)
    prompt_template_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("prompt_templates.id", ondelete="SET NULL"),
        nullable=True,
    )
    overall_confidence: Mapped[Any] = mapped_column(Numeric(3, 2), nullable=True)
    chain: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)
    sources_used: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default="'[]'::jsonb"
    )
    predicted_impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    detection_gaps: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default="'[]'::jsonb"
    )
    tlp: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="tlp:clear", index=True
    )
    embargo_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="draft", index=True
    )
    validated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    validated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_origin: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="local", index=True
    )
    commons_chain_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("coverage_assessment.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    superseded_by_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("coverage_assessment.id", ondelete="SET NULL"),
        nullable=True,
    )
    superseded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    behavioral_indicators: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)


class ChainTTPRow(Base):
    """One TTP step inside an ``AttackChainRow`` (M10).

    Flattened from the chain JSON so coverage queries can hit the
    ``technique_id`` index directly. ``source_refs`` stays JSONB because
    the per-TTP provenance list is variable-length and only ever read
    alongside the row.
    """

    __tablename__ = "chain_ttps"
    __table_args__ = (
        UniqueConstraint("chain_id", "seq_order", name="uq_chain_ttps_chain_seq"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    chain_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_chains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    seq_order: Mapped[int] = mapped_column(Integer, nullable=False)
    tactic: Mapped[str | None] = mapped_column(String(50), nullable=True)
    tactic_id: Mapped[str | None] = mapped_column(String(10), nullable=True, index=True)
    technique_id: Mapped[str | None] = mapped_column(
        String(20), nullable=True, index=True
    )
    technique_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    sub_technique_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    framework: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="attck", index=True
    )
    confidence: Mapped[Any] = mapped_column(Numeric(3, 2), nullable=True)
    preconditions: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default="'[]'::jsonb"
    )
    detection_opportunity: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_refs: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default="'[]'::jsonb"
    )
    behavioral_indicators: Mapped[list[Any] | None] = mapped_column(
        JSONB, nullable=True
    )


class SigmaSource(Base):
    """Configurable Sigma source repo — read existing rules into the library (M12).

    Operators can configure one or more git-hosted Sigma repos. The default
    deployment seeds the public SigmaHQ repo. ``last_pull_at`` / ``last_pull_status``
    / ``last_error`` mirror what the refresh task wrote on its most recent run.
    ``path_filter`` narrows the walk to a subdirectory inside the repo
    (e.g. ``rules`` for SigmaHQ).
    """

    __tablename__ = "sigma_sources"
    __table_args__ = (
        UniqueConstraint("name", name="uq_sigma_sources_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    git_url: Mapped[str] = mapped_column(Text, nullable=False)
    branch: Mapped[str] = mapped_column(String(100), nullable=False, server_default="main")
    auth_type: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="none"
    )
    auth_credentials_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    path_filter: Mapped[str | None] = mapped_column(String(255), nullable=True)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )
    last_pull_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_pull_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    last_pull_commit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    rules_imported: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class SigmaTarget(Base):
    """Configurable Sigma target — write approved rules back as PRs (M12).

    Multiple targets can coexist with different routing rules. The first
    routing rule whose condition matches a candidate rule wins; if no rule
    matches, the ``is_default`` target is selected. ``routing_rules`` is a
    JSON list of ``{if, target_name}`` clauses where ``if`` is a simple
    boolean expression over rule fields (see ``fragchain.sigma.targets``).
    """

    __tablename__ = "sigma_targets"
    __table_args__ = (
        UniqueConstraint("name", name="uq_sigma_targets_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    git_url: Mapped[str] = mapped_column(Text, nullable=False)
    branch: Mapped[str] = mapped_column(String(100), nullable=False, server_default="main")
    auth_type: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="token"
    )
    auth_credentials_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_default: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false", index=True
    )
    auto_pr: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )
    routing_rules: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )
    last_pr_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class SigmaRule(Base):
    """One Sigma rule — either imported from a source or generated locally (M12).

    ``origin`` distinguishes ``imported`` rows (parsed from a configured
    source repo by ``SigmaSourceClient``) from ``fragchain`` rows (drafts
    produced by the M15 rule generator).
    ``status`` runs ``generated`` → ``review`` → ``approved`` → ``merged``
    (for generated rules) and ``merged`` (for imported rules — they're
    already in the upstream repo). M16 owns the approval transitions; M12
    only writes the ``generated`` and ``merged`` end-states.
    """

    __tablename__ = "sigma_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    sigma_uuid: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), unique=True, nullable=True, index=True
    )
    chain_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_chains.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    cve_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cves.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    technique_ids: Mapped[list[str] | None] = mapped_column(
        ARRAY(String(20)), nullable=True
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    sigma_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="generated", index=True
    )
    origin: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="fragchain", index=True
    )
    source_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sigma_sources.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sigma_targets.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    source_rel_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    logsource_product: Mapped[str | None] = mapped_column(String(100), nullable=True)
    logsource_service: Mapped[str | None] = mapped_column(String(100), nullable=True)
    logsource_profile: Mapped[str | None] = mapped_column(String(50), nullable=True)
    detection_level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(String(255)), nullable=True)
    tlp: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="tlp:clear"
    )
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    merged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    git_pr_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    git_commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # Soft cross-store pointer to the existing rule this generated rule most
    # resembles. NOT a FK: the match comes from Qdrant and may reference an
    # external library rule or a point whose PG row was pruned — a hard FK
    # would reject the insert on that (benign) drift.
    similar_to_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    similarity_score: Mapped[float | None] = mapped_column(
        Numeric(4, 3), nullable=True
    )
    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    prompt_template_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("prompt_templates.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    deprecated_by_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sigma_rules.id", ondelete="SET NULL"),
        nullable=True,
    )
    deprecated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deprecated_by_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("coverage_assessment.id", ondelete="SET NULL"),
        nullable=True,
    )


class ReviewQueueItem(Base):
    """One pending-review row for a generated Sigma rule (M15 inserts, M16 lifecycle).

    The rule generator (:mod:`fragchain.rules.generator`) inserts one row per
    successfully-generated draft. M16 owns the lifecycle transitions
    (``pending`` → ``in_review`` → ``approved`` / ``rejected``) and the
    auto-PR step that fires on approve.

    ``priority_score`` is the integer carried over from M14's
    :class:`fragchain.coverage.CoverageStatus` so the queue can be
    ordered DESC without recomputing the formula. ``priority`` is the
    human-readable bucket the UI renders (critical / high / medium / low),
    derived from the score on insert.

    The partial unique index ``ux_review_queue_pending_rule`` (migration
    ``0013_review_queue``) guarantees at most one *pending* row per rule —
    re-running M15 on the same chain updates the priority of the existing
    row rather than duplicating it. Concluded rows (status='approved' or
    'rejected') stay around for the audit trail.
    """

    __tablename__ = "review_queue"
    __table_args__ = (
        # Partial unique index from migration 0013 — enforces "one pending
        # row per sigma rule" (M16's re-run-on-the-same-chain semantics);
        # multiple historical rows with status='approved' or 'rejected'
        # are allowed. Declared here so autogenerate doesn't drop it.
        Index(
            "ux_review_queue_pending_rule",
            "sigma_rule_id",
            unique=True,
            postgresql_where=text("status = 'pending'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    sigma_rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sigma_rules.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    priority: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="medium"
    )
    priority_score: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0", index=True
    )
    priority_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="pending", index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Migration 0016 — Phase A. ``status='superseded'`` reuses the existing
    # column; these two fields are populated only on supersede transitions.
    # The application layer requires a non-empty rationale when supersede
    # fires (mirrors ``coverage_benchmark.rationale``).
    supersede_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sigma_rules.id", ondelete="SET NULL"),
        nullable=True,
    )
    supersede_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("coverage_assessment.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    low_detectability_override: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    superseded_by_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("coverage_assessment.id", ondelete="SET NULL"),
        nullable=True,
    )


class LogsourceProfile(Base):
    """Per-platform rule generation profile (M13).

    A profile encodes how M15's rule generator should write detection
    logic for a specific environment: the Sigma ``logsource.product`` /
    ``logsource.service`` pair, the common field names used in that
    pipeline, and a handful of hand-curated example rules used as
    few-shot context in the LLM prompt.

    ``is_builtin=true`` rows are seeded by ``scripts/seed_profiles.py``
    and locked against PATCH by the API — operators can ``enable`` or
    ``disable`` them, but the body fields are owned by the engine.
    Operators creating their own profiles always get
    ``is_builtin=false``.
    """

    __tablename__ = "logsource_profiles"
    __table_args__ = (
        UniqueConstraint("name", name="uq_logsource_profiles_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(50), nullable=False)
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    platform: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    sigma_product: Mapped[str | None] = mapped_column(String(50), nullable=True)
    sigma_service: Mapped[str | None] = mapped_column(String(50), nullable=True)
    field_conventions: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    example_rules: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true", index=True
    )
    is_builtin: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false", index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class RuleEvaluation(Base):
    """Field-efficacy capture for a deployed Sigma rule (M17).

    After a rule lands in a target environment, analysts record TP /
    false-positive rates plus environment-shape metadata. Aggregated
    stats expose which rules actually work in practice; the analyst-
    optional ``contributed_to_commons`` flag tracks whether the
    evaluation was pushed back to a configured commons source via M7.

    The row is append-only — corrections land as a fresh row from the
    same evaluator. The :func:`fragchain.evaluations.store.aggregate`
    helper averages over all rows for a rule.
    """

    __tablename__ = "rule_evaluations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    sigma_rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sigma_rules.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evaluator_username: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    environment_platform: Mapped[str | None] = mapped_column(
        String(50), nullable=True
    )
    environment_logsource: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )
    environment_scale: Mapped[str | None] = mapped_column(
        String(50), nullable=True
    )
    true_positives: Mapped[int | None] = mapped_column(Integer, nullable=True)
    false_positives_per_day: Mapped[Any] = mapped_column(
        Numeric(6, 2), nullable=True
    )
    query_cost: Mapped[str | None] = mapped_column(String(20), nullable=True)
    deployment_complexity: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    contributed_to_commons: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )


class CoverageBenchmark(Base):
    """Hand-labeled ground truth for the coverage verify path (Phase A, M14+).

    One row per ``(cve, technique, rule)`` triple with a human verdict
    (``covered`` / ``partial`` / ``no_match``) and a mandatory rationale.
    Populated by ``scripts/label_coverage_benchmark.py`` and, from Day 5,
    by the analyst "Supersede with existing rule" action in the Review
    Queue (with ``source='supersede'`` and ``expected_verdict='covered'``).

    Read by the benchmark runner (``scripts/run_coverage_benchmark.py``)
    which scores the current mapper against the labeled set. Each run
    appends a row to :class:`CoverageBenchmarkRun` so prompt / threshold
    iteration is observable from a single SELECT.

    Commons-eligible at ``tlp:clear`` by default; contribution is the
    existing manual analyst action, not auto-push (see Phase A design
    note, §4).
    """

    __tablename__ = "coverage_benchmark"
    __table_args__ = (
        UniqueConstraint(
            "cve_id",
            "technique_id",
            "rule_id",
            name="uq_coverage_benchmark_cve_technique_rule",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cve_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cves.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sigma_rules.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    expected_verdict: Mapped[str] = mapped_column(String(20), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    labeled_by: Mapped[str] = mapped_column(String(255), nullable=False)
    labeled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    tlp: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="tlp:clear"
    )
    contributed_to_commons: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    # 'manual' (CLI / API) | 'supersede' (review-queue action) | 'commons'
    source: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="manual"
    )


class CoverageBenchmarkRun(Base):
    """One execution of the coverage benchmark against the labeled set.

    Confusion-matrix + P/R/F1 stored per run so two runs (``baseline``
    vs ``phase-a``) can be compared with a trivial JOIN. ``run_label`` is
    free-form by design — operators iterate prompts under labels like
    ``phase-a-v2``, ``phase-a-v3`` without ceremony.
    """

    __tablename__ = "coverage_benchmark_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    run_label: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    prompt_template_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("prompt_templates.id", ondelete="SET NULL"),
        nullable=True,
    )
    semantic_threshold: Mapped[Any] = mapped_column(Numeric(3, 2), nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    total_pairs: Mapped[int] = mapped_column(Integer, nullable=False)
    true_positives: Mapped[int] = mapped_column(Integer, nullable=False)
    false_positives: Mapped[int] = mapped_column(Integer, nullable=False)
    true_negatives: Mapped[int] = mapped_column(Integer, nullable=False)
    false_negatives: Mapped[int] = mapped_column(Integer, nullable=False)
    precision_score: Mapped[Any] = mapped_column(Numeric(5, 4), nullable=True)
    recall_score: Mapped[Any] = mapped_column(Numeric(5, 4), nullable=True)
    f1_score: Mapped[Any] = mapped_column(Numeric(5, 4), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class CoverageAssessment(Base):
    """One coverage assessment per CVE (assessment workflow, Plan A).

    Tracks the analyst's intent + the pasted sources + the loop outputs.
    State transitions are enforced by ``fragchain.assessments.state_machine``;
    the DB only stores the current state.
    """

    __tablename__ = "coverage_assessment"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    cve_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        # ondelete="CASCADE" matches the DB-level constraint created in
        # migration 0017; the ORM default (RESTRICT) would otherwise error on
        # CVE deletion from the mapped side even though the DB allows cascade.
        ForeignKey("cves.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    creator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )
    initial_trigger: Mapped[dict] = mapped_column(JSONB, nullable=False)
    context_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="created"
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    closed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    tlp: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="tlp:clear"
    )
    auto_advance: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AssessmentSource(Base):
    """Analyst-pasted source attached to an assessment.

    v1 only supports ``kind='free_text'``. URL and document uploads are
    deferred (spec §4.3). Soft-delete via ``deleted_at`` so audit history
    is preserved.
    """

    __tablename__ = "assessment_source"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("coverage_assessment.id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str | None] = mapped_column(String(200), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    tlp: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="tlp:clear"
    )
    embedding_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="pending"
    )
    embedding_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    injection_risk_score: Mapped[Any] = mapped_column(Numeric(3, 2), nullable=True)
    pasted_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )
    pasted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deleted_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    delete_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "assessment_id", "content_hash", name="uq_assessment_source_hash"
        ),
    )


class AssessmentLoopRun(Base):
    """Versioned per-loop execution row.

    Re-running Loop N creates a new row with ``version = max(version)+1``
    and ``is_active=true``. The prior active row for that
    ``(assessment_id, loop_number)`` is updated to
    ``is_active=false, status='superseded'`` by the orchestrator.
    """

    __tablename__ = "assessment_loop_run"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("coverage_assessment.id", ondelete="CASCADE"),
        nullable=False,
    )
    loop_number: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true")
    )
    output: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    gate_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    override_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    embedding_warned: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    prompt_template_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("prompt_templates.id"),
        nullable=True,
    )
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cost_usd: Mapped[Any] = mapped_column(Numeric(8, 4), nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        CheckConstraint(
            "loop_number IN (1, 2, 3)",
            name="ck_assessment_loop_run_loop_number",
        ),
        UniqueConstraint(
            "assessment_id",
            "loop_number",
            "version",
            name="uq_assessment_loop_run_version",
        ),
        # Partial UNIQUE index (migration 0026) — DB-enforces the docstring
        # invariant "one active row per (assessment_id, loop_number)" that
        # previously rested only on begin_run's app-level guard (a
        # concurrent double-dispatch could mint two active rows). Mirrors
        # the uq_generated_artifacts_active idiom: demote + flush BEFORE
        # activating the replacement row.
        Index(
            "uq_assessment_loop_run_active",
            "assessment_id",
            "loop_number",
            unique=True,
            postgresql_where=text("is_active"),
            # SQLite supports partial indexes too — without this, create_all
            # test DBs render a FULL unique index on (assessment_id,
            # loop_number) (the dialect ignores postgresql_where), which is
            # stricter than prod and breaks any test holding a demoted row
            # alongside the active one.
            sqlite_where=text("is_active"),
        ),
    )


class VulnClassToTTPRow(Base):
    """Curated mapping: a vuln class implies these TTPs in this order (Plan C)."""

    __tablename__ = "vuln_class_to_ttps"
    __table_args__ = (
        UniqueConstraint(
            "vuln_class", "technique_id",
            name="uq_vuln_class_to_ttps_class_tech",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    vuln_class: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)
    tactic_id: Mapped[str] = mapped_column(String(10), nullable=False)
    tactic: Mapped[str] = mapped_column(String(50), nullable=False)
    technique_name: Mapped[str] = mapped_column(String(200), nullable=False)
    seq_order: Mapped[int] = mapped_column(Integer, nullable=False)
    base_confidence: Mapped[Any] = mapped_column(
        Numeric(3, 2), nullable=False, server_default="0.50"
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class TTPCategoryRelevanceRow(Base):
    """Curated relevance: a TTP is best detected via these observable categories."""

    __tablename__ = "ttp_category_relevance"
    __table_args__ = (
        UniqueConstraint(
            "technique_id", "category",
            name="uq_ttp_category_relevance_tech_cat",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(20), nullable=False)
    weight: Mapped[Any] = mapped_column(
        Numeric(3, 2), nullable=False, server_default="1.00"
    )


class DetectabilityAssessmentRow(Base):
    """Phase 1 detectability classification for one Loop 2 run (ADR-0004).

    Advisory in Phase 1: consumed by the UI (and the Phase 2 artifact
    router later); never gates the assessment flow. One row per Loop 2
    run (UNIQUE on ``loop_run_id``); the "current" classification for an
    assessment is the row joined to the active Loop 2 run. ``payload``
    is the full ``DetectabilityAssessment`` schema round-trip; the class
    and confidence are flattened for relational queries.
    """

    __tablename__ = "detectability_assessments"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("coverage_assessment.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    loop_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessment_loop_run.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    detectability_class: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )
    confidence: Mapped[Any] = mapped_column(Numeric(4, 3), nullable=False)
    gate_passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    prompt_template_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("prompt_templates.id", ondelete="SET NULL"),
        nullable=True,
    )
    cost_usd: Mapped[Any] = mapped_column(Numeric(8, 4), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ArtifactPlanRow(Base):
    """Phase 2 artifact plan for one detectability classification (ADR-0004 §3).

    Compatibility mode: the plan records what the router WOULD generate or
    skip; Loop 3 behavior is unchanged. ``observed`` is filled after Loop 3
    runs (rules generated vs ``sigma_planned``) — the divergence evidence
    that decides when the router can flip to active gating. One plan per
    classification (UNIQUE on ``detectability_assessment_id``); the
    "current" plan is the row joined to the active Loop 2 run.
    """

    __tablename__ = "artifact_plans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("coverage_assessment.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    detectability_assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("detectability_assessments.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    loop_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessment_loop_run.id", ondelete="CASCADE"),
        nullable=False,
        # One plan per Loop 2 run (transitively true via the unique
        # detectability_assessment_id); unique gives the CASCADE FK an
        # index — the 0020 audit found unindexed CASCADE FKs seq-scan on
        # parent deletes.
        unique=True,
    )
    mode: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="compatibility"
    )
    sigma_planned: Mapped[bool] = mapped_column(Boolean, nullable=False)
    plan: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    policy_version: Mapped[str] = mapped_column(String(16), nullable=False)
    observed: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class GeneratedArtifactRow(Base):
    """Phase 2b non-Sigma generated artifact (ADR-0004 §4).

    One active row per ``(assessment_id, artifact_type)`` (partial unique
    index); regenerate deactivates the prior active row and inserts a new
    one with ``version = max(version)+1`` — the loop-run supersession idiom.
    ``content`` is the validated ``GeneratedArtifactContent`` round-trip,
    null until generation completes. ``validation_status`` is Phase 3
    territory: default-only here.
    """

    __tablename__ = "generated_artifacts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("coverage_assessment.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    artifact_plan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("artifact_plans.id", ondelete="SET NULL"),
        nullable=True,
    )
    artifact_type: Mapped[str] = mapped_column(String(32), nullable=False)
    version: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("1")
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true")
    )
    plan_recommended: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="generating"
    )
    validation_status: Mapped[str] = mapped_column(
        String(24), nullable=False, server_default="not_validated"
    )
    content: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    prompt_template_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("prompt_templates.id", ondelete="SET NULL"),
        nullable=True,
    )
    cost_usd: Mapped[Any] = mapped_column(Numeric(8, 4), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index(
            "uq_generated_artifacts_active",
            "assessment_id",
            "artifact_type",
            unique=True,
            postgresql_where=text("is_active"),
        ),
    )
