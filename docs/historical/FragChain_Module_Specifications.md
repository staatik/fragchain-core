> **Historical — preserved for context.** The original M1–M37 module specifications. The push-pipeline pieces here are now **dormant by design** ([`CLAUDE.md`](../../CLAUDE.md) §12.2); the active flow is documented in [`docs/architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md`](../architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md). What actually shipped vs. what's dormant is summarized in [`docs/historical/RECONCILIATION_2026-05-19.md`](RECONCILIATION_2026-05-19.md).

---

# FragChain — Module Specifications
**Status:** Definitive — replaces all prior sprint documents  
**Purpose:** Canonical specification of every module in FragChain v1 + deferred modules  
**Scope:** Use this document to derive build order, parallel work assignments, and Claude Code session prompts

---

## How To Read This Document

FragChain is built as **modules grouped into phases**. A module is a coherent unit of functionality with clear interfaces and dependencies. A phase is a delivery checkpoint where dependent modules become consumable.

**Module format:**
- **Status** — `in-scope-v1` (build now), `placeholder-v1` (schema only, no enforcement), `deferred-post-v1` (future)
- **Phase** — 1 through 8 for v1 modules
- **Effort** — S (1-3 days), M (4-7 days), L (8-14 days)
- **Dependencies** — modules that must exist before this one can be built
- **Schema** — DB tables/columns this module owns
- **API** — endpoints this module exposes
- **UI** — screens/components this module provides (or "backend only")
- **Interfaces** — what other modules consume from this one
- **Done** — specific completion criteria

---

## Phase Summary

| Phase | Theme | Modules | Outcome |
|-------|-------|---------|---------|
| 1 | Foundation | M1–M5 | Scaffold + protocols + auth |
| 2 | Data Ingestion | M6–M7 | Pipeline can receive CVEs |
| 3 | Vector + Prompts | M8–M9 | AI infrastructure ready |
| 4 | Synthesis | M10–M11 | Chains generated and validated |
| 5 | Coverage & Rules | M12–M17 | Detection rules generated and reviewed |
| 6 | Frontend | M18–M24 | All UI complete |
| 7 | Connectors | M25–M34 | Ecosystem of data sources (separate repos) |
| 8 | Polish | M35–M37 | Commons live, notifications, docs |

**Critical path through v1:** M1 → M4 → M6 → M5 → M8 → M11 → M14 → M15 → M16 → M21

**Parallel tracks possible:** Once M1 lands, M2/M3 can be built in parallel. Once M4/M5 land, M6/M7 are parallel. UI modules (M18+) can start as soon as their backend module is done.

---

## PHASE 1 — Foundation

---

### M1. Foundation
**Status:** in-scope-v1 | **Phase:** 1 | **Effort:** L

**Purpose**
Project scaffold, base infrastructure, and shared primitives. Every other module depends on this. Sets up the runtime environment, base schema, and the React frontend shell with DarkOps integrated.

**Dependencies**
None.

**Schema (base tables, others added by their modules)**
```
system_config           runtime-editable settings KV store
audit_log               cross-cutting audit trail
users (basic)           auth scaffolding (tier/clearance added by M2/M3)
```

**Docker Compose Services (Server 3)**
- nginx (port 80/443)
- fragchain-api
- fragchain-worker (Celery)
- fragchain-beat (scheduler)
- fragchain-ui
- postgres
- redis
- minio
- qdrant ← **NEW: moved into the stack**
- flower

External dependencies (NOT in this Compose):
- LiteLLM (mandatory, Server 1)
- Ollama (used by LiteLLM, external)

**API**
- `GET /api/v1/health` — service status (postgres, redis, minio, qdrant, litellm)
- `GET /api/v1/version`
- `POST /api/v1/auth/login` — JWT issue

**UI**
- App shell, routing for all 11 screens (login + 10 main screens, mostly empty)
- DarkOps CSS loaded from `frontend/src/styles/darkops.css`
- Topbar component with FRAGCHAIN logo and nav

**Interfaces Exposed**
- Base FastAPI app with router registration
- SQLAlchemy session factory
- Celery app for task registration
- Structured logging (structlog JSON)
- Pydantic settings from .env
- React router and base components

**Done Criteria**
- `docker compose up` starts cleanly, no errors
- `GET /api/v1/health` returns 200 with all services "ok"
- `alembic upgrade head` runs cleanly
- All screens load at https://localhost with DarkOps theme
- `npm run build` succeeds with no TS errors
- Default admin user can log in

---

### M2. TLP & Embargo
**Status:** in-scope-v1 | **Phase:** 1 | **Effort:** M

**Purpose**
Implements the TLP 2.0 classification system as the platform's core trust primitive. Adds TLP fields, propagation rules, enforcement middleware, and embargo handling. Other modules consume this to enforce data visibility.

**Dependencies**
M1.

**Schema**
```sql
-- TLP fields added to entities (other modules add their own tables with these)
-- This module owns:

CREATE TABLE tlp_access_grants (
    id UUID PRIMARY KEY,
    entity_type VARCHAR(50),
    entity_id UUID,
    granted_to_user_id UUID REFERENCES users(id),
    granted_to_deployment_id UUID,
    granted_by_user_id UUID,
    granted_at TIMESTAMP,
    expires_at TIMESTAMP,
    reason TEXT
);

CREATE TABLE embargo_participants (
    id UUID PRIMARY KEY,
    entity_type VARCHAR(50),
    entity_id UUID,
    user_id UUID REFERENCES users(id),
    granted_at TIMESTAMP DEFAULT NOW(),
    granted_by_user_id UUID
);
```

**Code**
- `fragchain/security/tlp.py` — TLP enum, propagation functions
- `fragchain/security/embargo.py` — embargo timer + auto-release
- `fragchain/api/middleware/tlp_filter.py` — response filter

**API**
- TLP enforcement is middleware, not its own endpoints
- `GET /api/v1/embargo/active` — list active embargoes (admin)
- `POST /api/v1/embargo/release/{entity_id}` — early release (maintainer)

**Celery Tasks**
- `release_embargoed_content` — every 5 minutes, auto-release expired embargoes

**UI**
- `TLPBadge` component (used by all entity displays)
- `EmbargoIndicator` component (countdown + lock icon)

**Interfaces Exposed**
- `TLP` enum and `max_tlp()` propagation function
- `can_user_access(user, entity_tlp, entity_id)` predicate
- TLP filter middleware (auto-applied)
- Embargo participant management API

**Done Criteria**
- TLP filter middleware rejects access to over-classified content
- Embargo timer correctly releases content at scheduled time
- `TLPBadge` renders all 5 levels with correct DarkOps styling
- Audit log entries created for TLP changes and embargo events

---

### M3. Identity Placeholder
**Status:** placeholder-v1 | **Phase:** 1 | **Effort:** S

**Purpose**
Schema and interface for future identity verification. Schema exists, endpoints exist but return 501. Provides the structure for later identity provider implementations without committing to a specific approach (GPG, SSH, Sigstore).

**Dependencies**
M1.

**Schema**
```sql
CREATE TABLE user_identities (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    identity_type VARCHAR(20),       -- 'gpg' | 'ssh' | 'sigstore' (none used in v1)
    public_key TEXT,
    fingerprint VARCHAR(128),
    verified_at TIMESTAMP,
    verification_challenge TEXT,
    verification_signature TEXT,
    revoked_at TIMESTAMP,
    revocation_reason TEXT
);

CREATE TABLE trust_attestations (
    id UUID PRIMARY KEY,
    attestor_user_id UUID REFERENCES users(id),
    subject_user_id UUID REFERENCES users(id),
    attestation_type VARCHAR(50),
    attestation_text TEXT,
    signed_attestation TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    revoked_at TIMESTAMP
);

CREATE TABLE contribution_signatures (
    id UUID PRIMARY KEY,
    entity_type VARCHAR(50),
    entity_id UUID,
    signer_user_id UUID REFERENCES users(id),
    signer_fingerprint VARCHAR(128),
    content_hash VARCHAR(64),
    signature TEXT,
    signed_at TIMESTAMP DEFAULT NOW(),
    verified BOOLEAN DEFAULT FALSE
);

-- Add to users table:
ALTER TABLE users ADD COLUMN tier VARCHAR(20) DEFAULT 'authenticated';
ALTER TABLE users ADD COLUMN clearance_level VARCHAR(20) DEFAULT 'tlp:green';
```

**Code**
- `fragchain/identity/base.py` — `IdentityProvider` Protocol (interface only)
- `fragchain/identity/registry.py` — empty dict `identity_providers = {}`

**API**
- `GET /api/v1/identity` — current user identity status (returns tier + clearance)
- All other `/api/v1/identity/*` endpoints — return `501 Not Implemented` with message: "Identity module deferred to post-v1"

**UI**
- Identity screen exists but shows placeholder message: "Identity verification module deferred to future release. All users currently authenticated tier with tlp:green clearance."

**Interfaces Exposed**
- `IdentityProvider` Protocol (interface only, no implementations in v1)
- `identity_providers` registry (empty, populated in post-v1)

**Done Criteria**
- All identity-related tables exist in schema
- IdentityProvider Protocol defined
- 501 endpoints return correct error message
- Identity screen renders placeholder text in DarkOps style

---

### M4. Connector Framework
**Status:** in-scope-v1 | **Phase:** 1 | **Effort:** M

**Purpose**
Plugin discovery, the IntelConnector protocol, and the enrichment orchestrator. fragchain-core has NO hardcoded data sources — all data ingestion happens through plugins discovered at startup. This module is the framework; specific connectors live in their own repos (M25-M34).

**Dependencies**
M1, M2.

**Schema**
```sql
CREATE TABLE connector_state (
    name VARCHAR(50) PRIMARY KEY,
    version VARCHAR(20),
    type VARCHAR(20),                -- source_stream | enrichment | hybrid
    enabled BOOLEAN DEFAULT TRUE,
    config JSONB,
    max_output_tlp VARCHAR(20),
    default_output_tlp VARCHAR(20) DEFAULT 'tlp:clear',
    last_health_check TIMESTAMP,
    health_status VARCHAR(20),
    error_count INTEGER DEFAULT 0,
    last_error TEXT,
    rate_limit_config JSONB
);
```

**Code**
- `fragchain/connectors/base.py` — `IntelConnector` Protocol
- `fragchain/connectors/discovery.py` — `importlib.metadata` entry-point loading
- `fragchain/connectors/orchestrator.py` — parallel enrichment with isolation
- `fragchain/connectors/registry_client.py` — fetches fragchain-registry index

**API**
- `GET /api/v1/connectors` — list installed
- `GET /api/v1/connectors/{name}` — detail + config
- `PATCH /api/v1/connectors/{name}` — update config
- `POST /api/v1/connectors/{name}/enable|disable|health`
- `GET /api/v1/connectors/registry` — browse fragchain-registry (available connectors not yet installed)

**UI**
- Connectors marketplace page (M24 builds the full UI; this module exposes the API)

**Interfaces Exposed**
- `IntelConnector` Protocol — implemented by external connector packages
- `discover_connectors()` — called on app startup
- `ConnectorOrchestrator.enrich_cve(cve_id)` — runs all enrichment connectors in parallel with per-connector isolation
- `ConnectorOrchestrator.stream_new_cves()` — runs source connectors

**Done Criteria**
- Installing a test connector package via pip → it auto-registers at next restart
- Three failures of one connector → marked unhealthy, surfaces in UI
- One connector's exception never blocks parallel connectors' enrichment
- Connector config can be edited in DB and reflected on restart

---

### M5. LLM Provider Framework
**Status:** in-scope-v1 | **Phase:** 1 | **Effort:** M

**Purpose**
Pluggable LLM access layer mirroring the connector pattern. The LLMProvider protocol abstracts whether the operator uses LiteLLM (v1 default and only implementation) or direct providers (OpenAI, Anthropic, Ollama) added post-v1. Handles interaction logging and MinIO I/O storage for every LLM call.

**Dependencies**
M1.

**Schema**
```sql
CREATE TABLE llm_interactions (
    id UUID PRIMARY KEY,
    entity_type VARCHAR(50),
    entity_id UUID,
    interaction_type VARCHAR(50),    -- 'chain_generation' | 'rule_generation' | 'coverage_verify' | 'embedding'
    provider VARCHAR(50),            -- 'litellm' (v1) | 'openai' | 'anthropic' | 'ollama' (post-v1)
    model VARCHAR(100),
    prompt_template_id UUID,         -- references prompt_templates from M9 if applicable
    prompt_version INTEGER,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    total_cost_usd DECIMAL(10,6),
    latency_ms INTEGER,
    success BOOLEAN,
    error_message TEXT,
    storage_path VARCHAR(500),       -- MinIO path for full I/O
    created_at TIMESTAMP DEFAULT NOW()
);
```

**Code**
- `fragchain/llm/base.py` — `LLMProvider` Protocol
- `fragchain/llm/litellm_provider.py` — LiteLLM implementation (uses `openai.AsyncOpenAI` pointed at LITELLM_BASE_URL)
- `fragchain/llm/registry.py` — provider registration (only `litellm` in v1)

**API**
- `GET /api/v1/llm/providers` — list installed providers
- `GET /api/v1/llm/providers/{name}/health` — provider health check
- `GET /api/v1/llm/interactions` — list recent interactions (admin)
- `GET /api/v1/llm/interactions/{id}` — single interaction with link to MinIO I/O

**UI**
- Settings → AI Providers (M24 builds; this exposes API)

**Interfaces Exposed**
- `LLMProvider.complete(system, prompt, model, **kwargs) → LLMResponse`
- `LLMProvider.embed(texts, model) → list[list[float]]`
- Automatic interaction logging on every call
- Automatic MinIO storage at `llm-io/{date}/{interaction_id}.json`

**Done Criteria**
- `LLMProvider` Protocol defined with chat + embedding methods
- LiteLLM provider successfully returns completions and embeddings from Server 1
- Every LLM call creates `llm_interactions` record + MinIO file
- Retry logic handles 429/500 errors with exponential backoff
- Health check verifies LiteLLM reachability

---

## PHASE 2 — Data Ingestion

---

### M6. Intel Ingestion
**Status:** in-scope-v1 | **Phase:** 2 | **Effort:** L

**Purpose**
Receives CVE data from connectors (webhook + polling), manages the CVE processing state machine, implements live + historical import modes with rate limiting and budget enforcement. Includes novelty filters (EPSS, AttackerKB, commons exclusion) and saved filter presets for analyst workflows. Does not implement any specific connector — consumes the framework from M4.

**Dependencies**
M1, M2, M4, M5, **M7 (build M7 first)** — `not_in_commons` filter requires M7's CommonsClient.

**Schema**
```sql
CREATE TABLE cves (
    id UUID PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    provisional_id VARCHAR(20),
    published_at TIMESTAMP,
    modified_at TIMESTAMP,
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(100),
    cisa_kev BOOLEAN DEFAULT FALSE,
    cisa_kev_date DATE,
    epss_score DECIMAL(6,5),
    epss_percentile DECIMAL(6,5),
    epss_fetched_at TIMESTAMP,
    ctid_techniques JSONB DEFAULT '[]',
    attackerkb_score DECIMAL(3,2),
    attackerkb_data JSONB,
    affected_products JSONB,
    import_mode VARCHAR(10) DEFAULT 'live',
    processing_status VARCHAR(20) DEFAULT 'pending',
    processing_stage VARCHAR(20),
    processing_error TEXT,
    approved_by VARCHAR(255),
    approved_at TIMESTAMP,
    enrichment_sources JSONB DEFAULT '{}',
    tlp VARCHAR(20) DEFAULT 'tlp:clear',
    embargo_until TIMESTAMP,
    raw_connector_data JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE source_documents (
    id UUID PRIMARY KEY,
    cve_id UUID REFERENCES cves(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    source_type VARCHAR(30),
    quality_score DECIMAL(3,2),
    tlp VARCHAR(20) DEFAULT 'tlp:clear',
    embargo_until TIMESTAMP,
    content_hash VARCHAR(64),
    storage_path VARCHAR(500),
    byte_size INTEGER,
    processed BOOLEAN DEFAULT FALSE,
    embedded BOOLEAN DEFAULT FALSE,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE import_jobs (
    id UUID PRIMARY KEY,
    created_by VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    status VARCHAR(20) DEFAULT 'staging',
    filters JSONB NOT NULL,
    preview_count INTEGER DEFAULT 0,
    staged_count INTEGER DEFAULT 0,
    approved_count INTEGER DEFAULT 0,
    processed_count INTEGER DEFAULT 0,
    skipped_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    completed_at TIMESTAMP
);

CREATE TABLE import_filter_presets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    filters JSONB NOT NULL,
    created_by VARCHAR(255),
    is_builtin BOOLEAN DEFAULT FALSE,  -- system-seeded presets cannot be edited
    use_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

**ImportFilters Pydantic Model**
```python
class ImportFilters(BaseModel):
    # Basic filters (applied at source connector level — fast)
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    cvss_min: Optional[float] = None
    kev_only: bool = False
    vendor: Optional[str] = None
    product: Optional[str] = None
    cve_ids: Optional[list[str]] = None  # overrides all other filters

    # Novelty filters (applied during preview + staging)
    published_within_days: Optional[int] = None  # sugar for date_from = now - N days
    epss_min: Optional[float] = None             # 0.0-1.0 exploitation probability
    attackerkb_min: Optional[float] = None       # community exploitability score
    not_in_commons: bool = False                 # exclude CVEs already in commons
```

**Pre-seeded Filter Presets** (via `scripts/seed_filter_presets.py`, all is_builtin=true)
- "Last 30 days KEV" — `{kev_only: true, published_within_days: 30}`
- "Critical Novel" — `{cvss_min: 9.0, epss_min: 0.2, not_in_commons: true}`
- "Linux Kernel — Last Quarter" — `{vendor: "linux", published_within_days: 90}`
- "High EPSS Without Coverage" — `{epss_min: 0.5, not_in_commons: true}`
- "Pre-patch Potential" — `{published_within_days: 7, kev_only: true, attackerkb_min: 3.0}`
- "May 2026" — `{date_from: "2026-05-01", date_to: "2026-05-31"}` (example monthly preset)

**Processing State Machine**
```
Live CVE:        pending → enriching → synthesizing → mapping → generating → complete
Historical:      staged → (approve) → pending → enriching → ... → complete
                       → (skip) → skipped
Any stage error: → failed (with processing_stage + processing_error)
```

**Celery Tasks**
- `ingest_cve(cve_id, import_mode='live')`
- `stage_historical_cves(job_id, filters)`
- `enrich_cve(cve_id)` — calls ConnectorOrchestrator
- `enforce_budget()` — every 5 min, respects rate limits
- `poll_connectors()` — scheduled, calls source connectors' stream_new()

**API**
- `GET /api/v1/cves` — list with filters
- `GET /api/v1/cves/{cve_id}` — detail
- `POST /api/v1/cves/{cve_id}/reprocess`
- `POST /api/v1/webhooks/connector/{name}` — generic connector webhook receiver
- `POST /api/v1/imports/preview` — preview filter results
  - Returns `{total_count, approximate: bool, sample[10], estimated_llm_cost_usd}`
  - `approximate=true` when novelty filters are active (count is approximate since
    novelty filtering happens during staging)
  - Sample IS accurately filtered with all filters (only 10 CVEs)
- `POST /api/v1/imports/start` — start staging job
- `GET /api/v1/imports` — list jobs
- `GET /api/v1/imports/{id}` — job detail
- `GET /api/v1/imports/{id}/staged` — staged CVEs
- `POST /api/v1/imports/{id}/approve` — selective approve
- `POST /api/v1/imports/{id}/approve-kev` — KEV-only approve
- `POST /api/v1/imports/{id}/approve-all` — bulk approve
- `POST /api/v1/imports/{id}/skip` — skip CVEs
- `GET /api/v1/imports/presets` — list saved filter presets
- `POST /api/v1/imports/presets` — create custom preset
- `PATCH /api/v1/imports/presets/{id}` — update (only is_builtin=false)
- `DELETE /api/v1/imports/presets/{id}` — delete (only is_builtin=false)
- `POST /api/v1/imports/presets/{id}/use` — increment use_count (for "popular" sorting)

**UI**
- CVE Explorer screen (M20 builds the full UI; this exposes API)
- Import Manager screen (M23 builds; this exposes API)

**Interfaces Exposed**
- CVE record lifecycle (state transitions, audit logged)
- Source document storage to MinIO
- WebSocket events: `cve_ingested`, `enrichment_complete`, `rate_limit_warning`, `budget_status`

**Done Criteria**
- Webhook POST with valid token → CVE lands in `pending` state, queue task fires
- Webhook POST with invalid token → 403
- Historical import: preview → start → staged → approve → pipeline runs
- AUTO_PROCESS_KEV=true bypasses staging for KEV CVEs
- Rate limit respected: excess live CVEs queue, never drop
- Daily budget respected: approved historical CVEs drain at configured rate
- Seed script populates CVE-2026-43284 for development
- Novelty filters work:
  - `published_within_days=30` filters correctly via computed date_from
  - `epss_min=0.5` excludes low-EPSS CVEs from staging
  - `attackerkb_min=3.0` excludes low-exploitability CVEs from staging
  - `not_in_commons=true` excludes CVEs that M7 commons already has
- Preview returns `approximate=true` when novelty filters active
- Sample in preview (10 CVEs) is accurately filtered with ALL filters
- 6 built-in presets seeded via `scripts/seed_filter_presets.py`
- Custom preset CRUD works (cannot mutate is_builtin=true presets)
- Preset use_count increments on "Use Preset" action

---

### M7. Commons Sources
**Status:** in-scope-v1 | **Phase:** 2 | **Effort:** M

**Purpose**
Configurable multi-source intelligence commons. Operators can configure one or more git-hosted commons repositories (default: public fragchain-intelligence, optional: private/internal repos). Implements bootstrap, hourly sync, and contribution workflows.

**Dependencies**
M1, M2.

**Schema**
```sql
CREATE TABLE commons_sources (
    id UUID PRIMARY KEY,
    name VARCHAR(100),
    url TEXT,                           -- git URL (github/gitlab/gitea)
    auth_type VARCHAR(20),              -- 'none' | 'token' | 'ssh'
    auth_credentials_ref VARCHAR(255),  -- secret reference, not the secret
    sync_enabled BOOLEAN DEFAULT TRUE,
    contribute_enabled BOOLEAN DEFAULT FALSE,
    priority INTEGER DEFAULT 0,         -- higher = wins in conflicts
    trust_level VARCHAR(20),            -- 'community' | 'partner' | 'internal'
    last_sync_at TIMESTAMP,
    last_release_version VARCHAR(20),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Pre-seeded with: public fragchain-intelligence repo
INSERT INTO commons_sources (name, url, trust_level)
VALUES ('Public Commons', 'https://github.com/fragchain/fragchain-intelligence', 'community');
```

**Code**
- `fragchain/commons/bootstrap.py`
- `fragchain/commons/sync.py`
- `fragchain/commons/contribute.py`

**API**
- `GET /api/v1/commons/sources` — list configured sources
- `POST /api/v1/commons/sources` — add new source
- `PATCH /api/v1/commons/sources/{id}` — update
- `DELETE /api/v1/commons/sources/{id}` — remove
- `POST /api/v1/commons/sources/{id}/sync` — manual sync trigger
- `POST /api/v1/commons/sources/{id}/test` — verify connectivity
- `GET /api/v1/commons/status` — overall sync state
- `POST /api/v1/chains/{id}/contribute` — submit chain to commons (later in M11)

**Celery Tasks**
- `sync_commons_source(source_id)` — hourly per enabled source
- `bootstrap_commons()` — runs on first startup

**UI**
- Settings → Commons Sources (M24 builds)

**Interfaces Exposed**
- `CommonsClient.check_chain_exists(cve_id) → AttackChain | None` — used by M11 to skip LLM synthesis
- `CommonsClient.contribute_chain(chain)` — creates GitHub/GitLab PR
- `CommonsClient.sync_all()` — pulls deltas from all enabled sources
- Conflict resolution: when multiple sources have a chain for the same CVE, higher `priority` wins; ties broken by `trust_level` (internal > partner > community)

**Done Criteria**
- Bootstrap from default public commons completes on first run
- Adding internal/private source via API works with token auth
- Hourly sync runs without errors, updates last_sync_at
- Contribution PR creates correctly via GitHub API
- Conflict resolution between sources behaves as specified

---

## PHASE 3 — Vector + Prompt Management

---

### M8. Vector Store
**Status:** in-scope-v1 | **Phase:** 3 | **Effort:** M

**Purpose**
Qdrant collections (now local in Server 3's Compose, no prefix workaround needed), embedding pipeline via LiteLLM, RAG retrieval. Used by chain synthesis (M11) and coverage mapping (M14).

**Dependencies**
M1, M5.

**Code**
- `fragchain/vector/collections.py` — collection lifecycle
- `fragchain/vector/embedder.py` — chunk + embed + upsert pipeline

**Qdrant Collections** (created on app startup)
- `source_chunks` — 768 dims, Cosine
  - Payload: cve_id, source_document_id, chunk_index, quality_score, source_type, url, tlp
- `sigma_rules` — 768 dims, Cosine
  - Payload: rule_id, sigma_uuid, technique_ids, status, logsource_product, logsource_service, origin, title
- `attack_chains` — 768 dims, Cosine
  - Payload: chain_id, cve_id, overall_confidence, technique_ids
- `attck_techniques` — 768 dims, Cosine
  - Payload: technique_id, tactic_id, tactic_name, technique_name, framework, has_subtechniques, parent_technique_id

**Celery Tasks**
- `embed_source_document(source_doc_id)` — chunks + embeds + upserts
- `embed_sigma_rule(rule_id)` — embeds rule for coverage mapping

**Setup Tasks**
- `scripts/seed_attck_techniques.py` — downloads ATT&CK STIX bundle, embeds all techniques

**API (admin/debug)**
- `GET /api/v1/vector/collections` — list collection stats
- `POST /api/v1/vector/embed/{source_doc_id}` — manual re-embed trigger
- `POST /api/v1/vector/search` — debug search interface (admin only)

**UI**
None (backend only).

**Interfaces Exposed**
- `VectorEmbedder.embed_source_document(id) → chunk count`
- `VectorEmbedder.embed_sigma_rule(id) → bool`
- `VectorEmbedder.search_source_chunks(query, cve_id, limit) → list[ChunkResult]`
- `VectorEmbedder.search_sigma_rules(technique_description, limit) → list[SigmaSearchResult]`
- `VectorEmbedder.search_attck_techniques(query, limit) → list[TechniqueResult]`

**Done Criteria**
- Qdrant container runs in Server 3 Compose
- All 4 collections created with correct schema on first startup
- ATT&CK seed populates `attck_techniques` collection (400+ techniques)
- Source document embedding pipeline completes for CVE-2026-43284
- Search returns relevant chunks scored by similarity

---

### M9. Prompt Management
**Status:** in-scope-v1 | **Phase:** 3 | **Effort:** L

**Purpose**
Runtime-managed prompt templates with version history, A/B testing, and evaluation framework. Different LLM models need different prompts (Claude vs GPT vs local models). Operators can iterate on prompts via UI without code changes. Eval framework lets operators benchmark prompt versions against ground-truth fixtures.

**Dependencies**
M1, M5.

**Schema**
```sql
CREATE TABLE prompt_templates (
    id UUID PRIMARY KEY,
    name VARCHAR(100),                  -- 'chain_generation' | 'rule_generation' | 'coverage_verify'
    task_type VARCHAR(50),              -- categorisation
    target_model VARCHAR(100),          -- specific model alias or '*' for any
    target_provider VARCHAR(50),        -- 'litellm' (v1) | '*'
    version INTEGER,
    system_prompt TEXT,
    user_template TEXT,                 -- with {placeholders}
    is_active BOOLEAN DEFAULT FALSE,    -- only one active per (task_type, target_model)
    created_by VARCHAR(255),
    created_at TIMESTAMP,
    notes TEXT,
    UNIQUE (name, target_model, version)
);

CREATE TABLE prompt_evaluations (
    id UUID PRIMARY KEY,
    prompt_template_id UUID REFERENCES prompt_templates(id),
    benchmark_set VARCHAR(100),         -- 'dirty_frag_groundtruth' | 'kev_chains_2025'
    technique_overlap DECIMAL(3,2),
    ordering_consistency DECIMAL(3,2),
    hallucination_count INTEGER,
    cost_per_run DECIMAL(8,4),
    avg_latency_ms INTEGER,
    sample_outputs JSONB,               -- a few example outputs for inspection
    evaluated_at TIMESTAMP,
    evaluated_by VARCHAR(255)
);

CREATE TABLE prompt_ab_tests (
    id UUID PRIMARY KEY,
    name VARCHAR(100),
    task_type VARCHAR(50),
    variant_a_template_id UUID REFERENCES prompt_templates(id),
    variant_b_template_id UUID REFERENCES prompt_templates(id),
    traffic_split DECIMAL(3,2) DEFAULT 0.50,  -- A vs B
    status VARCHAR(20) DEFAULT 'active',       -- active | paused | concluded
    started_at TIMESTAMP,
    concluded_at TIMESTAMP,
    winner VARCHAR(1)                          -- 'A' | 'B' | null
);
```

**Code**
- `fragchain/prompts/store.py` — load active prompt for (task, model, provider)
- `fragchain/prompts/eval.py` — run prompt against ground truth set
- `fragchain/prompts/ab.py` — A/B test routing

**API**
- `GET /api/v1/prompts` — list templates (filter: task_type, target_model)
- `GET /api/v1/prompts/{id}` — detail with eval history
- `POST /api/v1/prompts` — create new version
- `PATCH /api/v1/prompts/{id}` — update (creates new version, doesn't mutate)
- `POST /api/v1/prompts/{id}/activate` — make this version active
- `GET /api/v1/prompts/{id}/diff/{other_id}` — diff between versions
- `POST /api/v1/prompts/{id}/eval` — run evaluation against benchmark set
- `GET /api/v1/prompts/benchmarks` — list available benchmark sets
- `POST /api/v1/prompts/ab` — start A/B test
- `GET /api/v1/prompts/ab` — list active tests
- `POST /api/v1/prompts/ab/{id}/conclude` — pick winner

**UI**
- Prompts screen (M24 builds; this exposes API)

**Interfaces Exposed**
- `PromptStore.get_active(task_type, model, provider) → PromptTemplate`
- `PromptEvaluator.run(template_id, benchmark_set) → PromptEvaluation`
- `ABTestRouter.select_variant(task_type, model) → PromptTemplate`

**Done Criteria**
- Initial prompt for chain generation seeded as v1
- Evaluation against `dirty_frag_groundtruth` returns expected scores
- New prompt version creation works via API
- Active toggle functions correctly (only one active per task+model)
- Diff view between versions works
- A/B routing splits traffic correctly when test is active

---

## PHASE 4 — Synthesis

---

### M10. Chain Schema & Ground Truth
**Status:** in-scope-v1 | **Phase:** 4 | **Effort:** S

**Purpose**
The core contract for the platform: Pydantic models defining what an attack chain looks like. Includes ground truth fixtures used for prompt regression testing.

**Dependencies**
M1.

**Code**
- `fragchain/chain/schema.py`
  - `SourceRef`, `ChainTTP`, `AttackChain` Pydantic models
  - Validators: technique_id regex, seq_order sequential, source_refs non-empty
- `chains/CVE-2026-43284.json` — hand-validated Dirty Frag ground truth
- Additional fixtures for regression: 5-10 more well-known CVEs

**Schema**
```sql
CREATE TABLE attack_chains (
    id UUID PRIMARY KEY,
    cve_id UUID REFERENCES cves(id) ON DELETE CASCADE,
    version INTEGER DEFAULT 1,
    model VARCHAR(100),
    provider VARCHAR(50),
    prompt_template_id UUID REFERENCES prompt_templates(id),
    overall_confidence DECIMAL(3,2),
    chain JSONB NOT NULL,
    sources_used JSONB,
    predicted_impact TEXT,
    detection_gaps JSONB,
    tlp VARCHAR(20) DEFAULT 'tlp:clear',
    embargo_until TIMESTAMP,
    status VARCHAR(20) DEFAULT 'draft',
    validated_by VARCHAR(255),
    validated_at TIMESTAMP,
    rejection_reason TEXT,
    source_origin VARCHAR(20) DEFAULT 'local',  -- 'local' | 'commons'
    commons_chain_id VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE chain_ttps (
    id UUID PRIMARY KEY,
    chain_id UUID REFERENCES attack_chains(id) ON DELETE CASCADE,
    seq_order INTEGER,
    tactic VARCHAR(50),
    tactic_id VARCHAR(10),
    technique_id VARCHAR(20),
    technique_name VARCHAR(200),
    sub_technique_id VARCHAR(20),
    framework VARCHAR(20) DEFAULT 'attck',
    confidence DECIMAL(3,2),
    preconditions JSONB,
    detection_opportunity TEXT,
    source_refs JSONB NOT NULL DEFAULT '[]'
);
```

**Note on `prompt_template_id` (Pydantic model):** Optional[UUID] — required
when `provider != 'human'` (i.e. any LLM-generated chain), nullable for
hand-validated ground-truth fixtures where there is no originating prompt.
The DB column matches: nullable FK to `prompt_templates(id)` with
`ON DELETE SET NULL` (M10 migration `0010_attack_chains`).

**API**
None (consumed by M11, M14).

**UI**
None.

**Interfaces Exposed**
- `AttackChain`, `ChainTTP`, `SourceRef` Pydantic models — used by every chain-producing module

**Done Criteria**
- Schema validates correctly against ground truth fixtures
- Storage to attack_chains + chain_ttps tables works
- Ground truth fixtures pass schema validation

---

### M11. Chain Synthesis
**Status:** in-scope-v1 | **Phase:** 4 | **Effort:** L

**Purpose**
Generates ATT&CK attack chains from CVE data. First checks commons sources for an existing chain (skip LLM if found). If not in commons, builds RAG-augmented prompt and calls LLM via M5. Validates output against M10 schema. Stores result + offers contribution to commons.

**Dependencies**
M5, M7, M8, M9, M10.

**Code**
- `fragchain/chain/generator.py` — `ChainGenerator.generate(cve_id)`

**Pipeline**
```
1. Check commons sources (M7) for existing chain → if found, use directly
2. Load CVE + ATT&CK patterns from CTID enrichment + structured data
3. RAG: VectorEmbedder.search_source_chunks(cve_id, limit=20)
4. Budget by token count (sort by quality_score, fill ~55k tokens)
5. Load active prompt template (M9): get_active('chain_generation', model, provider)
6. Build prompt with structured + document context blocks
7. Call LLM via M5: llm_provider.complete(system, prompt, model)
8. Parse JSON response (strip fences if present)
9. Validate against AttackChain schema (M10)
10. On validation failure: retry with error feedback (max 2)
11. Apply TLP propagation: chain.tlp = max(explicit, max(source.tlp))
12. Store to attack_chains + chain_ttps
13. Queue map_coverage.delay(chain_id) (handed off to M14)
```

**Celery Tasks**
- `synthesize_chain(cve_id)`

**API**
- `GET /api/v1/chains` — list with filters
- `GET /api/v1/chains/{id}` — detail with TTP nodes
- `PATCH /api/v1/chains/{id}/validate` — mark validated
- `PATCH /api/v1/chains/{id}/reject` — reject with reason
- `POST /api/v1/chains/{id}/contribute` — submit to commons (via M7)
- `POST /api/v1/cves/{cve_id}/resynthesize` — force regenerate

**UI**
- Chain Viewer screen (M20 builds; this exposes API)

**Interfaces Exposed**
- WebSocket events: `chain_generated {cve_id, chain_id, confidence, source_origin}`
- WebSocket events: `chain_skipped_using_commons {cve_id, commons_source}`

**Done Criteria**
- CVE-2026-43284 generates a chain with ≥80% technique overlap vs ground truth
- A fresh CVE (not in commons) generates a chain successfully
- A CVE that exists in commons skips LLM entirely
- All chain TTPs have non-empty source_refs
- TLP propagation works correctly (chain inherits max source TLP)
- LLM interaction logged + MinIO I/O stored
- Contribution to commons creates correct PR

---

## PHASE 5 — Coverage & Rules

---

### M12. Sigma Integration
**Status:** in-scope-v1 | **Phase:** 5 | **Effort:** M

**Purpose**
Configurable multi-target Sigma repo support. Both for reading existing rules (used by Coverage Mapper M14) and for writing approved rules back. Operators configure one or more Sigma repos — own internal, SigmaHQ fork, public community, etc. Routing rules determine where approved rules go.

**Dependencies**
M1.

**Schema**
```sql
CREATE TABLE sigma_sources (
    id UUID PRIMARY KEY,
    name VARCHAR(100),
    git_url TEXT,
    branch VARCHAR(100) DEFAULT 'main',
    auth_type VARCHAR(20),
    auth_credentials_ref VARCHAR(255),
    path_filter VARCHAR(255),        -- subdirectory within repo
    last_pull_at TIMESTAMP,
    enabled BOOLEAN DEFAULT TRUE
);

CREATE TABLE sigma_targets (
    id UUID PRIMARY KEY,
    name VARCHAR(100),
    git_url TEXT,
    branch VARCHAR(100) DEFAULT 'main',
    auth_type VARCHAR(20),
    auth_credentials_ref VARCHAR(255),
    target_path VARCHAR(255),
    is_default BOOLEAN DEFAULT FALSE,
    auto_pr BOOLEAN DEFAULT TRUE,
    routing_rules JSONB,             -- conditions: tlp, level, technique, etc.
    enabled BOOLEAN DEFAULT TRUE
);

CREATE TABLE sigma_rules (
    id UUID PRIMARY KEY,
    sigma_uuid UUID UNIQUE,
    chain_id UUID REFERENCES attack_chains(id),
    cve_id UUID REFERENCES cves(id),
    technique_ids VARCHAR(20)[],
    title VARCHAR(500),
    sigma_yaml TEXT,
    status VARCHAR(20) DEFAULT 'generated',
    origin VARCHAR(20) DEFAULT 'fragchain',
    source_id UUID REFERENCES sigma_sources(id),
    target_id UUID REFERENCES sigma_targets(id),
    logsource_product VARCHAR(100),
    logsource_service VARCHAR(100),
    logsource_profile VARCHAR(50),    -- references M13 profile
    detection_level VARCHAR(20),
    tlp VARCHAR(20) DEFAULT 'tlp:clear',
    reviewed_by VARCHAR(255),
    reviewed_at TIMESTAMP,
    merged_at TIMESTAMP,
    git_pr_url VARCHAR(500),
    git_commit_sha VARCHAR(64),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

**Code**
- `fragchain/sigma/sources.py` — clone/pull source repos, parse rules, upsert
- `fragchain/sigma/targets.py` — Git PR creation, routing logic

**Celery Tasks**
- `refresh_sigma_sources()` — every 6 hours, pulls all enabled source repos
- `submit_rule_to_target(rule_id, target_id)` — creates PR

**API**
- `GET /api/v1/sigma/sources` / `POST` / `PATCH` / `DELETE`
- `GET /api/v1/sigma/targets` / `POST` / `PATCH` / `DELETE`
- `POST /api/v1/sigma/sources/{id}/refresh` — manual pull
- `POST /api/v1/sigma/targets/{id}/test` — verify connectivity

**UI**
- Settings → Sigma Sources / Sigma Targets (M24 builds)
- Target selector on Review Queue items (M22 builds)

**Interfaces Exposed**
- `SigmaSourceClient.refresh_all()` — pulls + parses all sources
- `SigmaTargetClient.submit_rule(rule, target)` — creates PR
- `RoutingEngine.select_target(rule) → SigmaTarget` — applies routing rules

**Done Criteria**
- Source repo cloned, rules parsed, sigma_rules table populated
- `embed_sigma_rule` queue progresses (the embed Celery task actually
  runs to completion — not just enqueues — so `sigma_rules` Qdrant
  collection point count climbs as rules are imported). Phase 5 audit
  L2 was exactly this: rules imported into Postgres, but every embed
  task died with "no provider registered" because the worker process
  hadn't bootstrapped the LLM provider registry.
- Target repo Git PR creation works (tested with sample rule)
- Routing rules correctly select target based on conditions, including
  the dotted bareword tag-probe form (`fragchain.generated`) which is
  pre-normalised to `'<tag>' in tags` before AST evaluation
- Multiple sources can coexist
- Multiple targets can coexist with different routing
- Multi-default detection: deployment refuses to start when more than
  one sigma_targets row is `is_default=true` (single source of
  ambiguity in the routing engine)
- `git_url` allowlist: the `^https?://host/owner/repo` shape is
  required unless `SIGMA_ALLOW_NON_HTTPS=true`

---

### M13. Logsource Profiles
**Status:** in-scope-v1 | **Phase:** 5 | **Effort:** M

**Purpose**
Per-platform rule generation profiles. A profile encodes how to write detection logic for a specific environment: product/service mapping, field naming conventions, common fields, example rules (for few-shot prompting). Operators enable profiles they care about; rule generator (M15) produces variants for each enabled profile.

**Dependencies**
M1.

**Schema**
```sql
CREATE TABLE logsource_profiles (
    id UUID PRIMARY KEY,
    name VARCHAR(50) UNIQUE,        -- 'linux-auditd' | 'linux-sysmon' | 'windows-security' | 'windows-sysmon' | etc.
    display_name VARCHAR(100),
    description TEXT,
    platform VARCHAR(20),           -- 'linux' | 'windows' | 'network' | 'cloud'
    sigma_product VARCHAR(50),      -- maps to Sigma logsource.product
    sigma_service VARCHAR(50),      -- maps to Sigma logsource.service
    field_conventions JSONB,        -- common field names + types
    example_rules JSONB,            -- few-shot examples for LLM
    enabled BOOLEAN DEFAULT TRUE,
    is_builtin BOOLEAN DEFAULT FALSE
);
```

**Built-in Profiles (seeded on first run)**
- `linux-auditd` (enabled by default)
- `linux-sysmon` (Sysmon for Linux)
- `linux-falco` (container/k8s)
- `windows-security` (enabled by default)
- `windows-sysmon`
- `network-zeek`
- `network-suricata`

**Code**
- `fragchain/profiles/store.py` — load profile, build prompt context
- `scripts/seed_profiles.py` — populate built-ins on first run

**API**
- `GET /api/v1/profiles` — list
- `GET /api/v1/profiles/{id}` — detail
- `POST /api/v1/profiles` — create custom profile
- `PATCH /api/v1/profiles/{id}` — update (only custom, not built-ins)
- `POST /api/v1/profiles/{id}/enable|disable`

**UI**
- Settings → Logsource Profiles (M24 builds)

**Interfaces Exposed**
- `ProfileStore.get_enabled() → list[LogsourceProfile]`
- `ProfileStore.get(name) → LogsourceProfile`
- `ProfileStore.build_prompt_context(profile) → dict` — used by M15

**Done Criteria**
- 7 built-in profiles seeded correctly
- Custom profile creation works
- Profile enable/disable persists
- `build_prompt_context()` returns correct dict for each profile

---

### M14. Coverage Mapper
**Status:** in-scope-v1 | **Phase:** 5 | **Effort:** L

**Purpose**
Two-phase comparison of chain TTPs against the Sigma rule library. Phase 1 is exact ATT&CK tag match (PostgreSQL). Phase 2 is semantic search via Qdrant for rules without technique tags. Outputs covered/partial/gap status per TTP plus priority scores. Also populates the full ATT&CK matrix data structure.

**Dependencies**
M8, M11, M12.

**Schema**
```sql
CREATE TABLE coverage_map (
    id UUID PRIMARY KEY,
    technique_id VARCHAR(20),
    sub_technique_id VARCHAR(20),
    tactic_id VARCHAR(10),
    tactic_name VARCHAR(50),
    technique_name VARCHAR(200),
    framework VARCHAR(20) DEFAULT 'attck',
    coverage_status VARCHAR(20) DEFAULT 'no_data',   -- covered | partial | gap | no_data
    covering_rule_ids UUID[] DEFAULT '{}',
    chain_cve_ids UUID[] DEFAULT '{}',
    chain_cve_count INTEGER DEFAULT 0,
    kev_cve_count INTEGER DEFAULT 0,
    kev_exposed BOOLEAN DEFAULT FALSE,
    last_refreshed TIMESTAMP DEFAULT NOW(),
    UNIQUE(technique_id, framework)
);
```

**Pipeline**
```
1. Load chain TTPs for the chain
2. PHASE 1 — Exact tag match:
   For each TTP: SELECT sigma_rules WHERE technique_ids @> ARRAY[technique_id]
3. PHASE 2 — Semantic match (for uncovered TTPs):
   For each uncovered: search fragchain_sigma_rules, top 5 with score > 0.75
   For each candidate: LLM cheap call "does this rule detect {technique}?"
4. Calculate priority score per gap
5. Upsert coverage_map for every technique in chain
6. Refresh Redis matrix cache (invalidates "matrix:*")
```

**Priority Scoring**
- +30 if cisa_kev
- +20 if cvss ≥ 9.0
- +20 if epss ≥ 0.50
- +15 if epss ≥ 0.20
- +15 if POC source available
- +10 if attackerkb_score ≥ 3.5
- +10 if seq_order ≤ 3
- +5 × count of other CVEs sharing this gap

**Code**
- `fragchain/coverage/mapper.py`
- `fragchain/coverage/matrix.py` — full matrix data with Redis cache

**Celery Tasks**
- `map_coverage(chain_id)` — called after synthesis completes
- `refresh_matrix_cache()` — every 1 hour
- `recompute_coverage()` — full rebuild on demand (admin)

**API**
- `GET /api/v1/coverage` — full coverage data
- `GET /api/v1/coverage/{technique_id}` — technique detail (CVEs, rules)
- `GET /api/v1/matrix` — structured matrix data (cached)
- `GET /api/v1/matrix/{technique_id}` — alias
- Query params: framework, cve_id, date_from, date_to, cvss_min, kev_only

**UI**
- ATT&CK Matrix screen (M21 builds; this exposes API)
- Mini-heatmap on Dashboard (M19)

**Interfaces Exposed**
- `CoverageMapper.map_coverage(chain_id) → CoverageReport`
- `MatrixCache.get(framework, filters) → MatrixData`
- WebSocket events: `coverage_mapped`, `matrix_updated`

**Done Criteria**
- CVE-2026-43284 coverage report matches expected covered/gap split
- Matrix data returns the 14 canonical ATT&CK Enterprise tactics
  (TA0001–TA0011, TA0040, TA0042, TA0043) with technique cells. The
  M8 ATT&CK seed must be filtered to this canonical set — any
  non-canonical tactics in the upstream STIX bundle (e.g. the
  `TA0112 — Defense Impairment` row observed in Phase 5 verification)
  are dropped at seed time. Backlogged as a tiny M8 seed-gating fix.
- Cache invalidates correctly on new chain or new rule merge
- Priority scores calculated correctly per test cases

---

### M15. Rule Generator
**Status:** in-scope-v1 | **Phase:** 5 | **Effort:** L

**Purpose**
Generates draft Sigma v2 YAML rules for each coverage gap. Produces variants for each enabled logsource profile (so one TTP gap might generate both a Linux auditd rule and a Windows sysmon rule). Validates output with pySigma before storage. Tags with `fragchain.generated` and TLP level.

**Dependencies**
M9, M11, M13, M14.

**Code**
- `fragchain/rules/generator.py`
- `fragchain/rules/validator.py` — pySigma wrapper

**Pipeline**
```
1. Load coverage gaps from M14
2. Load enabled logsource profiles from M13
3. For each gap × enabled profile:
   a. Load TTP detail, adjacent TTPs, top 3 source documents
   b. Load active prompt template (M9): get_active('rule_generation', model, provider)
   c. Build prompt with profile context + TTP context
   d. Call LLM via M5
   e. Parse YAML, strip fences
   f. Validate with pySigma → ValidationResult
   g. If invalid: retry with errors (max 2)
   h. Build complete rule with mandatory tags (fragchain.generated, tlp.X, attack.tXXXX)
   i. Insert sigma_rules (status='generated')
   j. Insert review_queue with priority_score from M14
```

**Mandatory Tags on Generated Rules**
- `attack.<tactic_lowercase>`
- `attack.<technique_id_lowercase>`
- `cve.<cve_id_lowercase_dashes>`
- `fragchain.generated`
- `tlp.<level>`
- `logsource.profile.<profile_name>`

**Celery Tasks**
- `generate_rules(chain_id)` — called after coverage mapping completes

**API**
- `POST /api/v1/cves/{cve_id}/regenerate-rules` — force regenerate
- `POST /api/v1/matrix/{technique_id}/generate-rule` — generate rule for specific technique (manual trigger)
- `GET /api/v1/rules` — list with filters
- `GET /api/v1/rules/{id}` — detail with YAML
- `POST /api/v1/rules/{id}/validate` — run pySigma

**UI**
- Sigma Library screen (M22 builds; this exposes API)

**Interfaces Exposed**
- `RuleGenerator.generate_rule(chain_id, gap, profile) → SigmaRule`
- `RuleGenerator.generate_all_gaps(chain_id) → list[SigmaRule]`
- `pySigmaValidator.validate(yaml_str) → ValidationResult`
- WebSocket events: `rules_ready {cve_id, rule_count, top_priority}`

**Done Criteria**
- Generates valid Sigma v2 YAML for CVE-2026-43284 gaps
- Multi-profile generation works (Linux + Windows variants for same TTP)
- pySigma validation passes on all generated rules
- Failed validation retries correctly, eventually fails gracefully
- All mandatory tags present
- Rules appear in review queue with correct priority

---

### M16. Review Queue
**Status:** in-scope-v1 | **Phase:** 5 | **Effort:** M

**Purpose**
Human-in-the-loop validation interface for generated rules. Analyst reviews YAML, evidence, chain context. Approves (creates Git PR to selected target), edits + approves, or rejects. Auto-advances through queue.

**Dependencies**
M12, M15.

**Schema**
```sql
CREATE TABLE review_queue (
    id UUID PRIMARY KEY,
    sigma_rule_id UUID REFERENCES sigma_rules(id) ON DELETE CASCADE,
    priority VARCHAR(20) DEFAULT 'medium',   -- critical | high | medium | low
    priority_score INTEGER DEFAULT 0,
    priority_reason TEXT,
    assigned_to VARCHAR(255),
    status VARCHAR(20) DEFAULT 'pending',    -- pending | in_review | approved | rejected
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP
);
```

**Code**
- `fragchain/queue/manager.py`

**API**
- `GET /api/v1/queue` — list with filters
- `GET /api/v1/queue/{id}` — item + rule + evidence (CVE, chain context, source docs, similar rules)
- `PATCH /api/v1/queue/{id}/assign` — assign to analyst
- `POST /api/v1/queue/{id}/approve` — approve, creates Git PR via M12
  - Body: `{target_id?: UUID}` — optional target override
- `POST /api/v1/queue/{id}/reject` — reject with reason
- `POST /api/v1/queue/{id}/edit` — save YAML edits + validate + approve

**UI**
- Review Queue screen (M22 builds)

**Interfaces Exposed**
- `QueueManager.approve(item_id, user, target_id?) → SigmaRule`
- `QueueManager.reject(item_id, user, reason) → SigmaRule`
- WebSocket events: `rule_approved`, `rule_rejected`, `git_pr_created`

**Done Criteria**
- Pending rules appear in queue ordered by priority_score DESC
- Approve creates Git PR via M12, returns PR URL
- Reject records reason in audit log
- Edit + approve persists YAML changes and creates PR
- Auto-advance to next item works after action

---

### M17. Rule Evaluations
**Status:** in-scope-v1 | **Phase:** 5 | **Effort:** M

**Purpose**
Capture rule efficacy data from real environments. After a rule is deployed, analysts record true positives, false positive rates, environment details. Aggregated stats expose which rules work in practice. Optional contribution to commons.

**Dependencies**
M7, M16.

**Schema**
```sql
CREATE TABLE rule_evaluations (
    id UUID PRIMARY KEY,
    sigma_rule_id UUID REFERENCES sigma_rules(id),
    evaluator_username VARCHAR(255),
    evaluated_at TIMESTAMP DEFAULT NOW(),
    environment_platform VARCHAR(50),
    environment_logsource VARCHAR(100),
    environment_scale VARCHAR(50),       -- 'small' | 'medium' | 'enterprise'
    true_positives INTEGER,
    false_positives_per_day DECIMAL(6,2),
    query_cost VARCHAR(20),
    deployment_complexity VARCHAR(20),
    notes TEXT,
    contributed_to_commons BOOLEAN DEFAULT FALSE
);
```

**Code**
- `fragchain/evaluations/store.py`

**Celery Tasks**
- `prompt_evaluations()` — daily, prompts analysts to evaluate rules deployed 7+ days ago

**API**
- `POST /api/v1/rules/{id}/evaluate` — submit evaluation
- `GET /api/v1/rules/{id}/evaluations` — list all evaluations for rule
- `GET /api/v1/rules/{id}/evaluations/aggregate` — aggregate stats
- `POST /api/v1/evaluations/{id}/contribute` — push to commons (via M7)

**UI**
- Rule detail panel (M22) shows evaluations + "Add evaluation" button
- Dashboard notification: "X rules ready for evaluation"

**Interfaces Exposed**
- `EvaluationStore.record(rule_id, evaluator, results)`
- `EvaluationStore.aggregate(rule_id) → AggregateStats`

**Done Criteria**
- Evaluation submission works via API
- Aggregate stats correctly compute average FP rate, recommendation level
- Contribution to commons creates correct PR

---

## PHASE 6 — Frontend

---

### M18. Frontend Core
**Status:** in-scope-v1 | **Phase:** 6 | **Effort:** M

**Purpose**
Shared frontend infrastructure: API client, WebSocket hook, auth, routing, layout, base components. Every UI module consumes this.

**Dependencies**
M1 (frontend shell), M2 (TLP component), M5 (LLM provider concept).

**Code**
- `frontend/src/api/client.ts` — axios with JWT interceptor
- `frontend/src/api/*.ts` — per-resource clients
- `frontend/src/hooks/useWebSocket.ts`
- `frontend/src/hooks/useAuth.ts`
- `frontend/src/components/` — Topbar, Sidebar, Badge, TLPBadge, StatBlock, DataTable, Toast, ProgressBar, ConfirmDialog

**UI**
- Login screen (full implementation)
- Auth context, protected routes
- Shared layout shell

**Done Criteria**
- All shared components render correctly with DarkOps tokens
- WebSocket connects, reconnects on disconnect
- JWT auth flows work (login, logout, refresh)
- 401 responses redirect to login

---

### M19. Dashboard
**Status:** in-scope-v1 | **Phase:** 6 | **Effort:** M

**Purpose**
Operational overview screen. Stats, mini ATT&CK heatmap, KEV gap list, live event feed, review queue preview.

**Dependencies**
M6, M11, M14, M16, M18.

**UI Layout**
- Stat grid (5 blocks): CVEs/24hr, Sigma coverage %, Pending review, KEV gaps, Staged
- Mini ATT&CK heatmap (abbreviated, links to /matrix)
- Review queue preview (top 5)
- KEV gap list with banner for staged KEV CVEs
- Live event feed via WebSocket

**Done Criteria**
- All stats reflect live DB data
- WebSocket events update stats in real-time
- Mini-heatmap renders 14 tactics
- KEV banner shows when staged KEV CVEs exist

---

### M20. CVE Explorer + Chain Viewer
**Status:** in-scope-v1 | **Phase:** 6 | **Effort:** L

**Purpose**
Two screens that work together: CVE Explorer for browsing/filtering CVEs, Chain Viewer for visualizing a CVE's attack chain as a directed graph.

**Dependencies**
M6, M11, M18.

**CVE Explorer UI**
- DarkOps data-table (CVE ID, CVSS, KEV badge, import mode, processing status, confidence, rule count, published date)
- Filter sidebar (date range, CVSS, KEV, status, source)
- Click row → detail sidebar (chain summary, source docs, processing timeline)

**Chain Viewer UI**
- React Flow directed graph (left-to-right, dagre layout)
- Tactic-colored nodes (per CLAUDE.md mapping)
- Click node → TTP detail sidebar (preconditions, detection opportunity, source evidence)
- Context bar: CVE ID, confidence, model, prompt version, "Re-synthesize" button

**Done Criteria**
- Data table sorts/filters correctly
- Chain Viewer renders CVE-2026-43284 chain with correct tactic colors
- Node click opens detail sidebar with full evidence
- Re-synthesize triggers API call and refreshes view

---

### M21. ATT&CK Matrix UI
**Status:** in-scope-v1 | **Phase:** 6 | **Effort:** L

**Purpose**
Full MITRE ATT&CK matrix screen with 4 view modes (Chain Exposure, Detection Coverage, Gap Analysis, KEV Focus). Click any cell for detail sidebar with CVE list and rule list.

**Dependencies**
M14, M18.

**UI Layout**
- Context bar: view mode buttons, framework toggle (ATT&CK/ATLAS/SPARTA), filter button, export button
- Main area: full matrix grid (14 tactic columns × all techniques, ~200+ cells with sub-technique expansion)
- Right sidebar: technique detail on cell click

**View Modes**
- Chain Exposure: intensity = chain_cve_count (cyan scale)
- Detection Coverage: green/amber/red/dim
- Gap Analysis: only gaps lit (red pulsing for KEV)
- KEV Focus: only KEV-CVE techniques highlighted

**Done Criteria**
- All techniques render with correct color per view mode
- Sub-technique expand works on parent technique cells
- Click cell → detail sidebar with CVEs + rules + "Generate Rule" button on gaps
- View mode switching is instant (data already loaded)
- Filters apply correctly

---

### M22. Sigma Library + Review Queue UI
**Status:** in-scope-v1 | **Phase:** 6 | **Effort:** L

**Purpose**
Sigma Library screen browses all rules. Review Queue screen has split-pane YAML editor + evidence panel for human-in-the-loop validation.

**Dependencies**
M15, M16, M18.

**Sigma Library UI**
- Data table (title, technique tags, logsource, status badge, origin badge, level, CVE link, date)
- Filter sidebar (status, technique, logsource, origin, level, date range)
- Click row → detail sidebar (YAML, metadata, "Validate" button, "Copy" button, target selector if approved)

**Review Queue UI**
- Left pane: CodeMirror YAML editor (JetBrains Mono, dark theme, live pySigma validation)
- Right pane: evidence (CVE context, chain context, source docs, similar rules, priority breakdown)
- Context bar: CVE ID, technique, priority, age, navigation buttons
- Actions: Approve (with target selector), Edit + Approve, Reject

**Done Criteria**
- Library lists all rules correctly filtered
- Review queue split-pane works
- Live validation shows pySigma errors as you edit
- Approve creates PR and shows URL in success toast
- Auto-advance to next queue item after action

---

### M23. Import Manager UI
**Status:** in-scope-v1 | **Phase:** 6 | **Effort:** M

**Purpose**
Two-tab screen for managing CVE imports: Live Feed (real-time webhook status) and Historical Import (filter, preview, stage, approve workflow).

**Dependencies**
M6, M18.

**Live Feed Tab**
- Stat blocks (Live CVEs today, processing rate, rate limit status, queue depth)
- Live event log (WebSocket-driven; subscribes to `cve_ingested`,
  `enrichment_complete`, `rate_limit_warning`, `chain_generated`,
  `coverage_mapped`, `rules_generated`, `queue_item.*`, `import_job.*`)
- Config card (current limits, AUTO_PROCESS_KEV toggle)

**Historical Import Tab**
- Collapsible import form (date range, CVSS min, KEV only, vendor, specific CVE IDs)
- Preview button → shows count + sample + estimated cost
- Start Import → creates job
- Active Jobs table with inline expand for staged CVEs
- Batch actions: APPROVE ALL, APPROVE KEV ONLY, SKIP ALL
- Budget warning banner when daily limit approaching

**Done Criteria**
- Preview returns count + sample from real OpenCTI
- Start Import creates job, stages CVEs
- Approve/skip flow works correctly
- Budget warning appears when limit close

---

### M24. Settings + Marketplace UI
**Status:** in-scope-v1 | **Phase:** 6 | **Effort:** L

**Purpose**
Combined settings screen and connectors marketplace. Settings has sections for all configurable subsystems. Marketplace browses fragchain-registry and installs new connectors.

**Dependencies**
M4, M7, M9, M12, M13, M18.

**Settings Sections**
- Connectors (per-connector config + health)
- Commons Sources (multi-source config)
- Sigma Sources / Sigma Targets (multi-repo config)
- Logsource Profiles (enabled/disabled, custom profiles)
- Processing Limits (rate limits, daily budget)
- Notifications (Slack, webhook, email)
- AI Providers (LLM provider config — v1 just LiteLLM)

**Marketplace (Connectors tab)**
- Browse fragchain-registry index
- Each entry: name, description, type, official badge, maintainer, version
- Install button (runs pip install via subprocess + restart prompt)
- Health badge for installed connectors

**Prompts Management (its own sub-screen)**
- List prompt templates grouped by task × model
- Version history per prompt
- Active toggle
- Diff view between versions
- Evaluation results
- A/B test management

**Done Criteria**
- All settings sections render with correct DarkOps form components
- Save changes persist to DB
- Test Connection buttons work for each external service
- Marketplace lists registry entries correctly
- Install button triggers correct pip install
- Prompts management UI complete with all CRUD operations

---

## PHASE 7 — Connector Ecosystem (Separate Repositories)

Each connector is its own GitHub repo, its own PyPI package, its own version cadence. All implement the IntelConnector protocol from M4. They are independent of fragchain-core's release cycle.

---

### M25. fragchain-connector-opencti
**Status:** in-scope-v1 | **Phase:** 7 | **Effort:** M | **Repo:** `fragchain/connector-opencti`

**Type:** SOURCE_STREAM | **Default TLP:** tlp:green

**What it does:** Pulls Vulnerability objects from OpenCTI's GraphQL API. Receives webhook events. Filters by date, KEV, CVSS, etc.

**Key Config:** OPENCTI_URL, OPENCTI_TOKEN, OPENCTI_WEBHOOK_SECRET

---

### M26. fragchain-connector-nvd2
**Status:** in-scope-v1 | **Phase:** 7 | **Effort:** M | **Repo:** `fragchain/connector-nvd2`

**Type:** SOURCE_STREAM | **Default TLP:** tlp:clear

**What it does:** Direct NVD 2.0 API integration. For deployments without OpenCTI.

**Key Config:** NVD_API_KEY (optional, higher rate limits)

---

### M27. fragchain-connector-epss
**Status:** in-scope-v1 | **Phase:** 7 | **Effort:** S | **Repo:** `fragchain/connector-epss`

**Type:** ENRICHMENT | **Default TLP:** tlp:clear

**What it does:** FIRST.org EPSS scores. Batch-fetches scores for all CVEs daily.

---

### M28. fragchain-connector-ctid
**Status:** in-scope-v1 | **Phase:** 7 | **Effort:** S | **Repo:** `fragchain/connector-ctid`

**Type:** ENRICHMENT | **Default TLP:** tlp:clear

**What it does:** CVE→ATT&CK mappings from Center for Threat-Informed Defense GitHub dataset. Downloads, indexes locally, refreshes weekly.

---

### M29. fragchain-connector-kev
**Status:** in-scope-v1 | **Phase:** 7 | **Effort:** S | **Repo:** `fragchain/connector-kev`

**Type:** ENRICHMENT | **Default TLP:** tlp:clear

**What it does:** Direct CISA KEV JSON feed. Enriches CVE with KEV detail (dateAdded, dueDate, requiredAction, ransomwareUse).

---

### M30. fragchain-connector-attackerkb
**Status:** in-scope-v1 | **Phase:** 7 | **Effort:** S | **Repo:** `fragchain/connector-attackerkb`

**Type:** ENRICHMENT | **Default TLP:** tlp:clear

**What it does:** Rapid7 AttackerKB community exploitation assessments.

---

### M31. fragchain-connector-exploitdb
**Status:** in-scope-v1 | **Phase:** 7 | **Effort:** S | **Repo:** `fragchain/connector-exploitdb`

**Type:** ENRICHMENT | **Default TLP:** tlp:clear

**What it does:** Exploit-DB search for CVE entries. Fetches writeups (not exploit code).

---

### M32. fragchain-connector-osssecurity
**Status:** in-scope-v1 | **Phase:** 7 | **Effort:** S | **Repo:** `fragchain/connector-osssecurity`

**Type:** ENRICHMENT | **Default TLP:** tlp:clear

**What it does:** oss-security mailing list archive. Only fetches for Linux/open source CVEs.

---

### M33. fragchain-connector-github
**Status:** in-scope-v1 | **Phase:** 7 | **Effort:** S | **Repo:** `fragchain/connector-github`

**Type:** ENRICHMENT | **Default TLP:** tlp:clear

**What it does:** GitHub Search API for CVE-ID in repos. Filters for POC indicators.

**Key Config:** GITHUB_TOKEN (optional)

---

### M34. Vendor Advisory Connectors
**Status:** in-scope-v1 | **Phase:** 7 | **Effort:** M each | **Repos:** `fragchain/connector-vendor-{redhat,msrc,ubuntu}`

Three separate packages:
- `fragchain-connector-vendor-redhat` — Red Hat security data API
- `fragchain-connector-vendor-msrc` — Microsoft Security Response Center
- `fragchain-connector-vendor-ubuntu` — Ubuntu security tracker

All ENRICHMENT type, tlp:clear default. Each only fetches when CVE's affected_products matches its vendor.

---

## PHASE 8 — Ecosystem & Polish

---

### M35. Commons Repository Setup
**Status:** in-scope-v1 | **Phase:** 8 | **Effort:** M | **Repo:** `fragchain/fragchain-intelligence`

**Purpose**
The actual community knowledge repository. Initial structure, CI for PR validation, weekly release pack generation, seed data.

**Repo Structure** (defined in Ecosystem Architecture doc)

**What this module produces:**
- The repo itself created and populated
- Seed chains: Dirty Frag + 10-20 reference chains from Sprint 4 testing
- README, CONTRIBUTING, GOVERNANCE docs
- CI workflows: validate_pr.yml, daily_snapshot.yml, weekly_release.yml
- First release pack: v1.0.0

**Done Criteria**
- Repo public on GitHub
- 10+ validated chains in chains/
- CI validates PRs correctly
- First release pack downloadable
- M7 (Commons Sources) successfully syncs from this repo

---

### M36. Notifications
**Status:** in-scope-v1 | **Phase:** 8 | **Effort:** S

**Purpose**
Multi-channel notification for pipeline events. Slack webhook, generic webhook, email.

**Dependencies**
M1.

**Schema**
```sql
CREATE TABLE notification_channels (
    id UUID PRIMARY KEY,
    name VARCHAR(100),
    type VARCHAR(20),               -- 'slack' | 'webhook' | 'email'
    config JSONB,
    enabled BOOLEAN DEFAULT TRUE,
    event_filter JSONB              -- which events trigger this channel
);
```

**Events Sent**
- `rules_ready` — new rules in review queue
- `kev_cve_processed` — KEV CVE completed pipeline
- `budget_warning` — approaching daily limit
- `pipeline_error` — failure in any stage
- `commons_sync_failed`

**API**
- `GET /api/v1/notifications/channels` / `POST` / `PATCH` / `DELETE`
- `POST /api/v1/notifications/channels/{id}/test` — send test message

**Done Criteria**
- Slack webhook delivers test message
- Generic webhook POSTs JSON correctly
- Event filtering routes correct events to correct channels

---

### M37. Documentation & Onboarding
**Status:** in-scope-v1 | **Phase:** 8 | **Effort:** M

**Purpose**
Complete operator-facing documentation. Setup guide, configuration reference, connector documentation, troubleshooting.

**Deliverables**
- `README.md` (main repo) — what is FragChain, quick start
- `docs/installation.md` — full setup walkthrough
- `docs/configuration.md` — every .env variable documented
- `docs/connectors.md` — how to install connectors, list of official connectors
- `docs/commons.md` — how the intelligence commons works
- `docs/contributing.md` — how to contribute chains, rules, evaluations
- `docs/litellm-setup.md` — how to set up LiteLLM with Ollama, OpenAI, Anthropic
- `docs/troubleshooting.md`
- `docs/architecture.md` — high-level architecture overview
- In-app help: "Help" link in Topbar opens contextual docs

**Done Criteria**
- New operator can install FragChain following docs alone
- Each configurable subsystem documented
- LiteLLM setup guide tested with Ollama, OpenAI, Anthropic

---

## DEFERRED — Post-v1 Modules

These exist in the architectural model but are explicitly out of scope for v1. The schema and interfaces may be in place; the implementations are not.

---

### M38. Identity & Trust (Full)
**Phase:** Post-v1

Full implementation of the identity verification workflow described in `FragChain_TLP_and_Identity.md`: GPG key upload, verification challenge, trust attestations, signed contributions, web of trust visualization, tier escalation.

Schema already exists in M3. Endpoints currently return 501. This module replaces those stubs with real implementations.

---

### M39. LLM Provider: OpenAI Direct
**Phase:** Post-v1 | **Repo:** `fragchain/provider-openai`

Direct OpenAI API provider (bypass LiteLLM). For operators with enterprise OpenAI contracts.

---

### M40. LLM Provider: Anthropic Direct
**Phase:** Post-v1 | **Repo:** `fragchain/provider-anthropic`

Direct Anthropic API provider.

---

### M41. LLM Provider: Ollama Direct
**Phase:** Post-v1 | **Repo:** `fragchain/provider-ollama`

Direct local Ollama provider. For fully air-gapped / sovereign deployments where no external LLM service is allowed.

---

### M42. ATLAS Framework Support
**Phase:** Post-v1

Adds MITRE ATLAS (AI/ML attack framework) alongside ATT&CK. Mostly a data update — chain schema already supports framework field. Coverage Mapper needs ATLAS technique seeding.

---

### M43. SPARTA Framework Support
**Phase:** Post-v1

Adds Aerospace SPARTA (space systems attack framework). Same pattern as ATLAS.

---

### M44. Multi-tenancy & RBAC
**Phase:** Post-v1

Multi-tenant SaaS hosting capability. Organisations, role-based access control, per-tenant isolation. Required for commercial hosted offering.

---

## Module Dependency Graph

```
PHASE 1 ──────────────────────────────────────────────────────
M1 Foundation
  ├─ M2 TLP & Embargo
  ├─ M3 Identity Placeholder
  ├─ M4 Connector Framework  ←── depends on M1, M2
  └─ M5 LLM Provider Framework

PHASE 2 ──────────────────────────────────────────────────────
M6 Intel Ingestion           ←── M1, M2, M4, M5
M7 Commons Sources            ←── M1, M2

PHASE 3 ──────────────────────────────────────────────────────
M8 Vector Store               ←── M1, M5
M9 Prompt Management          ←── M1, M5

PHASE 4 ──────────────────────────────────────────────────────
M10 Chain Schema              ←── M1
M11 Chain Synthesis           ←── M5, M7, M8, M9, M10

PHASE 5 ──────────────────────────────────────────────────────
M12 Sigma Integration         ←── M1
M13 Logsource Profiles        ←── M1
M14 Coverage Mapper           ←── M8, M11, M12
M15 Rule Generator            ←── M9, M11, M13, M14
M16 Review Queue              ←── M12, M15
M17 Rule Evaluations          ←── M7, M16

PHASE 6 ──────────────────────────────────────────────────────
M18 Frontend Core             ←── M1, M2, M5
M19 Dashboard                 ←── M6, M11, M14, M16, M18
M20 CVE Explorer + Viewer     ←── M6, M11, M18
M21 ATT&CK Matrix UI          ←── M14, M18
M22 Sigma Library + Queue UI  ←── M15, M16, M18
M23 Import Manager UI         ←── M6, M18
M24 Settings + Marketplace    ←── M4, M7, M9, M12, M13, M18

PHASE 7 — Connectors (parallel, separate repos)
M25–M34   ←── M4 (connector framework)

PHASE 8 ──────────────────────────────────────────────────────
M35 Commons Repo Setup        ←── M11 (need real chains to seed)
M36 Notifications             ←── M1
M37 Documentation             ←── everything
```

---

## Critical Path

The fastest path to a working end-to-end system:

```
M1 → M4 → M5 → M6 → M8 → M10 → M11 → M12 → M13 → M14 → M15 → M16
                                                              ↑
                                                              minimum viable
                                                              backend
                                                              
Then M18 → M22 minimum viable frontend (Review Queue alone)
Plus M25 (OpenCTI connector) for actual data ingestion
```

**Minimum viable demo: M1, M4, M5, M6, M8, M10, M11, M14, M15, M16, M18, M22, M25** = 13 modules.

Everything else makes it better but is not strictly required for "this thing works end to end."

---

## Where Sprints Map To Modules

If you prefer to think in time-boxed iterations, here's a reasonable mapping for a solo or small-team build:

| Iteration | Modules | Duration |
|-----------|---------|----------|
| Sprint 1 | M1, M2, M3 | 2 weeks |
| Sprint 2 | M4, M5, M6 | 2 weeks |
| Sprint 3 | M7, M8, M9 | 2 weeks |
| Sprint 4 | M10, M11 | 1-2 weeks |
| Sprint 5 | M12, M13, M14, M15 | 2-3 weeks |
| Sprint 6 | M16, M17 | 1-2 weeks |
| Sprint 7 | M18, M19, M20 | 2 weeks |
| Sprint 8 | M21, M22, M23 | 2 weeks |
| Sprint 9 | M24, M36 | 1-2 weeks |
| Sprint 10 | M25–M29 (in parallel, separate repos) | 2 weeks |
| Sprint 11 | M30–M34 (in parallel, separate repos) | 2 weeks |
| Sprint 12 | M35, M37 | 1-2 weeks |

**Total: ~20-26 weeks for full v1**, depending on parallelization and effort.

For Claude Code sessions: one module per session typically, larger modules (L effort) may need 2 sessions with a pause for review between major components.

---

*This is the canonical build reference. Update this document when modules are completed or specs change. Sprint plans, if used, derive from this document — they do not contradict it.*
