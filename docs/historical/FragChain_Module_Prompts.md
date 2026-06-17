> **Historical — preserved for context.** The original ready-to-paste kickoff prompts for modules M1–M37. The build proceeded with these and the per-module completion records live in [`docs/historical/MODULE_M*_DONE.md`](.). Active prompts now live in the database via the Prompt Management system ([`CLAUDE.md`](../../CLAUDE.md) §15).

---

# FragChain — Module Kickoff Prompts
**Purpose:** Ready-to-paste prompts for every module M1 through M37.  
**How to use:** Copy the prompt for the module you're building, paste into a fresh Claude Code session.

---

## How These Prompts Work

Every prompt has the same structure:
1. **Setup** — files to read before doing anything
2. **Scope** — what to build (defers most detail to the module spec)
3. **Not in scope** — what NOT to build (prevents scope creep)
4. **Done criteria** — specific verification checks
5. **Closing** — write MODULE_N_DONE.md before stopping

The prompts are intentionally short. The detail lives in:
- `CLAUDE.md` (operational rules, schemas, conventions)
- `FragChain_Module_Specifications.md` (per-module scope)

Claude Code reads those at the start of each session.

---

## Generic Template (Reference)

```
Read fully before doing anything else:
1. CLAUDE.md — every section
2. FragChain_Module_Specifications.md — focus on Module M{N}
3. docs/MODULE_M{X}_DONE.md and docs/MODULE_M{Y}_DONE.md for dependencies

We are building Module M{N}: {NAME}.

Scope is exactly what the module spec defines. Read it before you write code.

Build:
{specific deliverables}

Do not build:
{explicit out-of-scope items that other modules own}

Done criteria (verify each):
{specific checks}

When complete, write docs/MODULE_M{N}_DONE.md per the Build Workflow template
and stop. Do not start the next module.

Begin by confirming what you've read, listing the schema/API/UI surface
this module exposes, and noting any clarifying questions.
```

---

# PHASE 1 — FOUNDATION

---

## M1 — Foundation

**Reference:** Full kickoff prompt is in `FragChain_Build_Workflow.md` (section "M1 KICKOFF PROMPT").

Use that one — it's the most detailed because there are no predecessor done files.

---

## M2 — TLP & Embargo

```
Read fully before doing anything else:
1. CLAUDE.md — especially Section 8 (TLP) and Section 19 (Never Do List)
2. FragChain_Module_Specifications.md — Module M2 (TLP & Embargo)
3. FragChain_TLP_and_Identity.md — the architectural reference
4. docs/MODULE_M1_DONE.md

We are building Module M2: TLP & Embargo.

Build:
- fragchain/security/tlp.py — TLP enum (clear/green/amber/amber+strict/red),
  max_tlp() propagation function, can_user_access() predicate
- fragchain/security/embargo.py — embargo timer logic
- fragchain/api/middleware/tlp_filter.py — response filter that strips
  over-classified content based on user.clearance_level
- Alembic migration: tlp_access_grants table, embargo_participants table
- Celery task: release_embargoed_content (every 5 min, auto-release expired)
- Two admin API endpoints: GET /api/v1/embargo/active,
  POST /api/v1/embargo/release/{entity_id}
- React components: TLPBadge.tsx (renders all 5 levels with correct DarkOps styling),
  EmbargoIndicator.tsx (countdown + lock icon)
- Audit log entries for: TLP change, embargo grant, embargo release

Do not build:
- Identity verification (that's M3, schema only)
- TLP fields on entity tables — those are added by the modules that own
  those tables (M6 adds tlp to cves and source_documents, etc.)
- UI for managing TLP grants (Settings UI is M24)

Done criteria:
- TLP enum has all 5 levels with correct restriction_level ordering
- max_tlp() correctly returns highest of inputs
- TLP filter middleware rejects access to over-classified content (write a unit test)
- Embargo release task runs without error, releases expired embargoes
- TLPBadge renders all 5 variants matching darkops_design_system_v3.html
- EmbargoIndicator shows correct countdown
- Audit log entries created for TLP changes

When complete, write docs/MODULE_M2_DONE.md and stop.
```

---

## M3 — Identity Placeholder

```
Read fully before doing anything else:
1. CLAUDE.md — Section 9 (Identity Placeholder)
2. FragChain_Module_Specifications.md — Module M3
3. FragChain_TLP_and_Identity.md
4. docs/MODULE_M1_DONE.md, docs/MODULE_M2_DONE.md

We are building Module M3: Identity Placeholder.

This is SCHEMA ONLY. No identity logic. No verification. No signing.
Everything is placeholder until M38 (post-v1).

Build:
- Alembic migration adding:
  - users.tier (VARCHAR(20) DEFAULT 'authenticated')
  - users.clearance_level (VARCHAR(20) DEFAULT 'tlp:green')
  - user_identities table (identity_type, public_key, fingerprint, verified_at, etc.)
  - trust_attestations table
  - contribution_signatures table
  (All schemas exactly per CLAUDE.md Section 9 / FragChain_TLP_and_Identity.md)
- fragchain/identity/base.py — IdentityProvider Protocol (interface only)
- fragchain/identity/registry.py — `identity_providers = {}` (empty dict)
- API router fragchain/api/routers/identity.py with these endpoints:
  - GET /api/v1/identity → returns current user's tier + clearance (this works)
  - All other /api/v1/identity/* endpoints → return 501 with body:
    {"error": "not_implemented", "message": "Identity module deferred to post-v1 (M38)"}
- React screen: Identity.tsx
  - Shows current tier/clearance from /api/v1/identity
  - Below that: placeholder card with message about identity verification
    being deferred to a future release
  - DarkOps styled (use .card class and .text-dim for the placeholder)

Do not build:
- ANY identity verification logic
- GPG/SSH/Sigstore handling
- Trust attestation workflows
- Contribution signing
- Web of trust visualization

Done criteria:
- All schema tables created and visible in postgres
- All users have tier='authenticated' and clearance_level='tlp:green' by default
- GET /api/v1/identity returns current user's tier + clearance
- POST /api/v1/identity/key returns 501 with proper error message
- POST /api/v1/identity/verify returns 501
- Identity screen renders the placeholder message in DarkOps style
- IdentityProvider Protocol is importable but registry is empty

When complete, write docs/MODULE_M3_DONE.md and stop.
```

---

## M4 — Connector Framework

```
Read fully before doing anything else:
1. CLAUDE.md — Section 5 (Connector Plugin Architecture)
2. FragChain_Module_Specifications.md — Module M4
3. FragChain_Ecosystem_Architecture.md — connector plugin details
4. docs/MODULE_M1_DONE.md, docs/MODULE_M2_DONE.md

We are building Module M4: Connector Framework.

This is the framework only. No specific connectors are built here —
those are separate packages (M25-M34) in separate repos.

Build:
- fragchain/connectors/base.py — IntelConnector Protocol exactly as
  defined in CLAUDE.md Section 5
- fragchain/connectors/discovery.py — importlib.metadata entry-point loader
- fragchain/connectors/orchestrator.py — ConnectorOrchestrator class:
  - Runs all enrichment connectors in parallel via asyncio.gather
  - Per-connector try/except + timeout (configurable, default 30s)
  - One failure never blocks others
  - Tracks 3-failures-in-window → mark unhealthy
- fragchain/connectors/registry_client.py — fetches fragchain-registry JSON
- Alembic migration: connector_state table
- API router: connectors.py
  - GET /api/v1/connectors (list installed)
  - GET /api/v1/connectors/{name} (detail)
  - PATCH /api/v1/connectors/{name} (update config)
  - POST /api/v1/connectors/{name}/enable | disable
  - POST /api/v1/connectors/{name}/health (run health check now)
  - GET /api/v1/connectors/registry (browse available from registry)
- Dataclasses: ConnectorHealth, ConnectorConfig, CVERecord, EnrichmentResult,
  AttackPattern, RateLimit
- Discovery runs at app startup (lifespan event in main.py)
- Logs every connector loaded with name and version

Do not build:
- Any specific connector (those are separate packages)
- The actual enrichment pipeline (that's M6's job, this gives it the tool)
- Connectors marketplace UI (M24)

Done criteria:
- IntelConnector Protocol importable, all methods defined
- discover_connectors() returns empty list (no connectors installed yet)
- Installing a test stub connector package (write a minimal test fixture)
  causes it to auto-register after restart
- connector_state table reflects installed connectors
- GET /api/v1/connectors returns the test stub
- Three failures of test connector → marked unhealthy in connector_state
- Orchestrator runs N connectors in parallel, returns N results, even if
  one connector raises an exception
- fragchain-registry index can be fetched (mock the URL for now, or use
  a hardcoded JSON file in scripts/)

When complete, write docs/MODULE_M4_DONE.md and stop.
```

---

## M5 — LLM Provider Framework

```
Read fully before doing anything else:
1. CLAUDE.md — Section 6 (LLM Provider Plugin Architecture)
2. FragChain_Module_Specifications.md — Module M5
3. docs/MODULE_M1_DONE.md

We are building Module M5: LLM Provider Framework.

The framework + ONE provider: LiteLLM. Other providers (OpenAI/Anthropic/Ollama
direct) are deferred to M39-M41 post-v1.

Build:
- fragchain/llm/base.py — LLMProvider Protocol per CLAUDE.md Section 6
- fragchain/llm/registry.py — discovery via entry points (group: fragchain.providers)
- fragchain/llm/litellm_provider.py — LiteLLMProvider class:
  - Uses openai.AsyncOpenAI(base_url=LITELLM_BASE_URL, api_key=LITELLM_API_KEY)
  - NEVER imports anthropic
  - complete() method: chat completions with retry (3x on 429, 2x on 5xx,
    exponential backoff)
  - embed() method: embeddings via /v1/embeddings, batch up to 32
  - health_check() method: tests connection to LiteLLM
- Every call:
  - Measures wall-clock latency
  - Logs to llm_interactions table (provider='litellm', model, tokens,
    cost from LiteLLM headers, latency)
  - Stores full {system, prompt, response} as JSON to MinIO:
    llm-io/{YYYY-MM-DD}/{interaction_id}.json
- Alembic migration: llm_interactions table per CLAUDE.md spec
- API endpoints:
  - GET /api/v1/llm/providers (list installed)
  - GET /api/v1/llm/providers/{name}/health
  - GET /api/v1/llm/interactions (paginated list, admin only)
  - GET /api/v1/llm/interactions/{id} (detail + MinIO URL)
- pyproject.toml entry point registering litellm_provider:
  [project.entry-points."fragchain.providers"]
  litellm = "fragchain.llm.litellm_provider:LiteLLMProvider"

Do not build:
- Any direct provider (no OpenAI/Anthropic/Ollama direct integration)
- Provider-specific configuration UI (M24)
- Prompt management (M9)

Done criteria:
- LLMProvider Protocol defined with both complete() and embed() methods
- LiteLLMProvider discoverable via entry point
- LiteLLMProvider.complete() returns text response from Server 1 LiteLLM
- LiteLLMProvider.embed(["test"]) returns a list of 768 floats
- Every call creates an llm_interactions row
- Every call stores full I/O to MinIO at correct path
- Retry on 429 verified (mock the response)
- Health check verifies LiteLLM reachability
- NEVER imports anthropic anywhere (grep verifies this)

When complete, write docs/MODULE_M5_DONE.md and stop.
```

---

# PHASE 2 — DATA INGESTION

---

## M6 — Intel Ingestion

```
Read fully before doing anything else:
1. CLAUDE.md — Section 10 (CVE Import Strategy, including novelty filters)
2. FragChain_Module_Specifications.md — Module M6 (updated with novelty filters + presets)
3. docs/MODULE_M1_DONE.md through docs/MODULE_M5_DONE.md
4. docs/MODULE_M7_DONE.md  ← M7 must be built before M6 because the
   `not_in_commons` filter requires M7's CommonsClient

We are building Module M6: Intel Ingestion.

This module owns the cves, source_documents, import_jobs, and
import_filter_presets tables. It implements the live + historical CVE
ingestion workflow using whatever connectors are installed via M4.
It does NOT implement specific connectors.

Build:
- Alembic migration: cves, source_documents, import_jobs,
  import_filter_presets tables exactly per Module Specifications M6
- Pydantic models:
  - ImportFilters with ALL fields (basic + novelty) per spec
  - PreviewResult with `approximate` boolean
  - FilterPreset
- fragchain/worker/tasks/ingest.py:
  - ingest_cve(cve_id, import_mode='live')
  - stage_historical_cves(job_id, filters_dict):
    - Stream CVEs from source connectors matching basic filters
    - For each CVE: enrich with EPSS, AttackerKB, CTID if those connectors installed
    - Apply novelty filters AFTER enrichment:
      - epss_min: skip if cve.epss_score < threshold
      - attackerkb_min: skip if cve.attackerkb_score < threshold
      - not_in_commons: call M7 CommonsClient.check_chain_exists(cve_id), skip if found
    - Skipped CVEs marked processing_status='skipped' in same job
    - Increment import_jobs.skipped_count appropriately
  - poll_connectors() — scheduled, calls source connectors' stream_new()
  - enforce_budget() — every 5 min, respects rate limits
- fragchain/worker/tasks/enrich.py:
  - enrich_cve(cve_id) — only runs if processing_status='pending'
  - Calls M4 ConnectorOrchestrator.enrich_cve() to fan out
  - Transitions: pending → enriching → synthesizing (sets up M11)
  - On error: → failed with processing_stage + processing_error
- API endpoints (CVE):
  - GET /api/v1/cves (filters: kev, status, date, cvss, import_mode)
  - GET /api/v1/cves/{cve_id}
  - POST /api/v1/cves/{cve_id}/reprocess
- API endpoints (Import — preview & start):
  - POST /api/v1/imports/preview:
    - Accept ImportFilters
    - If `published_within_days` set: compute date_from = now - N days
    - Fetch matching CVEs from installed source connectors (basic filters only)
    - For sample (10 CVEs): also apply novelty filters by enriching them
      ad-hoc and filtering
    - Return total_count + approximate flag (true if novelty filters active)
      + sample + estimated_llm_cost_usd
  - POST /api/v1/imports/start (create job, queue stage_historical_cves)
  - GET /api/v1/imports (list jobs)
  - GET /api/v1/imports/{id}
  - GET /api/v1/imports/{id}/staged
  - POST /api/v1/imports/{id}/approve | approve-kev | approve-all | skip
  - DELETE /api/v1/imports/{id}
- API endpoints (Filter Presets):
  - GET /api/v1/imports/presets (list, optionally sort by use_count)
  - POST /api/v1/imports/presets (create custom)
  - PATCH /api/v1/imports/presets/{id} (only is_builtin=false)
  - DELETE /api/v1/imports/presets/{id} (only is_builtin=false)
  - POST /api/v1/imports/presets/{id}/use (increment use_count)
- Webhook receiver:
  - POST /api/v1/webhooks/connector/{name}
  - hmac.compare_digest token verification against connector's
    webhook_secret in connector_state.config
  - Returns 200 immediately, queues ingest_cve async
- WebSocket events emitted: cve_ingested, enrichment_complete,
  rate_limit_warning, budget_status
- Seed scripts:
  - scripts/seed_dirty_frag.py — CVE-2026-43284 with import_mode='live'
  - scripts/seed_filter_presets.py — seeds 6 built-in presets per M6 spec:
    "Last 30 days KEV", "Critical Novel", "Linux Kernel — Last Quarter",
    "High EPSS Without Coverage", "Pre-patch Potential", "May 2026"

Do not build:
- Specific connectors (M25+)
- Chain synthesis (M11)
- Coverage mapping (M14)
- UI for import manager (M23 will consume these APIs)

Done criteria:
- Webhook POST with correct token → 200, queues task
- Webhook POST with bad token → 403
- Historical import: preview returns sample (mock connector if needed)
- Import flow: preview → start → staged → approve → enrichment runs
- AUTO_PROCESS_KEV=true auto-approves KEV CVEs at staging
- Rate limit verified: 11th CVE in same hour queues instead of dropping
- Budget enforcement task runs and dequeues approved CVEs respecting limits
- CVE-2026-43284 created by seed script, lands in pending state
- State machine transitions logged to audit_log
- TLP propagates correctly from connector to CVE record
- Embargo handling: connector setting embargo_until on a CVE makes it
  inaccessible to non-participants

Novelty filter done criteria:
- published_within_days=30 filters correctly (date_from computed automatically)
- epss_min=0.5 excludes CVEs below threshold during staging
- attackerkb_min=3.0 excludes CVEs below threshold during staging
- not_in_commons=true excludes CVEs already in M7's commons sources
- Preview returns approximate=true when any novelty filter is active
- Sample of 10 CVEs in preview is accurately filtered with all filters

Preset done criteria:
- 6 built-in presets seeded with is_builtin=true
- Custom preset creation works (is_builtin=false)
- Cannot PATCH or DELETE is_builtin=true presets (returns 400)
- Preset use_count increments correctly
- Listing presets supports sort=popular query param

When complete, write docs/MODULE_M6_DONE.md and stop.
```

---

## M7 — Commons Sources

```
Read fully before doing anything else:
1. CLAUDE.md — Section 7 (Intelligence Commons)
2. FragChain_Module_Specifications.md — Module M7
3. FragChain_Ecosystem_Architecture.md — commons design
4. docs/MODULE_M1_DONE.md, docs/MODULE_M2_DONE.md

We are building Module M7: Commons Sources.

Configurable multi-source intelligence commons. Operators can configure
multiple commons sources (public default, internal private, partner
feeds). Bootstrap, sync, contribute workflows.

Build:
- Alembic migration: commons_sources table with default row pointing at
  github.com/fragchain/fragchain-intelligence (priority=0, trust_level=community)
- fragchain/commons/bootstrap.py — runs on first startup or manual trigger
- fragchain/commons/sync.py — hourly delta sync
- fragchain/commons/contribute.py — creates GitHub/GitLab PRs
- fragchain/commons/sources.py — multi-source orchestration with priority
  + trust-level conflict resolution
- Celery tasks:
  - sync_commons_source(source_id) — hourly per source
  - bootstrap_commons() — first-run import
- API endpoints:
  - GET/POST/PATCH/DELETE /api/v1/commons/sources
  - POST /api/v1/commons/sources/{id}/sync (manual)
  - POST /api/v1/commons/sources/{id}/test (connectivity)
  - GET /api/v1/commons/status
- Provides interface for M11 to consume:
  CommonsClient.check_chain_exists(cve_id) → AttackChain | None
- For development: if the public commons repo doesn't exist yet, mock the
  GitHub API responses so M11 can develop against a known-good stub

Do not build:
- The actual fragchain-intelligence repo (that's M35)
- Settings UI for managing commons sources (M24)
- Contribution UI on Chain Viewer (M20)

Done criteria:
- Default commons source seeded in DB
- Bootstrap fetches release pack (mock for now if public commons not ready)
- Sync task runs hourly without errors
- Adding internal commons source via POST works with token auth
- Conflict resolution test: same chain in two sources, higher priority + trust wins
- check_chain_exists() returns AttackChain for known CVE, None for unknown
- Contribution: PR creation API call works (mock GitHub API for tests)

When complete, write docs/MODULE_M7_DONE.md and stop.
```

---

# PHASE 3 — VECTOR + PROMPTS

---

## M8 — Vector Store

```
Read fully before doing anything else:
1. CLAUDE.md — Section 4.2 (Qdrant local)
2. FragChain_Module_Specifications.md — Module M8
3. docs/MODULE_M1_DONE.md, docs/MODULE_M5_DONE.md, docs/MODULE_M6_DONE.md

We are building Module M8: Vector Store.

Qdrant collections (LOCAL — no fragchain_ prefix), embedding pipeline,
RAG retrieval. Uses M5 LLM Provider for embeddings (LiteLLM routes to
nomic-embed-text on Server 1 Ollama).

Build:
- fragchain/vector/collections.py:
  - Lifespan hook that creates 4 collections at app startup if absent:
    - source_chunks (768 dim, Cosine, payload: cve_id, source_document_id,
      chunk_index, quality_score, source_type, url, tlp)
    - sigma_rules (same dims, payload per CLAUDE.md)
    - attack_chains (same dims)
    - attck_techniques (same dims)
  - NO collection prefix (Qdrant is local now)
- fragchain/vector/embedder.py — VectorEmbedder class:
  - embed_source_document(id) → chunk + embed + upsert, mark embedded=True
    - 512 tokens per chunk, 50 overlap (tiktoken cl100k_base)
    - Filter chunks < 50 tokens
  - embed_sigma_rule(id) → single embed of title+technique_ids+yaml[:500]
  - search_source_chunks(query, cve_id, limit=20) → list[ChunkResult]
  - search_sigma_rules(description, limit=5) → list[SigmaSearchResult]
  - search_attck_techniques(query, limit) → list[TechniqueResult]
- Celery tasks:
  - embed_source_document(source_doc_id) — called from M6 enrich_cve
  - embed_sigma_rule(rule_id) — called from M12 sigma source parse
- Update M6 enrich_cve to queue embed_source_document for each new doc
- Setup script: scripts/seed_attck_techniques.py
  - Downloads enterprise-attack.json STIX bundle from mitre-attack GitHub
  - Parses ~400 techniques, embeds them, upserts to attck_techniques collection
  - ALSO inserts each technique into coverage_map table with status='no_data'
    (this seeds the full ATT&CK matrix even before any chain exists)
  - Idempotent (skip if collection already populated)
- API endpoints (admin):
  - GET /api/v1/vector/collections (stats)
  - POST /api/v1/vector/embed/{source_doc_id} (manual re-embed)
  - POST /api/v1/vector/search (debug search)
- Update /api/v1/health to check Qdrant connectivity

Do not build:
- LLM synthesis (M11)
- Coverage mapping (M14)
- Sigma rule embedding logic for existing rules (M12 wires this up)

Done criteria:
- All 4 collections created in local Qdrant at app startup
- ATT&CK seed populates attck_techniques (verify count ~200-400)
- coverage_map table has all ATT&CK techniques with status='no_data'
- Embedding pipeline produces vectors for CVE-2026-43284 source docs
- search_source_chunks returns relevant results scored by similarity
- /health shows qdrant: ok
- No fragchain_ prefix anywhere in collection names

When complete, write docs/MODULE_M8_DONE.md and stop.
```

---

## M9 — Prompt Management

```
Read fully before doing anything else:
1. CLAUDE.md — Section 15 (Prompt Management)
2. FragChain_Module_Specifications.md — Module M9
3. docs/MODULE_M1_DONE.md, docs/MODULE_M5_DONE.md

We are building Module M9: Prompt Management.

Runtime-managed prompts with versioning, A/B testing, evaluation.
Different LLM models need different prompts.

Build:
- Alembic migration: prompt_templates, prompt_evaluations, prompt_ab_tests
- fragchain/prompts/store.py — PromptStore class:
  - get_active(task_type, target_model, target_provider) → PromptTemplate
  - Falls back to wildcard '*' model if no specific match
  - Caches active prompts in memory, invalidates on update
- fragchain/prompts/eval.py — PromptEvaluator class:
  - run(template_id, benchmark_set) → PromptEvaluation
  - Benchmark sets defined as JSON files in benchmarks/
  - Initial benchmark: benchmarks/dirty_frag_groundtruth.json
    (uses chains/CVE-2026-43284.json as the truth, runs prompt against it)
  - Measures: technique_overlap, ordering_consistency, hallucination_count,
    cost_per_run, avg_latency_ms
- fragchain/prompts/ab.py — ABTestRouter class:
  - select_variant(task_type, model) returns A or B based on traffic_split
- Default prompts seeded via scripts/seed_prompts.py:
  - chain_generation v1 for target_model='*'
  - rule_generation v1 for target_model='*'
  - coverage_verify v1 for target_model='*'
  - Use the prompt content from prompts/chain_v1.txt etc. if it exists,
    otherwise start fresh
- API endpoints:
  - GET /api/v1/prompts (filter by task_type, target_model)
  - GET /api/v1/prompts/{id}
  - POST /api/v1/prompts (create new version)
  - PATCH /api/v1/prompts/{id} (creates new version, doesn't mutate)
  - POST /api/v1/prompts/{id}/activate
  - GET /api/v1/prompts/{id}/diff/{other_id}
  - POST /api/v1/prompts/{id}/eval (run against benchmark)
  - GET /api/v1/prompts/benchmarks
  - POST /api/v1/prompts/ab (start A/B test)
  - GET /api/v1/prompts/ab
  - POST /api/v1/prompts/ab/{id}/conclude

Do not build:
- Prompts UI (M24)
- Actually using prompts in synthesis (M11 consumes this module)

Done criteria:
- Three default prompts seeded, all active
- PromptStore.get_active('chain_generation', 'claude-opus-4-6', 'litellm')
  returns the wildcard chain_generation v1
- New prompt version creation increments version, doesn't mutate old
- Only one prompt can be active per (task, model, provider) — verify by test
- Diff between versions works
- Evaluation runs prompt against dirty_frag_groundtruth benchmark and
  returns valid scores
- A/B routing splits traffic correctly when test is active

When complete, write docs/MODULE_M9_DONE.md and stop.
```

---

# PHASE 4 — SYNTHESIS

---

## M10 — Chain Schema & Ground Truth

```
Read fully before doing anything else:
1. CLAUDE.md — Section 11 (Attack Chain Schema)
2. FragChain_Module_Specifications.md — Module M10
3. docs/MODULE_M1_DONE.md

We are building Module M10: Chain Schema & Ground Truth.

Pydantic schema for chains + ground truth fixtures. Small module but
critical contract — every chain-producing/consuming module references this.

Build:
- fragchain/chain/schema.py — Pydantic models exactly per CLAUDE.md Section 11:
  - SourceRef
  - ChainTTP (validators: technique_id regex, source_refs min_length=1)
  - AttackChain (overall_confidence range, chain min_length=1)
  - Custom validator: seq_order must be 1..N sequential, no gaps
- Alembic migration: attack_chains table, chain_ttps table per CLAUDE.md
- Ground truth fixtures:
  - chains/CVE-2026-43284.json — hand-validated Dirty Frag chain
    (use the existing version from the previous design docs as a starting
    point, or create fresh per CLAUDE.md guidance — T1078 → T1068 → T1548 → T1014)
  - chains/README.md explaining purpose and how to add fixtures
- scripts/validate_chains.py — validates all chains/*.json against schema

Do not build:
- Chain generator (M11 consumes this)
- API endpoints (M11 adds them)
- UI (M20)

Done criteria:
- Schema validates correctly against CVE-2026-43284.json fixture
- Schema rejects invalid examples (technique_id format wrong, empty
  source_refs, gaps in seq_order, confidence out of range)
- attack_chains and chain_ttps tables migrate cleanly
- python scripts/validate_chains.py passes for all fixtures

When complete, write docs/MODULE_M10_DONE.md and stop.
```

---

## M11 — Chain Synthesis

```
Read fully before doing anything else:
1. CLAUDE.md — Sections 11 + 12 (Schema + Pipeline)
2. FragChain_Module_Specifications.md — Module M11
3. docs/MODULE_M5_DONE.md, docs/MODULE_M7_DONE.md, docs/MODULE_M8_DONE.md,
   docs/MODULE_M9_DONE.md, docs/MODULE_M10_DONE.md

We are building Module M11: Chain Synthesis.

This is the heart of the platform. RAG-augmented LLM chain generation,
with commons-first check to skip LLM when chain already exists.

Build:
- fragchain/chain/generator.py — ChainGenerator class:
  - generate(cve_id) → AttackChain
  - Step 1: Check commons via M7 CommonsClient.check_chain_exists()
    - If found: store as source_origin='commons', commons_chain_id=X,
      skip LLM, queue map_coverage
    - If not: continue to LLM synthesis
  - Step 2: Load CVE + ctid_techniques + structured enrichment
  - Step 3: RAG via M8 VectorEmbedder.search_source_chunks(
            query=f"{cve_id} exploitation TTPs", cve_id, limit=20)
  - Step 4: Budget chunks by token count (sort by quality, fill 55k tokens)
  - Step 5: Load active prompt via M9 PromptStore.get_active(
            'chain_generation', model=LITELLM_CHAT_MODEL, provider='litellm')
  - Step 6: Build prompt with structured context + document context blocks
  - Step 7: Call M5 LiteLLMProvider.complete()
  - Step 8: Parse JSON (strip ``` fences), validate against AttackChain schema
  - Step 9: Retry on validation failure (max 2, append errors to prompt)
  - Step 10: Apply TLP propagation: chain.tlp = max_tlp(*[s.tlp for s in sources])
  - Step 11: Store attack_chains + chain_ttps rows
  - Step 12: Queue map_coverage.delay(chain_id) for M14
- fragchain/worker/tasks/synthesize.py:
  - synthesize_chain(cve_id) — calls generator
  - State transitions: synthesizing → mapping → (M14 takes over)
  - On error: → failed with stage and error
- API endpoints:
  - GET /api/v1/chains (filters: status, min_confidence, cve_id)
  - GET /api/v1/chains/{id} (full chain with TTPs + source_refs)
  - GET /api/v1/cves/{cve_id}/chain
  - PATCH /api/v1/chains/{id}/validate
  - PATCH /api/v1/chains/{id}/reject
  - POST /api/v1/chains/{id}/contribute (via M7)
  - POST /api/v1/cves/{cve_id}/resynthesize
- scripts/eval_chain.py — runs generator against CVE-2026-43284,
  compares to chains/CVE-2026-43284.json:
  - Reports: technique overlap %, ordering consistency, hallucinations
  - Exit 0 if overlap ≥ 80% AND hallucinations ≤ 2
- WebSocket events: chain_generated, chain_skipped_using_commons
- Update M6 enrich_cve to queue synthesize_chain on enrichment complete

Do not build:
- Coverage mapping (M14)
- Rule generation (M15)
- Chain Viewer UI (M20)

Done criteria:
- CVE-2026-43284 generates a chain (or skips via commons)
- Generated chain has ≥80% technique overlap vs ground truth (eval_chain.py exits 0)
- A fresh CVE that's not in commons generates a chain successfully
- A CVE that IS in commons skips LLM entirely (verify via llm_interactions count)
- All chain TTPs have non-empty source_refs
- TLP correctly propagates from source documents to chain
- Failed validation retries with error feedback, eventually surfaces ChainGenerationError
- llm_interactions logged + MinIO I/O stored

When complete, write docs/MODULE_M11_DONE.md and stop.
```

---

# PHASE 5 — COVERAGE & RULES

---

## M12 — Sigma Integration

```
Read fully before doing anything else:
1. CLAUDE.md — Section 13 (Sigma Integration)
2. FragChain_Module_Specifications.md — Module M12
3. docs/MODULE_M1_DONE.md, docs/MODULE_M8_DONE.md

We are building Module M12: Sigma Integration.

Configurable multi-source (read existing rules) + multi-target (write
approved rules). Operators can have several Sigma repos.

Build:
- Alembic migration: sigma_sources, sigma_targets, sigma_rules tables
  per CLAUDE.md
- fragchain/sigma/sources.py:
  - SigmaSourceClient.refresh_all() — clones/pulls each enabled source
  - parse_all_rules() — walks rules/**/*.yml, parses, upserts sigma_rules
    (status='merged', origin='imported')
  - Queues M8 embed_sigma_rule for each parsed rule
  - Pre-seed one default source: SigmaHQ public repo
- fragchain/sigma/targets.py:
  - SigmaTargetClient.submit_rule(rule, target) — creates PR via GitHub/GitLab API
  - RoutingEngine.select_target(rule) — applies routing_rules JSONB conditions
    Example rules:
      {"if": "tlp == 'tlp:clear' AND level == 'critical'", "target_name": "production"}
      {"if": "fragchain.generated", "target_name": "staging"}
- Celery tasks:
  - refresh_sigma_sources() — every 6 hours
  - submit_rule_to_target(rule_id, target_id)
- API endpoints:
  - GET/POST/PATCH/DELETE /api/v1/sigma/sources
  - GET/POST/PATCH/DELETE /api/v1/sigma/targets
  - POST /api/v1/sigma/sources/{id}/refresh (manual pull)
  - POST /api/v1/sigma/targets/{id}/test (verify connectivity)
- gitpython for local clone management (data/sigma-repos/{source_id}/)
- httpx for GitHub/GitLab REST API calls

Do not build:
- Coverage mapping (M14)
- Rule generation (M15)
- Settings UI for sources/targets (M24)
- Review queue approval (M16)

Done criteria:
- Default SigmaHQ source seeded
- Refresh task clones repo, parses N rules, upserts to sigma_rules table
- Each imported rule queued for embedding
- Routing engine correctly selects target based on rule conditions
- Test PR creation works against a test repo (use a sandbox repo for testing)
- Adding internal source via API works with token auth

When complete, write docs/MODULE_M12_DONE.md and stop.
```

---

## M13 — Logsource Profiles

```
Read fully before doing anything else:
1. CLAUDE.md — Section 13 (Logsource Profiles subsection)
2. FragChain_Module_Specifications.md — Module M13
3. docs/MODULE_M1_DONE.md

We are building Module M13: Logsource Profiles.

Per-platform rule generation profiles. Built-in profiles for Linux +
Windows + Network. Consumed by M15 Rule Generator.

Build:
- Alembic migration: logsource_profiles table
- fragchain/profiles/store.py — ProfileStore class:
  - get_enabled() → list[LogsourceProfile]
  - get(name) → LogsourceProfile
  - build_prompt_context(profile) → dict with example rules, fields,
    naming conventions ready for LLM prompt insertion
- scripts/seed_profiles.py — populates 7 built-in profiles on first run:
  - linux-auditd (enabled by default)
  - linux-sysmon
  - linux-falco
  - windows-security (enabled by default)
  - windows-sysmon
  - network-zeek
  - network-suricata
  - Each with sigma_product, sigma_service, field_conventions (JSONB),
    example_rules (JSONB with 2-3 hand-crafted examples per profile)
- API endpoints:
  - GET /api/v1/profiles
  - GET /api/v1/profiles/{id}
  - POST /api/v1/profiles (custom profile)
  - PATCH /api/v1/profiles/{id} (only is_builtin=false ones)
  - POST /api/v1/profiles/{id}/enable | disable

Do not build:
- Rule generation (M15 consumes this)
- Profiles UI (M24)

Done criteria:
- 7 built-in profiles seeded with is_builtin=true
- linux-auditd and windows-security enabled by default, others disabled
- get_enabled() returns 2 profiles initially
- Custom profile creation works
- build_prompt_context() returns dict with product, service, field
  conventions, and 2-3 example rules
- Cannot modify is_builtin=true profiles (returns 400)

When complete, write docs/MODULE_M13_DONE.md and stop.
```

---

## M14 — Coverage Mapper

```
Read fully before doing anything else:
1. CLAUDE.md — Section 12 (Detection Pipeline Flow) including priority scoring
2. FragChain_Module_Specifications.md — Module M14
3. docs/MODULE_M5_DONE.md, docs/MODULE_M8_DONE.md, docs/MODULE_M11_DONE.md, docs/MODULE_M12_DONE.md

We are building Module M14: Coverage Mapper.

Two-phase comparison of chain TTPs against existing Sigma rules. Produces
full ATT&CK matrix data structure for the UI.

Build:
- fragchain/coverage/mapper.py — CoverageMapper class:
  - map_coverage(chain_id) → CoverageReport
  - Phase 1: PostgreSQL exact tag match
    SELECT id FROM sigma_rules WHERE technique_ids @> ARRAY[technique_id]
    AND status='merged'
  - Phase 2: Qdrant semantic search for uncovered techniques
    - Embed query: "{technique_id} {technique_name} detection in {tactic}"
    - Search sigma_rules collection, top 5, score > 0.75
    - For each candidate: cheap M5 LLM call:
      "Does this Sigma rule detect {technique_id}? Title: {t}, Detection: {d}.
       Answer: yes | partial | no"
    - Batch these LLM calls (asyncio.gather, max 10 in flight)
  - Priority scoring per gap (CLAUDE.md Section 12):
    +30 kev, +20 cvss>=9, +20 epss>=0.5, +15 epss>=0.2, +15 poc,
    +10 attackerkb>=3.5, +10 seq_order<=3, +5*shared_count
- fragchain/coverage/matrix.py — MatrixCache:
  - get_matrix_data(framework='attck', filters) → MatrixData
  - Redis cache key: matrix:{framework}:{hash(filters)}, TTL 3600s
  - Invalidate on: new chain, new merged rule
  - Returns MatrixData with tactics → techniques → coverage info
- Celery tasks:
  - map_coverage(chain_id) — called from M11 synthesize_chain
    Transitions: mapping → generating (sets up M15)
  - refresh_matrix_cache() — every 1 hour, pre-warms cache
- API endpoints:
  - GET /api/v1/coverage (full data)
  - GET /api/v1/coverage/{technique_id}
  - GET /api/v1/matrix (matrix data with filters: framework, cve_id,
    date_from, date_to, cvss_min, kev_only) — uses Redis cache
  - GET /api/v1/matrix/{technique_id}
- WebSocket events: coverage_mapped, matrix_updated

Do not build:
- Rule generation (M15)
- ATT&CK Matrix UI (M21)

Done criteria:
- CVE-2026-43284 coverage report shows correct covered/partial/gap split
- Matrix data returns all 14 tactics with technique cells
- All ~400 techniques present in coverage_map (seeded in M8)
- Cells without chain CVE data show coverage_status='no_data'
- Phase 2 semantic search verified against test fixtures
- Priority scores calculated correctly per spec
- Redis cache populated, hits on second call
- Cache invalidates on new chain insert

When complete, write docs/MODULE_M14_DONE.md and stop.
```

---

## M15 — Rule Generator

```
Read fully before doing anything else:
1. CLAUDE.md — Sections 12 + 14 (Pipeline + Sigma Rule Format)
2. FragChain_Module_Specifications.md — Module M15
3. docs/MODULE_M9_DONE.md, docs/MODULE_M11_DONE.md, docs/MODULE_M13_DONE.md, docs/MODULE_M14_DONE.md

We are building Module M15: Rule Generator.

Generates Sigma v2 YAML for each coverage gap, one variant per enabled
logsource profile. So one TTP might produce a linux-auditd rule AND a
windows-sysmon rule.

Build:
- fragchain/rules/validator.py — pySigma wrapper:
  - ValidationResult(valid, errors, warnings)
  - validate_yaml(yaml_str) — never raises, always returns Result
- fragchain/rules/generator.py — RuleGenerator class:
  - generate_rule(chain_id, gap, profile) → SigmaRule
  - generate_all_gaps(chain_id, coverage_report) → list[SigmaRule]
  - Per gap × per enabled profile (M13):
    - Load TTP detail, adjacent TTPs, top 3 source docs
    - Load active prompt via M9 ('rule_generation', model, 'litellm')
    - Build prompt with M13 ProfileStore.build_prompt_context(profile)
    - Call M5 LiteLLMProvider.complete()
    - Parse YAML, validate via pySigma
    - Retry on invalid (max 2), append errors to prompt
    - Build rule with mandatory tags:
      attack.<tactic>, attack.<tid>, cve.<cve>, fragchain.generated,
      tlp.<level>, logsource.profile.<profile_name>
    - Generate fresh sigma_uuid (UUID4)
    - Insert sigma_rules (status='generated', origin='fragchain')
    - Insert review_queue with priority_score from M14
- Celery task: generate_rules(chain_id) — called from M14 map_coverage
  Transitions: generating → complete on success, → failed on error
- API endpoints:
  - POST /api/v1/cves/{cve_id}/regenerate-rules
  - POST /api/v1/matrix/{technique_id}/generate-rule (manual trigger)
  - GET /api/v1/rules (filters: status, technique, origin, logsource_profile)
  - GET /api/v1/rules/{id}
  - POST /api/v1/rules/{id}/validate (pySigma)
- WebSocket events: rules_ready
- Invalidate matrix cache after rules generated

Do not build:
- Review Queue logic (M16)
- Sigma target submission / PR creation (M12 already built it, M16 calls it)
- UI (M22)

Done criteria:
- Coverage gaps for CVE-2026-43284 generate at least one rule per gap × enabled profile
- All generated rules pass pySigma validation (validator.valid = true)
- Multi-profile: if linux-auditd AND windows-security enabled, both variants
  produced for the same TTP (verify by checking sigma_rules count)
- All mandatory tags present on generated rules
- Failed validation triggers retry with errors in prompt
- After 2 failed retries, rule stored with review_notes flagging issue
- Review queue receives rules ordered by priority_score DESC

When complete, write docs/MODULE_M15_DONE.md and stop.
```

---

## M16 — Review Queue

```
Read fully before doing anything else:
1. CLAUDE.md — Sections 13 (Sigma Integration) + 14 (Rule Format)
2. FragChain_Module_Specifications.md — Module M16
3. docs/MODULE_M12_DONE.md, docs/MODULE_M15_DONE.md

We are building Module M16: Review Queue.

Human-in-the-loop validation. Analyst sees rule + evidence, approves
(creates Git PR via M12), edits + approves, or rejects.

Build:
- Alembic migration: review_queue table
- fragchain/queue/manager.py — QueueManager class:
  - approve(item_id, user, target_id=None) → SigmaRule
    - If no target_id: use M12 RoutingEngine.select_target(rule)
    - Update rule status='under_review' → 'approved'
    - Call M12 SigmaTargetClient.submit_rule(rule, target)
    - Update rule with git_pr_url, git_commit_sha, merged_at
    - Update queue item status='approved', completed_at=now
    - Update matrix cache invalidation
  - reject(item_id, user, reason) → SigmaRule
    - Update rule status='rejected', queue status='rejected'
    - Record reason in audit_log
  - edit_and_approve(item_id, user, new_yaml, target_id=None) → SigmaRule
    - Validate new_yaml via M15 pySigma validator
    - If valid: update sigma_yaml, then approve flow
    - If invalid: return errors, do not approve
- API endpoints:
  - GET /api/v1/queue (filters: priority, status, assigned_to)
  - GET /api/v1/queue/{id} — includes:
    - The sigma_rule + parsed YAML
    - CVE context, chain context (adjacent TTPs), top 3 source docs
    - Similar existing rules from Qdrant (semantic search)
    - Priority breakdown from M14
  - PATCH /api/v1/queue/{id}/assign
  - POST /api/v1/queue/{id}/approve
  - POST /api/v1/queue/{id}/reject
  - POST /api/v1/queue/{id}/edit (save YAML + validate + approve)
- WebSocket events: rule_approved, rule_rejected, git_pr_created

Do not build:
- Review Queue UI (M22)
- Sigma Library UI (M22)

Done criteria:
- Pending rules listed by priority_score DESC
- Approve creates real Git PR (test against sandbox repo), returns PR URL
- Reject records reason in audit_log
- Edit + approve: invalid YAML returns errors with HTTP 400, valid succeeds
- After action, queue item status updated correctly
- Matrix cache invalidates after approval

When complete, write docs/MODULE_M16_DONE.md and stop.
```

---

## M17 — Rule Evaluations

```
Read fully before doing anything else:
1. CLAUDE.md — none specific (refer to module spec)
2. FragChain_Module_Specifications.md — Module M17
3. docs/MODULE_M7_DONE.md, docs/MODULE_M16_DONE.md

We are building Module M17: Rule Evaluations.

Field efficacy capture. After a rule is deployed, analysts record TP/FP
rates. Aggregated stats expose which rules actually work.

Build:
- Alembic migration: rule_evaluations table per spec
- fragchain/evaluations/store.py — EvaluationStore class:
  - record(rule_id, evaluator, results) → RuleEvaluation
  - aggregate(rule_id) → AggregateStats (avg FP/day, platforms tested,
    recommendation level)
- Celery task: prompt_evaluations() — daily, identifies rules approved
  7+ days ago with no evaluation, emits notification (M36 will handle delivery,
  for now just log)
- API endpoints:
  - POST /api/v1/rules/{id}/evaluate (submit evaluation)
  - GET /api/v1/rules/{id}/evaluations
  - GET /api/v1/rules/{id}/evaluations/aggregate
  - POST /api/v1/evaluations/{id}/contribute (via M7 to commons)
- Update CLAUDE.md audit_log for evaluation submissions

Do not build:
- Evaluation UI (M22)
- Notification delivery (M36)

Done criteria:
- Evaluation submission creates row with all required fields
- Aggregate stats correctly compute average FP rate from multiple evaluations
- Recommendation level computed: production_ready (avg FP < 1, count >= 3),
  needs_tuning (FP 1-5), problematic (FP >= 5)
- Contribution to commons creates PR (via M7)
- Daily prompt task identifies rules without evaluation correctly

When complete, write docs/MODULE_M17_DONE.md and stop.
```

---

# PHASE 6 — FRONTEND

---

## M18 — Frontend Core

```
Read fully before doing anything else:
1. CLAUDE.md — Section 16 (UI Design DarkOps v3)
2. FragChain_Module_Specifications.md — Module M18
3. docs/MODULE_M1_DONE.md, docs/MODULE_M2_DONE.md, docs/MODULE_M5_DONE.md
4. darkops_design_system_v3.html — extract CSS into frontend/src/styles/darkops.css

We are building Module M18: Frontend Core.

Shared infrastructure: API client, WebSocket, auth, layout shell components.
The DarkOps v3 sidebar+topbar layout pattern.

Build:
- frontend/src/styles/darkops.css — extracted from darkops_design_system_v3.html
- frontend/src/api/client.ts — axios with JWT interceptor, 401 redirect
- frontend/src/api/auth.ts, cves.ts, chains.ts, matrix.ts, queue.ts,
  rules.ts, imports.ts, commons.ts, connectors.ts, prompts.ts, profiles.ts,
  sigma_sources.ts, sigma_targets.ts
- frontend/src/hooks/useAuth.ts, useWebSocket.ts
- frontend/src/components/:
  - AppShell.tsx — Topbar + Sidebar + Main layout from v3
  - Topbar.tsx — logo, search, status indicators, notifications, user menu
    - Status indicators consume /api/v1/health, render colored dots
  - Sidebar.tsx — collapsible, sections, nav items, count badges
    - Persists collapsed state in localStorage
    - Replace placeholder unicode glyphs with Lucide React icons
    - Active item gets left-border accent
  - TLPBadge.tsx — all 5 levels (clear, green, amber, amber+strict, red)
  - EmbargoIndicator.tsx — lock icon + countdown
  - Badge.tsx, StatBlock.tsx, DataTable.tsx
  - Toast.tsx + ToastProvider
  - ProgressBar.tsx
  - ConfirmDialog.tsx
  - Dropdown.tsx — custom dropdown per DarkOps v3 (single + multi-select + search)
  - Sidebar slide-in panel (right-side detail panels)
- frontend/src/screens/Login.tsx — full implementation
- frontend/src/App.tsx — React Router with all 10 routes + login
  - Route guard: redirect to /login if no JWT

Do not build:
- Actual screen content for other screens (each screen has its own module)
- Connector marketplace UI logic (M24)
- Real data fetching beyond /health and /auth/login

Done criteria:
- All DarkOps v3 CSS variables present in darkops.css
- AppShell renders topbar + collapsible sidebar correctly
- Sidebar collapse persists across reloads
- 4 service status indicators show real /health response
- All 10 routes load shells with correct title in context bar
- Login → JWT stored → redirects to /dashboard
- Logout clears JWT, returns to /login
- All components use DarkOps tokens (no inline color values, no Tailwind theme classes)
- npm run build succeeds with zero TS errors
- Mobile viewport: sidebar drawer pattern works below 768px

When complete, write docs/MODULE_M18_DONE.md and stop.
```

---

## M19 — Dashboard

```
Read fully before doing anything else:
1. CLAUDE.md — Section 16 (Screens)
2. FragChain_Module_Specifications.md — Module M19
3. docs/MODULE_M6_DONE.md, docs/MODULE_M11_DONE.md, docs/MODULE_M14_DONE.md, docs/MODULE_M16_DONE.md,
   docs/MODULE_M18_DONE.md

We are building Module M19: Dashboard.

Stats, mini ATT&CK heatmap, KEV gap list, live event feed, review queue preview.

Build:
- frontend/src/screens/Dashboard.tsx
- Stat grid (5 blocks via StatBlock component):
  - CVEs / 24hr — query: GET /api/v1/cves?published_after=24h_ago
  - Sigma coverage % — query: GET /api/v1/coverage (compute covered/total)
  - Pending review — query: GET /api/v1/queue?status=pending
  - KEV gaps — query: GET /api/v1/coverage with kev_exposed filter
  - Staged CVEs — query: GET /api/v1/cves?status=staged
- Mini ATT&CK heatmap (abbreviated):
  - 14 tactics × top 8 techniques per tactic
  - Color cells per coverage_status
  - Click cell → navigate to /matrix with technique pre-selected
- Review queue preview (right column, top 5):
  - Priority badge, CVE ID (mono accent), technique ID, time in queue
  - "View all →" link to /queue
- KEV gap list (bottom, max 5):
  - Red-bordered cards, CVE ID + description + CVSS badge
  - Banner above list if staged KEV CVEs exist: "X KEV CVEs staged"
    with link to /imports
- Live event feed:
  - useWebSocket hook subscribed to /ws/events
  - Renders last 8 events at top of feed area
  - New event animates in (slide from top)

Do not build:
- Other screens
- Backend API changes

Done criteria:
- All 5 stats display real data
- Stats refresh via WebSocket when relevant events fire
- Heatmap renders, click navigation works
- Review queue preview shows top 5 sorted by priority_score
- KEV gap list shows real KEV-exposed gap CVEs
- Live event feed updates in real-time
- All screens use DarkOps tokens (no overrides)

When complete, write docs/MODULE_M19_DONE.md and stop.
```

---

## M20 — CVE Explorer + Chain Viewer

```
Read fully before doing anything else:
1. CLAUDE.md — Section 16 (Screens)
2. FragChain_Module_Specifications.md — Module M20
3. docs/MODULE_M6_DONE.md, docs/MODULE_M11_DONE.md, docs/MODULE_M18_DONE.md

We are building Module M20: CVE Explorer + Chain Viewer.

Two screens. CVE Explorer is a filterable table. Chain Viewer is a
React Flow directed graph of the attack chain.

Build:
- frontend/src/screens/CVEExplorer.tsx:
  - DataTable with columns: CVE ID (mono accent link), CVSS (badge colored),
    KEV badge, import mode, processing status, confidence (progress bar),
    rule count, published date (mono)
  - Filter sidebar: date range, CVSS min, KEV toggle, status multi-select,
    source filter (Live | Historical | All)
  - Click row → slide-in detail panel:
    - CVE summary, processing timeline (state machine progress)
    - OpenCTI attack patterns (technique badges)
    - Source documents list (url, type badge, quality progress bar)
    - Chain summary + "View Chain →" link
    - Rule count + "View Rules →" link

- frontend/src/screens/ChainViewer.tsx:
  - Install @xyflow/react and dagre (for layout)
  - URL param: /chains/:cve_id
  - Load chain via GET /api/v1/cves/{cve_id}/chain
  - React Flow graph, dagre LR layout
  - Tactic-colored nodes per CLAUDE.md Section 16:
    - TA0001/02 → --accent border + 12% opacity bg
    - TA0003/06/08/09/11 → --accent2 border + 12% bg
    - TA0004/05 → --warning border + 12% bg
    - TA0010/40 → --danger border + 12% bg
    - TA0007 → --text-dim border + 12% bg
  - Node content: technique_id (mono 11px), technique_name (12px truncated 20ch)
  - Node opacity reflects confidence (0.5 confidence = 0.65 opacity, etc.)
  - Edges: arrows, color from source node border, label: seq_order
  - Click node → slide-in TTP detail sidebar:
    - Technique ID + name, tactic + framework badges
    - Confidence progress bar
    - Preconditions list
    - Detection opportunity text
    - Source evidence: links to source documents
  - Context bar shows: CVE ID, overall confidence bar, model, prompt version
    - "RE-SYNTHESIZE" button (confirm dialog → POST /resynthesize)

Do not build:
- Other screens
- Backend changes
- Chain validation flow (that's M22 logic)

Done criteria:
- CVE Explorer table renders all CVEs with correct filtering
- Detail sidebar shows full CVE context
- Chain Viewer renders CVE-2026-43284 graph correctly (4-5 nodes)
- Tactic colors per spec, on right nodes
- Click node opens detail with source evidence
- Re-synthesize button triggers API + refreshes graph

When complete, write docs/MODULE_M20_DONE.md and stop.
```

---

## M21 — ATT&CK Matrix UI

```
Read fully before doing anything else:
1. CLAUDE.md — Section 16 (Screens — Matrix)
2. FragChain_Module_Specifications.md — Module M21
3. docs/MODULE_M14_DONE.md, docs/MODULE_M18_DONE.md

We are building Module M21: ATT&CK Matrix UI.

Full MITRE ATT&CK matrix with 4 view modes. The defining screen of FragChain.

Build:
- frontend/src/screens/ATTACKMatrix.tsx at route /matrix
- Context bar:
  - 4 view mode buttons (toggle, one active):
    - CHAIN EXPOSURE (default)
    - DETECTION COVERAGE
    - GAP ANALYSIS
    - KEV FOCUS
  - Framework toggle (3-way): ATT&CK | ATLAS | SPARTA
    - ATLAS and SPARTA show "Coming in post-v1" if framework data not present
  - Filters button → slide-in filter sidebar:
    - CVE filter (text), date range, CVSS min, KEV toggle
  - Export CSV button
- Main canvas (full-bleed, padding 0):
  - 14 tactic columns (header: tactic name uppercase, technique count)
  - Vertical layout: techniques as rows within each tactic column
  - Cell dimensions: min 80px × 32px, 2px gap
  - Cell content: technique_id (mono 9px top-left), truncated name (10px)
  - Sub-technique indicator: "(+N)" if has children
  - Click parent technique → expand to show sub-techniques inline

- View mode color logic:
  CHAIN EXPOSURE:
    intensity by chain_cve_count: 0=surface2, 1=accent 12%, 2=22%,
    3-5=35%, 6-10=55%, 10+=75% with bright text
    KEV indicator: 3px red top-border if kev_cve_count > 0
  DETECTION COVERAGE:
    covered=accent3, partial=warning, gap=danger, no_data=surface2
    kev_exposed gap → pulse animation
  GAP ANALYSIS:
    only gap + chain_cve_count>0 lit (danger), everything else dim
    Stat bar above matrix: "X gaps | Y KEV-exposed | Z rules needed"
  KEV FOCUS:
    only kev_cve_count > 0 lit, others dim

- Click cell → right-slide sidebar with TechniqueDetail:
  - Technique ID (mono) + name, badges (tactic, framework, status)
  - Chain Exposure section: list of CVEs (link to /chains/:id),
    CVSS + KEV badges
  - Detection Coverage section: covering rules list, or "GENERATE RULE"
    button if gap (calls POST /api/v1/matrix/{id}/generate-rule)
  - Sub-techniques (if any)
  - External link: View on attack.mitre.org

- Data: GET /api/v1/matrix?framework=attck&filters from M14

Do not build:
- ATLAS or SPARTA framework actual support (post-v1)
- Settings or other screens
- Backend changes

Done criteria:
- All 14 tactics render
- All ~200 techniques render correctly per coverage_map data
- All 4 view modes correctly recolor cells
- Sub-technique expand works
- Click cell opens detail sidebar
- Filters apply correctly (verify with date range, KEV only)
- Generate Rule button in gap detail triggers rule generation
- Export CSV produces valid file with all matrix data

When complete, write docs/MODULE_M21_DONE.md and stop.
```

---

## M22 — Sigma Library + Review Queue UI

```
Read fully before doing anything else:
1. CLAUDE.md — Sections 13 (Sigma) + 14 (Rule Format) + 16 (Screens)
2. FragChain_Module_Specifications.md — Module M22
3. docs/MODULE_M15_DONE.md, docs/MODULE_M16_DONE.md, docs/MODULE_M17_DONE.md, docs/MODULE_M18_DONE.md

We are building Module M22: Sigma Library + Review Queue UI.

Two related screens. Library browses all rules. Review Queue is split-pane
YAML editor + evidence for analyst approval workflow.

Build:
- frontend/src/screens/SigmaLibrary.tsx at /rules:
  - DataTable: title (40ch truncated), technique tags (.badge.accent2,
    max 3 shown), logsource (mono product/service), status badge,
    origin badge (fragchain.generated/manual/imported), level badge,
    CVE link (mono if present), date (mono)
  - Filter sidebar: status multi-select, technique ID search,
    logsource product, origin, level, date range
  - Click row → slide-in detail:
    - Full Sigma YAML in CodeMirror (read-only, JetBrains Mono, dark theme)
    - Metadata: sigma_uuid (mono), author, tags list, references
    - Linked CVE → link to /chains/:cve_id if present
    - Evaluations section (from M17): list + aggregate stats + "Add Evaluation" button
    - Validate button (re-runs pySigma)
    - Copy YAML button

- frontend/src/screens/ReviewQueue.tsx at /queue:
  - Split pane (60/40):
  - LEFT: CodeMirror 6 YAML editor
    - @codemirror/lang-yaml, @uiw/react-codemirror
    - JetBrains Mono, dark theme (one-dark customized to DarkOps)
    - Live validation: debounced 600ms POST /api/v1/rules/{id}/validate
    - Bottom bar: --accent3 "Valid" or --danger "X errors" with details
  - RIGHT: Evidence panel:
    - CVE context card (ID, CVSS, KEV, published, products)
    - Chain context card:
      - "Step {seq} of {total}", current technique
      - ← Previous TTP | Next TTP →
      - Detection opportunity (from chain_ttps)
    - Source evidence card: source docs with quality bars + excerpts
    - Similar existing rules card (semantic search results)
    - Priority breakdown card (score + reasons list)
  - Context bar:
    - CVE ID (mono), technique (mono), priority badge, time in queue
    - ← N-1 | N+1 → queue navigation
    - Target selector dropdown (M12 sigma_targets, default = routing-engine pick)
  - Action buttons below editor:
    - APPROVE → (.btn.success.active) → POST /approve with target_id
    - EDIT + APPROVE (.btn.active) → POST /edit
    - REJECT (.btn.danger) → inline reason input → confirm
  - After action: auto-advance to next queue item

- Evaluation submission dialog (from Sigma Library "Add Evaluation"):
  - Form: TP count, FP/day, environment platform, scale, notes
  - Submit → POST /api/v1/rules/{id}/evaluate
  - Toast on success, "Contribute to commons?" follow-up dialog

Do not build:
- Other screens
- Backend changes

Done criteria:
- Sigma Library lists all rules with filtering
- Detail sidebar shows full YAML + metadata + evaluations
- Review Queue split pane functional
- Live YAML validation shows errors as you type
- Approve creates Git PR, returns URL in success toast
- Auto-advance after action
- Target selector defaults to routing engine pick but allows override
- Evaluation form submits and toast confirms

When complete, write docs/MODULE_M22_DONE.md and stop.
```

---

## M23 — Import Manager UI

```
Read fully before doing anything else:
1. CLAUDE.md — Section 10 (CVE Import Strategy)
2. FragChain_Module_Specifications.md — Module M23
3. docs/MODULE_M6_DONE.md, docs/MODULE_M18_DONE.md

We are building Module M23: Import Manager UI.

Two-tab screen for live feed monitoring and historical CVE import workflow.

Build:
- frontend/src/screens/ImportManager.tsx at /imports
- Tab navigation: "LIVE FEED" | "HISTORICAL IMPORT"

LIVE FEED tab:
- Stat blocks (4):
  - Live CVEs today
  - Processing rate (CVEs/hour, last hour)
  - Rate limit status (X/MAX with progress bar, color by %)
  - Queue depth (pending CVEs)
- Live event log (WebSocket, last 20):
  - Row: timestamp (mono), event type badge, CVE ID (mono), status
  - Event types emitted by the backend (see fragchain/api/routers/websocket.py):
    cve_ingested, enrichment_complete, rate_limit_warning, budget_status,
    chain_generated, chain_skipped_using_commons, coverage_mapped,
    rules_generated, queue_item.* (assign/approve/reject/submit),
    import_job.created, import_job.staged, webhook.received
    (each gets an appropriate badge color)
- Config card:
  - Current MAX_LIVE_CVE_PER_HOUR value
  - AUTO_PROCESS_KEV toggle (writes to system_config)

HISTORICAL IMPORT tab:
- "SAVED PRESETS" dropdown at top of tab:
  - Loads from GET /api/v1/imports/presets (sort by use_count DESC)
  - Built-in presets shown first, then custom presets
  - Selecting preset → pre-fills the filter form below
  - "Save current as preset" button → modal: name + description + save
  - "Manage presets" link → modal to edit/delete custom presets
- Collapsible "NEW IMPORT" card:
  - Filters form (organized in two sections):
    BASIC FILTERS:
    - Date range: from/to (date pickers)
    - "Or last N days" shortcut input (sets published_within_days)
    - Min CVSS: dropdown (Any, 6.0+, 7.0+, 8.0+, 9.0+, 10.0)
    - KEV only: toggle button (.btn / .btn.active)
    - Vendor/Product: text input with autocomplete
    - Specific CVE IDs: textarea (one per line, overrides other filters)
    NOVELTY FILTERS (collapsible section, "Show advanced filters"):
    - Min EPSS score: dropdown (Any, 0.1+, 0.2+, 0.5+, 0.8+)
    - Min AttackerKB score: dropdown (Any, 2.0+, 3.0+, 4.0+)
    - Exclude CVEs already in commons: toggle button
  - "PREVIEW" button (.btn.ghost):
    - Loading state: "QUERYING SOURCES..."
    - On response → preview panel:
      - "X CVEs match" (or "~X CVEs match (approximate)" if novelty filters active)
      - Estimated LLM cost ~$X.XX
      - Sample table (10 rows): CVE ID, CVSS, KEV, EPSS, published
      - If approximate: small info note "Final staged count may be lower
        after novelty filtering during staging"
      - Warning toast if count > 500
  - "START IMPORT" button (.btn.active, disabled until preview ran):
    - Creates job, calls POST /api/v1/imports/presets/{id}/use if using preset
    - Collapses form, shows toast
- "ACTIVE JOBS" card:
  - DataTable: Job ID (mono short), Created, Filters summary, Staged/Approved/Done counts,
    Status badge, Progress bar (approved/staged ratio)
  - Status badges: staging, staged, processing, complete, cancelled
  - Click row → inline expand panel:
    - Staged CVEs table (paginated 20/page):
      - CVE ID (mono link), CVSS, KEV badge, Published, Status badge
      - Approve (.btn.sm.success) + Skip (.btn.sm.danger.ghost) per row
    - Batch actions bar:
      - APPROVE ALL (.btn.active)
      - APPROVE KEV ONLY (.btn.accent2)
      - SKIP ALL (.btn.danger.ghost)
    - Filter tabs: All | Staged | Approved | Processing | Complete | Skipped
    - Budget warning banner when approving + daily budget approaching:
      "X CVEs approved. Daily budget: Y remaining. Excess will process tomorrow."

Do not build:
- Backend (M6 already has the API)
- Other screens

Done criteria:
- LIVE FEED stats update via WebSocket
- Rate limit progress bar colors correctly per threshold
- Preview returns count + sample from real OpenCTI (or mock)
- Start Import creates job, appears in Active Jobs
- Expand active job shows staged CVEs
- Approve flow moves CVEs to pending → pipeline runs
- KEV-only approve works
- Budget warning appears at correct threshold
- All form controls use DarkOps tokens

When complete, write docs/MODULE_M23_DONE.md and stop.
```

---

## M24 — Settings + Marketplace UI

```
Read fully before doing anything else:
1. CLAUDE.md — Section 16 (Screens — Settings + Marketplace)
2. FragChain_Module_Specifications.md — Module M24
3. docs/MODULE_M4_DONE.md, docs/MODULE_M7_DONE.md, docs/MODULE_M9_DONE.md, docs/MODULE_M12_DONE.md,
   docs/MODULE_M13_DONE.md, docs/MODULE_M18_DONE.md

We are building Module M24: Settings + Marketplace UI.

Catch-all configuration screen plus connectors marketplace plus prompts
management sub-screen.

Build:
- frontend/src/screens/Settings.tsx at /settings
- Left nav within settings (sub-routes):
  - Connectors
  - Commons Sources
  - Sigma Sources
  - Sigma Targets
  - Logsource Profiles
  - Processing Limits
  - Notifications
  - AI Providers

Each section uses .card with .card-title header and DarkOps form components.

CONNECTORS section:
- List installed connectors with health status (green/amber/red dot)
- Per-connector: enable/disable toggle, config form
- "Install New Connector" button → opens Marketplace modal/sidebar
- Marketplace:
  - Browse fragchain-registry entries
  - Filter by type (source_stream | enrichment), official badge
  - Each entry: name, description, version, maintainer
  - Install button (runs pip install via backend subprocess + prompts for restart)

COMMONS SOURCES section:
- List configured sources with priority + trust_level
- Add new source form
- Test Connection button per source

SIGMA SOURCES + SIGMA TARGETS sections:
- Same pattern: list, add, edit, test connection
- For Targets: routing_rules JSON editor (CodeMirror)

LOGSOURCE PROFILES section:
- List built-in + custom profiles
- Enable/disable toggles per profile
- "Add Custom Profile" form (cannot edit built-ins)

PROCESSING LIMITS section:
- Form: MAX_LIVE_CVE_PER_HOUR, MAX_HISTORICAL_CVE_PER_DAY,
  OPENCTI_POLL_MAX_PER_RUN, AUTO_PROCESS_KEV toggle

NOTIFICATIONS section:
- Slack webhook URL (masked), test button
- Generic webhook URL (masked), test button
- (Email deferred to M36)

AI PROVIDERS section:
- List installed LLM providers (v1: just LiteLLM)
- LiteLLM config: URL, key (masked), chat model, embedding model
- Test Connection button

Plus a separate /prompts route — Prompts Management screen:
- frontend/src/screens/Prompts.tsx
- List prompt templates grouped by task_type × target_model
- Per template: version history, active toggle, eval results
- Click template → detail view:
  - YAML/text editor for prompt + user template (CodeMirror)
  - Version history list, diff view between versions
  - "Create New Version" button
  - Evaluation panel:
    - Run evaluation against benchmark set
    - Show technique overlap, hallucinations, cost, latency
- A/B test management:
  - List active tests, traffic split, current winner if any
  - Start new test form
  - Conclude test button

Do not build:
- Other screens
- Backend changes

Done criteria:
- All settings sections render and save changes correctly
- Connectors marketplace browses registry, install triggers pip install
- Test Connection buttons work for each external service
- Routing rules editor validates JSON, saves correctly
- Custom logsource profile creation works
- Prompts screen lists all prompts with version history
- Prompt diff view shows correctly
- Evaluation run displays results
- A/B test creation and conclusion works

When complete, write docs/MODULE_M24_DONE.md and stop.
```

---

# PHASE 7 — CONNECTOR ECOSYSTEM (Separate Repos)

Each connector is its own GitHub repository and PyPI package. The prompts
below are slightly different because they create independent repos.

---

## M25 — fragchain-connector-opencti

```
Create a NEW REPO: fragchain-connector-opencti (separate from fragchain-core).

Read before starting:
1. CLAUDE.md from fragchain-core repo (you'll need a copy)
2. FragChain_Module_Specifications.md — Module M25
3. The IntelConnector Protocol from fragchain-core/fragchain/connectors/base.py

We are building Module M25: fragchain-connector-opencti.

This is a Python package that implements IntelConnector and is installable
via `pip install fragchain-connector-opencti`. fragchain-core discovers it
via the fragchain.connectors entry point.

Build:
- Repo: github.com/fragchain/connector-opencti
- pyproject.toml with:
  [project.entry-points."fragchain.connectors"]
  opencti = "fragchain_connector_opencti:OpenCTIConnector"
- fragchain_connector_opencti/connector.py — OpenCTIConnector class:
  - name = "opencti"
  - type = SOURCE_STREAM
  - output = BOTH (structured + documents)
  - default_output_tlp = TLP.GREEN
  - max_output_tlp = TLP.AMBER
  - GraphQL client for OpenCTI (use aiohttp)
  - stream_new(since, limit): paginated query for Vulnerabilities,
    rate-limited (10 req/min), cursor stored externally by fragchain-core
  - get_cve(cve_id): single vulnerability fetch
- README.md with setup, .env vars, OpenCTI permission requirements
- LICENSE: Apache 2.0
- Tests: pytest with mocked OpenCTI responses
- CI workflow (.github/workflows/test.yml + release.yml for PyPI publish)
- Implement against the fragchain-connector-testkit (a separate small
  package fragchain-core publishes for connector validation —
  if not yet published, write your own minimal tests)

Do not build:
- Anything that belongs in fragchain-core
- Other connectors

Done criteria:
- Package installable via pip
- pip install fragchain-connector-opencti registers it as a connector
- Running fragchain-core with this connector installed: it appears in
  /api/v1/connectors
- stream_new() pulls Vulnerability objects from a live OpenCTI instance
- Rate limit verified (10 req/min)
- Tests pass with mocked OpenCTI

When complete, write docs/MODULE_M25_DONE.md and stop.
```

---

## M26 — fragchain-connector-nvd2

```
Same pattern as M25. Create repo: fragchain-connector-nvd2.

This connector is SOURCE_STREAM, default_output_tlp=tlp:clear.

Build the connector that fetches CVEs directly from NVD 2.0 API
(https://services.nvd.nist.gov/rest/json/cves/2.0):
- Pagination support
- NVD_API_KEY optional (.env or config), enables higher rate limit
- Rate limit: 5 req/30s without key, 50 req/30s with key

For deployments without OpenCTI, this connector provides direct CVE feed.

Implementation pattern matches M25.

When complete, write docs/MODULE_M26_DONE.md and stop.
```

---

## M27 — fragchain-connector-epss

```
Same pattern. Repo: fragchain-connector-epss. Type: ENRICHMENT.
default_output_tlp=tlp:clear.

Build:
- API: https://api.first.org/data/v1/epss?cve={cve_id}
- Supports batch fetch: ?cve=CVE-A,CVE-B,CVE-C
- enrich_cve(cve_id) → returns EnrichmentResult with structured fields:
  epss_score, epss_percentile, fetched_at
- bulk_enrich(cve_ids) → batched lookup (max 100 per request)
- No auth needed, generous rate limit
- Daily refresh task pattern (if exposing a hook)

When complete, write docs/MODULE_M27_DONE.md and stop.
```

---

## M28 — fragchain-connector-ctid

```
Same pattern. Repo: fragchain-connector-ctid. Type: ENRICHMENT.
default_output_tlp=tlp:clear.

Build:
- Downloads CVE→ATT&CK mappings from
  github.com/center-for-threat-informed-defense/attack_to_cve
- Stores locally (config: data path), refreshes weekly
- enrich_cve(cve_id) → returns ctid_techniques list with technique_id,
  tactic_id, confidence, source
- bulk_enrich(cve_ids) → fast in-memory lookup

When complete, write docs/MODULE_M28_DONE.md and stop.
```

---

## M29 — fragchain-connector-kev

```
Same pattern. Repo: fragchain-connector-kev. Type: ENRICHMENT.
default_output_tlp=tlp:clear.

Build:
- Downloads CISA KEV catalog:
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- Cached locally with 24hr refresh
- enrich_cve(cve_id) → if in KEV: returns dateAdded, dueDate,
  requiredAction, notes, knownRansomwareCampaignUse, vendorProject, product

When complete, write docs/MODULE_M29_DONE.md and stop.
```

---

## M30 — fragchain-connector-attackerkb

```
Same pattern. Repo: fragchain-connector-attackerkb. Type: ENRICHMENT.

Build:
- API: https://attackerkb.com/api/v1
- enrich_cve(cve_id):
  - Search topics by CVE ID, then fetch assessments
  - Returns: attacker_value, exploitability, summary text, references
- Rate limit: 30 req/min, no auth for public data

When complete, write docs/MODULE_M30_DONE.md and stop.
```

---

## M31 — fragchain-connector-exploitdb

```
Same pattern. Repo: fragchain-connector-exploitdb. Type: ENRICHMENT.

Build:
- Search: https://www.exploit-db.com/search?cve={cve_id}
- Fetch description/writeup (NOT raw exploit code)
- enrich_cve(cve_id) → list of exploit metadata + description doc
- Use trafilatura for HTML extraction
- Quality score: 0.88 if exploit exists

When complete, write docs/MODULE_M31_DONE.md and stop.
```

---

## M32 — fragchain-connector-osssecurity

```
Same pattern. Repo: fragchain-connector-osssecurity. Type: ENRICHMENT.

Build:
- Scrapes oss-security mailing list archive: openwall.com/lists/oss-security/
- Searches recent months (current + 2 prior) for CVE ID in thread subjects
- Fetches matching thread pages, extracts message bodies
- Only fetches if CVE affects Linux/open source (check affected_products
  for linux, debian, ubuntu, redhat, kernel, etc.)
- quality_score: 0.92 (researcher-written technical content)

When complete, write docs/MODULE_M32_DONE.md and stop.
```

---

## M33 — fragchain-connector-github

```
Same pattern. Repo: fragchain-connector-github. Type: ENRICHMENT.

Build:
- GitHub Search API for "{cve_id} exploit OR poc OR proof-of-concept"
- Plus GHSA lookup: api.github.com/advisories?cve_id={cve_id}
- GITHUB_TOKEN optional in config (higher rate limits)
- Filter repos pushed after CVE published_at - 30 days
- Score by stars + has_readme + name contains 'poc'

When complete, write docs/MODULE_M33_DONE.md and stop.
```

---

## M34 — Vendor Advisory Connectors

```
Three separate repos, all same pattern. Type: ENRICHMENT.
default_output_tlp=tlp:clear.

M34a — fragchain-connector-vendor-redhat
  - API: https://access.redhat.com/labs/securitydataapi/cve/{cve_id}.json
  - Free, no auth
  - Trigger: only if CVE affects redhat/rhel

M34b — fragchain-connector-vendor-msrc
  - https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}
  - Or CVRF API by month
  - Trigger: only if CVE affects microsoft

M34c — fragchain-connector-vendor-ubuntu
  - https://ubuntu.com/security/cves/{cve_id}.json
  - Free, no auth
  - Trigger: only if CVE affects ubuntu/canonical

Each is its own repo with its own DONE file. Build one at a time:
M34a → M34_VENDOR_REDHAT_DONE.md
M34b → M34_VENDOR_MSRC_DONE.md
M34c → M34_VENDOR_UBUNTU_DONE.md
```

---

# PHASE 8 — POLISH

---

## M35 — Commons Repository Setup

```
Create a NEW REPO: fragchain-intelligence (separate from fragchain-core).

Read before starting:
1. CLAUDE.md from fragchain-core
2. FragChain_Module_Specifications.md — Module M35
3. FragChain_Ecosystem_Architecture.md — commons repo design

We are building Module M35: fragchain-intelligence repo.

Build:
- Repo: github.com/fragchain/fragchain-intelligence
- Directory structure per FragChain_Ecosystem_Architecture.md:
  chains/, mappings/, rules/, evaluations/, snapshots/, benchmarks/,
  releases/, .github/
- Seed content:
  - chains/2026/CVE-2026-43284.json (hand-validated Dirty Frag chain from
    fragchain-core/chains/)
  - 10-20 additional reference chains for high-profile CVEs
    (KEV catalog top entries, well-documented exploitation)
  - mappings/cve_attck_mappings.json (initial dump from CTID dataset)
- README.md explaining what this repo is for
- CONTRIBUTING.md with the workflow from FragChain_Ecosystem_Architecture
- GOVERNANCE.md with maintainership model
- LICENSE files: CC0 1.0 (data) + Apache 2.0 (scripts)
- CI workflows (.github/workflows/):
  - validate_pr.yml — runs schema validation on chain PRs
  - daily_snapshot.yml — pulls EPSS and KEV daily, commits to snapshots/
  - weekly_release.yml — builds intelligence-pack.tar.gz on Fridays,
    creates GitHub release
- METADATA.json with manifest, version, counts, last_update

Validation script in scripts/:
- validate_chain.py — checks chain JSON against AttackChain schema
- check_no_duplicates.py — ensures no duplicate chains for same CVE
- compute_metadata.py — refreshes METADATA.json

After repo is live, update fragchain-core's commons_sources default to
point at this repo URL (already done in M7 but verify).

Do not build:
- Anything in fragchain-core
- New connectors

Done criteria:
- Repo public on github.com/fragchain/fragchain-intelligence
- 10+ chains committed and CI-validated
- Mappings file present
- First weekly release pack downloadable
- README/CONTRIBUTING/GOVERNANCE clear
- M7 bootstrap successfully imports from this repo

When complete, write docs/MODULE_M35_DONE.md and stop.
```

---

## M36 — Notifications

```
Read fully before doing anything else:
1. CLAUDE.md — operational guidance
2. FragChain_Module_Specifications.md — Module M36
3. docs/MODULE_M1_DONE.md, docs/MODULE_M16_DONE.md

We are building Module M36: Notifications.

Multi-channel notification delivery for pipeline events.

Build:
- Alembic migration: notification_channels table
- fragchain/notifications/channels.py:
  - SlackChannel — POST to webhook URL with formatted message
  - WebhookChannel — generic POST JSON to configured URL
  - EmailChannel — SMTP (optional, defer if SMTP config not in v1 scope)
- Event router — subscribes to WebSocket events + matches against
  channel.event_filter, dispatches to each matching channel
- API endpoints:
  - GET/POST/PATCH/DELETE /api/v1/notifications/channels
  - POST /api/v1/notifications/channels/{id}/test (send test message)
- Settings UI integration: M24 already has the Notifications section,
  this module wires the backend
- Events to deliver:
  - rules_ready (with CVE ID, rule count, top priority, link)
  - kev_cve_processed
  - budget_warning
  - pipeline_error
  - commons_sync_failed

Done criteria:
- Slack channel test sends formatted message to webhook
- Generic webhook channel test POSTs valid JSON
- Event filter correctly routes events to channels
- Real pipeline event triggers configured notifications

When complete, write docs/MODULE_M36_DONE.md and stop.
```

---

## M37 — Documentation & Onboarding

```
Read fully before doing anything else:
1. All previous MODULE_DONE.md files (read enough to understand the system)
2. FragChain_Module_Specifications.md — Module M37

We are building Module M37: Documentation & Onboarding.

Operator-facing documentation. The thing that lets a new user install
and use FragChain without asking us questions.

Build the following docs in docs/:

- README.md (main repo root) — what is FragChain, quick start in 5 commands
- docs/installation.md — full walkthrough:
  - Prerequisites (Docker, Server 1 with LiteLLM running)
  - Clone, configure .env, run setup.sh
  - First boot, verify health
  - Default admin login
- docs/configuration.md — every .env variable documented with examples
- docs/litellm-setup.md — comprehensive guide:
  - Setting up LiteLLM on Server 1
  - Configuring LiteLLM to route to Ollama (for nomic-embed-text embeddings)
  - Configuring LiteLLM to route to OpenAI (chat completions)
  - Configuring LiteLLM to route to Anthropic (chat completions)
  - Cost tracking via LiteLLM
  - Multi-provider setup
- docs/connectors.md:
  - How connector plugin system works
  - Installing official connectors
  - Building a custom connector (link to fragchain-connector-template if created)
- docs/commons.md — how the intelligence commons works, contributing
- docs/sigma-targets.md — configuring Sigma source/target repos, routing rules
- docs/prompts.md — managing prompts, A/B testing, evaluation
- docs/troubleshooting.md — common issues, log locations, debugging
- docs/architecture.md — high-level architecture overview with diagrams

In-app help integration:
- Add "Help" link in topbar
- Open contextual docs based on current screen
- Initial implementation: just opens GitHub docs index in new tab

Done criteria:
- Following docs/installation.md, a new operator can install FragChain
  end-to-end on a clean server
- LiteLLM setup guide tested with Ollama + OpenAI + Anthropic
- Every config variable documented
- All key workflows documented
- Help link in UI works

When complete, write docs/MODULE_M37_DONE.md and stop.
```

---

# DEFERRED (Post-v1) — For Reference

These prompts are sketches for when you eventually build them.
Not needed for v1.

## M38 — Identity & Trust (Full Implementation)

Replaces M3's placeholders with real verification. GPG-based identity,
trust attestations, signed contributions, web of trust visualization.
See `FragChain_TLP_and_Identity.md` for full spec when ready to build.

## M39, M40, M41 — Direct LLM Providers

Separate packages: fragchain-provider-openai, fragchain-provider-anthropic,
fragchain-provider-ollama. Each implements LLMProvider Protocol. Pattern
mirrors connectors. Operators install the ones they want, configure in
Settings → AI Providers, optionally bypass LiteLLM.

## M42, M43 — ATLAS, SPARTA Frameworks

Add framework support beyond ATT&CK. Mostly data updates — chain schema
already supports `framework` field. Need to seed ATLAS techniques and
SPARTA techniques into coverage_map table, update UI framework toggle.

## M44 — Multi-tenancy & RBAC

Required for commercial SaaS. Organizations, role-based access, per-tenant
isolation, billing hooks.

---

# Final Checklist Before Starting Build

Before pasting the M1 prompt, verify these files exist in your project root:

- [ ] CLAUDE.md
- [ ] FragChain_Module_Specifications.md
- [ ] FragChain_Build_Workflow.md
- [ ] FragChain_Module_Prompts.md (this file)
- [ ] darkops_design_system_v3.html
- [ ] Optional reference: FragChain_Product_Design_Final.md,
      FragChain_Ecosystem_Architecture.md, FragChain_TLP_and_Identity.md

You're ready to build. Open Claude Code in a fresh session, paste the M1
kickoff prompt, and begin.

Good luck. Build well.
