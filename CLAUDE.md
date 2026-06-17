# CLAUDE.md — FragChain
**Version:** 3.0 — Wave 1 reliability + credibility (2026-06-11; supersedes 2.9)
**Read this fully before writing any code, making any decision, or touching any file.**

**What changed from 2.9 → 3.0:** Wave 1 landed — backend reliability (W1a) + frontend credibility (W1b). **Loop-run lifecycle is now supersede-at-success:** `begin_run` creates the new `assessment_loop_run` row `is_active=false, status='running'`; only an output-bearing finalize (`succeeded`/`gate_failed`) demotes the prior active row to `status='superseded'`, activates the new row, and invalidates downstream runs — a `failed` run never advances assessment state, never demotes the prior good output, never invalidates downstream. Migration `0026` makes the one-active-per-`(assessment, loop)` invariant a DB-enforced UNIQUE partial index (`uq_assessment_loop_run_active`, resolving pre-existing duplicates). New/real settings: `GATE_MIN_CATEGORIES` (was a hardcoded `=3` constructor default neither factory passed — now in `fragchain/config.py` and wired through both orchestrator factories); `LOOP2_PASS_TIMEOUT_SECONDS` (default 150, startup-validated ≥ `LLM_STRUCTURED_TIMEOUT_SECONDS`) bounds each Loop 2 pass; `STALE_INFLIGHT_MAX_SECONDS` (default 1800) drives the new 5-minute beat reaper `assessment.reap_stale_inflight` that fails stale `running`/`generating` rows via atomic conditional updates (a lost broker message can no longer 409-block an assessment). Worker startup hard-fails via `WorkerShutdown` when the expected assessment tasks aren't registered. A Redis pub/sub event bridge (`fragchain/notifications/bridge.py`, channel `fragchain.events`) carries worker-emitted events to API WS subscribers — the workspace's WS-completion refetch is now real (polling stays as fallback; local-only degradation when Redis is down). Cost visibility: `assessment_loop_run.model`/`cost_usd` populated at finalize; `llm_interactions.assessment_id` written for `coverage_assessment`-tagged calls (Loop 3 rule-generation calls are `chain_ttp`-tagged and not attributed there — the run's `cost_usd` does capture them). Frontend: failures now toast instead of vanishing, the assessments client is back on the shared axios instance, and §16's fake affordances are corrected — topbar search (⌘K) is intentionally absent until search exists, the Review Queue badge is a live pending count, the Prompts "A/B" badge is gone. No change to the §12.2 dormant allowlist or §19 rules.

**What changed from 2.8 → 2.9:** documentation-accuracy pass driven by the 2026-06-10 platform architecture review (Appendix D dead/stale-code audit) — **no behavior change**. Corrections: §17 file structure rewritten to match the actual tree (it predated the assessment pivot — now includes the `fragchain/assessments/` package that implements the active flow; removed nonexistent `api/routers/matrix.py`, `api/middleware/auth.py`, `notifications/channels.py`; reflects the real router/hook/screen lists); §15 seeded-prompt list corrected from 3 to the actual 10 task_types in `scripts/seed_prompts.py`; §12.2 `ChainGenerator`/`synthesize.py` rows corrected — the claim "no caller in the active flow" was false: `POST /cves/manual` (live ManualCveAdd screen), `POST /cves/{id}/resynthesize` (chains router), and `ingest/enrichment.py` all dispatch `synthesize_chain` (the entries stay dormant-by-design, but reachability is now documented honestly); §18 stale `aiohttp` mention removed alongside the dependency itself (unused, audit-verified). Companion changes outside this file: `docs/litellm-setup.md` now actually exists (§4.1/README link was broken); dead deps (`aiohttp`, `email-validator`, `python-multipart`, `@codemirror/merge`) and 11 dead frontend API functions removed; new mechanical-truth guards `scripts/verify_doc_claims.py` + `tests/test_dormancy_claims.py` keep doc path/setting references and §12.2 dormancy claims honest. No change to §12.1 behavior, the §12.2 dormant allowlist membership, or §19 rules.

**What changed from 2.7 → 2.8:** ADR-0004 Phase 2b landed — the three non-Sigma artifacts (`mitigation_plan`, `analyst_research_task`, `telemetry_contract`) are now generatable **on demand** from the workspace. New table `generated_artifacts` (migration `0025`): one ACTIVE row per `(assessment_id, artifact_type)` via partial unique index `uq_generated_artifacts_active`; regenerate supersedes (deactivate prior active, insert `version=max+1`); `content` is schema-validated JSONB (`GeneratedArtifactContent`, strict `extra='forbid'`); `plan_recommended` records the advisory router signal; `validation_status` defaults `not_validated` (Phase 3 territory). Service `fragchain/assessments/artifact_generation.py` splits `begin_generation` (sync precheck, 409 on already-generating) from headless-callable `ArtifactGenerator.generate` (one `structured_complete` call over Loop 1/2 + classification + plan context; advisory — marks its own row failed, never raises), mirroring the Plan A pattern; the Celery task `assessment.generate_artifact` is idempotent and emits `assessment.artifact.generated`. New endpoints `POST/GET /assessments/{id}/artifacts` (202 dispatch / newest-first list); three seeded prompt task_types; Generate buttons on `ArtifactPlanCard` + new `GeneratedArtifactsCard`. Hardening: `fragchain/worker/tasks/__init__.py` now side-effect-imports all assessment tasks — they were previously never registered with the Celery worker (latent Plan A bug, regression-guarded). **Generation is not gated by the plan** — compatibility mode and Loop 3 are unchanged. See §12.1 "Artifact generation" and [docs/superpowers/specs/2026-06-10-phase-2b-artifact-generation-design.md](docs/superpowers/specs/2026-06-10-phase-2b-artifact-generation-design.md). No change to the §12.2 dormant allowlist or §19 rules.

**What changed from 2.6 → 2.7:** loop execution moved off the synchronous API request onto the Celery worker (Plan A). `LoopOrchestrator.run_loop` is split into `begin_run` (sync precheck + create a `status='running'` `assessment_loop_run` row) and `execute_run(run_id)` (worker: LLM work + post-loop hooks + finalize); `run_loop` stays as a convenience wrapper. The loop-run endpoint now returns **202** + the running row and dispatches the worker — fixing the nginx-60s 504 root-caused on a slow gateway. New configurable timeouts `LLM_STRUCTURED_TIMEOUT_SECONDS` / `LITELLM_HTTP_TIMEOUT_SECONDS` (default 120 each); the loops pass the structured timeout to `structured_complete`. The frontend dispatches and refetches on the WS completion event. No schema/migration change (`'running'` is a new value of the existing `status` column). See §12.1 "Worker integration" and [docs/superpowers/specs/2026-06-10-async-loop-execution-design.md](docs/superpowers/specs/2026-06-10-async-loop-execution-design.md). No change to the §12.2 dormant allowlist or §19 rules.

**What changed from 2.5 → 2.6:** ADR-0004 Phase 2 landed in **compatibility mode**. A deterministic `ArtifactRouter` (`fragchain/assessments/artifact_router.py` — pure policy `build_plan`, `POLICY_VERSION="v1"`, **no LLM call**) chains off every successful detectability classification: class guardrails + `ROUTER_MIN_CONFIDENCE` floor (default 0.4) + gate-failed prerequisite produce a `RouterPlan` persisted to `artifact_plans` (migration `0024`, one row per classification). Guardrail overrides of the classifier are recorded in `policy_adjustments`, never silent. After a successful Loop 3 the router records `observed` (rules generated vs `sigma_planned`) and emits `assessment.artifact_plan.diverged` on mismatch. **Generation is still not gated** — Loop 3 behavior is unchanged; divergence records are the evidence for the Phase 2c flip. New endpoint `GET /assessments/{id}/artifact-plan`; `ArtifactPlanCard` renders below the detectability card. Details: [docs/architecture/005-artifact-router.md](docs/architecture/005-artifact-router.md). No change to the §12.2 dormant allowlist or §19 rules.

**What changed from 2.4 → 2.5:** ADR-0004 Phase 1 landed. An **advisory** `DetectabilityClassifier` (`fragchain/assessments/detectability.py`) now runs after every Loop 2 (on `succeeded` and `gate_failed`), producing a 5-class `DetectabilityAssessment` persisted to `detectability_assessments` (migration `0023`) and surfaced via `GET /assessments/{id}/detectability` + a read-only `DetectabilityCard` in the workspace. **Nothing gates yet** — the deterministic category gate remains the sole flow-controller and Loop 3 behavior is unchanged; the schema enforces that `sigma_rule` is explicitly recommended-with-reason or skipped-with-reason. New prompt task_type `detectability_classification` (seeded), new `InteractionType.DETECTABILITY_CLASSIFICATION`. Details: [docs/architecture/004-detectability-classifier.md](docs/architecture/004-detectability-classifier.md). No change to the §12.2 dormant allowlist or §19 rules.

**What changed from 2.3 → 2.4:** the Codex control pack (commit `5f632ec`) set a new product direction — FragChain evolves from a CVE-to-Sigma generator into a **vulnerability defense engineering workbench** (see `AGENTS.md` and [ADR-0002](docs/architecture/adr/ADR-0002-defense-engineering-layer.md)). §1 carries a direction note; adoption is staged per [ADR-0004](docs/architecture/adr/ADR-0004-staged-defense-engineering-adoption.md): Phase 1 adds a `DetectabilityAssessment` classifier alongside (not replacing) the deterministic gate; Phase 2 adds an `ArtifactPlan` router in compatibility mode first; Phase 3 persists validation states and aligns review states. Precedence: **this file remains authoritative**; `AGENTS.md` defers to it. The control-pack placeholders `docs/architecture/000`–`008` are now filled with the real mapping (`001` current architecture, `002` domain-object mapping, `003` pipeline contract). No change to §12.1 behavior, the §12.2 dormant allowlist, or §19 rules in this version.

**What changed from 2.2 → 2.3:** §12.1 brought 1:1 with the shipped code after the correctness pass + coverage redesign — the chain-synthesis bridge now documents synonym normalization + graceful fallback for unmapped `vuln_class` (F7); a new "Coverage verification — embedding-first" subsection documents that the chat-LLM verify is opt-in/off-by-default (`COVERAGE_LLM_VERIFY_ENABLED`, `COVERAGE_VERIFY_MAX_CALLS`) with embeddings deciding coverage, plus post-generation redundancy flagging (`RULE_SIMILARITY_THRESHOLD`, `sigma_rules.similar_to_rule_id`/`similarity_score`); the persistence table lists migrations 0019–0022; §15 reflects the prompt index re-key to `task_type` (migration 0021); the stale `prompt_builder.py` reference is removed. `docs/architecture/COVERAGE_VERIFICATION_DESIGN.md` is superseded (see its banner). No change to the §12.2 dormant allowlist or §19 rules.

**What changed from 2.1 → 2.2:** the M1–M24 build log, the original design corpus, and the post-phase audits moved into [`docs/historical/`](docs/historical/) so the public docs tree leads with active design notes; §20 and §21 now point at the new locations and treat the legacy corpus as preserved-for-context rather than "never existed in tree." No behavior or contract change.

**What changed from 2.0 → 2.1:** §1 acknowledges the assessment workspace as the primary workflow; §12 is now marked dormant and preserves the original linear-pipeline description; new §12.1 documents the active three-loop content engine and §12.2 lists the dormant-by-design code paths; §19 forbids deleting §12.2 paths without an explicit decision; §20 and §21 point at the architecture notes + plans + module-done records that actually exist. See [`docs/historical/RECONCILIATION_2026-05-19.md`](docs/historical/RECONCILIATION_2026-05-19.md) for the full 2.0→2.1 landing summary.

---

## 1. What Is FragChain

FragChain is an open-source **collaborative detection engineering platform** built around an intelligence commons.

It connects threat intelligence sources to a Sigma detection rule repository, uses an LLM to synthesize ordered ATT&CK attack chains from CVE data, maps those chains against existing Sigma rules to identify coverage gaps, and generates draft Sigma v2 detection rules for human review.

**Primary workflow (active):** an **analyst-initiated coverage assessment** drives a three-loop content engine (Loop 1 vulnerability analysis, Loop 2 threat intel, Loop 3 detection engineering) that produces a chain, behavioral indicators, and Sigma rules from sources the analyst pastes into an assessment workspace. The original push-driven pipeline (connector → enrichment → synthesis → coverage → rules) is preserved in tree but dormant — see §12 for the dormant path and §12.1 for the active assessment flow. Decision history: [docs/architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md](docs/architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md) §1–§3.

**Core differentiator:** Community-maintained intelligence commons. New deployments bootstrap from pre-validated chains, rule evaluations, and ATT&CK mappings — no cold start, no redundant LLM synthesis. Every validated chain contributes back. Assessment-produced chains feed the commons via the same contribute flow.

**Direction (2026-06):** FragChain is evolving into a **vulnerability defense engineering workbench** — "given a vulnerability, what can a serious defender realistically detect, hunt, validate, log, mitigate, or operationalize?" Sigma-by-default is being retired: a detectability classifier (5 classes) and an artifact router will gate generation, and **"no reliable detection exists" becomes a valid, successful output**. Scope boundary, target pipeline, and artifact types: `AGENTS.md` + [docs/architecture/000-fragchain-scope.md](docs/architecture/000-fragchain-scope.md). Staged adoption plan: [ADR-0004](docs/architecture/adr/ADR-0004-staged-defense-engineering-adoption.md). Until those phases land, §12.1 below remains the accurate description of shipped behavior.

**License:** Apache 2.0 (engine + connectors) + CC0 1.0 (intelligence commons data)

---

## 2. The Four-Repo Ecosystem

```
fragchain-core              ← THIS REPO. The engine.
fragchain-connectors-*      ← Separate packages per data source (PyPI)
fragchain-providers-*       ← Separate packages per LLM provider (PyPI) — post-v1
fragchain-intelligence      ← Community knowledge commons (default, configurable)
fragchain-registry          ← Index of known connectors and providers
```

**fragchain-core contains NO hardcoded data sources, NO hardcoded LLM access logic, NO hardcoded commons URL, NO hardcoded Sigma repo.** Everything is pluggable or configurable.

Plugins discovered via Python entry points:
- `fragchain.connectors` — data source connectors
- `fragchain.providers` — LLM providers (v1 ships with `litellm` only)

---

## 3. Three-Server Deployment Model

```
Server 1 — AI infrastructure (external, operator-managed)
└── LiteLLM   :4000   ← MANDATORY in v1. Routes to whatever LLMs operator configures
                       (Ollama, OpenAI, Anthropic, Azure, Bedrock, local models)

Server 2 — OpenCTI (optional, accessed via fragchain-connector-opencti)
└── OpenCTI   :443

Server 3 — FragChain (THIS PROJECT)
├── Nginx        :80/:443     (only public ports)
├── FragChain API (FastAPI, internal)
├── FragChain UI (React + DarkOps v2, internal)
├── PostgreSQL    (internal)
├── Redis         (internal)
├── MinIO         (internal)
├── Qdrant        (internal — NOW LOCAL to Server 3)
├── Celery workers + Beat
└── Flower        (internal)
```

**Architecture change from v1:** Qdrant moved INTO Server 3's Docker Compose. No more `fragchain_` collection prefix workaround. FragChain owns its vector data fully.

**v1 mandatory external dependency:** LiteLLM. Operator configures LiteLLM to route to whatever chat + embedding models they choose. FragChain talks to LiteLLM via OpenAI-compatible API.

---

## 4. External Service Configuration

### 4.1 LiteLLM (Server 1) — Required
- Base URL: `$LITELLM_BASE_URL`
- API Key: `$LITELLM_API_KEY`
- Chat model alias: `$LITELLM_CHAT_MODEL` (must be configured in LiteLLM, e.g., maps to claude-opus-4-6)
- Embedding model alias: `$LITELLM_EMBEDDING_MODEL` (e.g., maps to nomic-embed-text via Ollama)

Use OpenAI SDK, NEVER Anthropic SDK directly:

```python
# Correct
from openai import AsyncOpenAI
client = AsyncOpenAI(base_url=settings.LITELLM_BASE_URL, api_key=settings.LITELLM_API_KEY)

# Forbidden
import anthropic
```

LiteLLM setup documentation lives in `docs/litellm-setup.md` with worked examples for Ollama, OpenAI, and Anthropic backends.

### 4.2 Qdrant (Server 3, internal) — Local
- Host: `qdrant` (Docker service name)
- Port: 6333
- API Key: `$QDRANT_API_KEY` (generated by setup.sh)
- **No collection prefix.** Collections named directly: `source_chunks`, `sigma_rules`, `attack_chains`, `attck_techniques`
- 768 dimensions, Cosine distance

### 4.3 OpenCTI (Server 2) — Optional
Accessed via `fragchain-connector-opencti` package. If not installed, platform works without OpenCTI — uses other connectors like NVD2 direct.

---

## 5. Connector Plugin Architecture

### Discovery
```python
import importlib.metadata
connectors = [ep.load() for ep in importlib.metadata.entry_points(group='fragchain.connectors')]
```

Installed connectors auto-register at startup. No config changes when adding connectors — pip install + restart.

### The IntelConnector Protocol

```python
class ConnectorType(Enum):
    SOURCE_STREAM    # produces CVE events (OpenCTI, NVD2, MISP)
    ENRICHMENT       # enriches existing CVEs (EPSS, CTID, AttackerKB, vendor advisories)
    HYBRID

class ConnectorOutput(Enum):
    STRUCTURED  # typed fields
    DOCUMENTS   # text for RAG
    BOTH

class IntelConnector(Protocol):
    name: str
    version: str
    type: ConnectorType
    output: ConnectorOutput
    requires_auth: bool
    rate_limit: RateLimit
    max_output_tlp: TLP
    default_output_tlp: TLP
    supports_embargo: bool
    requires_verified_tier: bool = False    # placeholder, always False in v1
    description: str

    async def health_check() -> ConnectorHealth
    async def initialize(config) -> None
    async def shutdown() -> None
    async def stream_new(since, limit) -> AsyncIterator[CVERecord]      # if SOURCE_STREAM
    async def get_cve(cve_id) -> CVERecord | None                       # if SOURCE_STREAM
    async def enrich_cve(cve_id, cve_data) -> EnrichmentResult | None   # if ENRICHMENT
    async def bulk_enrich(cve_ids) -> dict[str, EnrichmentResult]       # if ENRICHMENT
```

### Failure Isolation
Orchestrator runs all enrichment connectors in parallel with per-connector try/except + timeout. One failure never blocks others. Three failures within window → mark connector unhealthy.

### Official Connectors (built as separate packages)
- `fragchain-connector-opencti`, `-nvd2`, `-epss`, `-ctid`, `-kev`
- `-attackerkb`, `-exploitdb`, `-osssecurity`, `-github`
- `-vendor-redhat`, `-vendor-msrc`, `-vendor-ubuntu`

---

## 6. LLM Provider Plugin Architecture

Mirrors the connector pattern. Same primitives, different domain.

### Discovery
```python
providers = [ep.load() for ep in importlib.metadata.entry_points(group='fragchain.providers')]
```

### The LLMProvider Protocol
```python
class LLMProvider(Protocol):
    name: str                          # 'litellm' (v1), future: 'openai', 'anthropic', 'ollama'
    version: str
    supports_chat: bool
    supports_embeddings: bool
    supports_streaming: bool

    async def complete(system, prompt, model, **kwargs) -> LLMResponse
    async def embed(texts, model) -> list[list[float]]
    async def health_check() -> ProviderHealth
```

### v1 Default
- Ships with `fragchain-provider-litellm` installed
- Operator configures LiteLLM on Server 1 to bridge to whatever LLM
- LiteLLM is the recommended path for v1

### Future (post-v1, deferred modules)
- `fragchain-provider-openai` — direct OpenAI API (M39)
- `fragchain-provider-anthropic` — direct Anthropic API (M40)
- `fragchain-provider-ollama` — direct local Ollama (M41, for air-gapped deployments)

When these land, operators install them via pip and select which provider is active per task (chat vs embeddings).

### Every LLM call is logged
- `llm_interactions` table records provider, model, tokens, cost, latency
- Full prompt + response stored to MinIO: `llm-io/{date}/{interaction_id}.json`
- Used for cost tracking, prompt regression testing, audit

**Note:** logging to `llm_interactions` and MinIO is best-effort. The LLM
response is returned to the caller even if logging fails. Logging failures
surface as `llm.io.minio_write_failed` or `llm.io.db_write_failed` in
structlog — operators monitor those events to detect persistent logging
outages without blocking the chat/embedding path.

---

## 7. Intelligence Commons (Multi-Source Configurable)

### Configurable Sources
Operators can configure multiple commons sources, not just the public default:

```sql
commons_sources (
    name, url, auth_type, auth_credentials_ref,
    sync_enabled, contribute_enabled, priority,
    trust_level     -- 'community' | 'partner' | 'internal'
)
```

Default deployment ships with one entry pointing at `github.com/fragchain/fragchain-intelligence` (public, community). Operators can:
- Add internal/private commons sources (their org's validated chains)
- Add partner commons sources (vetted external organizations)
- Disable the public commons in regulated environments
- Set priority for conflict resolution (higher priority + higher trust wins)

### Bootstrap on Startup
```python
# fragchain/commons/bootstrap.py
async def bootstrap():
    for source in get_enabled_sources_ordered_by_priority():
        release = await get_latest_release(source)
        pack = await download_pack(release.url)
        await import_chains(pack.chains)        # tlp:clear only in public commons
        await import_mappings(pack.mappings)
        await import_epss_snapshot(pack.epss)
```

A fresh deployment becomes useful in minutes (commons imported), not days (LLM synthesis from scratch).

### Sync
Hourly Celery task pulls delta from each enabled source. Conflicts resolved by priority + trust level.

### Contribute
When analyst validates a chain → "Contribute to Commons" → choose which commons source(s) to contribute to → FragChain creates appropriate PR.

### Public Commons = tlp:clear Only
Higher TLP levels stay in deployment-local DB or restricted partner feeds. Public commons is unrestricted by design.

### Commons projection: forward-compat + recursion guard
When projecting a commons chain into the local schema, the engine strips
unknown top-level keys before Pydantic validation so a forward-compatible
commons payload (e.g. one that adds a `provenance` field a future engine
version will model) doesn't crash synthesis. The strict `extra='forbid'`
default on `AttackChain` (§11) still applies to LLM output.

If validation still fails (the payload is genuinely malformed), the
fallback re-enters `ChainGenerator.generate(cve_id, force_skip_commons=True)`.
That flag bypasses the commons check on the recursive call, so the
fallback cannot re-find the same commons row and recurse forever. Phase 5
audit L3 and Phase 4 audit D5 both reported this; the guard now lives in
the generator's `_persist_commons_hit` path.

---

## 8. TLP Classification System

### Levels (TLP 2.0)
- `tlp:clear` — public, no restrictions
- `tlp:green` — limited to community, authenticated users
- `tlp:amber` — org + named partners
- `tlp:amber+strict` — single org only
- `tlp:red` — named participants only

### TLP On Every Contributable Entity
`tlp` field exists on: `cves`, `source_documents`, `attack_chains`, `sigma_rules`.

### Propagation Rules (enforced at write time)
- **Inheritance:** Chain TLP = `max(explicit, max(source.tlp for source in sources))`. Rule TLP = `max(explicit, parent_chain.tlp)`.
- **No silent downgrade:** Only original contributor can downgrade, with recorded reason.
- **Embargo overrides:** If `embargo_until > now()`, effective TLP is `tlp:red`.
- **Connector declarations:** Each connector declares `max_output_tlp` and `default_output_tlp`.

### Enforcement
TLP middleware filters every API response. Never trust the client.

### Default Behaviour
All entities default to `tlp:clear`. Framework only matters when explicitly classified.

---

## 9. Identity & Verification (Placeholder Module in v1)

### Status
Schema exists. Enforcement does NOT. All `/api/v1/identity/*` endpoints return 501. All users default to `tier='authenticated'`, `clearance_level='tlp:green'`.

### Schema in v1 (ready but unused)
- `user_identities` (identity_type, public_key, fingerprint, verification fields)
- `trust_attestations` (attestor, subject, signed attestation)
- `contribution_signatures` (signed contributions)

### IdentityProvider Protocol (interface only in v1)
```python
class IdentityProvider(Protocol):
    name: str
    async def verify(user_id, challenge, signature) -> bool
    async def sign_contribution(user_id, content_hash) -> str

identity_providers = {}  # empty in v1, populated post-v1 by M38
```

### Future Identity Types (deferred)
- GPG (planned primary)
- SSH key signing (deferred)
- Sigstore (future)

---

## 10. CVE Import Strategy

### Two Modes

**Live Feed (automatic):**
- Source: Connector webhooks/streams
- Processing: immediate, no analyst gate
- Rate limit: `MAX_LIVE_CVE_PER_HOUR` (default 10). Excess queued, never dropped.

**Historical Import (manual, analyst-gated):**
- Source: UI Import Manager
- Basic filters: date range, CVSS min, KEV only, vendor/product, specific CVE IDs
- Novelty filters: published_within_days, epss_min, attackerkb_min, not_in_commons
- Saved presets: operators save common filter combinations for reuse
  (e.g., "Last 30 days KEV", "Critical novel without coverage")
- Preview before commit (count + 10 sample + estimated LLM cost)
- CVEs land in `processing_status='staged'` — LLM pipeline waits for approval
- Daily budget: `MAX_HISTORICAL_CVE_PER_DAY` (default 20)
- `AUTO_PROCESS_KEV=true`: bypass staging for KEV CVEs

### Processing State Machine
```
Live:        pending → enriching → synthesizing → mapping → generating → complete
Historical:  staged → (approve) → pending → enriching → ... → complete
                   → (skip)    → skipped
Failure:     → failed (with processing_stage + processing_error)
```

Every transition updates `cves.processing_status` and writes `audit_log`.

---

## 11. Attack Chain Schema (Core Contract)

```python
# fragchain/chain/schema.py

class SourceRef(BaseModel):
    url: str
    source_type: str
    quality_score: float = Field(ge=0.0, le=1.0)
    excerpt_summary: str

class ChainTTP(BaseModel):
    seq_order: int
    tactic: str
    tactic_id: str           # TA####
    technique_id: str        # T#### or T####.### — regex validated
    technique_name: str
    sub_technique_id: Optional[str]
    framework: Literal['attck', 'atlas', 'sparta'] = 'attck'
    confidence: float = Field(ge=0.0, le=1.0)
    preconditions: list[str] = Field(min_length=1)
    detection_opportunity: str
    source_refs: list[SourceRef] = Field(min_length=1)  # REQUIRED

class AttackChain(BaseModel):
    cve_id: str
    version: int = 1
    model: str
    provider: str            # 'litellm' (v1)
    prompt_template_id: Optional[UUID] = None  # references prompt_templates from M9 — required when provider != 'human'
    overall_confidence: float = Field(ge=0.0, le=1.0)
    chain: list[ChainTTP] = Field(min_length=1)
    sources_used: list[SourceRef]
    predicted_impact: str
    detection_gaps: list[str]
    tlp: TLP = TLP.CLEAR
    embargo_until: Optional[datetime] = None
    source_origin: Literal['local', 'commons'] = 'local'
    commons_chain_id: Optional[str] = None
```

**Ground truth:** `chains/CVE-2026-43284.json` — hand-validated Dirty Frag. Use for regression testing prompts.

**Schema strictness + commons forward-compat:** `AttackChain` (and its nested
`ChainTTP` / `SourceRef`) runs with `model_config = ConfigDict(extra="forbid")`.
LLM outputs that introduce an unknown field are rejected loudly so the
operator catches prompt drift. Commons projections (see §7) are different:
when projecting a commons chain into the local schema, the engine strips
top-level keys outside `AttackChain.model_fields` before validation. That
lets a future commons feed add metadata fields without breaking older
engine versions. Validation failures still happen (a structurally broken
commons row will fail) but the fallback uses `force_skip_commons=True` so
recovery routes around the bad row instead of recursing on the same hit.

---

## 12. Linear push pipeline (DORMANT)

This section describes the original connector-driven push pipeline as it was designed in M1–M24. It is **preserved in tree** so the connector ecosystem can be revived without rewriting downstream stages, but it is **not the active flow**. New work goes through the assessment workspace in §12.1.

Why dormant: see [docs/architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md](docs/architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md) §1 — push-driven synthesis depended on a rich connector ecosystem (OpenCTI, AttackerKB, ExploitDB, vendor PSIRT) that doesn't exist yet, and running it against thin NVD-only input produced generic detections. The assessment workspace replaces it as the primary workflow until that connector layer ships. The dormant code remains in tree because (a) live-feed coexistence is a forward-compat requirement (see design note §4.8) and (b) removing it now would force a second rewrite when connectors do come online.

```
Connector webhook → Intel ingestion (TLP from connector)
                          ↓
              Enrichment orchestrator (parallel, isolated)
              All installed enrichment connectors run in parallel
                          ↓
              COMMONS CHECK first
                  ├── Chain exists in any commons source → use directly, skip LLM
                  └── No commons chain → LLM Synthesis (via LiteLLM)
                                          RAG from Qdrant source_chunks
                                          Active prompt from Prompt Management (M9)
                                          Validate ChainSchema
                          ↓
              Attack chain stored (TLP propagated, contribution offered)
                          ↓
              Coverage Mapper
                  Phase 1: Exact ATT&CK tag match (PostgreSQL)
                  Phase 2: Semantic search (Qdrant sigma_rules)
                          ↓
              Rule Generator (multi-profile: Linux + Windows variants)
              pySigma validation (mandatory)
                          ↓
              Review Queue (priority-scored, TLP-tagged)
                          ↓
              Human Approve / Edit / Reject
                          ↓
              Git PR to configured Sigma Target
              (target selected per rule based on routing rules)
```

### Priority Scoring
- +30 if cisa_kev
- +20 if cvss ≥ 9.0
- +20 if epss ≥ 0.50
- +15 if epss ≥ 0.20
- +15 if POC source available
- +10 if attackerkb_score ≥ 3.5
- +10 if seq_order ≤ 3 (early chain stage)
- +5 × count of other CVEs sharing this gap

---

## 12.1. Assessment workspace + three-loop content engine (ACTIVE)

The active flow is analyst-initiated, not connector-pushed. An analyst opens a `coverage_assessment` for a CVE, pastes the source material they consider relevant, and drives the platform through three gated loops to produce a chain, behavioral indicators, and Sigma rules. Connectors stay in the architecture as on-demand lookups; nothing requires them to be installed for the assessment workflow to function.

Canonical reference: [docs/architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md](docs/architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md) (§4 entity model, §5 loop engine). Frontend surface: [docs/architecture/ASSESSMENT_WORKSPACE_FRONTEND_DESIGN.md](docs/architecture/ASSESSMENT_WORKSPACE_FRONTEND_DESIGN.md).

### State machine (`coverage_assessment.state`)

```
created → loop1_done → loop2_done → loop3_done → completed
                              │  (gate failed: re-run, override, or abandon)
                              └──────────────────────────────────────────┘
```

Each new run is a new row in `assessment_loop_run` with `version = max(version)+1`, created `is_active=false, status='running'` (**supersede-at-success**, Wave 1a): only when the run finalizes with real output (`succeeded` or `gate_failed`) does the orchestrator demote the prior active same-loop row to `status='superseded'`, activate the new row, invalidate downstream loop runs, and revert the state to `loop(N)_done`. A `failed` run never advances assessment state, never demotes the prior active output, and never invalidates downstream — a transient LLM failure leaves the previous good run (and the detectability/plan rows that join on it) intact. The already-running guard keys on `status='running'`. State machine implemented in `fragchain/assessments/state_machine.py`; the orchestrator (`fragchain/assessments/orchestrator.py::LoopOrchestrator.run_loop`) enforces it.

### The three loops

| Loop | Purpose | Shape | Code |
|---|---|---|---|
| **Loop 1 — Vulnerability Analysis** | CVE + pasted sources → `VulnProfile` + `DetectionQuestion[]`. Emits no TTPs; the chain is built after Loop 2 from real evidence. | Single-shot LLM call via `structured_complete`. Token-budget truncation drops lowest-priority sources first. | `fragchain/assessments/loops/loop1.py` |
| **Loop 2 — Threat Intel** | Answers Loop 1's detection questions with concrete `BehavioralIndicator`s per `ObservableCategory` (process / command_line / file / network / registry / parent_child / api_call). | Bounded bulk-then-gap orchestration over RAG. Bulk pass dispatches one RAG query per Loop 1 question in parallel and asks the model once; gap pass re-asks for empty categories. Max 2 passes, ≤ 8 RAG calls, `LOOP2_PASS_TIMEOUT_SECONDS` per pass (default 150). No web fetch, no on-demand connector dispatch in v1. | `fragchain/assessments/loops/loop2.py`, `fragchain/assessments/loops/rag.py` |
| **Loop 3 — Detection Engineering** | Generates Sigma rules per enabled profile per TTP gap, grounded in the behavioral indicators. | Single-shot LLM call. Wraps `fragchain/rules/generator.py::RuleGenerator` with `behavioral_indicators` added to prompt context; pySigma validation + review_queue persistence. Gaps come from the embedding-first coverage mapper (see "Coverage verification" below). Generated rules get a fresh `id` (always stamped), exact `content_hash` dedup, and a semantic redundancy flag against the library. | `fragchain/assessments/loops/loop3.py` |

### Detectability gate (deterministic)

Between Loop 2 and Loop 3, a category-coverage gate counts non-empty `ObservableCategory` buckets in Loop 2's output. Threshold: `GATE_MIN_CATEGORIES` (default 3 of 7) — a real setting in `fragchain/config.py` since Wave 1a (previously a hardcoded constructor default that neither factory passed), wired through both the API and worker orchestrator factories to the gate and to Loop 2's gap-pass threshold. On fail the orchestrator stops at `loop2_done`; the analyst can re-run Loop 2 with new sources, override with a recorded rationale (propagated as `low_detectability_override=true` on every Loop-3 rule), or abandon. Implementation: `fragchain/assessments/loops/stubs.py::evaluate_detectability_gate`.

### Detectability classification (advisory, Phase 1 of ADR-0004)

After every Loop 2 run (both `succeeded` and `gate_failed`), the orchestrator invokes `DetectabilityClassifier` (`fragchain/assessments/detectability.py`) — one schema-validated LLM call (task_type `detectability_classification`) that classifies defender-realistic detectability into `directly_detectable` / `indirectly_detectable` / `environment_dependent` / `control_only` / `insufficient_information`, with rationale, confidence, telemetry requirements, blind spots, and recommended/skipped artifact types (v1 vocabulary: `sigma_rule`, `analyst_research_task`, `mitigation_plan`, `telemetry_contract`). The schema rejects output that doesn't explicitly justify Sigma (recommended-with-reason or skipped-with-reason). **Advisory only:** the classifier swallows its own failures, cannot alter loop status/state, and Loop 3 is not gated by it (that's Phase 2's router). Persisted one row per Loop 2 run in `detectability_assessments`; read via `GET /assessments/{id}/detectability`; displayed read-only in the workspace between the Loop 2 and Loop 3 cards. Spec: [docs/architecture/004-detectability-classifier.md](docs/architecture/004-detectability-classifier.md).

### Artifact routing (compatibility mode, Phase 2 of ADR-0004)

When the classifier succeeds, the deterministic `ArtifactRouter` (`fragchain/assessments/artifact_router.py`, **not** an LLM call) applies policy v1 to the classification: class guardrails (`insufficient_information`/`control_only` force-skip Sigma and recommend research-task/mitigation-plan; `environment_dependent` adds a telemetry prerequisite + telemetry contract), a `ROUTER_MIN_CONFIDENCE` floor, and a gate-failed override prerequisite. The resulting `RouterPlan` (recommended/skipped with reasons, `policy_adjustments` for every guardrail override) persists to `artifact_plans` (one per classification). After a successful Loop 3, `observed` records rules-generated vs `sigma_planned`; mismatches emit `assessment.artifact_plan.diverged`. **Compatibility mode: the plan gates nothing** — Loop 3 is unchanged until Phase 2c. Read via `GET /assessments/{id}/artifact-plan`; rendered by `ArtifactPlanCard`. Spec: [docs/architecture/005-artifact-router.md](docs/architecture/005-artifact-router.md).

### Artifact generation (on-demand, Phase 2b of ADR-0004)

The three non-Sigma artifact types (`mitigation_plan`, `analyst_research_task`, `telemetry_contract`) are generatable **on demand**: the analyst clicks Generate on a recommended artifact in `ArtifactPlanCard` (or requests any of the three types directly — generation is **not** gated on assessment state or on the plan; compatibility mode is preserved, and `plan_recommended` merely records the advisory signal). `POST /assessments/{id}/artifacts` runs the sync precheck `begin_generation` (`fragchain/assessments/artifact_generation.py`): supersession (deactivate the prior active row, insert `version=max+1`; one ACTIVE row per `(assessment_id, artifact_type)` enforced by partial unique index `uq_generated_artifacts_active`), plan provenance recorded via the shared `active_plan_stmt`, and a 409-mapped `ArtifactAlreadyGeneratingError` guard if the same type is mid-generation. The endpoint commits the `status='generating'` row, dispatches Celery task `assessment.generate_artifact` (`fragchain/worker/tasks/generate_artifact.py`), and returns **202** + the generating row. The worker calls the headless-callable `ArtifactGenerator.generate`: bounded context assembled from the active Loop 1/2 outputs + detectability classification + artifact plan, one `structured_complete` call producing a strict `GeneratedArtifactContent` (title/summary/headed sections + assumptions/limitations/references/confidence, `extra='forbid'`). The generator is advisory — it marks its own row `failed`, never raises; the task is idempotent on non-`generating` rows with a fresh-session finalize-failed backstop. On finalize it emits `assessment.artifact.generated`; the workspace refetches (WS event + polling fallback) and renders rows in `GeneratedArtifactsCard` (plain text only). `validation_status` defaults to `not_validated` — validation states await Phase 3. Spec: [docs/superpowers/specs/2026-06-10-phase-2b-artifact-generation-design.md](docs/superpowers/specs/2026-06-10-phase-2b-artifact-generation-design.md).

### Chain synthesis bridge (not an LLM call)

After Loop 2 passes the gate, a deterministic builder maps `VulnProfile.vuln_class` + Loop 2 indicators into an `AttackChain` row:

1. `VulnClassMapper._normalize` lowercases the LLM's `vuln_class` and applies a **synonym map** (`mapping.py::_SYNONYMS`) so off-vocabulary phrasings collapse to one of the curated canonical classes — e.g. `race condition`/`use-after-free`/`buffer overflow` → `memory corruption`, `os command injection`/`rce` → `command injection`, `xxe` → `ssrf`.
2. `vuln_class_to_ttps` table → which TTPs cover the (normalized) vuln class.
3. **Graceful fallback (no dead-end):** if the class still maps to no TTPs, the bridge synthesizes a generic exploitation chain (`chain_synthesis.py::_FALLBACK_TTPS` = T1190 + T1203, low base confidence) instead of raising, and flags it via `detection_gaps=["… vuln_class '<x>' unmapped; review TTPs"]` for analyst review. The assessment always completes.
4. `ttp_category_relevance` table → which `ObservableCategory` buckets matter per TTP.
5. Indicators assigned to TTPs by category match; per-TTP confidence from indicator density.
6. Row written with `source_origin='assessment'`, `assessment_id=<id>`, and the legacy `chain` JSONB column populated from the serialized TTP list. Any prior active chain for the same CVE is hard-superseded via `superseded_by_assessment_id` + `superseded_at` (**all** active rows, not just one). The partial unique index `uq_attack_chains_active_per_cve` (migration `0017_assessment_centric`) enforces one active chain per CVE.

Curated tables seeded by `scripts/seed_vuln_class_mappings.py`. Lookup service: `fragchain/assessments/mapping.py::VulnClassMapper`. Bridge: `fragchain/assessments/chain_synthesis.py`.

### Coverage verification — embedding-first (supersedes the LLM-verify design)

`CoverageMapper.map_coverage` (run inside Loop 3's `generate_all_gaps` and dispatched as a Celery task after the chain) decides which chain techniques are already covered by existing library rules, so Loop 3 only generates for genuine gaps. **The chat LLM is out of this loop by default** — embeddings + Qdrant carry the coverage signal:

- **Default (`COVERAGE_LLM_VERIFY_ENABLED=False`):** a technique is `covered` only if an existing rule is **semantically similar** (Qdrant `query_points`, score ≥ `SEMANTIC_SCORE_THRESHOLD`) to the chain's behavior. A bare ATT&CK-tag match no longer auto-covers. Zero `coverage_verify` chat-LLM calls.
- **Opt-in (`COVERAGE_LLM_VERIFY_ENABLED=True`):** the legacy precision layer (Phase 1.5 tag-verify + Phase 2 candidate-verify) runs, but bounded: `n_samples=1`, capped at `COVERAGE_VERIFY_MAX_CALLS` per run.

This replaced the per-existing-rule, 3-sample LLM verification described in [`docs/architecture/COVERAGE_VERIFICATION_DESIGN.md`](docs/architecture/COVERAGE_VERIFICATION_DESIGN.md) (now superseded — see its banner).

**Generated-rule redundancy (post-generation):** after Loop 3 writes a rule it is embedded and semantic-searched against the `sigma_rules` library; if a near-duplicate exists (score ≥ `RULE_SIMILARITY_THRESHOLD`), the rule is persisted **flagged** (`sigma_rules.similar_to_rule_id` + `similarity_score`, migration `0022`) for human review — never dropped. Kept rules are embedded into Qdrant so later assessments see them. Exact byte-duplicate dedup is separate: `content_hash` (stable — excludes the volatile `id`/`date`) short-circuits the insert.

### Pipeline diagram

```
Analyst opens assessment (multi-input: CVE / ticket / PSIRT URL → resolved CVE)
                          ↓
              Existing-chain check  (commons or live-feed candidate)
                  ├── Use as starting point → synthetic Loop 1 row, no LLM
                  └── Start fresh → Run Loop 1
                          ↓
              Analyst pastes sources (free-text only in v1; ≤100KB/source, ≤2MB total)
                          ↓
              Embed task tags chunks into Qdrant `source_chunks` (assessment-scoped)
                          ↓
              Loop 1 — Vulnerability Analysis  (single-shot LLM via structured_complete)
                          ↓
              Loop 2 — Threat Intel  (bulk-then-gap RAG over assessment-scoped chunks)
                          ↓
              Detectability gate  (≥3 of 7 ObservableCategory buckets non-empty)
                  ├── pass → Chain synthesis bridge → attack_chains row
                  │           (prior chain hard-superseded; one active per CVE)
                  │             ↓
                  │   Loop 3 — Detection Engineering  (per profile per TTP gap)
                  │   Reuses RuleGenerator + pySigma + exact-hash dedup
                  │             ↓
                  │   RuleSuperseder marks prior live-feed rules deprecated for
                  │   the same (cve, technique, profile)
                  │             ↓
                  │   map_coverage Celery task fires on the new chain
                  │             ↓
                  │   Review Queue (`assessment_id` filter, `low_detectability_override` badge)
                  │             ↓
                  │   Human Approve / Edit / Reject / Supersede → Sigma Target PR
                  └── fail → analyst re-runs Loop 2, overrides, or abandons
                          ↓
              Analyst clicks "Close Assessment" → state = 'completed' (terminal)
```

### Persistence model

| Table | Role | Migration |
|---|---|---|
| `coverage_assessment` | 1:1 with CVE; owns analyst intent + state | `0017_assessment_centric` |
| `assessment_source` | Pasted sources (UNIQUE on `(assessment_id, content_hash)`; soft-deletable) | `0017_assessment_centric` |
| `assessment_loop_run` | Versioned per-loop runs (`UNIQUE (assessment_id, loop_number, version)`; one `is_active=true` per `(assessment, loop)`); `model` + `cost_usd` populated at finalize from the loop's `_llm` metadata (Wave 1a) | `0017_assessment_centric` |
| `attack_chains` + columns | `assessment_id`, `superseded_by_assessment_id`, `superseded_at`, `behavioral_indicators`; partial unique index `uq_attack_chains_active_per_cve` | `0017_assessment_centric` |
| `review_queue` + columns | `assessment_id`, `low_detectability_override`, `superseded_by_assessment_id` | `0017_assessment_centric` |
| `sigma_rules` + columns | `deprecated_by_rule_id`, `deprecated_at`, `deprecated_by_assessment_id` | `0017_assessment_centric` |
| `llm_interactions.assessment_id` | Per-assessment cost roll-up — actually written since Wave 1a for `coverage_assessment`-tagged calls (known gap: Loop 3 rule-generation calls are `chain_ttp`-tagged and not attributed here; the run's `cost_usd` does capture them) | `0017_assessment_centric` |
| `vuln_class_to_ttps`, `ttp_category_relevance`, `chain_ttps.behavioral_indicators` | Curated lookups + per-TTP indicators | `0018_vuln_class_mappings` |
| `cves.title`, `cves.description` | CVE metadata for Loop 1 context | `0019_cve_title_description` |
| FK `ondelete` fixes + `assessment_id` indexes (`attack_chains`, `review_queue`, `llm_interactions`) | hot-path indexes + ORM/DB ondelete alignment | `0020_assessment_fk_indexes` |
| `uq_prompt_templates_active` re-keyed `name` → `task_type` (backfilled) | one active prompt per `(task_type, model, provider)` | `0021_prompt_active_by_task_type` |
| `sigma_rules.similar_to_rule_id` (soft pointer, no FK), `sigma_rules.similarity_score` | generated-rule semantic redundancy flagging | `0022_rule_similarity` |
| `detectability_assessments` | advisory 5-class detectability per Loop 2 run (UNIQUE `loop_run_id`; payload JSONB + flattened class/confidence) | `0023_detectability_assessments` |
| `artifact_plans` | compatibility-mode artifact plan per classification (UNIQUE `detectability_assessment_id`; plan JSONB + flattened `sigma_planned` + post-Loop-3 `observed`) | `0024_artifact_plans` |
| `generated_artifacts` | on-demand non-Sigma artifacts (one active per `(assessment_id, artifact_type)` via partial unique index; structured content JSONB; plan provenance) | `0025_generated_artifacts` |
| `uq_assessment_loop_run_active` (UNIQUE partial index) | one active run per `(assessment_id, loop_number)` enforced in the DB — replaces 0017's non-unique `idx_assessment_loop_run_active`; pre-existing duplicates resolved (highest version stays active, rest demoted to `superseded`) | `0026_loop_run_active_unique` |

### API surface

`fragchain/api/routers/assessments.py` exposes the workspace CRUD (`POST/GET/DELETE /assessments/{id}/sources`, `POST /assessments/{id}/loops/{n}/run`, `GET /assessments/{id}/loops/{n}`, `POST /assessments/{id}/use-existing-chain`, `POST /assessments/{id}/close`, `GET /assessments/{id}/detectability`, `GET /assessments/{id}/artifact-plan`, `POST/GET /assessments/{id}/artifacts`). The queue router (`fragchain/api/routers/queue.py`) accepts `?assessment_id=` and projects the new fields. The matrix endpoint (`GET /matrix` in `fragchain/api/routers/coverage.py`, **not** `matrix.py`) accepts `?assessment_id=` to scope coverage to one assessment.

### Worker integration

Loop execution is **asynchronous**. `POST /assessments/{id}/loops/{n}/run` runs only a cheap synchronous precheck (`LoopOrchestrator.begin_run`: transition validation, already-running guard, Loop-3 gate-override check), creates an `assessment_loop_run` row with `status='running'` (and `is_active=false` — activation happens only at an output-bearing finalize; see the state-machine subsection), commits, dispatches the Celery task `fragchain/worker/tasks/run_assessment_loop.py` with the run id, and returns **202** + the running row. The worker calls `LoopOrchestrator.execute_run(run_id)` — the slow LLM work + post-loop hooks (`ChainSynthesizer`, `RuleSuperseder`, `DetectabilityClassifier`, `ArtifactRouter`, `map_coverage` dispatcher) — and finalizes the row to `succeeded`/`failed`/`gate_failed`, emitting `assessment.loop.run.completed`. `execute_run` no-ops on a non-`running` row (Celery-delivery idempotency). `run_loop` remains as a `begin_run`+`execute_run` convenience wrapper for tests and the deterministic in-process path. Worker-emitted events actually reach browser WS subscribers via the Redis pub/sub **event bridge** (Wave 1a): `emit_event` publishes every event to Redis channel `fragchain.events` (sync best-effort publish, 30s circuit breaker, warn-once local-only degradation when Redis is down), tagged with a per-process origin; the API lifespan runs an `EventBridge` subscriber (`fragchain/notifications/bridge.py`) that re-emits foreign-origin events into the local bus — skipping its own origin and never republishing, so events can't ping-pong between processes. The frontend dispatches and then refetches on the WS completion event (with a `status='running'` polling fallback). This split (Plan A) removed the synchronous LLM call from the request path that previously 504'd at nginx's 60s `proxy_read_timeout`. LLM timeouts are configurable: `LLM_STRUCTURED_TIMEOUT_SECONDS` (the `structured_complete` `asyncio.wait_for` bound, default 120) and `LITELLM_HTTP_TIMEOUT_SECONDS` (httpx client, default 120); each Loop 2 pass is bounded by `LOOP2_PASS_TIMEOUT_SECONDS` (default 150, startup-validated ≥ `LLM_STRUCTURED_TIMEOUT_SECONDS` so the inner structured timeout + repair budget governs — the previous hardcoded 60s pass timeout fired first and silently defeated the Plan A timeout fix). A **stale in-flight reaper** (beat task `assessment.reap_stale_inflight`, every 5 minutes, `fragchain/worker/tasks/reaper.py`) fails `running` loop runs and `generating` artifacts older than `STALE_INFLIGHT_MAX_SECONDS` (default 1800) via atomic conditional updates (only-flip-if-still-in-flight; counts/emits completion events only for rows actually flipped) — a lost broker message can no longer leave a 409-blocking row forever (this retires the Plan A "no stale-running reaper" limitation). Source embedding is its own task: `fragchain/worker/tasks/embed_assessment_source.py`. Artifact generation (Phase 2b) follows the same begin/execute pattern via `fragchain/worker/tasks/generate_artifact.py`; `fragchain/worker/tasks/__init__.py` side-effect-imports all assessment tasks so they register with the Celery worker (fixing the Plan A registration gap, regression-guarded by `tests/worker/test_task_registration.py`), and on `worker_ready` the worker asserts the expected task names (the EXPECTED_TASKS tuple in `fragchain/worker/celery.py`) ⊆ registered task names and hard-fails via `WorkerShutdown` (a `SystemExit` subclass Celery's signal dispatch cannot swallow) when any are missing — a half-registered worker refuses to start instead of silently rejecting dispatches.

### Priority scoring

The §12 priority-scoring weights apply unchanged to rules landed by Loop 3 (the review queue is shared with the dormant path).

---

## 12.2. Dormant by design — allowlist

The following code paths are preserved in tree by deliberate decision (assessment-centric design note §4.8 and §10). They are **not** orphan code and **must not be deleted** without an explicit decision to remove the connector / live-feed track entirely. Audits should treat this list as the boundary between "intentionally inert" and "actually dead."

| Path | What it does | Why dormant | Revival trigger |
|---|---|---|---|
| `fragchain/chain/generator.py::ChainGenerator` | M11 linear LLM-only chain synthesis (CVE description + RAG → `AttackChain` via validate-and-retry). **Reachability (be honest):** it is *not* unreachable — three production sites dispatch the `synthesize_chain` task that drives it: `POST /cves/manual` (`api/routers/cves.py`, the live **ManualCveAdd** UI screen), `POST /cves/{id}/resynthesize` (`api/routers/chains.py`), and the enrichment pipeline (`ingest/enrichment.py`). One click in the UI runs this path today. | Dormant as the *primary* flow, not as code: the assessment workspace synthesizes deterministically via `chain_synthesis.py` from real Loop 2 evidence; the LLM-only path produces generic chains when sources are thin and is kept for the manual-add / resynthesize escape hatches. | Connector ecosystem returns with enough artifact density that LLM-only synthesis becomes useful again. |
| `fragchain/worker/tasks/synthesize.py` | M11 Celery task that drives `ChainGenerator` from the `cves.processing_status` state machine. | Dispatched from the three sites listed in the `ChainGenerator` row (manual CVE add, resynthesize endpoint, enrichment) — but not part of the assessment workspace, which dispatches its own runner (`run_assessment_loop.py`). | Same trigger as `ChainGenerator`. |
| `fragchain/ingest/webhooks.py`, `fragchain/api/routers/webhooks.py` | Live-feed ingestion entry points for connector webhooks. | Connectors don't push anything yet; no traffic to handle. | First real connector ships. |
| `fragchain/ingest/rate_limit.py` + `MAX_LIVE_CVE_PER_HOUR` setting | Live-feed throttling. | No live feed running. | Same as webhooks. |
| `fragchain/api/routers/imports.py` (Import Manager / historical-import bulk) + `MAX_HISTORICAL_CVE_PER_DAY`, `AUTO_PROCESS_KEV` | Analyst-gated historical import pulling CVEs through the linear pipeline. | Bulk historical import drives synthesis through `ChainGenerator` — dormant alongside it. The assessment workspace covers the "I want to assess this CVE" intent for now. | Same trigger as `ChainGenerator`. |
| `cves.processing_status` state machine (`pending → enriching → synthesizing → mapping → generating → complete`) and related transitions in `fragchain/ingest/state.py` | Per-CVE state machine for the linear pipeline. | The active flow uses its own state machine on `coverage_assessment.state`. | Same. |
| Connector enrichment orchestrator (`fragchain/connectors/orchestrator.py`) running on a live-feed schedule | Parallel per-connector enrichment with failure isolation. | The orchestrator and `IntelConnector` protocol stay — only one in-tree connector exists today (NVD-direct) and there's no live feed running it on a schedule. | Same trigger as webhooks. |

Anything outside this list that looks unused is fair game for an audit to flag. Anything inside it should be challenged at the design-doc level, not silently removed.

---

## 13. Sigma Integration (Multi-Source + Multi-Target)

### Deployment requirements
The `git` system binary MUST be installed in any container that runs the
API or the worker — `gitpython` is a wrapper around the `git` CLI and
every `_sync_repo` call shells out to `git fetch` / `git rev-parse`.
`Dockerfile.api` and `Dockerfile.worker` install it explicitly; operators
forking the project must keep that line. Without it, `POST
/api/v1/sigma/sources/{id}/refresh` returns a clean error rather than
silently no-op'ing.

The local clone root is configurable via `SIGMA_REPOS_DIR` (default
`data/sigma-repos`) — mount this on a persistent volume so refreshes are
incremental fast-forwards rather than full re-clones.

### Configurable Sigma Sources (Read)
Multiple sources for existing rules to compare coverage against:
```sql
sigma_sources (name, git_url, branch, path_filter, enabled)
```

Default: SigmaHQ public repo. Operators can add internal Sigma repos.

`git_url` must match `^https?://host/owner/repo` unless the operator
sets `SIGMA_ALLOW_NON_HTTPS=true`. `file:`, `ssh://`, and `git://` URLs
are rejected by default to prevent a malicious URL from causing a clone
into a sensitive local path or an unauthenticated SSH fetch.

### Configurable Sigma Targets (Write)
Multiple destinations for approved rule PRs:
```sql
sigma_targets (
    name, git_url, branch, target_path,
    auto_pr, routing_rules, is_default
)
```

Routing rules determine where each approved rule lands:
- Example: `{"if": "level=critical", "target": "production-repo"}`
- Example: `{"if": "fragchain.generated AND status=experimental", "target": "staging-repo"}`

Multiple targets coexist. First match wins across all targets — see
"Multi-target semantics" below.

### Routing expression syntax
Routing-clause expressions support a narrow allowlist:

- **Boolean combinators:** `AND`, `OR`, `NOT` (case-insensitive — internally lowered)
- **Comparisons:** `==`, `!=`, `IN`, `NOT IN`
- **Grouping:** parentheses
- **Identifiers:** rule-field references on the `RuleContext`:
  `tlp`, `level`, `status`, `origin`, `logsource_product`,
  `logsource_service`, `logsource_profile`, `technique_ids`, `tags`
- **Literals:** single- or double-quoted strings, integers
- **Tag probes:** dotted barewords such as `fragchain.generated` or
  `tlp.amber` are equivalent to `'<tag>' in tags`. They are pre-processed
  to that quoted form before AST evaluation, so both
  `{"if":"fragchain.generated", ...}` and
  `{"if":"'fragchain.generated' in tags", ...}` work identically.
- **Disallowed:** function calls, attribute access on identifiers,
  subscripting, `import`, `eval`. Any other AST node is rejected at
  compile time.

### Multi-target semantics
Targets are walked in `id` order (random UUID, deterministic but not
human-controllable). The first clause that compiles and matches wins;
additional matching targets are logged as `sigma.routing.multiple_matches`
so operators can spot ambiguous routing. For deterministic order,
operators should make routing clauses mutually exclusive. Fallback to
`is_default=true` is allowed; having more than one default-true row is
a startup error (`sigma.config.multiple_default_targets`) so the
deployment refuses to come up with an ambiguous default.

### Logsource Profiles
Per-platform rule generation. A profile encodes how to write detection logic for a specific environment:

Built-in profiles (seeded on first run):
- `linux-auditd` (enabled by default)
- `linux-sysmon`
- `linux-falco`
- `windows-security` (enabled by default)
- `windows-sysmon`
- `network-zeek`
- `network-suricata`

Each profile contains: product/service mapping, field naming conventions, example rules (few-shot for LLM prompt).

**The rule generator produces variants for each enabled profile.** One TTP gap → potentially multiple rules (one Linux variant, one Windows variant) sharing the same chain_id but different logsource targeting.

---

## 14. Sigma Rule Output Format

```yaml
title: <descriptive>
id: <uuid4>
status: experimental                  # always experimental until human-validated
description: >
  <what + cite CVE>
references: [URLs]
author: FragChain (LLM-generated, human-reviewed)
date: <generation date>
tags:
  - attack.<tactic_lowercase>
  - attack.<technique_id_lowercase>
  - cve.<cve_id_lowercase_dashes>
  - fragchain.generated               # REQUIRED
  - tlp.<level>                       # REQUIRED
  - logsource.profile.<profile_name>  # REQUIRED — which profile this targets
logsource:
  product: <from profile>
  service: <from profile>
detection: <logic>
falsepositives:
  - Unknown — requires validation in target environment
level: <critical|high|medium|low|informational>
```

**Never auto-merge.** Rules tagged `fragchain.generated` until reviewed.

---

## 15. Prompt Management

### Runtime-Managed Prompts (not static files)
Prompts live in DB with versioning, A/B testing, and evaluation:

```sql
prompt_templates (
    name, task_type, target_model, target_provider,
    version, system_prompt, user_template, is_active
)

prompt_evaluations (
    prompt_template_id, benchmark_set,
    technique_overlap, ordering_consistency, hallucination_count,
    cost_per_run, avg_latency_ms
)

prompt_ab_tests (
    name, task_type, variant_a, variant_b, traffic_split, status, winner
)
```

Only one row per `(task_type, target_model, target_provider)` can have
`is_active=true`. Enforced by partial unique index
`uq_prompt_templates_active`. Originally created on `(name, …)` in
migration `0008_prompts`; re-keyed to `(task_type, …)` in migration
`0021_prompt_active_by_task_type` (the cache, the `activate()`
sibling-deactivation, and the index all key on `task_type` — the engine
resolves prompts by `task_type`, so a cloned/renamed template must not
create a second active row for the same task).

### Why Runtime
- Different models need different prompts (Claude vs GPT vs local)
- Operators iterate via UI without code changes
- A/B testing routes traffic between versions, measures real-world performance
- Evaluation framework runs prompts against ground-truth fixtures

### Default Prompts Seeded on First Run
`scripts/seed_prompts.py` seeds one v1 template for `*` (any model) per task_type — 10 task_types:
- Linear pipeline era: `chain_generation`, `rule_generation`, `coverage_verify`
- Assessment loops: `vuln_analysis` (Loop 1), `threat_intel` (Loop 2), `detection_engineering` (Loop 3)
- ADR-0004: `detectability_classification` (Phase 1), `mitigation_plan`, `analyst_research_task`, `telemetry_contract` (Phase 2b)

Operators clone these and tune per model. UI shows diff view between versions.

---

## 16. UI Design — DarkOps v3

All frontend MUST use DarkOps v3 design system. Reference file: `frontend/src/styles/darkops.css` (derived from [`docs/historical/darkops_design_system_v3.html`](docs/historical/darkops_design_system_v3.html), preserved as a component-reference mockup).

### Layout Pattern (v3)
**Slim topbar (48px) + collapsible left sidebar (220px expanded, 56px collapsed) + main content area.**

```
┌────────────────────────────────────────────────────────────────┐
│  FRAGCHAIN [search]    [status: ● litellm qdrant opencti] [🔔][👤] │  ← 48px topbar
├──────────┬─────────────────────────────────────────────────────┤
│ OVERVIEW │                                                      │
│  · Dash  │   [context bar]                                     │
│ INTEL    │                                                      │
│  · CVEs  │   MAIN CONTENT AREA                                  │
│  · Chain │                                                      │
│  · Matrix│                                                      │
│ DETECT   │                                                      │
│  · Queue │                                                      │
│  · Sigma │                                                      │
│ ...      │                                                      │
│ [« coll] │                                                      │
└──────────┴─────────────────────────────────────────────────────┘
```

**Topbar contains:** logo, service status indicators (LiteLLM, Qdrant, OpenCTI, Sigma repo with health-color dots), notifications bell with count, user menu. Global search (⌘K) is **intentionally absent** until search actually exists — the original input had no handler (a fake affordance, removed in Wave 1b; restore the `.topbar-search` block when search ships).

**Sidebar contains:** nav items grouped into sections (OVERVIEW, INTEL, DETECT, AUTOMATION, CONFIG). Items have icons, labels, and optional count badges. Active item shows accent-colored left border. Collapse button at bottom drops to icon-only mode.

**Sidebar section grouping (final):**
- OVERVIEW: Dashboard
- INTEL: CVEs, Chains, ATT&CK Matrix
- DETECT: Review Queue (badge = live pending-review count fetched from the queue API; fetch failure → no badge, never a fake number), Sigma Library
- AUTOMATION: Imports, Prompts (the placeholder "A/B" badge was removed in Wave 1b — no static badge until a real signal exists)
- CONFIG: Connectors, Commons, Settings, Identity (placeholder)

### Design Tokens
```css
/* Typography scale */
--text-micro:   10px      /* badges, labels */
--text-xs:      11px      /* metadata, dense data */
--text-sm:      12px      /* secondary text */
--text-base:    13px      /* default body */
--text-md:      14px      /* emphasized */
--text-lg:      16px      /* section headers */
--text-xl:      18px      /* page subheaders */
--text-2xl:     20px      /* page headers */
--text-3xl:     28px      /* big stats */

/* Spacing scale (4px base) */
--space-1: 4px    --space-2: 8px    --space-3: 12px
--space-4: 16px   --space-5: 20px   --space-6: 24px
--space-8: 32px   --space-10: 40px  --space-12: 48px

/* Border radius scale */
--radius-sm: 4px      --radius-md: 6px (default)
--radius-lg: 8px      --radius-xl: 12px

/* Layout (v3) */
--topbar-height:     48px
--sidebar-width:    220px
--sidebar-collapsed: 56px
--context-bar-height: 44px

/* Colors */

### Design Tokens (v2)
```css
/* Typography scale */
--text-micro:   10px      /* badges, labels */
--text-xs:      11px      /* metadata, dense data */
--text-sm:      12px      /* secondary text */
--text-base:    13px      /* default body */
--text-md:      14px      /* emphasized */
--text-lg:      16px      /* section headers */
--text-xl:      18px      /* page subheaders */
--text-2xl:     20px      /* page headers */
--text-3xl:     28px      /* big stats */

/* Spacing scale (4px base) */
--space-1: 4px    --space-2: 8px    --space-3: 12px
--space-4: 16px   --space-5: 20px   --space-6: 24px
--space-8: 32px   --space-10: 40px  --space-12: 48px

/* Border radius scale */
--radius-sm: 4px      --radius-md: 6px (default)
--radius-lg: 8px      --radius-xl: 12px

/* Colors (unchanged from v1) */
--bg:       #0a0e17     --surface:  #111827
--surface2: #1a2235     --surface3: #222d42
--border:   #1e2d45     --border-hi:#2d4a6f
--text:     #c9d1d9     --text-dim: #6b7b90
--text-bright: #e6edf3
--accent:   #38bdf8     --accent2:  #818cf8
--accent3:  #34d399     --danger:   #f87171
--warning:  #fbbf24

/* Transitions */
--transition-fast: 150ms ease
--transition-base: 200ms ease

/* Focus ring */
--focus-ring: 0 0 0 2px var(--accent)

/* Fonts */
--font-display: 'JetBrains Mono', monospace
--font-body:    'DM Sans', sans-serif
```

### Rules
- CVE IDs, technique IDs, hashes, timestamps, YAML → `font-display`
- Body text, descriptions → `font-body`
- ATT&CK tactic colors consistent across Chain Viewer and Matrix:
  - Initial Access, Execution → --accent (cyan)
  - Privilege Escalation, Defense Evasion → --warning
  - Persistence, Credential Access, Lateral Movement, Collection, C2 → --accent2
  - Impact, Exfiltration → --danger
- Coverage status colors:
  - covered → --accent3, partial → --warning, gap → --danger, no_data → --surface2
  - KEV gap → --danger pulsing
- TLP badges:
  - clear → no border, text-dim
  - green → --accent3 border
  - amber → --warning border
  - amber+strict → --warning border + diagonal stripes
  - red → --danger background
- **Use the custom dropdown component, not native `<select>`** (see DarkOps v2 reference)
- Form controls have focus rings (2px --accent outline on focus)
- No Tailwind utility classes for theming — DarkOps CSS only

### Screens (11 total)
1. Login
2. Dashboard
3. CVE Explorer
4. Chain Viewer
5. **ATT&CK Matrix** (full MITRE, 4 view modes)
6. Review Queue
7. Sigma Library
8. Import Manager (Live Feed + Historical tabs)
9. Settings + Connectors Marketplace (combined)
10. Prompts Management
11. Identity (placeholder — shows "not implemented" message)

---

## 17. File Structure

Brought 1:1 with the actual tree in v2.9 (it previously predated the assessment pivot); every path below was spot-checked against `ls`. (`scripts/verify_doc_claims.py` mechanically guards the backtick-quoted path references throughout this file and `docs/architecture/`.)

```
fragchain-core/
├── CLAUDE.md, AGENTS.md, MANIFEST.md, SECURITY.md, README.md
├── docker-compose.yml              ← Server 3 services (includes Qdrant)
├── .env.example, alembic.ini, setup.sh
├── Dockerfile.api, Dockerfile.worker
├── nginx/                          ← nginx.conf, conf.d/, certs/
├── chains/                         ← ground-truth fixtures (CVE-2026-43284.json = Dirty Frag, + 3 classics)
├── benchmarks/                     ← dirty_frag_groundtruth.json (coverage benchmark)
├── prompts/                        ← seed prompt text (one .system.txt/.user.txt pair per task_type v1)
├── scripts/
│   ├── seed_dirty_frag.py, seed_attck_techniques.py, seed_profiles.py
│   ├── seed_prompts.py, seed_vuln_class_mappings.py, seed_filter_presets.py
│   ├── eval_chain.py, validate_chains.py
│   ├── run_coverage_benchmark.py, label_coverage_benchmark.py, clear_coverage_map.py
│   ├── verify_doc_claims.py        ← mechanical doc-truth guard (paths + settings)
│   └── hooks/                      ← pre-commit (host-path gate, §19)
├── fragchain/                      ← Python package
│   ├── api/
│   │   ├── main.py, security.py, ws_tickets.py
│   │   ├── routers/
│   │   │   ├── assessments.py      ← active-flow workspace API (§12.1)
│   │   │   ├── cves.py, chains.py, queue.py, rules.py
│   │   │   ├── coverage.py         ← includes GET /matrix (no separate matrix.py)
│   │   │   ├── coverage_benchmarks.py, evaluations.py, imports.py
│   │   │   ├── webhooks.py, websocket.py, auth.py, health.py, version.py
│   │   │   ├── connectors.py, commons.py, prompts.py, llm.py, vector.py
│   │   │   ├── sigma.py            ← sources + targets in one router
│   │   │   ├── profiles.py, embargo.py
│   │   │   └── identity.py         ← placeholder, all endpoints return 501
│   │   └── middleware/
│   │       └── tlp_filter.py       ← auth lives in api/security.py, not middleware
│   ├── assessments/                ← ACTIVE FLOW (§12.1)
│   │   ├── orchestrator.py, state_machine.py, service.py, source_service.py
│   │   ├── chain_synthesis.py, chain_reuse.py, mapping.py, mapping_seeds.py
│   │   ├── detectability.py        ← ADR-0004 Phase 1 classifier
│   │   ├── artifact_router.py      ← ADR-0004 Phase 2 router
│   │   ├── artifact_generation.py  ← ADR-0004 Phase 2b generator
│   │   ├── rule_supersession.py, trigger_resolver.py, cve_summary.py
│   │   ├── access.py, content.py, schemas.py
│   │   └── loops/                  ← loop1.py, loop2.py, loop3.py, rag.py,
│   │                                  base.py, schemas.py, stubs.py (gate), token_budget.py
│   ├── audit.py                    ← audit_entity_state_change (§19)
│   ├── chain/
│   │   ├── generator.py            ← dormant (§12.2); prompt building inlined here
│   │   └── schema.py               ← AttackChain contract (§11)
│   ├── commons/                    ← bootstrap.py, sync.py, contribute.py, sources.py,
│   │                                  client.py, factory.py, transport.py
│   ├── config.py
│   ├── connectors/                 ← base.py (IntelConnector Protocol), discovery.py,
│   │                                  orchestrator.py, registry_client.py
│   ├── coverage/                   ← mapper.py, matrix.py, benchmark.py
│   ├── db/                         ← models.py, session.py, migrations/ (Alembic, head 0025)
│   ├── evaluations/                ← store.py
│   ├── identity/                   ← base.py (Protocol only), registry.py (empty in v1)
│   ├── ingest/                     ← service.py, state.py, enrichment.py, webhooks.py,
│   │                                  rate_limit.py, budget.py, filters.py (largely §12.2-dormant)
│   ├── llm/                        ← base.py (LLMProvider Protocol), registry.py,
│   │                                  litellm_provider.py (only provider in v1), structured.py
│   ├── notifications/              ← events.py
│   ├── profiles/                   ← store.py (logsource profiles)
│   ├── prompts/                    ← store.py, eval.py, ab.py
│   ├── queue/                      ← manager.py, supersede.py
│   ├── rules/                      ← generator.py, validator.py (pySigma wrapper)
│   ├── security/                   ← tlp.py, embargo.py, git_url.py,
│   │                                  webhook_hardening.py, yaml_safe.py
│   ├── sigma/                      ← sources.py, targets.py, parser.py, transport.py
│   ├── storage/                    ← minio.py
│   ├── vector/                     ← embedder.py, collections.py
│   └── worker/
│       ├── celery.py
│       └── tasks/                  ← run_assessment_loop.py, embed_assessment_source.py,
│                                      generate_artifact.py, coverage.py, rules.py,
│                                      ingest.py, sigma.py, synthesize.py (§12.2), vector.py
├── frontend/
│   ├── src/
│   │   ├── styles/darkops.css      ← DarkOps v3 tokens (§16)
│   │   ├── components/             ← AppShell, Topbar, Sidebar, TLPBadge, DataTable,
│   │   │   │                          Dropdown (custom), Toast, Modal, etc.
│   │   │   └── assessments/        ← LoopCard, SourcesCard, DetectabilityCard,
│   │   │                              ArtifactPlanCard, GeneratedArtifactsCard, …
│   │   ├── screens/                ← 15 routed screens (AssessmentWorkspace,
│   │   │   │                          AssessmentsList, CVEExplorer, ManualCveAdd, …)
│   │   │   └── settings/           ← Settings sections (Connectors, Commons, Sigma, …)
│   │   ├── api/                    ← per-resource clients
│   │   ├── hooks/                  ← useAssessment, useAssessments, useAuth,
│   │   │                              useHealth, useWebSocket
│   │   ├── App.tsx
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
└── tests/                          ← mirrors package structure (incl. test_dormancy_claims.py,
                                       test_verify_doc_claims.py — mechanical-truth guards)
```

---

## 18. Code Conventions

- Python 3.12, async/await throughout
- FastAPI, SQLAlchemy 2.0 async, Pydantic v2, asyncpg, httpx, structlog
- All Celery tasks idempotent (safe to retry)
- Every LLM call logged to `llm_interactions` + full I/O to MinIO
- Secrets only via env vars
- Type hints on every function signature
- No `print()` — use structlog (JSON output)
- Tests in `tests/` mirroring package structure

---

## 19. Never Do List

- NEVER auto-merge a Sigma rule to a target repo (human review gate is inviolable)
- NEVER call Anthropic/OpenAI SDKs directly in v1 — use LiteLLM provider via the LLMProvider abstraction
- NEVER expose PostgreSQL, Redis, MinIO, or Qdrant ports externally
- NEVER commit .env files
- NEVER use a collection prefix on Qdrant in v1 — Qdrant is local, prefix is gone
- NEVER skip pySigma validation on generated rules
- NEVER proceed without source attribution on chain TTPs
- NEVER hardcode the commons URL — always read from `commons_sources` table
- NEVER hardcode the Sigma repo URL — always use `sigma_sources` / `sigma_targets`
- NEVER hardcode prompts in files — use the prompt_templates table via Prompt Store
- NEVER override DarkOps CSS variables — extend, don't replace
- NEVER ignore TLP enforcement in API responses
- NEVER implement identity verification logic in v1 — return 501
- NEVER let one connector failure block enrichment for others
- NEVER skip writing an `audit_log` row for an entity status transition. Use `audit_entity_state_change` from `fragchain/audit.py` for any endpoint that mutates entity status.
- NEVER assume a Celery worker process inherits the lifespan setup of the API process. Worker processes need their own provider bootstrap, their own connection management, their own startup validation. Apply the same `worker_process_init` discipline used for the API lifespan — Phase 5 audit L2 was an entire pipeline stuck on this exact gap.
- NEVER write absolute host paths (`/Users/<name>/...`, `/home/<name>/...`) into committed docs or code — they leak the committer's username and machine layout. Use `<repo-root>` in prose, or repo-relative paths in shell snippets (those snippets are meant to be run from the repo root anyway). The `scripts/hooks/pre-commit` gate enforces this on staged Markdown; activate it once per checkout with `git config core.hooksPath scripts/hooks`. Append `# allow-host-path` on a line to bypass intentionally.
- NEVER delete code listed in §12.2 "Dormant by design — allowlist" without an explicit decision (recorded in `docs/architecture/`) to retire the connector / live-feed track. These paths are preserved on purpose; an audit flagging them as orphan/dead is a doc-staleness signal, not a removal signal.

---

## 20. Build Reference

**Historical (M1–M24, linear pipeline era):** the original "canonical" doc was [`docs/historical/FragChain_Module_Specifications.md`](docs/historical/FragChain_Module_Specifications.md), which defined 37 modules in 8 phases plus 7 deferred post-v1 modules. It's preserved in tree as historical context, not as active scope — the assessment-centric pivot reset what "shipped" means (see §12.1). Per-module completion records ([`docs/historical/MODULE_M1_DONE.md`](docs/historical/MODULE_M1_DONE.md) … [`docs/historical/MODULE_M24_DONE.md`](docs/historical/MODULE_M24_DONE.md)) plus the Phase 4/5/6 audits ([`docs/historical/AUDIT_PHASE4.md`](docs/historical/AUDIT_PHASE4.md), [`docs/historical/AUDIT_PHASE5.md`](docs/historical/AUDIT_PHASE5.md), [`docs/historical/AUDIT_PHASE6.md`](docs/historical/AUDIT_PHASE6.md)) are the authoritative record of what was built, what was deferred, and what audit findings remained open at each phase boundary.

**Active source of truth:** the architecture design notes under [`docs/architecture/`](docs/architecture/). The assessment-centric design note is the canonical "what to build" doc for the active flow; the Phase A coverage-verification note covers the mapper / dedup / supersede work that underpins it.

**Open question:** whether to consolidate the active design into a single `docs/CURRENT_ARCHITECTURE.md` is unresolved — the architecture notes plus this CLAUDE.md cover the same ground today. The original `FragChain_Module_Specifications.md` is preserved at [`docs/historical/`](docs/historical/) but is not the active scope; if you need a "what's left" view, read the architecture notes and the open plans under [`docs/superpowers/plans/`](docs/superpowers/plans/).

For build workflow, see [`docs/superpowers/plans/`](docs/superpowers/plans/) (per-plan TDD-shaped task lists). The original [`docs/historical/FragChain_Build_Workflow.md`](docs/historical/FragChain_Build_Workflow.md) is preserved as the pre-pivot procedure but is no longer the live workflow.

---

## 21. Key References

**Active architecture (read for any new design decision):**

- Defense-engineering direction + staged adoption: `AGENTS.md`, [`docs/architecture/000-fragchain-scope.md`](docs/architecture/000-fragchain-scope.md), [`docs/architecture/adr/ADR-0004-staged-defense-engineering-adoption.md`](docs/architecture/adr/ADR-0004-staged-defense-engineering-adoption.md)
- Current-architecture baseline + domain/pipeline mapping: [`docs/architecture/001-current-architecture.md`](docs/architecture/001-current-architecture.md), [`docs/architecture/002-domain-model.md`](docs/architecture/002-domain-model.md), [`docs/architecture/003-pipeline-contract.md`](docs/architecture/003-pipeline-contract.md)
- Assessment-centric architecture (primary): [`docs/architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md`](docs/architecture/ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md)
- Assessment Workspace frontend: [`docs/architecture/ASSESSMENT_WORKSPACE_FRONTEND_DESIGN.md`](docs/architecture/ASSESSMENT_WORKSPACE_FRONTEND_DESIGN.md)
- Coverage verification (Phase A): [`docs/architecture/COVERAGE_VERIFICATION_DESIGN.md`](docs/architecture/COVERAGE_VERIFICATION_DESIGN.md)
- Phase A status audit (what's landed vs missing): [`docs/architecture/PHASE_A_STATUS_AUDIT.md`](docs/architecture/PHASE_A_STATUS_AUDIT.md)
- Latest reconciliation summary: [`docs/historical/RECONCILIATION_2026-05-19.md`](docs/historical/RECONCILIATION_2026-05-19.md)

**Plans (per-feature TDD task lists):**

- [`docs/superpowers/plans/2026-05-17-assessment-foundation.md`](docs/superpowers/plans/2026-05-17-assessment-foundation.md) (Plan A — backend foundation, shipped)
- [`docs/superpowers/plans/2026-05-18-plan-b-assessment-workspace.md`](docs/superpowers/plans/2026-05-18-plan-b-assessment-workspace.md) (Plan B — frontend)
- [`docs/superpowers/plans/2026-05-18-plan-c-assessment-real-loops.md`](docs/superpowers/plans/2026-05-18-plan-c-assessment-real-loops.md) (Plan C — real Loop 1/2/3, shipped)
- [`docs/superpowers/plans/2026-05-18-phase-a-completion.md`](docs/superpowers/plans/2026-05-18-phase-a-completion.md) (Phase A completion, shipped)

**Historical record (M1–M24 build) — all under [`docs/historical/`](docs/historical/):**

- `MODULE_M1_DONE.md` … `MODULE_M24_DONE.md` (per-module completion notes)
- `AUDIT_PHASE4.md`, `AUDIT_PHASE5.md`, `AUDIT_PHASE6.md` (post-phase audits)
- `AUDIT_2026-05-19.md` (platform-wide audit that drove the assessment-centric pivot)
- `PHASE4_CLEANUP_DONE.md`, `PHASE5_CLEANUP_DONE.md`
- `SCOPE_REVIEW_M22_M24.md`, `SCOPE_CATCHUP_M22_M24_DONE.md`
- `FragChain_Module_Specifications.md`, `FragChain_Build_Workflow.md`, `FragChain_Product_Design_Final.md`, `FragChain_Ecosystem_Architecture.md`, `FragChain_TLP_and_Identity.md`, `FragChain_Module_Prompts.md` (original pre-pivot design corpus)
- `darkops_design_system_v3.html` (component-reference mockup; live tokens are in `frontend/src/styles/darkops.css`)
- See [`docs/historical/README.md`](docs/historical/README.md) for an index.

**Operational references:**

- TLP spec for FragChain: this file, §8. Identity placeholder: §9. The original design addendum is preserved at [`docs/historical/FragChain_TLP_and_Identity.md`](docs/historical/FragChain_TLP_and_Identity.md), but the shipped contract lives in this file.
- DarkOps Design System: `frontend/src/styles/darkops.css` (per §16). The historical HTML mockup at [`docs/historical/darkops_design_system_v3.html`](docs/historical/darkops_design_system_v3.html) is component reference only, not part of the build.
- Ground truth chain: `chains/CVE-2026-43284.json`
- TLP 2.0 Spec: https://www.first.org/tlp/
- Sigma spec: https://github.com/SigmaHQ/sigma-specification
- pySigma: https://github.com/SigmaHQ/pySigma
