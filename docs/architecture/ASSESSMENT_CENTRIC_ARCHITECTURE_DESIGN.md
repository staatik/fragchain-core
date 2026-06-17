# Assessment-Centric Architecture — Design Note

**Status:** **Reconciled 2026-05-19** — the design landed via Plan A (foundation), Plan B (frontend), and Plan C (real Loop 1/2/3 + chain synthesis + supersession + coverage map dispatch). The §8 sequencing table is historical at this point; the workstreams it lists have all merged. Two pieces of drift to be aware of when reading the design text below:

- **Migration number:** §8 step 1 names the migration `0010_assessment_centric.py`; it actually shipped as `0017_assessment_centric.py` because earlier modules consumed migration slots 0010–0016 between when the design was written and when Plan A landed. Migration `0018_vuln_class_mappings.py` is the Phase 1 Plan C migration that this design's §5.5 anticipated.
- **Loop 2 framing:** §5.3 calls Loop 2 a "bounded tool-using agent." The shipped code (`fragchain/assessments/loops/loop2.py`) is a hand-rolled bulk-then-gap orchestration over RAG — no true tool-call loop, no `lookup_connector` tool wired (the design's §5.3 tools table marks it `Stubbed in v1`). The iteration shape in §5.3 (bulk pass + gap pass) accurately describes the shipped behavior; only the "agent" framing differs.

For the dormant-by-design code paths that this design preserves in tree (§4.8, §10), see CLAUDE.md §12.2.

**Status (original):** Draft for review
**Date:** 2026-05-17
**Author:** Elie M (drafted with Claude)
**Decides:** the shift from background-ingestion-driven processing to analyst-initiated coverage assessments, the entity model for assessments, and the three-loop content engine (vulnerability analysis → threat intel → detection engineering) that produces chains and rules inside an assessment. Live-feed and Import Manager paths coexist (not removed) but are dormant until connector work resumes.

---

## 1. Problem

Today's pipeline (CLAUDE.md §12) is push-driven: connectors stream CVEs in, enrichment happens in parallel, chain synthesis runs on whatever connector data landed, the coverage mapper compares against existing Sigma rules, and the rule generator produces drafts. The analyst is downstream of the pipeline, reviewing whatever the LLM emitted.

This model has three structural problems that became visible during M1–M24 build and the Phase A coverage-verification work:

1. **Generic rules from generic input.** A CVE description from NVD prose alone rarely contains the concrete observable artifacts (process names, command-line patterns, registry writes, ETW providers, network signatures) needed for non-generic detection. The pipeline runs synthesis whether or not those artifacts are available. The result is "log4j → look for java.exe" rules.

2. **Connectors not built.** The original architecture depended on a rich connector ecosystem (OpenCTI, NVD2, AttackerKB, ExploitDB, vendor PSIRT) to deliver the artifact density that synthesis needs. Those connectors don't exist yet. Until they do, push-driven processing has nothing useful to push, and the platform cannot demonstrate value.

3. **Cost and intent mismatch.** Three-loop LLM pipelines (when we add them) are expensive per CVE. Running them on every NVD entry doesn't scale. Real mature SOCs don't auto-process every CVE — they assess coverage when triggered (KEV listing, VM applicability flag, incident referral, customer ask). The platform should match that pattern.

The fix is a product reframing: FragChain becomes an **assessment workspace** where an analyst initiates intentional coverage validation, brings the source material they consider relevant, and drives the platform through a gated three-loop content engine to produce chain + indicators + rules. Connectors stay in the architecture as on-demand lookups, not background ingest. The platform stays usable even with the connector layer unbuilt.

---

## 2. Goals / non-goals

**Goals (v1 of this design):**

- Establish a `coverage_assessment` entity as the primary unit of work, owned by an analyst.
- Provide a free-text-paste source ingest path with paste guardrails (size, charset, dedup, prompt-injection-aware schema).
- Define a three-loop content engine where Loop 1 (vulnerability analysis) and Loop 3 (detection engineering) are single-shot LLM calls and Loop 2 (threat intel) is a bounded tool-using agent.
- Define a category-coverage detectability gate that refuses to generate rules when intel density is insufficient, but lets the analyst override with a recorded rationale.
- Per-loop versioned re-runs so the analyst can iterate (paste more sources, re-run Loop 2, compare versions).
- Reuse existing infrastructure (LiteLLM provider, prompt management, vector store, MinIO, TLP middleware, rule generator, coverage mapper, review queue, Phase A coverage benchmark) without rebuild.

**Non-goals (deferred — see §10):**

- URL ingest and document upload (security surface; Phase 2 of assessment workflow).
- Asset / CMDB integration (analyst carries org context implicitly).
- Multi-analyst collaboration on a single assessment (single owner in v1; viewers respect TLP).
- Auto-progression toggle (per-loop manual gates only in v1).
- Connector implementation work — the framework hooks exist; building OpenCTI/NVD2/etc. is its own track.
- LLM judge on Loop 1 output quality.
- Versioning of the assessment itself — 1:1 CVE→assessment in v1; multi-version is future expansion.
- Prompt-injection scoring on pasted content — schema exists, logic deferred.
- TLP-based LLM routing enforcement — schema and settings switch exist, enforcement deferred.
- Connection between live-feed ingestion and assessments — live feed isn't running today, so supersession semantics (§4.8) are designed forward-compat but not exercised.
- Removal of the existing linear pipeline (`ChainGenerator`, `synthesize_chain` task) — these stay in tree for coexistence, dormant for now.

---

## 3. Architecture overview

The assessment is the first-class entity. It owns the analyst's intent, the sources they provide, and the loop outputs. The three loops are a content engine the assessment invokes; they assume nothing about how they were triggered.

```
┌─────────────────────────────────────────────────────────────────┐
│                  Assessment Workspace (new)                      │
│                                                                  │
│  Analyst initiates ──▶ coverage_assessment row                   │
│  (multi-input:           │                                       │
│   CVE / ticket / URL)    │                                       │
│                          ▼                                       │
│                  ┌───────────────────────────────┐               │
│                  │  Existing chain check         │               │
│                  │  (use as start / start fresh) │               │
│                  └───────────────┬───────────────┘               │
│                                  │                               │
│  Analyst pastes sources ──▶ assessment_source rows               │
│  (free-text only in v1)          │                               │
│                                  ▼                               │
│                          ┌────────────────┐                      │
│                          │ Embedding task │ ──▶ source_chunks    │
│                          │  (async)       │     (Qdrant, tagged) │
│                          └────────────────┘                      │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  │ analyst clicks Run Loop N
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│             Three-Loop Content Engine (new)                      │
│                                                                  │
│   ┌─ Loop 1: Vulnerability Analysis (single-shot) ──────┐        │
│   │  Input: CVE + concatenated assessment sources        │        │
│   │  Output: VulnProfile + DetectionQuestion[]           │        │
│   │  Persists: assessment_loop_run(loop=1, version=N)    │        │
│   └──────────────────────────────────────────────────────┘        │
│                          │ analyst reviews, clicks Run Loop 2     │
│                          ▼                                        │
│   ┌─ Loop 2: Threat Intel (bounded agent) ──────────────┐         │
│   │  Tools: RAG over assessment-scoped source_chunks +  │         │
│   │         on-demand connector lookups (when built)    │         │
│   │  Iteration: bulk pass → gap pass; max 2 passes,     │         │
│   │             max 8 tool calls total                   │         │
│   │  Output: BehavioralIndicators (flat map by category) │         │
│   │  Persists: assessment_loop_run(loop=2, version=N)    │         │
│   │  Gate result attached: pass / fail with reason       │         │
│   └──────────────────────────────────────────────────────┘         │
│                          │                                        │
│                ┌─────────┴──────────┐                              │
│                │ gate passed        │ gate failed                  │
│                ▼                    ▼                              │
│    ┌──────────────────────┐    ┌──────────────────────┐            │
│    │ Chain synthesis      │    │ Analyst chooses:     │            │
│    │ (deterministic       │    │  (a) add sources +   │            │
│    │  builder, not LLM)   │    │      re-run Loop 2   │            │
│    │ Builds AttackChain   │    │  (b) override +      │            │
│    │ TTPs from VulnProfile│    │      proceed with    │            │
│    │ + indicators         │    │      rationale       │            │
│    │ Persists attack_     │    │  (c) abandon         │            │
│    │ chains row           │    └──────────────────────┘            │
│    └──────────┬───────────┘                                        │
│               │                                                    │
│               │ analyst reviews, clicks Run Loop 3                 │
│               ▼                                                    │
│   ┌─ Loop 3: Detection Engineering (single-shot, per-profile) ─┐   │
│   │  Input: AttackChain + behavioral_indicators                │   │
│   │  Output: Sigma rule(s), one per enabled profile per TTP    │   │
│   │  Reuses existing fragchain/rules/generator.py              │   │
│   │  Passes through pySigma validation + exact-hash dedup      │   │
│   │  Persists rules into review_queue with assessment_id       │   │
│   └────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ analyst clicks "Close Assessment"
                                  ▼
                          coverage_assessment.state = 'completed'
```

The dotted line of reuse: every box marked "existing" in §4 below already exists in the codebase. The new code in §4 is the orchestrator that drives them in this new order, plus the three loops in §5.

---

## 4. Assessment workspace

### 4.1 Entity model

Three new tables, single Alembic migration.

```sql
-- New table: assessment, 1:1 with CVE
CREATE TABLE coverage_assessment (
    id                  UUID PRIMARY KEY,
    cve_id              UUID NOT NULL REFERENCES cves(id),
    creator_id          UUID NOT NULL,
    initial_trigger     JSONB NOT NULL,             -- {kind: 'cve_id'|'ticket'|'psirt_url', value, resolved_cve}
    context_note        TEXT,                       -- analyst free-text "why are we assessing this?"
    state               VARCHAR(32) NOT NULL,       -- see state machine
    completed_at        TIMESTAMPTZ,
    closed_by           UUID,
    tlp                 VARCHAR(20) NOT NULL DEFAULT 'tlp:clear',  -- v1 default; field exists for future tightening
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (cve_id)                                  -- 1:1 enforced
);

-- New table: analyst-pasted sources
CREATE TABLE assessment_source (
    id                  UUID PRIMARY KEY,
    assessment_id       UUID NOT NULL REFERENCES coverage_assessment(id) ON DELETE CASCADE,
    kind                VARCHAR(32) NOT NULL,       -- 'free_text' in v1; 'url'|'upload' deferred
    title               VARCHAR(200),
    content             TEXT NOT NULL,
    content_hash        VARCHAR(64) NOT NULL,       -- SHA-256 of normalized content
    size_bytes          INTEGER NOT NULL,
    tlp                 VARCHAR(20) NOT NULL DEFAULT 'tlp:clear',
    embedding_status    VARCHAR(20) NOT NULL DEFAULT 'pending',  -- 'pending'|'embedded'|'failed'
    embedding_error     TEXT,
    injection_risk_score NUMERIC(3,2),              -- placeholder, NULL in v1
    pasted_by           UUID NOT NULL,
    pasted_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ,                 -- soft-delete
    deleted_by          UUID,
    delete_rationale    TEXT,
    UNIQUE (assessment_id, content_hash)
);

CREATE INDEX idx_assessment_source_emb_status ON assessment_source(assessment_id, embedding_status)
    WHERE deleted_at IS NULL;

-- New table: versioned per-loop runs
CREATE TABLE assessment_loop_run (
    id                  UUID PRIMARY KEY,
    assessment_id       UUID NOT NULL REFERENCES coverage_assessment(id) ON DELETE CASCADE,
    loop_number         SMALLINT NOT NULL CHECK (loop_number IN (1, 2, 3)),
    version             INTEGER NOT NULL,
    status              VARCHAR(32) NOT NULL,       -- 'running'|'succeeded'|'failed'|'gate_failed'|'superseded'
    is_active           BOOLEAN NOT NULL DEFAULT true,
    output              JSONB,                       -- shape depends on loop_number; see §5
    gate_result         JSONB,                       -- Loop 2 only: {passed, categories_filled, categories_empty, ...}
    override_rationale  TEXT,                        -- Loop 2 only: set when analyst overrides a failed gate
    embedding_warned    BOOLEAN NOT NULL DEFAULT false,  -- run started while some sources still embedding
    prompt_template_id  UUID REFERENCES prompt_templates(id),
    model               VARCHAR(100),
    cost_usd            NUMERIC(8,4),
    latency_ms          INTEGER,
    error               TEXT,
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at        TIMESTAMPTZ,
    UNIQUE (assessment_id, loop_number, version)
);

CREATE INDEX idx_assessment_loop_run_active ON assessment_loop_run(assessment_id, loop_number)
    WHERE is_active = true;
```

Modifications to existing tables:

```sql
-- attack_chains: support assessment-produced chains and supersession
ALTER TABLE attack_chains
    ADD COLUMN assessment_id UUID NULL REFERENCES coverage_assessment(id),
    ADD COLUMN superseded_by_assessment_id UUID NULL REFERENCES coverage_assessment(id),
    ADD COLUMN superseded_at TIMESTAMPTZ;

-- existing source_origin enum gets new value 'assessment' (next to 'local', 'commons')
-- enforced via CHECK constraint or app-layer enum

-- Partial unique: one active chain per CVE
CREATE UNIQUE INDEX uq_attack_chains_active_per_cve
    ON attack_chains(cve_id)
    WHERE superseded_at IS NULL;

-- review_queue: tag rules by source assessment + detectability override
ALTER TABLE review_queue
    ADD COLUMN assessment_id UUID NULL REFERENCES coverage_assessment(id),
    ADD COLUMN low_detectability_override BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN superseded_by_assessment_id UUID NULL REFERENCES coverage_assessment(id);

-- sigma_rules: track deprecation by an assessment-produced replacement
ALTER TABLE sigma_rules
    ADD COLUMN deprecated_by_rule_id UUID NULL REFERENCES sigma_rules(id),
    ADD COLUMN deprecated_at TIMESTAMPTZ,
    ADD COLUMN deprecated_by_assessment_id UUID NULL REFERENCES coverage_assessment(id);

-- llm_interactions: optional direct join to assessment
ALTER TABLE llm_interactions
    ADD COLUMN assessment_id UUID NULL REFERENCES coverage_assessment(id);

-- attack_chains: indicator storage for Loop 2 output
ALTER TABLE attack_chains
    ADD COLUMN behavioral_indicators JSONB;
```

### 4.2 Lifecycle / state machine

```
                        ┌──────────────┐
                        │   created    │  ← POST /assessments
                        │  (sources    │     analyst pastes sources
                        │   accumulating)│
                        └──────┬───────┘
                               │ analyst clicks Run Loop 1
                               │ OR clicks "Use existing chain"
                               ▼
                        ┌──────────────┐
                        │ loop1_done   │
                        └──────┬───────┘
                               │ analyst clicks Run Loop 2
                               ▼
                  ┌─────►┌──────────────┐
                  │      │ loop2_done   │
        analyst   │      └──────┬───────┘
        adds      │             │ gate passed: analyst clicks Run Loop 3
        sources   │             │ gate failed: (a) re-run Loop 2, OR
        & re-runs │             │              (b) override + Run Loop 3, OR
        Loop 2 ───┘             │              (c) abandon
                                ▼
                        ┌──────────────┐
                        │ loop3_done   │
                        │ (rules in    │
                        │  review)     │
                        └──────┬───────┘
                               │ analyst clicks "Close Assessment"
                               ▼
                        ┌──────────────┐
                        │  completed   │   read-only terminal state
                        └──────────────┘
```

Re-running Loop N invalidates all downstream loops (their active rows go `status='superseded', is_active=false` and state reverts to `loop(N)_done`). Re-running creates a new `assessment_loop_run` row with `version = max(version)+1, is_active=true` for that `(assessment_id, loop_number)`.

### 4.3 Source ingest (v1: free-text only)

URLs and document upload are explicitly deferred to a Phase 2 of the workflow because they bring a distinct security surface (SSRF, malicious PDFs, polyglots, prompt injection from fetched content, retention/PII for uploads) that would distract from validating the loop architecture. The schema is forward-compatible (`kind` column on `assessment_source`).

**Guardrails (all enforced at paste time):**

| Guardrail | Rule | Config | Failure |
|---|---|---|---|
| Per-source size | `len(content) ≤ 100KB` | `ASSESSMENT_MAX_SOURCE_BYTES=102400` | 413 |
| Per-assessment cumulative | sum ≤ 2MB | `ASSESSMENT_MAX_TOTAL_BYTES=2097152` | 413 with current-usage breakdown |
| Per-source dedup | UNIQUE on `(assessment_id, content_hash)` | n/a | 409 |
| Token budget pre-check | est. tokens (chars/4) ≤ Loop 1 prompt budget | `LOOP1_PROMPT_TOKEN_BUDGET=50000` | 413 with estimate |
| Charset | UTF-8 only; reject null bytes + control chars `0x01–0x1F` except `\t\n\r` | n/a | 400 with sanitized preview |
| Injection-risk advisory | placeholder column, no logic in v1 | n/a | n/a |
| TLP per-source | column exists, default = assessment TLP | n/a | n/a |
| LLM-routing TLP gate | column + settings switch exist, enforcement OFF | `STRICT_TLP_LLM_GATING=false` | n/a in v1 |

**Storage model:**

- Sources stored in Postgres (`assessment_source.content`). Small enough that MinIO indirection adds latency without benefit.
- Embedding into Qdrant `source_chunks` (existing collection) tagged with `payload={assessment_id, source_id, kind: 'assessment_source', tlp}`. Triggered by Celery task `embed_assessment_source(source_id)` on insert.
- Loop runs **do not block** on pending embeddings. A run started while embedding is pending writes `embedding_warned=true`. UI shows a banner "Embedding in progress for N source(s) — result accuracy may degrade if Loop 2 RAG misses these."

**Soft-delete:** sources are soft-deleted (rationale required, audit-logged). The Qdrant vector is removed at delete time so subsequent Loop 2 RAG doesn't see it. Hard-delete is an admin operation, not a routine analyst action.

### 4.4 Existing chain reuse

When an analyst creates an assessment and `attack_chains` already has an active row for the CVE (live-feed-produced or commons-projected), the create-flow returns the existing chain summary:

```
POST /api/v1/assessments
Body: { trigger: {kind, value}, context_note }
Returns:
{
  assessment_id,
  cve_id,
  existing_chain: {
    chain_id, source_origin, version, created_at,
    summary: { ttp_count, overall_confidence, top_technique_ids }
  } | null,
  state: 'created'
}
```

UI surfaces two buttons: **Use as starting point** and **Start fresh**.

**Use as starting point** (`POST /assessments/{id}/use-existing-chain { chain_id }`):

1. Insert a synthetic `assessment_loop_run` row: `loop_number=1, version=1, status='succeeded', is_active=true, output={kind: 'imported_from_chain', chain_id, origin: <source_origin>}, prompt_template_id=NULL, model=NULL, cost_usd=0`.
2. Update assessment state to `loop1_done`.
3. No LLM call. No new `attack_chains` row.
4. Loop 2 runs against the assessment's pasted sources and the imported chain's TTPs as context.
5. Loop 3, when it runs, references the existing `chain_id`. The chain's `assessment_id` is back-filled.

**Start fresh** (analyst clicks Run Loop 1 normally):

1. Loop 1 runs. Produces a vuln profile + detection question list.
2. When Loop 2 + chain synthesis complete, a **new** `attack_chains` row is created with `source_origin='assessment', assessment_id=<id>`.
3. The previous chain (live-feed or commons) is hard-superseded: `superseded_by_assessment_id=<id>, superseded_at=now()`. The partial unique index on `attack_chains(cve_id) WHERE superseded_at IS NULL` enforces one active chain per CVE.
4. The old chain row stays in the DB for audit/history. It does not appear in matrix / dashboards by default; a "show superseded" toggle reveals it.

This means there is exactly **one active chain per CVE at any time**. Assessment work always wins over prior automated work.

### 4.5 Review queue integration

Rules produced by Loop 3 land in the existing `review_queue` table with:

- `assessment_id` set to the parent assessment.
- `low_detectability_override` set if the assessment proceeded past a failed Loop 2 gate.

UI changes:

- **Global Review Queue screen** (existing): gains an "Assessment" filter chip. Default view unchanged (shows everything pending across all sources).
- **Assessment Workspace screen**: has its own review panel scoped via `?assessment_id=<id>`. Same component as the global screen, different default filter.
- **Low-detectability badge**: red `low-detectability-override` badge on rows where the flag is set, visible in both global and assessment-scoped views. Tooltip explains the override.
- **Phase A similar-rules panel + Supersede action**: works unchanged on assessment-produced rules.

**Rule-level supersession of prior live-feed work:**

When Loop 3 produces a rule for a `(cve_id, technique_id, profile_id)` triple where a prior rule already exists (regardless of origin), the prior rule is superseded:

- If in `review_queue` (status=`pending`): set `superseded_by_assessment_id`, hide from active queue.
- If already in `sigma_rules` (status=`approved`): mark `deprecated_by_rule_id=<new>, deprecated_at=now(), deprecated_by_assessment_id=<id>`. The new assessment-produced rule enters review queue as the replacement.

This implements the user-decided rule: **analyst work supersedes live-feed work for the same CVE**.

### 4.6 Coverage map integration

When Loop 3 produces rules for an assessment, the existing `map_coverage` Celery task runs against the assessment's chain — unchanged from today's behavior. Phase A's `mapper_version` column tags new rows. The Phase A similar-rules panel + Supersede action surface in the assessment's review panel.

Matrix screen aggregates as today. New: an optional `?assessment_id=<id>` filter on the matrix to scope coverage to one assessment.

### 4.7 Commons integration

The commons subsystem (`fragchain/commons/`) is unchanged in structure. The calling pattern shifts:

- **Bootstrap-time commons import** (existing): still runs at startup, still imports pre-validated chains into `attack_chains` with `source_origin='commons'`.
- **Per-assessment commons check** (new): when an analyst creates an assessment, the existing commons-hit logic runs. A commons-projected chain shows up as an "existing chain" candidate in §4.4's flow. Analyst decides to use it as start or start fresh.

Contribute-to-commons works on assessment-produced chains as today. The `attack_chains.source_origin='assessment'` row carries through the existing contribute flow.

### 4.8 Live-feed coexistence (forward-compat)

Live feed isn't running today. When it comes back online (its own work track), the following rules apply automatically:

- Live-feed-produced chains land in `attack_chains` with `source_origin='live_feed'` (existing).
- If an analyst later opens an assessment for that CVE, §4.4's existing-chain reuse kicks in.
- If the analyst picks "start fresh," the live-feed chain is hard-superseded per §4.4.
- If the analyst picks "use as start," the live-feed chain is preserved; Loop 2 and Loop 3 run with fresh intel.

No live-feed code is deleted. The existing `synthesize_chain` Celery task, the Import Manager UI, `AUTO_PROCESS_KEV`, and connector webhook handlers stay in tree, dormant. They will be revisited once connector work resumes, at which point the supersession semantics above are exercised for real.

`cve_status` is computed (not stored), joining `cves`, `attack_chains`, and `coverage_assessment`:

| Computed state | Meaning |
|---|---|
| `unassessed` | No assessment, no active chain |
| `live_feed_processed` | Active chain exists with `source_origin='live_feed'`, no assessment |
| `assessment_in_progress` | Assessment exists, state ≠ `completed` |
| `assessment_complete` | Assessment in `completed` state |

Surfaced as badges on the CVE Explorer screen. CVE volumes stay small (low hundreds) until live feed resumes, so the computed query is cheap. Denormalization is a future optimization, not a v1 concern.

---

## 5. Three-loop content engine

The loops are invoked by the assessment workspace. They assume:
- An assessment with at least one source pasted (or an imported chain).
- The active LiteLLM provider has a chat model configured.
- The existing `prompt_templates` table has rows for `vuln_analysis`, `threat_intel`, `detection_engineering` (three new task_types seeded on first run).

The loops themselves know nothing about the assessment workflow. They take typed inputs, return typed outputs, and persist through the `assessment_loop_run` table that the workspace orchestrator manages.

### 5.1 Overview

- **Loop 1**: single-shot LLM call. Pure transformation (CVE + sources → vuln profile + question list). Reuses `fragchain/llm/structured.py` (Phase A's structured-output utility) with `schema=VulnProfile`.
- **Loop 2**: tool-using agent, bounded. Two passes max, eight tool calls max. Pre-fetched data only (no web fetch, no on-demand connector dispatch in v1). Output: flat behavioral_indicators map by category.
- **Detectability gate**: deterministic check after Loop 2. Counts non-empty categories. Configurable threshold.
- **Chain synthesis**: not a loop, not an LLM call. Deterministic builder that maps Loop 1's vuln profile + Loop 2's indicators into an `AttackChain` row with TTPs. The TTP technique IDs come from the vuln-class → technique mapping (a curated table seeded with the standard mappings, e.g. "deserialization RCE → T1190 + T1059"). The indicators populate `ChainTTP.behavioral_indicators`. Confidence scores come from indicator density per TTP.
- **Loop 3**: single-shot LLM call, per enabled profile, per TTP gap. Reuses existing `fragchain/rules/generator.py` with `behavioral_indicators` added to the prompt context.

### 5.2 Loop 1 — Vulnerability Analysis

**Purpose:** Describe the vulnerability and emit the detection questions Loop 2 must answer. **Does not** emit TTPs (those come after Loop 2, grounded in real evidence).

**Input:** CVE record + assessment sources concatenated (with per-source delimiters + titles). If sources exceed `LOOP1_PROMPT_TOKEN_BUDGET`, the orchestrator truncates lowest-priority sources first (oldest-pasted, highest injection_risk_score) and surfaces what was excluded.

**Output schema (Pydantic):**

```python
class VulnProfile(BaseModel):
    model_config = ConfigDict(extra='forbid')

    vuln_class: str                    # e.g. "deserialization RCE", "SSRF", "auth bypass"
    affected_component: str            # e.g. "log4j JNDI lookup", "Spring Cloud Gateway routing"
    trigger_conditions: list[str]      # what must be true for exploitation
    attacker_preconditions: list[str]  # network position, auth state, prerequisite access
    expected_impact: str               # RCE, info disclosure, DoS, etc.
    exploitation_surface: str          # short narrative

class DetectionQuestion(BaseModel):
    model_config = ConfigDict(extra='forbid')

    id: str                            # 'q1', 'q2', ...
    category: ObservableCategory       # process|command_line|file|network|registry|parent_child|api_call
    question: str                      # "what command-line argument is unique to exploitation?"
    why_it_matters: str

class Loop1Output(BaseModel):
    model_config = ConfigDict(extra='forbid')

    vuln_profile: VulnProfile
    detection_questions: list[DetectionQuestion] = Field(min_length=3, max_length=20)
```

**Prompt template:** new row in `prompt_templates`, `task_type='vuln_analysis'`. Seeded with a default v1 prompt; analysts iterate via the existing Prompts Management UI.

**Persistence:** `assessment_loop_run(loop_number=1)` with `output={vuln_profile, detection_questions}`. Cost + latency + model captured from the structured_complete call.

### 5.3 Loop 2 — Threat Intel (agentic)

**Purpose:** Answer the detection questions with concrete observables.

**Tools available in v1:**

| Tool | Status |
|---|---|
| `rag_search(query, k=5)` | Active. Semantic search over Qdrant `source_chunks` scoped to `assessment_id`. |
| `list_assessment_sources()` | Active. Returns titles + IDs of all sources attached to this assessment. |
| `get_source_content(source_id)` | Active. Returns full content of a specific source. |
| `lookup_connector(connector_name, cve_id)` | Stubbed in v1 (returns empty). Hooked for future when connectors land. |

No web fetch. No on-demand fetching of new sources. The agent is bounded to what the analyst has already pasted.

**Iteration shape:**

- **Bulk pass (always runs):** orchestrator dispatches RAG queries for all Loop 1 detection questions in parallel. Agent receives concatenated results and emits a first-cut indicator map.
- **Gap pass (conditional):** if any observable category is empty after bulk pass, the agent is invoked with `{remaining_questions, empty_categories}` and can dispatch focused RAG queries (max 5) targeting specific categories.
- **Budget:** max 2 passes total, max 8 tool calls across both passes, max 60s wall-clock per pass.

**Output schema:**

```python
class ObservableCategory(str, Enum):
    PROCESS = "process"
    COMMAND_LINE = "command_line"
    FILE = "file"
    NETWORK = "network"
    REGISTRY = "registry"
    PARENT_CHILD = "parent_child"
    API_CALL = "api_call"

class BehavioralIndicator(BaseModel):
    model_config = ConfigDict(extra='forbid')

    value: str                         # literal or pattern string
    kind: Literal['literal', 'regex', 'substring']
    source_ref: str                    # source_id or RAG chunk_id
    confidence: float = Field(ge=0.0, le=1.0)
    answers_question_id: str | None    # which Loop 1 question this answers (optional)

class Loop2Output(BaseModel):
    model_config = ConfigDict(extra='forbid')

    indicators: dict[ObservableCategory, list[BehavioralIndicator]]
    unanswered_questions: list[str]    # question IDs the agent couldn't answer
```

**Prompt template:** new row in `prompt_templates`, `task_type='threat_intel'`. The system prompt defines tool semantics; user prompt embeds Loop 1 output.

**Persistence:** `assessment_loop_run(loop_number=2)` with `output={indicators, unanswered_questions}` and `gate_result` populated by §5.4.

### 5.4 Detectability gate

**Algorithm (deterministic):**

```
filled_categories = {cat for cat, indicators in Loop2Output.indicators.items()
                     if any(i for i in indicators)}
empty_categories  = set(ObservableCategory) - filled_categories

passed = len(filled_categories) >= GATE_MIN_CATEGORIES

gate_result = {
  passed: passed,
  filled_categories: list(filled_categories),
  empty_categories: list(empty_categories),
  threshold: GATE_MIN_CATEGORIES,
}
```

**Configuration:**

- `GATE_MIN_CATEGORIES` default = 3 (of 7 total). Configurable per deployment via env var.
- Future per-profile thresholds (e.g. "linux-auditd needs at least one process + one command_line"): the schema accommodates this (gate_result is JSONB), the v1 implementation only checks the global threshold.

**Outcomes:**

- **Pass:** `assessment_loop_run.status='succeeded'`, state machine progresses to `loop2_done`. Chain synthesis (§5.5) is now eligible to run when analyst clicks Run Loop 3.
- **Fail:** `assessment_loop_run.status='gate_failed'`, state stays at `loop2_done`. UI offers three actions: re-run Loop 2 (with new sources), override + proceed with rationale, or abandon.

**Override path:** if analyst overrides, `override_rationale` is required (non-empty, max 500 chars, audit-logged). All rules produced by Loop 3 carry `low_detectability_override=true` on the review_queue row.

### 5.5 Chain synthesis bridge

Deterministic; not an LLM call.

**Input:** Loop 1's `VulnProfile` + Loop 2's `BehavioralIndicator` map.

**Output:** an `AttackChain` row (schema unchanged from today's `fragchain/chain/schema.py`, plus the new `behavioral_indicators` field on the chain row and per-TTP).

**Algorithm:**

1. Look up TTPs for the `vuln_class` from a curated mapping table `vuln_class_to_ttps` (seeded with the standard mappings — deserialization RCE, SSRF, path traversal, auth bypass, etc.). This table is operator-extensible.
2. For each TTP, look up which observable categories are relevant via a curated `ttp_category_relevance` table (e.g., T1059 → command_line, parent_child; T1190 → network, process).
3. Assign indicators to TTPs by category match.
4. Compute per-TTP `confidence` from indicator density (number of indicators in relevant categories, weighted by source confidence).
5. Set chain `overall_confidence = mean(ttp_confidences)`.
6. Set `source_origin='assessment'`, `assessment_id=<id>`.

The curated mapping tables are not LLM-driven — they're a small data file maintained alongside the codebase. v1 ships with a starter set covering common vuln classes.

**Why deterministic:** the previous chain generator used LLM synthesis to map CVE → TTPs because there was no other source of truth. Now Loop 1 gives us the vuln class explicitly, and the mapping is well-known industry knowledge that doesn't benefit from LLM judgment. Deterministic = testable + free.

### 5.6 Loop 3 — Detection Engineering

**Purpose:** Generate Sigma rules grounded in concrete behavioral indicators, one per enabled profile per TTP that lacks coverage.

**Reuse:** `fragchain/rules/generator.py` (1275 lines) is reused unchanged in structure. The only delta: the prompt template gets `behavioral_indicators` (filtered to indicators relevant to the target TTP + profile) added to the prompt context. The pySigma validation, multi-profile generation loop, exact-hash dedup (from Phase A), and review_queue persistence all work as today.

**Prompt template:** the existing `rule_generation` task_type row is duplicated as `detection_engineering` for assessments. Operators can keep both prompts active (one for live-feed, one for assessment) and iterate independently.

**Persistence:** rules land in `review_queue` with `assessment_id` set. If `low_detectability_override=true` on the parent loop run, that flag propagates to each rule.

---

## 6. Failure modes & operations

| Failure | Behavior | UX |
|---|---|---|
| Loop N LLM error or timeout | `assessment_loop_run.status='failed', error=<text>`. State stays at previous loop. | Inline error, retry button (creates new version). Audit-logged. |
| Loop 2 gate failure | Run persists with `status='gate_failed'`, `gate_result` shows empty categories. | UI offers: paste more sources + re-run, override + proceed (rationale required), or abandon. |
| Embedding pending when Loop N starts | Run starts anyway, `embedding_warned=true`. | Banner: "Embedding in progress for N source(s). Result accuracy may degrade." Re-run after embedding completes is comparable. |
| Source embedding fails | `assessment_source.embedding_status='failed'`. | Banner: "1 source failed to embed — won't be in Loop 2 RAG. Retry?" Doesn't block runs. |
| Loop 1 produces bad output | No auto-detection in v1. | Analyst eyeballs at `loop1_done` gate, re-runs with edited context if needed. |
| Bad source pasted (e.g. analyst pasted by mistake) | Soft-delete with rationale (audit). Qdrant vector removed at delete time. | Source disappears from RAG on next loop run. |

**Audit:** every analyst action writes to `audit_log` with `entity_type='coverage_assessment' | 'assessment_source' | 'assessment_loop_run'`. Actions: create, source_paste, source_delete, loop_run_trigger, gate_override, close, supersede_prior_rule.

**Observability:**

- LLM cost per assessment: `SELECT sum(cost_usd) FROM llm_interactions WHERE assessment_id = ...` (existing table + new column).
- Time-to-completion: `assessment.completed_at - assessment.created_at`.
- Re-run heatmap: count of versions per loop per assessment. High re-run counts on Loop 2 → analyst struggling with intel density.

---

## 7. Measurement & Phase A integration

The Phase A `coverage_benchmark` and `coverage_benchmark_runs` tables and labeling CLI work unchanged on assessment-produced chains.

**Comparison runs:**

- Label a benchmark set of 20 CVEs (Phase A baseline).
- Run benchmark against assessment-produced coverage maps → P/R/F1 with `run_label='phase-a-assessment-v1'`.
- Compare against the existing Phase A baseline (`run_label='baseline'`) and the Phase A improved mapper (`run_label='phase-a'`).
- Decision gate: if assessment-produced chains lift F1 meaningfully (and the rules are non-generic per analyst spot-check), the new pipeline graduates from "additional path" to "preferred path." Live-feed remains in tree but the docs steer new operators toward assessments.

**Per-loop measurement (future, post-v1):**

- `assessment_loop_run.cost_usd` already captures per-loop cost.
- Loop 2 indicator density (number of indicators per category) per source pasted → measures whether adding source X improved intel coverage. The versioned re-run model makes this trivially computable: compare `loop2 v_n` against `loop2 v_(n+1)` after a paste.

---

## 8. Sequencing

Eight workstreams. Each can be a separate PR; dependencies noted.

| # | Workstream | Depends on | Output |
|---|---|---|---|
| 1 | Alembic migration: new tables + column adds to existing tables. | — | `0010_assessment_centric.py` |
| 2 | Backend skeleton: assessment CRUD, source CRUD, state machine, audit-log wiring. Stub loops returning canned outputs. | 1 | `fragchain/assessments/` module + `routers/assessments.py` |
| 3 | Source embedding integration (assessment-tagged chunks into existing `source_chunks` Qdrant collection). | 2 | `worker/tasks/embed_assessment_source.py` |
| 4 | Existing-chain reuse path (`POST .../use-existing-chain`). | 2 | endpoint + tests |
| 5 | Loop runner infrastructure: generic per-loop Celery task, versioning logic, structured_complete integration. Loops still return canned outputs. | 2, 3 | `worker/tasks/run_assessment_loop.py` |
| 6 | Frontend Assessment Workspace screen: create flow, source paste UI, per-loop gates with version diffs. | 5 | `frontend/src/screens/AssessmentWorkspace.tsx` |
| 7 | Review queue integration: `assessment_id` filter, `low_detectability_override` badge, rule-level supersession of prior live-feed work. | 5 | router changes + queue UI changes |
| 8 | Real Loop 1 / Loop 2 / Loop 3 implementations. Replace stubs. | 5, plus three new `prompt_templates` rows seeded | `fragchain/assessments/loops/loop1.py`, `loop2.py`, `loop3.py` |

After step 6, the UX is testable end-to-end with stub loops. Steps 7 and 8 can land in either order.

Phase A's coverage-verification work (in flight, sequenced on days 1–6 of its own design note) continues independently. It does not block this work and is not blocked by it.

---

## 9. Decisions (locked from brainstorming)

For traceability — each row is a question that was raised in brainstorming and the answer that locked.

| # | Question | Decision |
|---|---|---|
| 1 | Loop autonomy spectrum (single-shot ↔ fully agentic). | Hybrid: Loop 1 + Loop 3 single-shot, Loop 2 bounded agent. |
| 2 | What does Loop 1 emit — chain, profile-only, or two-pass? | Vuln profile + detection questions only. No TTPs. Chain is built after Loop 2 from real evidence. |
| 3 | Detectability gate criterion. | Category-coverage gate. Threshold = ≥3 of 7 categories, configurable. |
| 4 | Loop 2 tools palette. | Pre-enriched data only (RAG over assessment-scoped chunks + connector lookups when they exist). No web fetch. |
| 5 | Loop 2 output shape. | Flat behavioral_indicators map per category. Each indicator has `{value, kind, source_ref, confidence, answers_question_id?}`. |
| 6 | Commons hit semantics. | Skip Loop 1 + chain synthesis; Loop 2 + Loop 3 still run. (Same path as existing-chain-reuse §4.4.) |
| 7 | Integration approach (drop-in / feature-flag / incremental). | Feature flag + side-by-side. Phase A benchmark measures lift. |
| 8 | Ingestion model coexistence. | Coexist: live feed isn't running but isn't deleted either. Assessment workflow is the new primary path. |
| 9 | Assessment scope per CVE. | 1:1 in v1. Versioning is future expansion. |
| 10 | Create flow / minimum inputs. | Multi-input: CVE-ID, ticket ID, or PSIRT URL. Multi-input resolver normalizes to CVE-ID + audit context. |
| 11 | Source types in v1. | Free-text paste only. URLs + uploads deferred (Phase 2 of assessment workflow). |
| 12 | Loop progression. | Per-loop manual gates in v1. Auto-progression is future toggle. |
| 13 | Re-run model. | Per-loop versioned re-run. Downstream loops invalidated until re-run. |
| 14 | Existing chain coexistence. | Offer as starting point; analyst chooses use-as-start vs start-fresh. One active chain per CVE enforced. |
| 15 | Completion. | Manual close by analyst. |
| 16 | Embedding-blocking-loop-start. | Don't block. Warn the analyst; flag run as `embedding_warned`. |
| 17 | TLP enforcement on LLM routing. | Field + settings switch exist, enforcement OFF in v1. |
| 18 | Prompt-injection scoring. | Placeholder column, no logic in v1. |
| 19 | Two chains per CVE allowed? | No. One active chain per CVE; assessment supersedes prior. |
| 20 | Rule-level supersession of live-feed work. | Yes. Prior rules for the same `(CVE, technique, profile)` get marked deprecated when assessment produces a replacement. |
| 21 | `cve_status` computed vs stored. | Computed. CVE volumes stay small until live feed resumes. |
| 22 | Single spec or two. | Single combined spec (this document). Split later if needed. |

---

## 10. Out of scope (explicit — won't drift in)

- URL ingest, document upload, screenshot ingest.
- Asset / CMDB integration.
- Multi-analyst collaboration on one assessment.
- Auto-progression toggle through loops.
- Connector implementation (the protocol exists; building specific connectors is a separate track).
- LLM-judged quality scoring on Loop 1 output.
- Versioning of the assessment itself.
- Prompt-injection scoring logic.
- TLP-based LLM routing enforcement.
- Removal or deletion of the existing linear pipeline.
- Sharing / export of assessments (e.g. PDF report, JIRA back-write).
- Notifications when assessments transition states.
- Assessment templates ("standard SSRF assessment checklist," etc.).
- ATT&CK Atlas / SPARTA framework support (the loops are framework-agnostic but seeded with ATT&CK mappings only).

---

## 11. Open questions

- **Curated mapping tables (`vuln_class_to_ttps`, `ttp_category_relevance`):** initial seed set size and source. Proposal: borrow from MITRE CTID's published mappings + Atomic Red Team test catalog metadata. Resolve before §5.5 lands.
- **Threshold tuning:** `GATE_MIN_CATEGORIES=3` is a guess. Resolve with first 20 benchmark assessments.
- **Per-profile gate variations:** the schema supports per-profile thresholds (e.g., linux-auditd needs at least one process + one command_line). Implementation deferred until benchmark data shows the global threshold is too coarse.
- **Loop 2 agent budget:** 8 tool calls / 2 passes / 60s per pass — guesses. Tune after first 20 assessments.
- **Multi-tenant ownership / TLP visibility:** v1 has single-creator assessments with read access controlled by the existing TLP middleware. The exact "who can see whose assessment" semantics need product-side definition. Out of scope here; flagged for a follow-up product decision.
- **Stub-loops sequencing decision (§8 step 5):** workstream 8 (real loops) is the largest single piece. Whether to ship the workspace publicly with stub loops or hold release until real loops exist is a release decision, not a design one.
