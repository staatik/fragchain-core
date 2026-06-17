# Current Architecture

## Status

Baseline — completed 2026-06-09 (Codex Stage 0 / Phase 0 reconciliation).
Supersedes the generic placeholder shipped with the control pack.

This document describes FragChain as implemented **before** the defense-engineering
pipeline work (detectability classifier, artifact router, validation states) begins.
Adoption decisions are recorded in
[`adr/ADR-0004-staged-defense-engineering-adoption.md`](adr/ADR-0004-staged-defense-engineering-adoption.md).

## Backend Framework and Entry Points

- **Language/runtime:** Python 3.12, async/await throughout.
- **API:** FastAPI — entry point `fragchain/api/main.py`. Middleware: TLP response
  filtering (`fragchain/api/middleware/tlp_filter.py`); auth is JWT helpers in
  `fragchain/api/security.py` + the login router (`fragchain/api/routers/auth.py`),
  not a middleware.
- **Workers:** Celery + Redis — entry point `fragchain/worker/celery.py`. Worker
  processes bootstrap providers themselves via `worker_process_init` (they do not
  inherit API lifespan setup — see CLAUDE.md §19).
- **Persistence:** PostgreSQL via SQLAlchemy 2.0 async + asyncpg; Alembic migrations
  `0001`–`0022` under `fragchain/db/migrations/versions/`.
- **Vector store:** Qdrant (local to the deployment, no collection prefix) —
  collections `source_chunks`, `sigma_rules`, `attack_chains`, `attck_techniques`.
- **Object storage:** MinIO (full LLM I/O archive under `llm-io/`).
- **LLM access:** LiteLLM only, via the OpenAI-compatible SDK behind the
  `LLMProvider` protocol (`fragchain/llm/base.py`, `fragchain/llm/litellm_provider.py`).
  Direct Anthropic/OpenAI SDK use is forbidden.
- **Frontend:** React + Vite, DarkOps v3 design system (`frontend/`).

## API Route Structure

Routers under `fragchain/api/routers/`:
`assessments`, `auth`, `chains`, `commons`, `connectors`, `coverage`,
`coverage_benchmarks`, `cves`, `embargo`, `evaluations`, `health`, `identity`
(placeholder, all 501), `imports` (dormant), `llm`, `profiles`, `prompts`, `queue`,
`rules`, `sigma`, `vector`, `version`, `webhooks` (dormant), `websocket`.

## Two Flows: Active vs. Dormant

FragChain has one **active** workflow and one **dormant** one. This split is
deliberate and documented in CLAUDE.md §12/§12.1/§12.2.

### Active — analyst-initiated assessment workspace

An analyst opens a `coverage_assessment` for a CVE, pastes source material, and
drives three gated loops:

1. **Loop 1 — Vulnerability analysis** (`fragchain/assessments/loops/loop1.py`):
   single-shot LLM call via `structured_complete` → `VulnProfile` +
   `DetectionQuestion[]` (schemas in `fragchain/assessments/loops/schemas.py`,
   `extra='forbid'`).
2. **Loop 2 — Threat intel** (`loop2.py` + `rag.py`): bounded bulk-then-gap RAG over
   assessment-scoped Qdrant chunks → `BehavioralIndicator`s per `ObservableCategory`
   (process / command_line / file / network / registry / parent_child / api_call).
3. **Detectability gate** (deterministic, `loops/stubs.py::evaluate_detectability_gate`):
   passes when ≥ `GATE_MIN_CATEGORIES` (default 3) of 7 categories are non-empty.
   On fail: re-run Loop 2, override with recorded rationale, or abandon.
4. **Chain synthesis bridge** (`fragchain/assessments/chain_synthesis.py` +
   `mapping.py`): deterministic (no LLM) — normalized `vuln_class` → curated TTP
   tables → `attack_chains` row, one active chain per CVE enforced by partial unique
   index. Unmapped classes fall back to a generic T1190+T1203 chain, flagged for
   review.
5. **Loop 3 — Detection engineering** (`loop3.py`): wraps
   `fragchain/rules/generator.py::RuleGenerator` per enabled logsource profile per
   TTP gap; pySigma validation is a mandatory inline gate; exact `content_hash`
   dedup plus semantic redundancy flagging (`similar_to_rule_id`, migration `0022`);
   rules land in `review_queue`.

State machine on `coverage_assessment.state`
(`fragchain/assessments/state_machine.py`, enforced by
`fragchain/assessments/orchestrator.py::LoopOrchestrator`):
`created → loop1_done → loop2_done → loop3_done → completed`, with versioned re-runs
in `assessment_loop_run`.

Celery integration: `fragchain/worker/tasks/run_assessment_loop.py` (loop runner with
post-loop hooks: `ChainSynthesizer`, `RuleSuperseder`, `map_coverage` dispatch) and
`embed_assessment_source.py` (chunk + embed pasted sources).

### Dormant — connector-driven linear pipeline

`webhook → enrich → commons check → LLM chain synthesis → coverage → rule gen →
review`. Preserved per the CLAUDE.md §12.2 allowlist (`ChainGenerator`,
`synthesize.py`, webhooks, import manager, `processing_status` state machine,
enrichment orchestrator). **Do not delete; do not treat as dead code.** Revival
trigger: a real connector ecosystem.

## CVE Intake Logic

- Active: `POST /assessments` (multi-input trigger resolution in
  `fragchain/assessments/trigger_resolver.py` — CVE id / ticket / PSIRT URL).
- Dormant: connector webhooks (`fragchain/ingest/webhooks.py`) and the historical
  Import Manager (`fragchain/api/routers/imports.py`).

## Source Collection Logic

Pasted free text only in v1: `assessment_source` rows (≤100KB each, ≤2MB per
assessment), UNIQUE on `(assessment_id, content_hash)`, soft-deletable. An embed
task chunks and tags them into Qdrant `source_chunks`, assessment-scoped. There is
no web fetch and no on-demand connector dispatch inside loops.

## LLM Orchestration

- `fragchain/llm/` — provider protocol, registry, LiteLLM provider,
  `structured.py::structured_complete` (schema-validated structured output with
  retry-on-validation-failure).
- Every call logged to `llm_interactions` (with `assessment_id` for cost roll-up)
  plus full I/O to MinIO, best-effort (failures surface as structlog events, never
  block the call).
- LLM output is treated as untrusted: Pydantic `extra='forbid'` on loop schemas and
  `AttackChain`; validation before persistence.

## Prompt Templates

Runtime-managed in DB (`prompt_templates`, keyed by `task_type`; one active row per
`(task_type, model, provider)` via partial unique index, re-keyed in migration
`0021`). A/B tests and evaluations supported. Seeded task types:
`chain_generation`, `rule_generation`, `coverage_verify`, plus the assessment loop
prompts. No prompts hardcoded in files.

## Detection Generation Logic

- `fragchain/rules/generator.py::RuleGenerator` — multi-profile Sigma v2 generation,
  grounded in Loop 2 behavioral indicators when invoked from Loop 3.
- Coverage gaps come from the embedding-first
  `fragchain/coverage/mapper.py::CoverageMapper` (chat-LLM verify is opt-in and
  bounded; embeddings + Qdrant decide coverage by default).
- **Sigma is currently the only artifact type, and generation runs for every TTP gap
  × enabled profile once the gate passes.** There is no per-artifact routing
  decision and no "no reliable detection" outcome. This is the central gap the
  defense-engineering pivot addresses.

## Validation Logic (current)

- `fragchain/rules/validator.py` — pySigma wrapper producing a transient
  `ValidationResult` (errors/warnings). Validation is a **blocking inline gate** at
  generation time: invalid YAML never persists.
- There is **no persisted validation state** on `sigma_rules` (no
  `not_validated / validated / validated_with_warnings / validation_failed` field).
  Rules that exist implicitly passed pySigma at generation time.

## Persistence Model for Generated Outputs

Typed relational rows, not blobs: `attack_chains` (+ `chain_ttps` with
per-TTP `behavioral_indicators`), `sigma_rules` (YAML + flattened metadata, dedup
hash, similarity flag), `review_queue` (priority-scored, TLP-tagged,
`assessment_id`-filterable), `assessment_loop_run` (full loop outputs as versioned
JSONB), `llm_interactions`, `coverage_map`.

## Review and Export (current)

- `review_queue` / `sigma_rules.status`: `generated → review → approved → merged`;
  human gate is inviolable (never auto-merge).
- Export: approved rules go to configured `sigma_targets` via routing-rule
  expressions and Git PR creation (`fragchain/sigma/targets.py`). No per-export
  result record is persisted beyond rule status.

## Test Structure

75 test files under `tests/`, mirroring the package (suites for `assessments`,
`coverage`, `queue`, `db`, `llm`, `api`, plus module-level files). Async pytest;
external network calls mocked.

## Documentation Structure

- `docs/architecture/` — active design notes (assessment-centric design is the
  canonical one) + this control-pack series (`000`–`008`) + `adr/`.
- `docs/codex/` — control-pack governance: change log, open questions, known risks,
  prompt harness, skills.
- `docs/historical/` — M1–M24 build record and pre-pivot design corpus.
- `docs/superpowers/plans/` — per-feature TDD plans.
- `CLAUDE.md` — authoritative project instructions (v2.4+ acknowledges the
  defense-engineering direction; `AGENTS.md` defers to it).

## Security-Sensitive Code Paths

- TLP enforcement middleware on every API response; embargo override logic
  (`fragchain/security/`).
- Git URL validation on sigma sources/commons (`https` only by default; `file:`,
  `ssh://`, `git://` rejected) — clone-path / SSRF guard.
- Prompt-injection surface: analyst-pasted sources flow into RAG context. Schemas
  bound what the model can return; source content must never control pipeline flow.
- Auth middleware; identity verification intentionally stubbed (501) in v1.
- Secrets via env vars only; LLM I/O archive may contain sensitive source text —
  MinIO is internal-only.

## Coupling and Duplication Observations

- Loop 3 is tightly coupled to `RuleGenerator` and to the Sigma-only artifact model
  (`sigma_rules` assumes YAML). Generic artifacts will need either a new table or a
  type-discriminated extension.
- `CoverageMapper` runs both inside Loop 3 and as a post-chain Celery task —
  intentional but worth watching.
- The dormant linear pipeline coexists with the active flow by design (§12.2);
  audits must not flag it as dead code.
- `review_queue` is shared between both flows — convenient now, but review-state
  changes ripple into both.

## Current CVE Processing Flow

See the assessment pipeline diagram in CLAUDE.md §12.1. Summary: analyst opens
assessment → pastes sources → embed → Loop 1 → Loop 2 → deterministic gate →
chain synthesis → Loop 3 (Sigma per profile per gap) → review queue → human
approve → PR to sigma target.

## Current Artifact Generation Flow

Gap-driven and Sigma-only: chain TTPs minus embedding-covered techniques → for each
gap × enabled profile → LLM rule generation → pySigma gate → dedup/redundancy
check → `review_queue`. No routing, no skip-with-reason, no alternative artifact
types.

## Known Risks

Tracked in [`../codex/known-risks.md`](../codex/known-risks.md) (corrected against
the actual codebase in Phase 0 — several of the control pack's generic guesses did
not apply).

## Recommended First Refactor Target

Insert a `DetectabilityAssessment` stage in
`LoopOrchestrator` between the Loop 2 gate and chain synthesis / Loop 3:

- The deterministic category gate **stays** as a hard floor (non-breaking).
- The classifier adds the 5-class assessment (class, rationale, confidence,
  telemetry, blind spots, recommended/skipped artifacts) consumed later by the
  artifact router.
- Persist alongside loop runs; existing assessments behave identically until the
  router (Phase 2) consumes the output.

See ADR-0004 for the staged plan.
