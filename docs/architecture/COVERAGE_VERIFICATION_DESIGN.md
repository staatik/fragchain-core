# Coverage Verification — Design Note (Phase A)

> ⚠️ **SUPERSEDED (2026-05-28) by the embedding-first coverage redesign.**
> This note describes a **per-existing-rule chat-LLM verification** model
> (Phase 1.5 verifies every ATT&CK-tag match; `structured_complete(schema=VerifyVerdict,
> n_samples=3)`; budget `len(ttps) × 8` verify calls). That approach is **no longer
> the active design** — a real assessment fired ~1,428 `coverage_verify` LLM calls,
> against the platform's "embeddings + Qdrant carry the coverage signal" principle.
>
> **Current model (authoritative):** see CLAUDE.md §12.1 → "Coverage verification —
> embedding-first." In short:
> - Coverage is decided by **embedding similarity** (Qdrant `query_points`, score ≥
>   `SEMANTIC_SCORE_THRESHOLD`) to the chain's behavior. A bare tag match no longer
>   auto-covers.
> - The chat-LLM verify (Phase 1.5 + Phase 2 verify) is **opt-in, off by default**
>   (`COVERAGE_LLM_VERIFY_ENABLED=False`); when enabled it is bounded — `n_samples=1`,
>   capped at `COVERAGE_VERIFY_MAX_CALLS`.
> - Generated-rule redundancy is checked **post-generation** by embedding the rule and
>   semantic-searching the library (`RULE_SIMILARITY_THRESHOLD` →
>   `sigma_rules.similar_to_rule_id`/`similarity_score`, migration `0022`), flagged for
>   review, never dropped. Exact byte-duplicates are caught by the stable `content_hash`.
>
> The rest of this document is retained as historical design context (the
> `structured_complete` / benchmark / similar-rules-panel pieces below are still live).
> Where it conflicts with the bullets above, the bullets win.

**Status:** **Reconciled 2026-05-19** — Phase A shipped via the completion plan (`docs/superpowers/plans/2026-05-18-phase-a-completion.md`). Re-verified against current `main`:

| Spec section | Status | Evidence |
|---|---|---|
| §3.1 `structured_complete` | ✅ landed | `fragchain/llm/structured.py` |
| §3.2 benchmark schema + CLI scripts | ✅ landed | migration `0016_coverage_verification`, `scripts/label_coverage_benchmark.py`, `scripts/run_coverage_benchmark.py` |
| §3.2 benchmark endpoints | ✅ landed | `fragchain/api/routers/coverage_benchmarks.py` (`POST/GET /runs[/{id}]`) |
| §3.3 mapper prompt updates (CVE-grounded query, expanded verify, Phase 1.5 tag-verify) | ✅ landed | `fragchain/coverage/mapper.py` (`grep "Phase A\|phase_1_5\|verify_tag"` returns hits) |
| §3.5 exact-hash dedup at rule-gen time | ✅ landed | `fragchain/rules/generator.py::_content_hash` |
| §3.6 similar-rules panel data + manual Supersede action | ✅ landed | `fragchain/queue/manager.py::_fetch_similar_rules`, plus a `supersede` endpoint in `fragchain/api/routers/queue.py` |
| §3.7 `mapper_version` column + clear/redeploy script | ✅ schema landed (migration `0016`); admin script status unverified — re-check before relying on it |
| §3.5 `backfill_content_hash.py` (planned for `scripts/`, never created) | ⏸ deliberately deferred per audit §2.10 (non-blocker; new rules already populate `content_hash`) |
| Chain-generator migration to `structured_complete` | ⏸ deliberately deferred per audit §2.9 (legacy `ChainGenerator` is dormant per assessment-centric design §4.8 and CLAUDE.md §12.2) |

Plan B and Plan C (assessment-centric refactor) now build on this Phase A foundation. Phase B (exploit-analysis stage, semantic dedup, per-profile gap accounting) remains future scope; the assessment workflow has not yet been benchmarked against the Phase A baseline (assessment-centric design §7 — measurement track).

**Status (original):** Draft for review
**Date:** 2026-05-16
**Author:** Elie M (drafted with Claude)
**Decides:** scope, schema, and prompt changes for the first coverage-correctness pass, including exact-hash deduplication and the analyst-facing similar-rules workflow. Phase B (exploit-analysis stage, behavioral-indicators schema, per-profile accounting, semantic dedup) is sequenced after measurement.

---

## 1. Problem

The coverage mapper currently classifies an attack-chain TTP as `covered` if either:

- a SigmaHQ rule has the technique tag (`technique_ids @> [tid]`, [mapper.py:387–395](../../fragchain/coverage/mapper.py#L387)), or
- a semantic candidate scores ≥ `0.75` on Qdrant **and** a generic verify-prompt returns `yes` ([mapper.py:422](../../fragchain/coverage/mapper.py#L422), [mapper.py:490–497](../../fragchain/coverage/mapper.py#L490)).

Neither path uses CVE context. Tag matching has no quality gate at all. Verified empirically on CVE-2026-7813: all 5 chain TTPs marked `covered` (12–46 tagged rules each), zero rules generated, zero gaps surfaced. None of the matched rules were written for this CVE; the chain was synthesized correctly but the coverage layer claimed it was already handled.

A separate but related problem surfaces when generation does run: nothing prevents the LLM from producing rules that duplicate existing ones (FragChain-generated or SigmaHQ-imported) and nothing surfaces near-matches to the analyst during review.

## 2. Goals / non-goals

**Goals (Phase A):**
- Drop the false-coverage rate by introducing CVE-aware verification on both tag-matched and semantically-matched candidates.
- Prevent exact structural duplicates from being persisted as new rules.
- Surface partial-coverage rules to the analyst in the review queue so the human is the final dedup layer.
- Make every future prompt or threshold change quantitatively measurable against a fixed labeled set.

**Non-goals (Phase A — pushed to Phase B or decided out):**
- Schema changes to `ChainTTP` (no `behavioral_indicators` field yet) — Phase B.
- Exploit-analysis as a separate pipeline stage — Phase B.
- Per-profile (logsource) gap accounting — Phase B.
- Semantic dedup (Qdrant + LLM compare-two-rules at generation time) — Phase B.
- Collapsing `partial` coverage into a binary `covered` / `gap` — **decided out**, partial stays.
- Changes to the rule generator's core prompt. Coverage classification + dedup + review UX only.
- New top-level module or public API.

## 3. Components

### 3.1 Structured-output utility — `fragchain/llm/structured.py`

A thin helper, not a module. No DB, no API. Used by callers that want a Pydantic-validated LLM response with optional voting.

```python
T = TypeVar("T", bound=BaseModel)

@dataclass
class StructuredResult(Generic[T]):
    value: T                # consensus or single parsed sample
    confidence: float       # 1.0 if n_samples=1; else agreement ratio in [0,1]
    samples: list[T]
    attempts: int
    cost_usd: float

async def structured_complete(
    provider: LLMProvider,
    system: str,
    user: str,
    model: str,
    schema: type[T],
    *,
    interaction_type: InteractionType,
    n_samples: int = 1,
    max_repair_attempts: int = 2,
    temperature: float = 0.0,
    timeout_seconds: float = 30.0,
    entity_type: str | None = None,
    entity_id: uuid.UUID | None = None,
) -> StructuredResult[T]:
    """Validated LLM call with optional repair retry and majority-vote sampling."""
```

Behaviors:
- `n_samples=1`: one call, parse with `schema.model_validate_json`, on `ValidationError` retry with the prior response + the validation error message appended to the user prompt, up to `max_repair_attempts`.
- `n_samples≥2`: run N calls in parallel at `temp=0`, parse each, return field-level majority consensus with `confidence = agreement_ratio`.
- Every underlying call still logs to `llm_interactions` and MinIO via the existing M5 path. No new logging surface.
- On all-samples-fail: raise `StructuredOutputError`; caller decides degradation (skip / conservative-default / propagate).

Migration target: today's chain validate-and-retry loop ([chain/generator.py](../../fragchain/chain/generator.py)) is reimplemented as one `structured_complete(schema=AttackChain, n_samples=1, max_repair_attempts=2)` call.

### 3.2 Benchmark schema

Two new tables, both behind one Alembic migration. Default `tlp:clear` and commons-eligible. Contribution happens via the existing manual "Contribute to Commons" analyst action (same flow as chains/rules) — no auto-push. Per-row TLP override available for regulated deployments.

```sql
coverage_benchmark (
    id                UUID PRIMARY KEY,
    cve_id            UUID NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    technique_id      VARCHAR(20) NOT NULL,
    rule_id           UUID NOT NULL REFERENCES sigma_rules(id) ON DELETE CASCADE,
    expected_verdict  VARCHAR(20) NOT NULL,   -- 'covered' | 'partial' | 'no_match'
    rationale         TEXT NOT NULL,
    labeled_by        VARCHAR(255) NOT NULL,
    labeled_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (cve_id, technique_id, rule_id)
)

coverage_benchmark_runs (
    id                   UUID PRIMARY KEY,
    run_label            VARCHAR(100) NOT NULL,
    prompt_template_id   UUID REFERENCES prompt_templates(id),
    semantic_threshold   NUMERIC(3,2),
    started_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at         TIMESTAMPTZ,
    total_pairs          INTEGER NOT NULL,
    true_positives       INTEGER NOT NULL,
    false_positives      INTEGER NOT NULL,
    true_negatives       INTEGER NOT NULL,
    false_negatives      INTEGER NOT NULL,
    precision_score      NUMERIC(5,4),
    recall_score         NUMERIC(5,4),
    f1_score             NUMERIC(5,4),
    notes                TEXT
)
```

Two CLI scripts (no UI in Phase A):
- `scripts/label_coverage_benchmark.py <CVE-ID>` — surfaces candidate rules per technique and prompts for `covered / partial / no_match` + one-line rationale.
- `scripts/run_coverage_benchmark.py --label <name>` — runs current mapper against labeled set, computes confusion matrix + P/R/F1, persists to `coverage_benchmark_runs`.

Endpoints (Phase A — read-mostly, no UI panel yet):

- `POST /api/v1/coverage/benchmarks/runs` — trigger a run by `run_label`. Wraps the CLI runner.
- `GET /api/v1/coverage/benchmarks/runs` — list runs with summary metrics (P/R/F1 per row).
- `GET /api/v1/coverage/benchmarks/runs/{id}` — single-run detail including per-pair predictions for error analysis.

These exist so the operator can eyeball results from `curl` / Postman / the upcoming Phase B Prompts Management panel without a dedicated UI in Phase A.

### 3.3 Phase A prompt changes — `fragchain/coverage/mapper.py`

| Location | Before | After |
|---|---|---|
| Qdrant query — [mapper.py:422](../../fragchain/coverage/mapper.py#L422) | `f"{tid} {name} detection in {tactic}"` | `f"CVE {cve.cve_id} affects {cve.affected_product}: {cve.title}. Technique {tid} {name}. Detection opportunity: {ttp.detection_opportunity}"` |
| Verify prompt — [mapper.py:490–497](../../fragchain/coverage/mapper.py#L490) | "Does this rule detect the technique?" | "Does this Sigma rule's detection logic specifically detect the exploitation of `{cve_id}` via technique `{tid}`? Consider: CVE description, affected product, the TTP's detection opportunity, and the rule's `detection:` block. Answer `yes` only if the rule would fire on this CVE's specific exploitation. Answer `partial` if it covers the technique but targets a different product/CVE. Answer `no` otherwise." Plus include `cve.description[:500]`, `cve.affected_product`, `ttp.detection_opportunity` in the user prompt. |
| **New Phase 1.5** — verify tag matches | (no verify; tag match = unconditional `covered`) | For each rule from `_phase1_exact_match`, run the verify call above. `yes` → keep in `covering`. `partial` → demote to `partial_rule_ids`. `no` → drop entirely. |

Verify schema (used by both Phase 1.5 and Phase 2):

```python
class VerifyVerdict(BaseModel):
    verdict: Literal['yes', 'partial', 'no']
    one_line_reason: str = Field(max_length=200)
```

All three calls go through `structured_complete(schema=VerifyVerdict, n_samples=3)` — majority vote across 3 samples at temp=0. `one_line_reason` is persisted on the coverage status row (used by 3.6's review UI; not surfaced elsewhere yet).

### 3.4 Budget rules

| Scope | Limit | Behavior on breach |
|---|---|---|
| Per call | 20s timeout, 2 schema-repair retries | Verdict = `error` → treated as `partial` (conservative; surfaces to review queue rather than silently passing) |
| Per chain | `len(ttps) × 8` total verify calls (Phase 1.5 + Phase 2 combined) | Log `coverage.budget.exceeded`, remaining TTPs classified `partial` |
| Per CVE per day | No new cap; rely on existing `MAX_HISTORICAL_CVE_PER_DAY` and `llm_interactions.total_cost_usd` aggregation | Operator-visible only |
| Sampling | `n_samples=3` for verify calls; `n_samples=1` for chain & rule generation | Voting only on the cheap classification path |

For a typical 5-TTP chain: ≤ 40 verify calls × 3 samples = 120 LLM hits. At Haiku rates for a ~400-token I/O envelope, roughly $0.02/chain. Phase A is intentionally permissive on cost; tightening lives in Phase B (cache Phase 1.5 verdicts by `(cve_id, rule_id)`).

### 3.5 Exact-hash deduplication at rule-generation time

Two duplication risks; Phase A handles only the cheap one (exact). Semantic dedup is Phase B.

**Pipeline insertion point:** [rules/generator.py](../../fragchain/rules/generator.py), inside the per-gap-per-profile loop, **after** pySigma validation succeeds and **before** the new row is committed.

**Canonical hash computation:**
1. Parse the candidate rule YAML.
2. Keep only `logsource:` + `detection:` blocks. Drop everything else (id, date, title, references, author, tags, description, level, falsepositives — all metadata that varies between equivalent rules).
3. Recursively sort dict keys, normalize whitespace, lowercase string keys.
4. SHA-256 of the resulting canonical YAML string → `candidate_content_hash`.

**Lookup:** `SELECT id FROM sigma_rules WHERE content_hash = :candidate_content_hash LIMIT 1`.

**On hit:**
- Skip insertion of the new rule.
- Log `rule.dedup.exact_hit` with `(chain_id, gap_technique_id, profile, matched_rule_id)`.
- Append the matched rule to the parent chain's `coverage_map.covering_rule_ids` for that technique (if not already present).
- Drop the corresponding `review_queue` insert.

**On miss:** insert as today; populate `sigma_rules.content_hash` on the new row.

**One-time backfill task** (`backfill_content_hash.py`, planned for `scripts/` — never created; deferred per PHASE_A_STATUS_AUDIT §2.10): walk every `sigma_rules` row where `content_hash IS NULL`, compute and write the canonical hash. Required because nothing populates `content_hash` today (column exists but is unused). Idempotent; safe to re-run.

**Cost:** ~80 LOC + one Alembic-less change (column exists). Backfill is a one-time scan over ~3,200 rows (current SigmaHQ corpus).

**What this catches:** byte-identical detection logic after canonicalization. The LLM regenerating the same gap on a re-run; two chains with the same TTP+profile producing identical YAML.

**What this misses:** semantically-equivalent but syntactically-different rules (e.g., `image|endswith` vs `image|contains` for the same observable). Handed off to 3.6 (analyst as third layer) and Phase B (semantic dedup).

### 3.6 Review Queue: similar-rules side panel + "Supersede" analyst action

For every FragChain-generated rule that reaches the review queue, surface two sources of similar rules so the analyst can compare, edit, or decide the candidate is redundant.

**Data sources (both pre-existing — no new infrastructure):**

1. **Partial-coverage rules from the parent chain's coverage map.** When Phase 1.5 or Phase 2 verify returns `partial`, the rule is persisted in `coverage_status.partial_rule_ids` for the relevant technique. These are the closest near-matches the system already considered. Joined on `(chain_id, technique_id)`.

2. **Top-K Qdrant nearest neighbors of the candidate.** Generated rules are embedded on insert by M8's embedder. One Qdrant query per review-render fetches the K nearest existing rules by embedding similarity, excluding the candidate itself. K=5 to start.

**Backend:** new endpoint `GET /api/v1/queue/{review_id}/similar` returns `{partial_coverage: [...], nearest_neighbors: [...]}` with rule id, title, level, logsource, similarity score, and the verify `one_line_reason` (for partial-coverage entries).

**Frontend:** new right-hand side panel on the Review Queue screen, two stacked sections (partial coverage above, nearest-by-embedding below). Each row is clickable and opens the existing rule's YAML in a diff view against the candidate.

**New analyst action — "Supersede with existing rule":**

Fourth button alongside the existing approve / edit / reject. Triggers when the analyst decides an existing rule covers the gap the candidate was generated for. Effect:

- Candidate rule is **not** persisted to `sigma_rules`; review item is closed with status `superseded`.
- `coverage_map.covering_rule_ids` for the parent chain × technique is updated to include the chosen existing rule.
- If that existing rule was previously in `partial_rule_ids`, it's removed from there.
- A `rule_evaluations` row is written with `(rule_id, chain_id, action='supersede', actor, rationale, created_at)`. This becomes ground-truth labeling data for future benchmark runs — analyst judgment auto-feeds the labeled set. Same commons treatment as `coverage_benchmark`: `tlp:clear` default, manual contribute via the existing flow, per-row TLP override available.
- Mandatory: analyst must enter a one-line rationale (validated server-side, max 200 chars). Same schema as `coverage_benchmark.rationale` so the data shapes converge.

**Backend changes:**
- New `review_queue.status` value: `'superseded'` (existing values: `pending`, `approved`, `rejected`).
- New column `review_queue.supersede_rule_id UUID NULL` references `sigma_rules(id)`.
- New endpoint `POST /api/v1/queue/{review_id}/supersede { rule_id, rationale }`.

### 3.7 Baseline preservation for benchmark comparison

Phase 1.5 is a behavioral change — chains already classified `covered` under the old logic would silently shift if the mapper re-ran against them. Two opposing pressures:

- We want a **comparable baseline** to measure Phase A's lift against. That means *not* re-mapping old chains automatically.
- Old `coverage_map` rows still live in the DB and will be queried by the matrix UI alongside new rows.

Resolution: tag every `coverage_map` row with the mapper version that produced it, so the benchmark runner (and any future analyst query) can distinguish.

```sql
ALTER TABLE coverage_map
    ADD COLUMN mapper_version VARCHAR(20) NOT NULL DEFAULT 'v0-baseline',
    ADD COLUMN last_verified_at TIMESTAMPTZ;
```

- Existing rows backfill as `v0-baseline`.
- New rows written by the Phase A mapper get `mapper_version = 'phase-a'`.
- `last_verified_at` updates on every map_coverage run for that (chain, technique) pair — useful operational visibility (e.g., "when was this last checked?") and a future hook for cache-eviction in Phase B verdict caching.

**Clear/redeploy paths** (admin, opt-in — not automatic):

- `scripts/clear_coverage_map.py [--mapper-version v0-baseline]` — truncates the table (or a version slice). Forces a full re-map on the next chain access.
- Standard "redeploy from fresh" already wipes the volume via `docker compose down -v` — no special handling needed.

This gives the user the comparable baseline they asked for without locking the system into stale data forever.

## 4. Decisions

All four prior open questions resolved this round; capturing the locked-in answers here for traceability.

| # | Decision | Reasoning / scope |
|---|---|---|
| 1 | **Commons-eligibility** — `coverage_benchmark` and `rule_evaluations` supersede rows default to `tlp:clear`, commons-eligible. Contribution is the **manual** "Contribute to Commons" action; no auto-push. Per-row TLP override available. | Matches the platform's intelligence-commons identity (CLAUDE.md §7) while preserving operator control. Same default for both tables keeps contribution semantics consistent. |
| 2 | **Historical chains stay as-is** under `mapper_version='v0-baseline'`. New rows tagged `phase-a`. Admin script provided for clear/redeploy. | Comparable benchmark baseline. Drift can be inspected per-version rather than silently absorbed. |
| 3 | **Phase A benchmark endpoints** — read-only `GET` list + detail confirmed for Phase A; Prompts Management UI panel stays in Phase B. | Operator can eyeball results from `curl` immediately. Avoids frontend work in Phase A. |
| 4 | **Benchmark size** — 20 hand-labeled CVEs to start. Expand if per-tactic statistics are noisy after Phase A run. | Two hours of human labeling. Allows quick first-pass measurement; growth is cheap. |

### Decisions from earlier in this conversation (retained for traceability)

- Partial coverage **stays** — do not collapse the matrix to binary.
- Exploit-analysis stage → **Phase B** (not in Phase A).
- Exact-hash deduplication → **Phase A** (§3.5).
- Similar-rules side panel + "Supersede" action → **Phase A** (§3.6).
- "Supersede" rationale → **mandatory** for now (can become optional later if friction is too high).
- Semantic dedup (Qdrant + LLM compare-two-rules) → **Phase B**.

## 5. Sequencing

| Day | Work | Output |
|---|---|---|
| 1 | Alembic migration: `coverage_benchmark` + `coverage_benchmark_runs` + `review_queue.supersede_rule_id` + `review_queue.status='superseded'` + `coverage_map.mapper_version` + `coverage_map.last_verified_at`. Labeling CLI scaffolding. Admin clear script. | Migration `0009_coverage_verification.py` + `scripts/label_coverage_benchmark.py` + `scripts/clear_coverage_map.py` |
| 2 | Hand-label 20 CVEs. Run `scripts/run_coverage_benchmark.py --label baseline`. | Baseline row in `coverage_benchmark_runs` |
| 3 | `structured_complete` utility + unit tests. | `fragchain/llm/structured.py` + `tests/llm/test_structured.py` |
| 4 | Phase A prompt changes ([mapper.py:422](../../fragchain/coverage/mapper.py#L422), [:490](../../fragchain/coverage/mapper.py#L490)), Phase 1.5 tag-verify, exact-hash dedup at rule-gen time, `content_hash` backfill task. Re-run benchmark as `phase-a`. | Updated mapper + updated rule generator + `backfill_content_hash.py` (deferred — never created) + second `coverage_benchmark_runs` row |
| 5 | Review Queue similar-rules side panel (backend endpoint + frontend panel) + "Supersede" action (backend + frontend). Benchmark read endpoints (`GET /runs` list + detail). | `/api/v1/queue/{id}/similar`, `/api/v1/queue/{id}/supersede`, `/api/v1/coverage/benchmarks/runs`, frontend changes |
| 6 | Integration test on CVE-2026-7813 + write-up: P/R/F1 lift, dedup hit rate, error analysis on remaining FPs/FNs, recommended Phase B scope. | Short follow-up doc in this directory |

Decision gate after day 6: if Phase A lifts F1 meaningfully (target: false-positive rate cut by ≥ 40% with no recall loss) and exact-hash dedup catches ≥ 5% of generated rules, commit to Phase B full design. If not, error analysis tells us whether the gap is in retrieval, in the verify prompt, in the lack of behavioral indicators, or in semantic-dedup absence — and Phase B is scoped against the actual failure mode.

## 6. Phase B scope (provisional, refine after Phase A measurement)

**In:**
1. **Exploit-analysis stage** as own prompt template + pipeline stage. Output: structured exploit model (prereqs, attacker capabilities, post-conditions, environmental assumptions, observable indicators). Runs before chain synthesis; output feeds both chain synthesis and coverage verify. Human-readable summary surfaced in CVE Explorer.
2. **`behavioral_indicators` field on `ChainTTP`** (process / network / file / registry / api / payload / command — regex or literal). Populated by exploit-analysis stage. Used by coverage verify and rule generator.
3. **Per-profile (logsource) gap accounting**: `covering_rule_ids` becomes `{profile_name: [rule_ids]}`. Linux-only rule no longer satisfies Windows-only CVE.
4. **Semantic dedup**: after LLM generates a candidate, Qdrant search top-N + LLM compare-two-rules. Link on equivalence, insert otherwise. Same `structured_complete` infrastructure as Phase A verify.
5. **UI**: matrix breakdown by profile, benchmark scores panel under Prompts Management, exploit-analysis summary on CVE Explorer.
6. **Phase 1.5 verdict caching** by `(cve_id, rule_id)` to amortize verify cost across re-runs.

**Out → Phase C / later:**
- Negative validation (does rule fire on benign traffic).
- SIEM feedback loop (real fire-rate data feeds coverage weight).
- Chain-as-narrative correlation-rule coverage (Sigma correlation rules).
- Cross-chain gap aggregation.
- Rule specificity scoring (level + falsepositives length + selector specificity).

## 7. Not in scope (explicit acknowledgment, won't accidentally drift in)

- ATT&CK sub-sub-technique IDs (the framework does not have them; Phase B's `behavioral_indicators` is the equivalent).
- Collapsing partial coverage to binary covered/gap — **decided out**.
- Changes to the rule generator's core prompt. Only the dedup gate around it changes in Phase A.
- New top-level module or service.
