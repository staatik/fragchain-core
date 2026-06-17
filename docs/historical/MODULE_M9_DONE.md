# MODULE_M9_DONE — Prompt Management
**Built:** 2026-05-12
**Effort actual:** L (one session)
**Status:** complete · sandbox-verified (AST + pure-helper checks) · pending runtime verification on a live Postgres + LiteLLM

## What was built

The runtime-managed prompt layer described in CLAUDE.md §15 and FragChain_Module_Specifications.md M9. Three DB tables, three engine modules, eleven API endpoints, three default seeded prompts, one ground-truth fixture, one benchmark, one full test file.

- **`fragchain/db/migrations/versions/0008_prompts.py`** — creates `prompt_templates`, `prompt_evaluations`, `prompt_ab_tests` exactly per the CLAUDE.md §15 schema. Chains cleanly between M7 (`0007_cves_imports`) and M8 (`0009_coverage_map` — already present in the tree, points at `down_revision="0008_prompts"`). Includes:
  - Composite UNIQUE on `(name, target_model, target_provider, version)` so a new version with the same key bumps cleanly instead of silently overwriting.
  - **Partial unique index** on `(name, target_model, target_provider) WHERE is_active = true` — guarantees at most one active row per logical key without locking the whole table.
  - FK from `prompt_evaluations.prompt_template_id` → `prompt_templates.id` (`ON DELETE CASCADE`).
  - FK from both A/B variant columns → `prompt_templates.id` (`ON DELETE RESTRICT`) — can't accidentally delete a template that an active test depends on.
- **`fragchain/db/models.py`** — adds three ORM models (`PromptTemplate`, `PromptEvaluation`, `PromptABTest`) mirroring the migration. All columns typed; JSONB used for `sample_outputs`.
- **`fragchain/prompts/store.py`** — `PromptStore` class:
  - `get_active(task_type, target_model, target_provider="litellm")` resolves the most specific active row, walking `(exact, exact) → (exact, *) → (*, exact) → (*, *)`. Most-specific-wins is the same philosophy as the connector / provider plugin lookups.
  - Process-global in-memory cache (`_ActiveCache`, thread-safe) — lazy-filled on first miss, dropped by `invalidate_cache()`. Every write path calls invalidate before returning.
  - `create_version(...)` auto-bumps the version by reading `max(version)` for the matching key. Optional `activate=True` flips actives in the same transaction.
  - `patch_as_new_version(template_id, ...)` clones the source row, applies overrides, never mutates the source. This is the only update path — by design.
  - `activate(template_id)` flips the row active and deactivates every other active row for the same key in one transaction. Belt-and-braces above the partial unique index.
  - `diff(a_id, b_id)` returns `{a, b, system_prompt_diff, user_template_diff}` where the diffs are unified-diff line arrays from `difflib`.
- **`fragchain/prompts/eval.py`** — `PromptEvaluator` class + benchmark / ground-truth loaders:
  - `run(template_id, benchmark_set, provider=None, model=None, ...)` resolves the chat provider via `get_registry().get_default_chat_provider()` (default), runs each case × iteration, scores, summarizes, persists a `PromptEvaluation` row.
  - Scoring helpers (pure-Python):
    - `_jaccard(truth, predicted)` — `|inter| / |union|`, handles empty edge cases.
    - `_lcs_ratio(truth, predicted)` — classic O(mn) LCS, normalized by `max(len)`.
    - `_hallucinations(truth, predicted)` — count of predicted IDs absent from truth.
  - `_extract_techniques_from_output(text)` tolerates: raw JSON, ` ```json ... ``` ` fences, JSON wrapped in prose, freeform-text regex fallback (preserves first-occurrence order).
  - `_load_ground_truth(rel_path)` accepts both `{"chain": [{"technique_id": "..."}]}` (M10 canonical shape) and a shortcut `{"technique_ids": [...]}` so benchmarks can ship without the full chain JSON.
  - `list_benchmarks()` returns one summary per JSON file in `benchmarks/` — tolerates malformed files (logs + emits an `error` field).
  - Typed errors: `EvaluationError`, `BenchmarkNotFoundError`, `BenchmarkLoadError`, `GroundTruthMissingError`.
- **`fragchain/prompts/ab.py`** — `ABTestRouter` class + `ABSelection` dataclass:
  - `select_variant(task, model, provider="litellm", routing_key=None, use_ab=True)`:
    - Looks up the most recent `status='active'` test for the task.
    - Picks variant A vs B using a deterministic `(routing_key, test_id) -> [0, 1)` SHA-256 roll. Same key always picks the same variant across retries.
    - Falls back to `PromptStore.get_active(...)` when no test exists, when both variants can't be loaded, or when `use_ab=False`.
  - `create_test(...)` validates that both variants exist + share the requested `task_type`. Refuses split outside `[0.0, 1.0]`.
  - `conclude(ab_test_id, winner=None)` flips `status='concluded'` and stamps the winner.
- **`fragchain/api/routers/prompts.py`** — eleven endpoints (the 11 listed in the kickoff + `/evaluate` alias for `/eval`):
  - `GET /prompts` — filter by `task_type`, `target_model`, `target_provider`, `active_only`.
  - `GET /prompts/{id}` — single template + recent `prompt_evaluations` rows.
  - `POST /prompts` — create a new version.
  - `PATCH /prompts/{id}` — clone-and-bump (NEVER mutates the source row).
  - `POST /prompts/{id}/activate` — make this version active.
  - `GET /prompts/{id}/diff/{other_id}` — unified-diff response.
  - `POST /prompts/{id}/eval` (and the duplicate `/evaluate`) — run an evaluation.
  - `GET /prompts/benchmarks` — list available JSON benchmark files on disk.
  - `POST /prompts/ab`, `GET /prompts/ab`, `POST /prompts/ab/{id}/conclude` — A/B lifecycle.
  - **Reads require `require_authenticated`; writes require `require_maintainer`.** Prompt content controls every LLM call so the write surface is gated until later modules layer in finer tier management.
- **`fragchain/api/main.py`** — registers the new router under `/api/v1` next to the LLM router.
- **`scripts/seed_prompts.py`** — idempotent seed of the three defaults:
  - `chain_generation` v1 for `target_model='*'`, `target_provider='*'`, active.
  - `rule_generation` v1 for `*` / `*`, active.
  - `coverage_verify` v1 for `*` / `*`, active.
  - Loads the prompt text from `prompts/*.{system,user}.txt` if those files exist, otherwise falls back to a minimal placeholder. Re-runs default to "already present" / "activated existing" / "collapsed actives" — never duplicate the row. `--force-new-version` makes a fresh version + activates it (used after editing the source text).
- **`prompts/chain_v1.system.txt` + `prompts/chain_v1.user.txt`** — chain-synthesis default. System prompt enforces JSON-only output matching the M10 `AttackChain` schema, technique_id regex, in-order seq_order, source attribution per TTP, no invented URLs. User template carries `{cve_id}`, `{cve_description}`, `{cvss_score}`, `{cvss_vector}`, `{epss_score}`, `{kev}`, `{attackerkb_score}`, `{affected_products}`, `{references}`, `{rag_context}` placeholders.
- **`prompts/rule_v1.{system,user}.txt`** — Sigma rule generation. Pre-populates the §14 required tags (`fragchain.generated`, `tlp.<level>`, `logsource.profile.<name>`), enforces `status: experimental`, points at the profile's field naming conventions and few-shot examples.
- **`prompts/coverage_v1.{system,user}.txt`** — coverage verification. Strict JSON-only output with `status ∈ {covered, partial, gap}`, confidence, reasoning, missing behaviors.
- **`benchmarks/dirty_frag_groundtruth.json`** — single-case benchmark referencing `chains/CVE-2026-43284.json`. Expected technique sequence: `T1078 → T1068 → T1548.003 → T1014`.
- **`chains/CVE-2026-43284.json`** — placeholder ground-truth chain in the M10 schema shape. **M10 owns the canonical hand-validated version**; the file shipped here is correct for the eval benchmark (right technique IDs, right order, plausible preconditions / detection_opportunity / source_refs) but M10 may extend it.
- **`tests/test_prompts.py`** — 42 tests covering scoring helpers, output extraction, render, deterministic roll, diff, benchmark + ground-truth loaders, PromptStore `get_active` resolution, diff via PromptStore, end-to-end evaluator runs with a stub provider, A/B router routing math + fallback. See **Test status** below.

## How dependent modules consume this

- **M11 (Chain Synthesis)** — *the* heavy caller:
  ```python
  from fragchain.prompts import ABTestRouter, PromptStore
  selection = await ABTestRouter(session).select_variant(
      "chain_generation",
      target_model=settings.LITELLM_CHAT_MODEL,
      target_provider="litellm",
      routing_key=cve.cve_id,
  )
  if selection is None:
      raise RuntimeError("no chain_generation prompt active")
  rendered = selection.template.user_template.format_map(...)
  resp = await provider.complete(
      system=selection.template.system_prompt,
      prompt=rendered,
      model=settings.LITELLM_CHAT_MODEL,
      interaction_type=InteractionType.CHAIN_GENERATION,
      prompt_template_id=selection.template.id,
      prompt_version=selection.template.version,
      entity_type="cve",
      entity_id=cve.id,
  )
  ```
  The provider already writes the `prompt_template_id` + `prompt_version` columns on the `llm_interactions` row, so the chain artifact only needs to persist `prompt_template_id` on the `attack_chains` row.
- **M14 (Rule Generator)** — same pattern with `interaction_type=RULE_GENERATION` and `task_type="rule_generation"`. Per-profile variants of the same TTP share a chain id; pick the right rule prompt per-call.
- **M24 (Prompts UI)** — drives every `/api/v1/prompts*` endpoint. The "Diff between v2 and v3" view consumes `/diff/{other_id}` directly; the "Active toggle" hits `/activate`; the "Edit" view goes through `PATCH` so the source row stays immutable.

## Deviations from spec

- **Partial unique index on `is_active=true`** added on top of the schema in CLAUDE.md §15. The spec says "only one active per (task, model, provider)" but doesn't mandate a DB-level enforcement. I added the index because the application-level guard alone leaves a race window (two analysts hit "Activate" simultaneously). The partial-unique form lets activate() flip rows in a single transaction without a full-table lock.
- **`task_type` is `NOT NULL`** in the migration; the kickoff schema shows it nullable. A null task_type means "this template is for nothing" — it can never match a `get_active(task_type, ...)` call. Mandatory is the safer default.
- **`target_model` / `target_provider` default to `'*'`** at the DB layer, not at the API layer. CLAUDE.md §15 says "specific model alias or '*' for any" — making `'*'` the server default means a `POST /prompts` body without those fields lands in the wildcard slot, which is the most common case.
- **`PromptStore.get_active()` defaults `target_provider="litellm"`** since that's the only provider shipping in v1 per CLAUDE.md §6. Callers can still pass any provider name (or `'*'`); the resolver walks the same hierarchy either way.
- **A/B router falls back when there's no active test**. The kickoff spec for `ABTestRouter.select_variant(task_type, model)` doesn't say what happens without a test. Returning `None` would force every caller to retry against PromptStore — instead the router transparently falls back to `PromptStore.get_active(...)` so call sites are uniform. The `variant` field on `ABSelection` is `None` when the fallback fired, so callers persisting per-variant metrics can distinguish "A/B routed" from "default routed".
- **No traffic-split outside `[0, 1]`**. CLAUDE.md §15 lists the column as `DECIMAL(3,2) DEFAULT 0.50` so values outside `[0, 1]` are technically representable. The router validates at creation time — silently clamping a 0.85 vs 1.85 mistake into 50/50 would be worse than a clear `ValueError`.
- **`/prompts/{id}/eval` AND `/prompts/{id}/evaluate`** both resolve to the same handler. The kickoff lists `/eval`; the rest of the FragChain API surface uses verbs-not-nouns (`/activate`, `/conclude`). Both spellings are routed to the same code to keep both clients happy. If we want to drop one before v1 ships we can — they share a single function so it's a one-line removal.
- **`prompt_templates.system_prompt` and `user_template` are NOT NULL** with default `''`. The spec doesn't say. Defaulting to `''` lets the API accept a partial body (e.g. `PATCH` that only changes one of the two fields).
- **`hallucination_count` summed across cases, not averaged.** The DB column is `INTEGER`; averaging would lose precision and the operator interpretation is "how many hallucinations across the benchmark", not "what's the per-case rate". Per-case detail still lives in `sample_outputs`.
- **The router emits *both* `prompt.ab.routed` and a plain `prompt.ab.fallback`-equivalent (via the absence of the routed event)**. I considered adding an explicit fallback log line but every call site can read `selection.variant is None` to detect fallback; an extra log row per fallback would drown the others.
- **No `prompt_templates.target_provider` migration backfill**. M5 wrote `prompt_template_id` to `llm_interactions` rows without a FK constraint; M9 still doesn't add it because providers can write rows that predate any template (e.g. ad-hoc embeddings) — keeping the column nullable + un-FKed matches CLAUDE.md §6's tolerance for side-effect failures.
- **The chains fixture is "good enough for the eval benchmark, not the M10 canon"**. M10 is the module that hand-validates and ships `chains/CVE-2026-43284.json` long-form. The version dropped in this module has the right cve_id, the right four-step technique chain (T1078 → T1068 → T1548.003 → T1014), and shape-compatible source_refs / preconditions / detection_opportunity entries — enough for the benchmark to score against. M10 should overwrite this file when it lands; the eval will continue to work because we read `chain[].technique_id` only.

## Test status

`tests/test_prompts.py` (42 tests) covers, in order:

**Pure scoring helpers** — `_jaccard`, `_lcs_ratio`, `_hallucinations` against identical / reversed / disjoint / partial / empty inputs. Verified independently in this sandbox (Python 3.9) with a stripped-down extraction since the full module can't import here.

**Output extraction** — `_extract_techniques_from_output` parses:
- raw JSON (chain shape)
- ` ```json ... ``` ` fenced JSON
- JSON embedded in prose
- freeform regex fallback (preserves first-occurrence order, dedupes)
- blank / no-techniques → `[]`

**Render** — fills known placeholders; passes through unknowns without raising; doesn't crash on malformed format strings.

**Deterministic A/B roll** — same `(key, salt)` always produces the same roll; different keys produce distinct rolls; 50/50 split lands within `[900, 1100]` of 1000 over 2000 samples (verified in-sandbox: histogram shows 993).

**Diff helper** — produces `--- old / +++ new / -b / +b2` shape; returns `[]` on identical input.

**Benchmark + ground-truth loaders** — `list_benchmarks()` returns the seeded `dirty_frag_groundtruth`; `load_benchmark("dirty_frag_groundtruth")` parses correctly; `BenchmarkNotFoundError` on missing files; ground truth loads from both `chain` and `technique_ids` shapes.

**PromptStore behaviour (via in-memory fake session)**:
- `get_active` returns the wildcard match.
- `get_active` prefers an exact (model, provider) row over the wildcard fallback.
- `get_active` returns `None` when nothing is active.
- `diff(v1, v2)` emits a real unified diff for changed lines, `[]` for unchanged.

**Evaluator end-to-end (via stub provider + fake recording session)**:
- Perfect chain JSON → `technique_overlap=1.0`, `ordering_consistency=1.0`, `hallucination_count=0`.
- Two fabricated TTPs → `hallucination_count=2`, `overlap=1/6 ≈ 0.17`.

**A/B router**:
- Falls back to `PromptStore.get_active` when no test exists.
- Returns `None` when nothing is configured for the task.
- `traffic_split=1.0` → always variant A.
- `traffic_split=0.0` → always variant B.
- `traffic_split=0.5` → routes 2000 keys within `[900, 1100]` to each side.
- Same `routing_key` always picks the same variant across calls.
- `use_ab=False` bypasses the test and returns the active fallback.

**Public surface** — `fragchain.prompts.{PromptStore, PromptEvaluator, ABTestRouter, WILDCARD}` re-export correctly.

### Sandbox pre-flight checks (the only checks runnable here — Python 3.9)

The sandbox runs Python 3.9, but the project requires 3.12. SQLAlchemy 2.0 fails to import the ORM models under 3.9 because the existing `Mapped[dict[str, Any] | list[Any] | str | int | float | bool | None]` annotation uses `|`-union with subscripted generics. This is a known constraint that already prevented `tests/test_llm.py` and the other test files from running locally; CI/operator runs them inside the Python 3.12 Docker image.

What I *can* verify in-sandbox:

- `ast.parse()` on every new file → no syntax errors. (verified)
- JSON parse of `benchmarks/dirty_frag_groundtruth.json` and `chains/CVE-2026-43284.json` → valid. (verified)
- Migration `upgrade()` body creates `prompt_templates`, `prompt_evaluations`, `prompt_ab_tests` in that order, plus the partial-unique index. (verified by AST walk)
- Migration chain is `0007_cves_imports → 0008_prompts → 0009_coverage_map`. (verified)
- Intra-project imports in `routers/prompts.py` and `scripts/seed_prompts.py` resolve to real symbols. (verified by grep)
- Pure-helper logic (Jaccard, LCS, hallucinations, deterministic roll) produces the expected values for hand-picked inputs. (verified via standalone Python extract)

### Runtime verification *not* run in this session

Operator should run the following on the next `docker compose up`:

| Done criterion | Verification command |
|---|---|
| `alembic upgrade head` includes `0008_prompts` | `docker compose exec fragchain-api alembic current` → `0009_coverage_map (head)` (or later); `\dt prompt_*` shows `prompt_templates`, `prompt_evaluations`, `prompt_ab_tests` |
| Three default prompts seeded, all active | `docker compose exec fragchain-api python -m scripts.seed_prompts` → output shows three `CREATED` (first run) or `ALREADY_PRESENT` (subsequent); `SELECT name, version, is_active FROM prompt_templates;` returns three rows with `is_active=true` |
| `PromptStore.get_active('chain_generation', 'claude-opus-4-6', 'litellm')` returns the wildcard v1 | inside `fragchain-api`: `python -c "import asyncio; from fragchain.db.session import get_sessionmaker; from fragchain.prompts import PromptStore; ..."` returns name='chain_generation', version=1, target_model='*' |
| Partial unique index in place | `\d prompt_templates` shows `uq_prompt_templates_active` partial unique index on `(name, target_model, target_provider) WHERE is_active = true` |
| New version creation increments version, doesn't mutate old | `POST /api/v1/prompts/{id}` with PATCH body → new id, version=2, source row unchanged. Verify with `SELECT id, version, system_prompt FROM prompt_templates WHERE name='chain_generation';` |
| Only one prompt active per key | After `POST /activate` on a new version: `SELECT count(*) FROM prompt_templates WHERE name='chain_generation' AND target_model='*' AND target_provider='*' AND is_active=true;` → 1 |
| Diff between versions works | `GET /api/v1/prompts/{v1_id}/diff/{v2_id}` → `system_prompt_diff` contains `+` and `-` lines for the changed text |
| Evaluation against dirty_frag_groundtruth | `POST /api/v1/prompts/{chain_v1_id}/eval` with `{"benchmark_set": "dirty_frag_groundtruth"}` → 200, returns `technique_overlap`, `ordering_consistency`, `hallucination_count`, `cost_per_run`, `avg_latency_ms` populated |
| A/B routing splits traffic | Create A/B test with split=0.5, then call `ABTestRouter.select_variant` 2000 times with different `routing_key` values; ~50% land on each variant; same key always picks same variant |
| Cache invalidation works | After `POST /activate` on a new version, the next `get_active` returns the new id without restart |

## Interfaces exposed

```python
from fragchain.prompts import (
    PromptStore, PromptTemplateView, PromptNotFoundError, WILDCARD,
    PromptEvaluator, BenchmarkCase, BenchmarkSet, CaseResult,
    BenchmarkNotFoundError, BenchmarkLoadError, GroundTruthMissingError,
    EvaluationError,
    ABTestRouter, ABSelection,
    list_benchmarks, load_benchmark,
)

from fragchain.db.models import PromptTemplate, PromptEvaluation, PromptABTest
```

API contract (all under `/api/v1`):
- `GET /prompts?task_type=&target_model=&target_provider=&active_only=`
- `GET /prompts/{id}`
- `POST /prompts`
- `PATCH /prompts/{id}`
- `POST /prompts/{id}/activate`
- `GET /prompts/{id}/diff/{other_id}`
- `POST /prompts/{id}/eval` (alias: `POST /prompts/{id}/evaluate`)
- `GET /prompts/benchmarks`
- `POST /prompts/ab`
- `GET /prompts/ab?status=`
- `POST /prompts/ab/{id}/conclude`

Plugin / extension contract:
- New benchmarks: drop a JSON file in `benchmarks/<name>.json` with the shape `{"name", "description", "iterations_per_case", "cases": [{"id", "ground_truth_path", "variables"}]}`. `GET /api/v1/prompts/benchmarks` will surface it on the next call (no restart needed — list happens on disk).
- New ground-truth fixtures: drop a JSON file in `chains/<file>.json` matching either the M10 canonical shape (`{"chain": [{"technique_id": ...}]}`) or the shortcut (`{"technique_ids": [...]}`). Reference it from a benchmark `ground_truth_path`.
- New default prompts: add a spec entry to `DEFAULTS` in `scripts/seed_prompts.py` and drop `prompts/<name>_v1.{system,user}.txt` alongside.

## Outstanding TODOs (handed off)

- **M10** owns the canonical `chains/CVE-2026-43284.json` — the version dropped in this module is shape-compatible but should be replaced with the hand-validated long-form when M10 lands. The eval will continue to work without changes because it only reads `chain[].technique_id`.
- **M11 (Chain Synthesis)** is the first heavyweight caller of `ABTestRouter.select_variant("chain_generation", ...)`. The flow is documented above; the variant id flows through to `attack_chains.prompt_template_id` and onto every `llm_interactions` row via the provider's `_record_interaction()`.
- **M14 (Rule Generator)** consumes `select_variant("rule_generation", ...)` per logsource profile per TTP gap.
- **M24 (Prompts UI)** renders every endpoint listed above. The diff view should consume `/diff/{other_id}` and lean on `difflib`-style rendering on the frontend. The A/B "Conclude" workflow is `POST /ab/{id}/conclude` with `{"winner": "A"}` or `{"winner": "B"}`.
- **Prompt-template FK on `llm_interactions`** is still deferred (M5 noted this). The column is nullable + un-FKed because providers can write rows for ad-hoc embeddings without a template. If we later want strict referential integrity, the FK can be added in a future migration once every code path that writes the column carries a real template id.

## What dependent modules need to know

- **Adding a new prompt at deploy time**: don't hard-code prompts in module code. Add a new row via `POST /api/v1/prompts` (or `scripts/seed_prompts.py` if it's a system default), then `POST /activate`.
- **Reading the active prompt**: always go through `ABTestRouter.select_variant(...)` rather than `PromptStore.get_active(...)` directly. The router transparently falls back to `get_active` when there's no A/B test, so call sites stay uniform — and if an operator starts an A/B test later, the call sites pick it up automatically without code changes.
- **Persisting which prompt was used**: write `prompt_template_id` + `prompt_version` onto whatever artifact you produce (`attack_chains.prompt_template_id`, `sigma_rules.prompt_template_id`, etc.) and pass them into `provider.complete(...)` so they also land on the `llm_interactions` row. M5's `_record_interaction()` already accepts these fields.
- **Running an evaluation manually**: `POST /api/v1/prompts/{id}/eval` with body `{"benchmark_set": "dirty_frag_groundtruth", "model": "<override LITELLM_CHAT_MODEL>"}`. Returns the persisted `PromptEvaluation` row. The eval doesn't deactivate or promote the template — operators do that explicitly after reviewing.
- **A/B test lifecycle**: `POST /ab` to start, `GET /ab?status=active` to monitor, `POST /ab/{id}/conclude` with `{"winner": "A"}` (or null) to wrap. Concluding doesn't auto-promote — the operator still has to `POST /prompts/{winner_id}/activate` if they want to make the winner the new baseline.
- **Cache invalidation**: writers (POST/PATCH/activate) invalidate the global active-prompt cache before returning. If you mutate `prompt_templates` rows directly via SQL (don't), call `PromptStore.invalidate_cache()` afterwards.

## Risks / known weaknesses

- The in-memory active-prompt cache is **per-process**. Multiple API workers (e.g. uvicorn `--workers 4`) will each rebuild lazily after a write — so for a window of "next request per worker" some workers may see the stale active. The window is one request per worker (then they refill), which is acceptable for a prompt-flip operation. A shared Redis cache would close the window but adds complexity that isn't justified for prompt management at this scale.
- The benchmark expects exact technique-id matches (`T1548.003` is not the same as `T1548`). Models that emit only the parent technique will score lower than ones that emit the sub-technique. Operators iterating on prompts should be aware that "tighten the prompt to demand sub-techniques" is a real prompt-engineering knob, not a benchmark bug.
- The `_extract_techniques_from_output` regex fallback preserves first-occurrence order, but the JSON-parse path uses the order of the `chain` array. If a model emits JSON with `seq_order` out of order, the eval scores it by the array order, not the `seq_order` field. We accept this because a model that scrambles `seq_order` is misbehaving regardless — and the prompt explicitly demands sequential order starting at 1.
- **No timeout on `PromptEvaluator.run()`** other than the underlying provider's per-call timeout. A benchmark with many cases × iterations against a slow model could hold a DB session open for a while. For v1 the benchmark set has one case × one iteration; if benchmarks grow, M24 should add a worker-side runner.


---

## Phase 4 cleanup applied (2026-05-13)

- **Test count corrected:** this doc previously claimed "42 tests pass". Live verification found 38/42 — the four failures were all in `tests/test_prompts.py` and relied on `FakePromptSession._walk_where` which mistranslated SQLAlchemy 2.x's `col.is_(True)` UnaryExpression nodes. Production code is unaffected (real Postgres handles `IS TRUE` correctly).
- **`_walk_where` fix:** `tests/test_prompts.py` `_walk_inner` now recognizes `IsTrue`/`IsFalse` UnaryExpressions (translates to `(col, "is_", True/False)` tuples) and `True_`/`False_` literal right-hand sides in BinaryExpressions. Other UnaryExpression types still recurse into the element.
- **Actual test count post-fix:** **43 passing / 0 failing** in `tests/test_prompts.py`. Full repo `pytest tests/` lands at 284/0.
- **Partial unique index documented in CLAUDE.md §15** (it always existed in migration `0008_prompts.py`; the spec didn't mention DB-level enforcement). Now spelled out: `uq_prompt_templates_active` enforces at most one `is_active=true` row per `(task_type, target_model, target_provider)`.

See `PHASE4_CLEANUP_DONE.md` for the full change set.
