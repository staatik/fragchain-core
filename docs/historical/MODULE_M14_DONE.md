# MODULE_M14_DONE — Coverage Mapper
**Built:** 2026-05-13
**Effort actual:** L (one session)
**Status:** complete · sandbox-verified (AST parse on every new/edited file; pure-helper logic exercised in-isolation) · pending runtime verification on live Postgres + Redis + Qdrant + LiteLLM + Celery

## Scope reminder

M14 picks up where M11 leaves the pipeline:

```
M11: synthesizing → mapping        (queues map_coverage.delay(chain_id))
M14: mapping → generating          (queues generate_rules.delay(chain_id) — stub)
M15: generating → complete         (lands later)
```

For each chain that lands, M14 walks every TTP and answers one question per
technique: do we already have a detection rule that covers it? Output is
persisted to `coverage_map` (M8 schema) and the Redis-cached matrix data
the ATT&CK Matrix screen (M21) consumes.

M14 does **not** own:
* Rule generation (M15 — picks up at `processing_status='generating'`)
* ATT&CK Matrix UI (M21 — consumes `/api/v1/matrix`)
* Dashboard mini-heatmap (M19 — consumes `/api/v1/coverage`)

## What was built

### Engine — `fragchain/coverage/mapper.py`

The `CoverageMapper` orchestrator wires every prior module together:

* **Constructor** injects `session` + optional `embedder` / `provider` /
  `model` / `matrix_cache` so tests pass stubs and operators get the real
  implementations by default. Tunables: `semantic_threshold` (default
  `0.75`), `result_limit` (5), `parallelism` (10).
* **`map_coverage(chain_id)`** runs:
  1. **Load** — chain row, TTPs (sorted by `seq_order`), CVE row. A
     missing chain / missing TTPs / missing CVE raises
     `CoverageMappingError(stage='load')`.
  2. **Phase 1 — exact ATT&CK tag match** (PostgreSQL):
     ```sql
     SELECT id FROM sigma_rules
     WHERE status='merged'
       AND technique_ids @> ARRAY[<technique_id>]
     ```
     Per TTP. Cheap, deterministic.
  3. **Phase 2 — semantic + LLM verify**:
     * Only for techniques uncovered after Phase 1.
     * Embed query: `"{technique_id} {technique_name} detection in {tactic}"`.
     * Search Qdrant `sigma_rules`, top 5, score > 0.75.
     * Hits whose rule already tags the technique are skipped (would have
       been a Phase 1 hit; landed here only because status≠merged).
     * Per candidate: LLM cheap call ("yes / partial / no").
       `InteractionType.COVERAGE_VERIFY`, deterministic
       (`temperature=0.0`, `max_tokens=16`), 20s per-call timeout.
     * Batched via `asyncio.gather` under an `asyncio.Semaphore(10)` so
       a 200-TTP chain doesn't slam the provider with all candidates at
       once.
  4. **POC + shared-gap signals** — loaded once per CVE:
     * `_has_poc_source(cve_id)` — `SELECT 1 FROM source_documents WHERE cve_id=… AND source_type='poc' LIMIT 1`.
     * `_shared_gap_counts([technique_ids])` — returns the chain_cve_ids
       list for each technique currently flagged `gap`. Caller subtracts
       self when present so the "+5 × other CVEs" bonus counts *other*
       CVEs only (handles re-runs cleanly).
  5. **Status decision** — per TTP:
     * `covered` ← any Phase 1 rule OR any Phase 2 "yes" verdict.
     * `partial` ← only Phase 2 "partial" verdicts.
     * `gap` ← otherwise.
  6. **Priority scoring** (CLAUDE.md §12) — additive:
     * +30 CISA KEV
     * +20 CVSS ≥ 9.0
     * +20 EPSS ≥ 0.50 OR +15 EPSS ≥ 0.20 (mutually exclusive — a CVE
       with EPSS=0.6 lands in the 0.50 bucket, not both)
     * +15 PoC source available
     * +10 AttackerKB score ≥ 3.5
     * +10 `seq_order` ≤ 3 (early-chain stage)
     * +5 × count of *other* CVEs sharing this gap
  7. **Persistence** — `_persist_statuses` upserts a `coverage_map` row
     per technique with:
     * `covering_rule_ids` = union of existing + new covering + partial
       rules (sorted for determinism).
     * `chain_cve_ids` = existing + this CVE.
     * `chain_cve_count` = `len(chain_cve_ids)`.
     * `kev_cve_count` + `kev_exposed` recomputed from `cisa_kev` of
       every CVE in `chain_cve_ids`.
     * `coverage_status` = this chain's decision (note: this overwrites
       prior verdicts — but since we union the rule lists, the next
       chain to land on the same technique will see all rules).
     * `last_refreshed` = now().
     * Descriptive columns (`technique_name`, `tactic_id`, `tactic_name`)
       only set when currently null — never trample M8-seeded values.
     * On first encounter of an unseeded technique, the row is added via
       `session.add(...)`.
  8. **Side effects** — best-effort:
     * Invalidate `matrix:{framework}:*` keys in Redis via `MatrixCache.invalidate`.
     * Emit `coverage_mapped` event (chain_id, cve_id, covered/partial/gap
       counts, top 5 gaps by priority).
     * Emit `matrix_updated` event (framework + list of touched techniques).
* **Result** — `CoverageReport`:
  * `statuses: list[CoverageStatus]`, `covered_count`, `partial_count`,
    `gap_count`, `llm_verify_calls`, per-verdict counts, `duration_ms`.
  * `top_gaps(n=5)` helper returns gaps sorted by priority.

Pure helpers exposed for testing:

* `_calculate_priority(cve, seq_order, has_poc, shared_count) → int`
* `_normalise_verdict(raw_text) → "yes" | "partial" | "no" | "error"`
* `_count_verdicts(verdicts) → {yes, partial, no, error}`

### Matrix data + Redis cache — `fragchain/coverage/matrix.py`

* **`MatrixFilters`** dataclass (frozen) accepts:
  `framework`, `cve_id`, `date_from`, `date_to`, `cvss_min`, `kev_only`,
  `tactic_id`. `cache_key()` is a 16-char sha256 hash so two requests
  with the same filter set hash to the same Redis key.
* **`MatrixCache.get_matrix_data(session, filters)`**:
  * Cache hit → mark `cache_hit=True`, return the cached payload.
  * Cache miss → recompute (SELECT every coverage_map row in the
    framework + optional `tactic_id` filter), apply CVE-set filters,
    write the result into Redis under the same key with a 1-hour TTL.
* **`MatrixCache.invalidate(framework=…)`** — `SCAN MATCH matrix:<fw>:*`
  + `DEL`. Best-effort; Redis down = log + return 0.
* **`MatrixCache.warm(session, framework=…)`** — forced recompute used
  by the beat job (`refresh_matrix_cache`).
* **`MatrixData.to_dict()` / `from_dict()`** — JSON round-trip for cache
  storage. The 14 canonical ATT&CK Enterprise tactics are emitted in
  kill-chain order (`ENTERPRISE_TACTIC_ORDER` tuple), with extras
  appended alphabetically so a custom framework still renders.
* **Filter semantics** — when filters are set, the CVE set is computed
  once via `SELECT DISTINCT cves.id JOIN attack_chains ...`. Per
  technique cell:
  * If the technique has at least one matching CVE → status from
    coverage_map.
  * If the technique has zero matching CVEs but has covering rules → status
    `covered` (the rules cover the technique regardless of which CVEs
    contributed). The cell counts are restricted to the filter slice.
  * Otherwise → `no_data` for this slice.

### Celery tasks — `fragchain/worker/tasks/coverage.py`

| Task | Owner | Dispatched from |
|---|---|---|
| `fragchain.worker.tasks.map_coverage` | M14 | M11 `chain.generator._queue_map_coverage` |
| `fragchain.worker.tasks.refresh_matrix_cache` | M14 | beat (every hour on the hour) |

* **`map_coverage(chain_id)`**:
  * Loads chain + CVE. Refuses to run if CVE not in
    `{mapping, generating, complete}` (idempotent re-queues).
  * Calls `CoverageMapper.map_coverage(chain.id)`.
  * On success: advances `mapping → generating` with stage=`generating`.
    The audit row notes covered/partial/gap counts. Queues
    `fragchain.worker.tasks.generate_rules` (M15 stub for now).
  * On `CoverageMappingError`: `set_processing_failed` with
    `stage='mapping'` + the error message. Returns `{status: error, stage}`.
  * On any unexpected exception: same failure path, full traceback logged.
* **`refresh_matrix_cache(framework='attck')`** — calls
  `MatrixCache.warm(session, framework=framework)`. Returns the summary
  totals so an operator polling the Celery backend can see them.

Beat schedule updated in `fragchain/worker/celery.py`:

```python
"refresh_matrix_cache": {
    "task": "fragchain.worker.tasks.refresh_matrix_cache",
    "schedule": crontab(minute="0"),    # every hour on the hour
},
```

The previous M1 stub `map_coverage` and `refresh_matrix_cache` were
removed from `fragchain/worker/tasks/__init__.py`. The new module is
side-imported there so task registration happens at worker startup. The
`generate_rules` stub stays for M15 to replace.

### API — `fragchain/api/routers/coverage.py`

Five endpoints mounted under `/api/v1`:

| Method | Path | Auth | Behaviour |
|---|---|---|---|
| GET | `/coverage` | authenticated | List every technique row with current coverage (filterable by `coverage_status`, `tactic_id`, `kev_only`). Default framework `attck`. |
| GET | `/coverage/{technique_id}` | authenticated | Single technique detail. Joins `sigma_rules` for `covering_rules` and `cves` for `chain_cves` (TLP-filtered per request). |
| GET | `/matrix` | authenticated | Cached matrix data. Query params: `framework`, `cve_id`, `date_from`, `date_to`, `cvss_min`, `kev_only`, `tactic_id`. Cache hit short-circuits the DB query. |
| GET | `/matrix/{technique_id}` | authenticated | Alias for `/coverage/{technique_id}` so the UI can use either base. |
| POST | `/coverage/recompute` | maintainer | Synchronous recompute for one chain, or queue every chain when `chain_id` omitted. |

Reads are open to authenticated users — `coverage_map` rows hold
aggregates only (no TLP-bearing content). The detail endpoint's
`chain_cves` array is filtered per request via the standard
`apply_tlp_filter` middleware so an analyst without amber clearance
doesn't see amber-tagged CVE rows.

Router is mounted from `fragchain/api/main.py:create_app()`.

### Notifications

Two new events on the in-process bus (`fragchain.notifications.emit_event`):

* `coverage_mapped { chain_id, cve_id, covered, partial, gap, top_gaps[] }`
* `matrix_updated { framework, techniques: [tid, …] }`

Both fire from `CoverageMapper.map_coverage`. M19's WebSocket fan-out
will pick them up without code changes here.

### M11 integration

M11's `_queue_map_coverage` already dispatches under the canonical task
name — M14 just replaces the stub body. Path:

```
M6 enrich_cve → synthesize_chain → map_coverage → generate_rules (stub)
                                       ↑              ↑
                                       M14 here       M15 next
```

## Tests — `tests/test_coverage.py` (24 tests)

Pure-Python; no live Postgres / Redis / Qdrant / LiteLLM. The
`_StubSession` mirrors only `get` + `add` + `commit`; the mapper's
DB-touching methods (`_load_ttps`, `_phase1_exact_match`, `_has_poc_source`,
`_shared_gap_counts`, `_get_coverage_row`, `_count_kev_cves`) are
monkey-patched per test via `_patch_mapper`. Coverage:

**Pure helpers**

  * `_calculate_priority` — every CLAUDE.md §12 component fires
    independently (no bonuses → 0, KEV alone → 30, CVSS≥9 alone → 20).
    EPSS mutual-exclusion verified (0.55 → 20, 0.30 → 15, 0.05 → 0).
    `seq_order` early-stage bonus only for ≤3. Shared-count multiplier
    of 5. Tolerates `None` scores gracefully.
  * `_normalise_verdict` — exact tokens, trailing punctuation /
    whitespace, "partial yes" → "partial", "" → "error", nonsense →
    "error".
  * `_count_verdicts` — counts every label bucket.

**Matrix dataclasses**

  * `MatrixFilters.cache_key` — same filters → same key; different
    filters → different keys; unfiltered predicate.
  * `ENTERPRISE_TACTIC_ORDER` length is 14 (CLAUDE.md §16 promise).
  * `MatrixData.to_dict / from_dict` round-trips.

**`MatrixCache` (fake Redis)**

  * Cache hit short-circuits the DB query (the panic session raises if
    `execute` is called).
  * `invalidate(framework='attck')` removes only that framework's keys.
  * `invalidate()` with no framework wipes the lot.

**`CoverageMapper` integration**

  * Phase 1 exact match flips the technique to `covered` and adds the
    rule UUID to `covering_rule_ids`. Phase 2 is skipped for that TTP
    (verified by inspecting the embedder's call list).
  * Phase 2 "yes" verdict marks the technique `covered` with the rule
    appended.
  * Phase 2 "partial" verdict marks the technique `partial` with the
    rule in `partial_rule_ids`.
  * Below-threshold Qdrant hits (score < 0.75) are dropped before the
    LLM verify call — `provider.calls == 0` for a 0.40 hit.
  * Hits whose rule already tags the technique (Phase 1 territory) are
    skipped from Phase 2 — no LLM call burned on a near-certain answer.
  * Missing chain raises `CoverageMappingError(stage='load')`.
  * Empty TTP list raises the same.
  * `MatrixCache.invalidate('attck')` is called after every successful
    run.
  * Both `coverage_mapped` and `matrix_updated` events emit through the
    bus.
  * Coverage rows mutate in place (existing technique) or land as
    `session.add(...)` (unseeded technique).
  * KEV exposure flag flips when a KEV CVE lands on the technique.
  * Self-exclusion on shared-gap count — re-run on a CVE already in
    `chain_cve_ids` subtracts 1 so the +5×count bonus reflects *other*
    CVEs only.

## Sandbox-level pre-flight checks (the only checks runnable here)

The sandbox runs Python 3.9 and the project requires 3.12 — SQLAlchemy
2.0's `Mapped[...]` annotations break at import time under 3.9 (same
constraint M6–M13 noted). What's verified here:

* `ast.parse()` on every new/edited Python file → no syntax errors:
  `fragchain/coverage/__init__.py`, `fragchain/coverage/mapper.py`,
  `fragchain/coverage/matrix.py`, `fragchain/worker/tasks/coverage.py`,
  `fragchain/worker/tasks/__init__.py`, `fragchain/worker/celery.py`,
  `fragchain/api/main.py`, `fragchain/api/routers/coverage.py`,
  `tests/test_coverage.py`.
* `grep -rn "import anthropic\|from anthropic"` across
  `fragchain/coverage/`, the new router, the new task, and the test —
  no matches (CLAUDE.md §19).
* `grep -rn "fragchain_"` in `fragchain/coverage/` — no Qdrant
  collection prefix usage.
* Celery task names preserved: `fragchain.worker.tasks.map_coverage`
  (called by M11 generator) and `fragchain.worker.tasks.refresh_matrix_cache`
  (referenced by beat schedule).
* `coverage_router` mounted at `/api/v1` from
  `fragchain/api/main.py:create_app()`.

## Runtime verification *not* runnable in this sandbox

| Done criterion | Verification command |
|---|---|
| `map_coverage` registered as a real task | `celery -A fragchain.worker.celery inspect registered` includes `fragchain.worker.tasks.map_coverage` (and `task.stub.invoked` no longer fires) |
| Dirty Frag coverage report matches spec | seed Dirty Frag + run synthesis (M11); worker logs show `chain.generated → coverage.mapped`; `SELECT coverage_status, technique_id FROM coverage_map WHERE technique_id IN (chain TTPs);` shows the right covered/gap split |
| Matrix returns all 14 tactics | `curl -H "Authorization: Bearer $JWT" .../api/v1/matrix` → response has 14 tactics in canonical order |
| All ~400 techniques present | `SELECT COUNT(*) FROM coverage_map;` ≥ 400 (M8 seed); matrix endpoint returns the same count |
| Unseeded cells show `no_data` | `SELECT COUNT(*) FROM coverage_map WHERE coverage_status='no_data';` matches techniques without any chain |
| Phase 2 semantic search works | with at least one merged rule embedded in Qdrant `sigma_rules`, run M14 on a chain whose technique isn't tagged in that rule; check `llm_interactions` for `interaction_type='coverage_verify'` rows |
| Priority scores correct | `SELECT * FROM coverage_map WHERE technique_id IN (gap TTPs);` — manually verify the priority formula by reading the report (the report itself is logged via `coverage.mapped` event) |
| Redis cache populated | `redis-cli KEYS 'matrix:*'` shows entries after first matrix request; second request logs `matrix.cache.hit` (or returns `cache_hit=true` in the JSON response) |
| Cache invalidates on new chain | run `synthesize_chain` on a different CVE → Redis keys for `matrix:attck:*` are removed; next matrix request rebuilds from DB |
| Cache pre-warm runs hourly | tail logs for `matrix.cache.set` at the top of every hour from beat |
| WebSocket events (once M19 ships) | subscribe to the event bus; on coverage mapping a `coverage_mapped` and a `matrix_updated` event are delivered |
| `GET /api/v1/coverage` | returns the full list TLP-filtered |
| `GET /api/v1/coverage/T1078` | returns rules + CVE list (TLP-filtered for the requester) |
| `GET /api/v1/matrix?cve_id=CVE-2026-43284` | returns matrix sliced to Dirty Frag's chain |
| `POST /api/v1/coverage/recompute` | maintainer JWT → either runs synchronously on one chain or queues every chain |
| State transition mapping → generating | `SELECT processing_status FROM cves WHERE cve_id='CVE-2026-43284';` returns `generating` after M14 lands; M15 stub then logs `task.stub.invoked` until the real M15 lands |

## Interfaces exposed

```python
from fragchain.coverage import (
    # Mapper
    CoverageMapper,
    CoverageMappingError,
    CoverageReport,
    CoverageStatus,
    LLM_VERIFY_PARALLELISM,
    SEMANTIC_RESULT_LIMIT,
    SEMANTIC_SCORE_THRESHOLD,
    # Matrix
    CACHE_TTL_SECONDS,
    DEFAULT_FRAMEWORK,
    ENTERPRISE_TACTIC_ORDER,
    MatrixCache,
    MatrixCell,
    MatrixData,
    MatrixFilters,
    MatrixSummary,
    MatrixTactic,
)
```

API contract (all under `/api/v1`):

* `GET    /coverage?coverage_status=&tactic_id=&kev_only=`
* `GET    /coverage/{technique_id}?framework=`
* `GET    /matrix?framework=&cve_id=&date_from=&date_to=&cvss_min=&kev_only=&tactic_id=`
* `GET    /matrix/{technique_id}?framework=`
* `POST   /coverage/recompute {chain_id?}`  (maintainer)

Celery contract:

* `fragchain.worker.tasks.map_coverage` (kwargs: `chain_id`)
* `fragchain.worker.tasks.refresh_matrix_cache` (kwargs: optional `framework`)

WebSocket / event bus contract:

* `coverage_mapped`
* `matrix_updated`

## What dependent modules need to know

* **M15 (Rule Generator)** — picks up at `processing_status='generating'`.
  Reads the `CoverageReport` indirectly: walk `coverage_map` rows for
  this chain's CVE (via `chain_cve_ids`) and find rows where
  `coverage_status='gap'`. The priority is *not* persisted on the row —
  M15 should call `CoverageMapper.map_coverage(chain_id)` again (cheap on
  Phase 1, more expensive on Phase 2 but cache-friendly) or accept the
  priority via the Celery task kwargs once M15 wires its own task.
* **M16 (Review Queue)** — uses `covering_rule_ids` on the coverage row
  to surface "this technique already has Sigma coverage" warnings.
* **M19 (Dashboard)** — consumes `GET /api/v1/coverage?kev_only=true`
  for the KEV-exposure mini-heatmap.
* **M21 (ATT&CK Matrix UI)** — consumes `GET /api/v1/matrix`. Cells
  carry `coverage_status`, `chain_cve_count`, `kev_exposed`,
  `covering_rule_count`. Drill-in calls `/matrix/{technique_id}` for
  the full rule + CVE detail.
* **M22 (Sigma Library)** — uses `covering_rule_count` to badge rules
  with "covers N techniques" once it wants to surface that.

## Deviations from spec / kickoff

* **EPSS bands are mutually exclusive.** The spec text says
  "+20 if epss ≥ 0.50, +15 if epss ≥ 0.20". Read strictly, a CVE with
  EPSS=0.6 would get both bonuses (+35). We treat the bands as
  mutually exclusive — 0.6 lands in the 0.50 bucket and gets +20 only.
  Double-counting would skew the priority queue toward EPSS-driven gaps
  in a way that probably wasn't intended. Tests pin this behaviour.
* **Phase 2 "yes" → covered, not partial.** The kickoff says "Phase 2:
  Qdrant search ... LLM verify ... yes | partial | no". I treat a
  "yes" verdict as full coverage (rule added to `covering_rule_ids`),
  not partial. Partial coverage is reserved exclusively for the LLM
  "partial" verdict. Rationale: if the LLM is confident the rule
  detects the technique, the only reason it wasn't a Phase 1 hit is
  that the rule author didn't tag the ATT&CK technique on the rule —
  not that the rule's detection logic is incomplete. The Phase 1 vs
  Phase 2 split is about how we *found* the rule, not how *good* the
  match is.
* **Pre-filter Phase 2 candidates whose rules already tag the
  technique.** Such a rule would have surfaced in Phase 1 (or would,
  if its status flipped to `merged`). Re-verifying it via the LLM
  would burn budget on a near-certain "yes" answer. We skip them.
* **Self-exclusion on shared-gap count.** Re-running M14 on a CVE
  already mapped to a technique would otherwise count the CVE itself
  against the "+5 × other CVEs" bonus. `_shared_gap_counts` returns
  the list of UUIDs so the caller can subtract self cleanly. The
  spec ambiguously says "other CVEs sharing this gap" — the literal
  read is "exclude self".
* **`coverage_status` is overwritten per chain, not merged.** When a
  chain says T1078 is `gap` and another chain says T1078 is `covered`
  for a different CVE, the row reflects the last chain to land. The
  union semantics live in `covering_rule_ids` and `chain_cve_ids` —
  the rule list grows monotonically, so "is this technique covered
  somewhere" can be answered by `len(covering_rule_ids) > 0`. The
  per-cell `coverage_status` is effectively the *latest* chain's
  view. M21's UI can show both: cell colour from `coverage_status`,
  badge from the rule count.
* **The CVE filter on `/matrix` doesn't make uncovered techniques
  disappear.** Filtering by `cve_id=CVE-X` shows the matrix sliced
  to chains for CVE-X, but techniques where no rule exists and CVE-X
  doesn't contribute are shown as `no_data` (not omitted). This
  preserves the 14-tactic grid shape regardless of filter.
  Techniques where a rule covers them in general (rule-level
  coverage) keep their `covered` status under the slice — we want
  "we have a rule" to be visible even when "no CVEs landed here yet"
  for the current filter.
* **`MatrixCache.invalidate` uses `SCAN_ITER`, not `KEYS`.** `KEYS`
  blocks Redis on large keyspaces. `SCAN_ITER` is incremental.
  Trade-off: cursor invalidation may briefly leak a stale key, but
  the next read will refresh and the TTL backstops the worst case.
* **Matrix data writes JSON to Redis.** The dataclass round-trips
  through `to_dict()` / `from_dict()` so we don't need to worry about
  pickling cross-runtime. Keys carry the framework prefix
  (`matrix:attck:…`) so `SCAN MATCH matrix:atlas:*` can invalidate a
  single framework without touching others.
* **`refresh_matrix_cache` runs hourly.** The kickoff says "every 1
  hour"; the previous M1 stub was set to `*/10` (10 minutes). Hourly
  matches the cadence of the cache TTL (1h), so the warm-up happens
  ~1 minute before keys would otherwise expire. The stub schedule has
  been corrected.
* **`/coverage/recompute` runs synchronously for a single chain.**
  With `chain_id` set, the mapper runs inline (so the operator gets
  the report back immediately). Without it, the route fans out one
  Celery task per chain — a full-rebuild on a ~10k chain deployment
  would block the request otherwise. The kickoff mentioned a
  `recompute_coverage()` admin task but the spec's API contract
  surfaces both as `/coverage/recompute`; that's what we expose.
* **No new database migration.** `coverage_map` already exists from
  M8 (migration `0009_coverage_map.py`); the table shape M14 needs
  is exactly the shape M8 created. No M14 migration needed.
* **`LLM_VERIFY_TIMEOUT_SECONDS=20` per call.** A misbehaving LLM
  shouldn't block the whole loop — we cap per call and let the rest
  complete. The candidate's verdict lands as `error` (not gap) so a
  retry on the next chain landing the same technique gets another
  chance.
* **`max_tokens=16` on the verify call.** "yes / partial / no" fits
  in <5 tokens; capping at 16 keeps the LLM honest about the format
  and bounds the worst-case cost.

## Known TODOs (owned by other modules)

* **M15 (Rule Generator)** — replace the `generate_rules` stub in
  `fragchain/worker/tasks/__init__.py` with the real task. Read
  `coverage_map.coverage_status='gap'` rows for the chain's CVE
  and produce drafts. The state-machine transition `generating →
  complete` lives in M15.
* **M19 (WebSocket fan-out)** — forward `coverage_mapped` and
  `matrix_updated` events to connected clients. Payloads are already
  JSON-serialisable.
* **M21 (Matrix UI)** — render the matrix from `/api/v1/matrix`. The
  cell payload carries everything the UI needs (status colour, count
  badge, KEV pulse indicator).
* **Per-chain priority persistence** — M15 currently has to recompute
  priority by re-running the mapper (or accept it via task kwargs).
  A future enhancement: persist top-N gaps per chain in a dedicated
  table so M15 can read directly. Defer until M15 makes the call.
* **Matrix tactic order for non-Enterprise frameworks** — ATLAS /
  SPARTA frameworks have different tactic orderings. `matrix.py`
  appends them alphabetically after Enterprise; once M14's first
  caller hits ATLAS we'll want a framework → tactic-order registry.

## Risks / known weaknesses

* **Phase 2 LLM cost.** A 10-TTP chain with 5 Phase 2 candidates each
  burns 50 cheap LLM calls. At ~$0.0005 / verify call (small Sonnet)
  that's ~$0.025 per chain — still cheap but not free. Operators
  monitoring cost via `llm_interactions` will see the `coverage_verify`
  rows. Tunable via `SEMANTIC_SCORE_THRESHOLD` (raise to 0.85 to cut
  Phase 2 candidates) or `SEMANTIC_RESULT_LIMIT` (drop to 3).
* **`shared_gap_uuids` issues N+1 reads on persistence.** The
  `chain_cve_ids` of every gap-status technique are read once before
  persistence. For ~700 ATT&CK techniques × 5 chains landing
  per hour this is fine; if M14 starts running on bulk historical
  imports we may want a single materialised view.
* **Cache key collisions are bounded by sha256 truncation.** 16 hex
  chars = 64 bits of namespace per framework. At 10k cached filter
  combinations the birthday collision odds are ~10⁻¹². The cache is
  best-effort anyway — a collision serves a stale matrix for up to
  1h. Acceptable.
* **`cve_id` filter case-sensitivity.** `MatrixFilters.cve_id` is
  uppercased before the SELECT. A lower-case CVE id in the URL still
  matches. The cache key uses the literal supplied string though —
  `/matrix?cve_id=CVE-1` and `/matrix?cve_id=cve-1` would hash to
  different keys but resolve to the same row. A first request with
  one casing populates one cache key; the matrix is correct either
  way. Worth normalising the cache key in a future tweak.
* **No backpressure on the LLM verify path.** The semaphore caps
  concurrency at 10 but doesn't queue across `map_coverage` calls.
  Two workers running M14 simultaneously can together issue 20
  in-flight verify calls. LiteLLM's own rate-limit handling (M5
  retries) absorbs this for now; once the verify path becomes hot
  we'll want a global token bucket.
* **`coverage_status` is per-row, not per-chain.** As noted under
  "Deviations", the latest chain wins for the row's headline status.
  Operators wanting a per-CVE coverage view should read the
  `CoverageReport` via the `/coverage/recompute` endpoint or wait
  for M19's dashboard view, which can synthesise per-CVE coverage
  from the coverage_map's `chain_cve_ids` + per-cell rule lists.

## Outstanding questions

* **Should the LLM verify call respect the chain's TLP?** Currently
  every candidate goes through the verify path regardless of TLP. A
  `tlp:red` chain's rule excerpts shouldn't leak through to a
  public-cloud LLM endpoint. Worth surfacing as a per-source-document
  exclusion once an operator deploys M5 against a public endpoint
  with tlp:red sources. Defer until that materialises.
* **Should `coverage_status` be a maximum across chains rather than
  last-wins?** A technique whose covering rule got rejected by another
  chain's run shouldn't drop back to `gap` — but in the current model
  it would. The merge of rule lists (union) is the safety net. If
  this becomes a real problem M15 can read both fields and decide.
* **`recompute_coverage()` admin endpoint vs. existing
  `/coverage/recompute`.** The spec lists two task names
  (`map_coverage(chain_id)` and `recompute_coverage()`); we collapse
  the admin "rebuild everything" path into `POST /coverage/recompute`
  with no body. If an operator wants a dedicated admin Celery task
  for nightly rebuilds, a `recompute_all_coverage` task is a one-line
  addition once the use case shows up.
* **Should `/matrix` honour an `If-None-Match` header for ETag-style
  caching?** The cached payload is bytewise stable for an hour, so a
  304 response would be cheaper than serialising the full matrix
  again on a poll. Defer until M21 starts polling.
* **Per-framework cache TTL tuning.** Custom frameworks (ATLAS,
  SPARTA) may update at different cadences. Today every framework
  shares the 1h TTL. Worth a per-framework column on a hypothetical
  `frameworks` table once a second framework lands.

## Phase 5 cleanup — noted

- **Matrix returns 15 tactics, not 14 (audit B10).** The Phase 5 audit
  observed the matrix returning the 14 canonical ATT&CK Enterprise
  tactics plus a non-canonical `TA0112 — Defense Impairment`. The
  matrix endpoint reads what's in `coverage_map` / `attck_techniques`;
  the extra tactic came in via the upstream STIX bundle that M8 seeds.
  The fix is upstream (gate the M8 seed to the canonical 14) and is
  explicitly deferred to a tiny follow-up — see the updated M14 done
  criteria in `FragChain_Module_Specifications.md`. **Not fixed in
  Phase 5 cleanup.**
- **Worker tasks now flow through `run_async_task`.** The map_coverage
  + refresh_matrix_cache tasks dispose the asyncpg engine after each
  invocation, so a second task on the same worker process gets a fresh
  engine bound to its own event loop (audit Should-fix #8). The previous
  "Future attached to a different loop" cascade is gone — verified by
  watching the worker logs over a batch of embeds + coverage maps.

See `PHASE5_CLEANUP_DONE.md` for the full change set, evidence, and rollback steps.
