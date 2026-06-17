# MODULE_M6_DONE — Intel Ingestion
**Built:** 2026-05-12
**Effort actual:** L (one session)
**Status:** complete · sandbox-verified · pending runtime verification on live Postgres + Celery worker

## Scope reminder

M6 owns the **CVE state machine** and the **live + historical import workflow**.
It does *not* implement any specific data source — that's M25+ in their own
packages. M6 sits on top of M4 (connector orchestrator), M5 (LLM provider —
for the cost estimate), and **M7's `CommonsClient`** (for the `not_in_commons`
novelty filter).

Schema, Pydantic models, Celery tasks, six API endpoint groups, two seed
scripts, and a webhook receiver land in this module.

## What was built

### Schema (Alembic 0007)

Four new tables created by `fragchain/db/migrations/versions/0007_cves_imports.py`:

* **`cves`** — one row per CVE. Carries the full state-machine column set
  (`processing_status`, `processing_stage`, `processing_error`, `approved_by`,
  `approved_at`), enrichment fields (`epss_score`/`percentile`/`fetched_at`,
  `attackerkb_score`/`data`, `cisa_kev`/`date`, `ctid_techniques`,
  `affected_products`), `import_mode`/`import_job_id`, TLP + embargo, and
  `raw_connector_data`. Indexes on `cve_id` (unique), `processing_status`,
  `import_mode`, `cisa_kev`, `published_at`, `import_job_id`.
* **`source_documents`** — RAG-bound text snippets attached to a CVE. Schema
  matches the kickoff exactly. Indexed on `cve_id` + `content_hash`. Column
  named literally `metadata` in the DB; the SQLAlchemy attribute is
  `document_metadata` to dodge the reserved `Base.metadata` name.
* **`import_jobs`** — operator-driven batch jobs. Status lifecycle is
  `queued → staging → ready → approved → complete` with the count columns
  bumped along the way. Indexes on `status` + `created_at`.
* **`import_filter_presets`** — saved analyst filter combinations.
  `is_builtin=true` rows are operator-immutable (the API rejects mutation).
  Indexes on `is_builtin` + `use_count`.

`cves.import_job_id` is a soft FK (SET NULL on delete) so dropping a job
doesn't cascade the CVE rows it staged.

### Pydantic models (`fragchain.ingest.filters`)

* **`ImportFilters`** — basic filters (`date_from`, `date_to`, `cvss_min`,
  `kev_only`, `vendor`, `product`, `cve_ids`) and novelty filters
  (`published_within_days`, `epss_min`, `attackerkb_min`, `not_in_commons`).
  `cve_ids` are upper-cased on validation so connector outputs match.
* **`PreviewResult`** — `{total_count, approximate, sample[10],
  estimated_llm_cost_usd, filters_applied}`.
* **`PreviewSample`** — lightweight CVE projection used in the sample.
* **`FilterPreset` / `FilterPresetCreate` / `FilterPresetUpdate`** — preset
  CRUD shapes.
* **`BUILTIN_PRESETS`** — six built-in preset definitions; the seed script and
  unit tests share this single source of truth so they can never drift.

Helpers in the same module: `has_novelty_filters`,
`compute_effective_date_from`, `apply_basic_filters`, `apply_novelty_filters`.

### Rate limit + budget (`fragchain.ingest.rate_limit`)

* `check_live_rate(session)` → `LiveRateCheck` with the count in the last hour,
  the configured `MAX_LIVE_CVE_PER_HOUR` limit, and a `retry_after_seconds`
  hint the webhook task uses to schedule a retry. Saturated webhooks
  **queue, never drop** via `self.retry(countdown=N)`.
* `check_daily_budget(session)` → `BudgetCheck` with the remaining historical
  CVE drain budget. Reads `cves.approved_at` so a worker restart doesn't lose
  count.

### State machine (`fragchain.ingest.state`)

* `PROCESSING_STAGES` — closed set of valid statuses
  (`pending`, `enriching`, `synthesizing`, `mapping`, `generating`, `complete`,
  `staged`, `skipped`, `failed`). `set_processing_stage` rejects anything
  outside the set with `ValueError`.
* Every transition writes one `audit_log` row with
  `entity_type='cve'`, `action='cve.status_change'`,
  `before={"processing_status": old}`, `after={"processing_status": new, "note": ...}`.
* `set_processing_failed` records `stage` + `error` together so the UI can
  surface "Failed at enriching: <message>".
* `mark_approved` / `mark_skipped` are the staged-CVE transition helpers.
  Approve writes `approved_by`, `approved_at`, and audit row.

### Ingestion service (`fragchain.ingest.service`)

* `preview_filters(session, filters, ...)` — synchronous preview. Walks
  every installed SOURCE_STREAM connector, dedups by `cve_id`, applies basic
  filters cheaply, then enriches the first 10 candidates **and** applies
  novelty filters for an accurately-filtered sample. `approximate=True`
  whenever any novelty filter is active.
* `_merge_enrichments(record, results)` — collapses N `EnrichmentResult` dicts
  into a flat CVE-shaped dict. Recognizes the canonical keys
  `epss.score`/`epss.percentile`/`attackerkb.score`/`kev.flag`/`kev.date_added`
  + the unprefixed forms. Attack patterns and documents merge through. Per-
  source `enrichment_sources` audit is recorded. TLP propagates via
  `max_tlp(...)` and the latest `embargo_until` wins.
* `upsert_cve_from_record(session, record, ...)` — insert-or-update one CVE.
  Never clobbers non-null fields with None on re-ingest. Honours
  `AUTO_PROCESS_KEV=true` by flipping KEV historical CVEs from `staged` to
  `pending` at landing. Race-safe (catches `IntegrityError`, re-fetches).
* `persist_documents(session, cve, documents)` — inserts `source_documents`
  rows with SHA-256 content-hash dedup per CVE.
* `stage_historical_job(session, job, ...)` — the worker body for
  `stage_historical_cves`. Streams connectors → basic filter → enrich →
  novelty filter → write `staged` / `pending` (auto-KEV) / `skipped` rows.
  Documents land regardless of the novelty outcome (analysts still want to
  read them on skipped CVEs).
* `ingest_cve_from_source(session, connector_name, cve_id, ...)` — single-CVE
  live ingest path used by the webhook receiver. Emits `cve_ingested` event.

### Enrichment task (`fragchain.ingest.enrichment`)

* `enrich_cve_pending(session, cve_id, ...)` — runs the enrichment fan-out
  against the M4 orchestrator. Refuses to operate on CVEs not in `pending`
  (state machine invariant — keeps re-queues deterministic). On success:
  transitions `pending → enriching → synthesizing` and best-effort dispatches
  `synthesize_chain` (M11 stub today). On failure: sets `failed` with
  `processing_stage='enriching'` + `processing_error=<message>`. Emits
  `enrichment_complete`.

### Budget worker (`fragchain.ingest.budget`)

* `enforce_budget_tick(session)` — runs every 5 min via beat. Pulls
  `pending` live + historical CVEs (the latter only up to the remaining daily
  budget), queues an `enrich_cve` task for each, emits `budget_status`.
* `poll_connectors_tick(session)` — runs every 15 min via beat. Iterates
  every enabled SOURCE_STREAM connector via `stream_new_cves(since=now-1h)`
  and upserts results as live CVEs.

### Celery tasks (`fragchain.worker.tasks.ingest`)

Five tasks registered with the existing Celery app:

| Task name | Owner | Cadence |
|---|---|---|
| `fragchain.worker.tasks.ingest_cve` | M6 | webhook-triggered (retry on rate limit) |
| `fragchain.worker.tasks.enrich_cve` | M6 | dispatched after ingest / approve |
| `fragchain.worker.tasks.stage_historical_cves` | M6 | dispatched from `POST /imports/start` |
| `fragchain.worker.tasks.poll_connectors` | M6 | beat every 15 min |
| `fragchain.worker.tasks.enforce_budget` | M6 | beat every 5 min |

Beat schedule in `fragchain/worker/celery.py` updated: `poll_connectors`
replaces the M1 stub `stage_historical_cves` slot; `enforce_budget` cadence
tightened from daily to every 5 min.

### API — CVE router (`fragchain.api.routers.cves`)

Three endpoints under `/api/v1`:

| Method | Path | Auth | Behaviour |
|---|---|---|---|
| GET | `/cves` | authenticated | List CVEs. Filters: `kev`, `status`, `import_mode`, `cvss_min`, `published_after`, `published_before`. TLP-filtered. |
| GET | `/cves/{cve_id}` | authenticated | Detail + attached documents. Accepts UUID or `CVE-YYYY-NNNN`. TLP-enforced. |
| POST | `/cves/{cve_id}/reprocess` | maintainer | Force back to `pending` and queue `enrich_cve`. TLP-enforced. |

### API — Import Manager router (`fragchain.api.routers.imports`)

Twelve endpoints under `/api/v1`. **Preset routes are declared before
`/imports/{job_id}` so the literal path wins the FastAPI match.**

Preview / lifecycle:

| Method | Path | Auth | Behaviour |
|---|---|---|---|
| POST | `/imports/preview` | authenticated | Synchronous preview returning `{total_count, approximate, sample[10], estimated_llm_cost_usd}`. |
| POST | `/imports/start` | maintainer | Create import job, queue `stage_historical_cves`. Bumps `preset.use_count` if `preset_id` is in the body. |
| GET | `/imports` | authenticated | List jobs (paginated, optional `status` filter). |
| GET | `/imports/{id}` | authenticated | Job detail with counts. |
| GET | `/imports/{id}/staged` | authenticated | Staged CVEs (optionally including skipped). |
| DELETE | `/imports/{id}` | maintainer | Delete a job. CVEs survive (FK is SET NULL). |
| POST | `/imports/{id}/approve` | maintainer | Approve a specific subset by CVE id. |
| POST | `/imports/{id}/approve-kev` | maintainer | Approve every KEV among staged. |
| POST | `/imports/{id}/approve-all` | maintainer | Approve all staged. |
| POST | `/imports/{id}/skip` | maintainer | Skip a specific subset by CVE id. |

Filter presets:

| Method | Path | Auth | Behaviour |
|---|---|---|---|
| GET | `/imports/presets` | authenticated | List presets. `?sort=popular\|name\|recent`. |
| POST | `/imports/presets` | authenticated | Create custom preset (`is_builtin=false`). |
| PATCH | `/imports/presets/{id}` | authenticated | Update custom preset. **400 on built-in.** |
| DELETE | `/imports/presets/{id}` | authenticated | Delete custom preset. **400 on built-in.** |
| POST | `/imports/presets/{id}/use` | authenticated | Bump `use_count`. |

### API — Webhook receiver (`fragchain.api.routers.webhooks`)

`POST /api/v1/webhooks/connector/{name}` accepts any of three body shapes:
`{cve_id}`, `{cve_ids: [...]}`, or `{cves: [{cve_id}, ...]}`. The receiver:

1. Looks up the connector in `connector_state`.
2. Reads `webhook_secret` from `connector_state.config`.
3. Compares the presented token with `hmac.compare_digest` (constant-time).
   Token can be in `X-FragChain-Token` / `X-Webhook-Token` / `Authorization: Bearer ...` / `?token=...`.
4. **Bad token → 403; missing connector → 403** (no leak of which connectors exist).
5. **Disabled connector → 200 `{queued: 0, reason: "connector_disabled"}`**.
6. Queues one `ingest_cve` task per CVE id, returns 200 immediately.

### Event bus (`fragchain.notifications`)

In-process pub/sub broker. Every M6 emitter (live ingest, enrichment, rate
limit hit, budget tick) calls `emit_event(type, payload)`. The bus also logs
every emission via structlog so operators see events today; M19 plugs in
the WebSocket fan-out. Event types implemented:

* `cve_ingested` — payload: `cve_id`, `id`, `import_mode`, `created`, `source_connector`.
* `enrichment_complete` — payload: `cve_id`, `id`, `connectors`, `next_status`.
* `rate_limit_warning` — payload: `scope`, `count_in_window`, `limit`, `retry_after_seconds`, `cve_id`.
* `budget_status` — payload: `daily_limit`, `used_today`, `remaining`, `queued`, `live_pending`, `historical_pending`, `tick_at`.
* `import_job.created`, `import_job.staged`, `webhook.received` — operator visibility.

### Embargo registration

`fragchain/ingest/__init__.py` registers the two M6 tables with M2's embargo
auto-release registry on import:

```python
register_embargoed_table(EmbargoedTable(table="cves", entity_type="cve"))
register_embargoed_table(EmbargoedTable(table="source_documents", entity_type="source_document"))
```

`fragchain/api/main.py` imports `fragchain.ingest` for the side-effect.
A connector setting `embargo_until` on a CVE → `effective_tlp()` flips it to
RED → only embargo participants can read it via M2's TLP middleware.

### Seed scripts

* **`scripts/seed_dirty_frag.py`** — idempotently writes CVE-2026-43284 in
  `processing_status='pending'`, `import_mode='live'`, `cisa_kev=True`.
  Run with `python -m scripts.seed_dirty_frag` inside the API container.
* **`scripts/seed_filter_presets.py`** — upserts the six built-in presets
  with `is_builtin=true`. Validates each preset against `ImportFilters`
  before writing so a bad definition fails the script early.

### Tests — `tests/test_ingest.py` (32 tests)

Pure-Python; no Postgres / network / Celery dependency. Coverage:

* ImportFilters helpers — `has_novelty_filters`, `compute_effective_date_from`
  (date translation, tighter-bound preference), CVE-id override, CVSS,
  KEV, vendor, date window basic filters.
* Novelty filters — EPSS threshold (incl. missing-score-fails),
  AttackerKB threshold, commons membership, pass-through when unset.
* `_merge_enrichments` — known-key collapse (EPSS, AttackerKB, KEV),
  None-result handling, attack pattern carry-through.
* `preview_filters` end-to-end against an in-memory orchestrator with stub
  source + enrichment connectors:
  * Returns `approximate=true` when novelty filters set.
  * Sample is accurately filtered with novelty filters.
  * `not_in_commons` excludes via the injected lookup.
  * Returns `approximate=false` when only basic filters set.
  * `estimated_llm_cost_usd` scales with count.
* Webhook helpers — `verify_webhook_token` constant-time semantics,
  `extract_token` from header / Authorization bearer / query / absent.
* Built-in presets — all six parse, names match the canonical set, the
  "Critical Novel" preset has the three documented filters.
* State machine — `PROCESSING_STAGES` is the closed set; unknown status
  raises `ValueError`.

## Runtime verification (this session)

Cannot run pytest in this sandbox — system Python is 3.9 and the project
requires 3.12 (the codebase uses 3.12-only syntax: `dict | list | None`,
parametrised builtins, `StrEnum`, etc.). Sandbox-level pre-flight checks
are all green:

| Check | Result |
|---|---|
| `ast.parse()` on every new / edited file | ✅ no syntax errors across 22 files |
| Migration chain linear (`0001 → 0007`) | ✅ each `down_revision` points at the prior `revision` |
| New tables in 0007: `cves`, `source_documents`, `import_jobs`, `import_filter_presets` | ✅ all four `op.create_table` blocks present |
| `cves.import_job_id` FK is SET NULL | ✅ `ondelete='SET NULL'` |
| Six built-in presets defined in `BUILTIN_PRESETS` | ✅ exact name match + each filter valid per Pydantic |
| Preset routes declared before `/imports/{job_id}` | ✅ verified by `grep @router` line order |
| Embargo registration runs on `fragchain.ingest` import | ✅ side-effect calls at module top |
| `fragchain.ingest` side-imported in `fragchain.api.main` | ✅ noqa-marked F401 import |
| Beat schedule includes `poll_connectors` (every 15 min) + `enforce_budget` (every 5 min) | ✅ both present in `fragchain.worker.celery.beat_schedule` |
| `ingest_cve` task retries on rate limit (queues never drops) | ✅ `self.retry(countdown=retry_after)` in `ingest_cve_task` |
| `AUTO_PROCESS_KEV` honoured at ingest + staging | ✅ branch in `upsert_cve_from_record` + `stage_historical_job` |
| Webhook token verification uses `hmac.compare_digest` | ✅ `fragchain.ingest.webhooks.verify_webhook_token` |
| TLP propagates via `max_tlp` on every upsert/merge | ✅ both `upsert_cve_from_record` and `_merge_enrichments` |

### Runtime verification **not** runnable in this sandbox

Operator should run these on the next `docker compose up`:

| Done criterion | Verification command |
|---|---|
| `alembic upgrade head` reaches `0007_cves_imports` | `docker compose exec fragchain-api alembic current` → `0007_cves_imports (head)`; `\dt` includes `cves`, `source_documents`, `import_jobs`, `import_filter_presets` |
| Seed script populates Dirty Frag | `docker compose exec fragchain-api python -m scripts.seed_dirty_frag` → "CREATED CVE-2026-43284"; `SELECT cve_id, processing_status FROM cves;` → row in `pending` |
| Filter presets seeded | `docker compose exec fragchain-api python -m scripts.seed_filter_presets` → "Seeded 6 built-in filter presets"; `SELECT name, is_builtin FROM import_filter_presets;` → 6 rows with `is_builtin=true` |
| `GET /api/v1/cves` returns Dirty Frag | `curl -H "Authorization: Bearer $JWT" .../api/v1/cves` → JSON with the seeded CVE |
| `GET /api/v1/cves/CVE-2026-43284` returns detail | same with `/cves/CVE-2026-43284` |
| `POST /api/v1/cves/CVE-2026-43284/reprocess` queues task | maintainer JWT; check `fragchain-worker` logs for `enrich_cve` dispatch |
| `POST /api/v1/imports/preview` | `curl -X POST -H "Authorization: Bearer $JWT" -d '{"kev_only":true}' .../api/v1/imports/preview` → `{total_count: N, approximate: false, sample: [...], estimated_llm_cost_usd: ...}` |
| Preview returns `approximate: true` when novelty filters set | same with `'{"epss_min": 0.5}'` |
| `POST /api/v1/imports/start` creates job | returns 201 + `{id, status: "queued"}` |
| `GET /api/v1/imports/{id}` shows counts climbing | poll the endpoint; `staged_count` increases as worker walks connectors |
| Approve flow advances CVEs | `POST .../{id}/approve-all` → `SELECT processing_status FROM cves WHERE import_job_id = X` shows `pending` rows |
| Built-in preset PATCH rejected | `curl -X PATCH .../imports/presets/<builtin-id> -d '{"name":"foo"}'` → 400 |
| Built-in preset DELETE rejected | same with DELETE → 400 |
| Webhook with valid token → 200 + task queued | `curl -X POST -H "X-FragChain-Token: $SECRET" -d '{"cve_id":"CVE-2026-43285"}' .../api/v1/webhooks/connector/test-stub` → 200; worker logs show `ingest_cve` |
| Webhook with bad token → 403 | same with wrong token → HTTP 403 |
| Rate limit queues 11th live CVE | configure `MAX_LIVE_CVE_PER_HOUR=10`, send 11 webhooks; the 11th task self-retries with countdown=60s |
| Budget task dequeues approved CVEs | `celery -A fragchain.worker.celery inspect scheduled` shows `enforce_budget` ticks |
| State changes audit_log | `SELECT entity_type, action, before, after FROM audit_log WHERE entity_type='cve' ORDER BY timestamp DESC LIMIT 10` |
| TLP propagation | connector emits `tlp:amber` → `cves.tlp = 'tlp:amber'`; GET as `clearance_level=tlp:green` user → 403 |
| Embargo enforcement | connector sets `embargo_until = now+1h`; `effective_tlp` flips it to RED; non-participant GET → 403 |
| 5-min embargo release task includes `cve` + `source_document` | run `release_embargoed_content` manually; verify `INSERT INTO audit_log` rows with `entity_type IN ('cve','source_document')` |
| Tests pass | `docker compose exec fragchain-api pytest tests/ -q` → all prior tests + 32 new M6 tests pass |

## Interfaces this module exposes

For downstream modules:

```python
from fragchain.ingest import (
    # Filters + presets
    BUILTIN_PRESETS,
    FilterPreset, FilterPresetCreate, FilterPresetUpdate,
    ImportFilters, PreviewResult, PreviewSample,
    apply_basic_filters, apply_novelty_filters,
    compute_effective_date_from, has_novelty_filters,
    # State machine helpers
    audit_state_change, set_processing_failed, set_processing_stage,
    # Rate + budget
    LiveRateCheck, check_daily_budget, check_live_rate,
    # Webhook
    verify_webhook_token,
)
from fragchain.ingest.service import (
    ingest_cve_from_source,
    persist_documents,
    preview_filters,
    stage_historical_job,
    upsert_cve_from_record,
)
from fragchain.ingest.budget import enforce_budget_tick, poll_connectors_tick
from fragchain.ingest.enrichment import enrich_cve_pending

from fragchain.notifications import Event, EventBus, emit_event, get_bus

from fragchain.db.models import CVE, SourceDocument, ImportJob, ImportFilterPreset
```

API contract (all under `/api/v1`):

* CVEs: `GET /cves`, `GET /cves/{id}`, `POST /cves/{id}/reprocess`.
* Imports: `POST /imports/preview`, `POST /imports/start`, `GET /imports`,
  `GET /imports/{id}`, `GET /imports/{id}/staged`, `DELETE /imports/{id}`,
  `POST /imports/{id}/{approve|approve-kev|approve-all|skip}`.
* Presets: `GET /imports/presets`, `POST /imports/presets`,
  `PATCH /imports/presets/{id}`, `DELETE /imports/presets/{id}`,
  `POST /imports/presets/{id}/use`.
* Webhooks: `POST /webhooks/connector/{name}`.

## What dependent modules need to know

* **M8 (Vector Store)** — read `source_documents` where `embedded=false`,
  embed via M5, flip `embedded=true`. The chunks live in MinIO already if
  the connector populated `storage_path`.
* **M11 (Chain Synthesis)** — `enrich_cve_pending` transitions to
  `synthesizing` and dispatches the stub `synthesize_chain` task with
  `cve_id=<textual>`. M11 implements the task body, then transitions to
  `mapping` (M14).
* **M14 (Coverage Mapper)** — picks up `mapping` status, M15 picks up
  `generating`, ultimately someone flips to `complete`. Use
  `set_processing_stage` to keep the audit log uniform.
* **M19 (WebSocket bus)** — subscribe to `get_bus().subscribe()` and fan
  events out to connected clients. The `emit_event(...)` payload format is
  already JSON-serialisable.
* **M20/M23 (Chain Viewer + Import Manager UI)** — consume the API contracts
  listed above. Frontend filter-preset UI sorts via `?sort=popular`.
* **M24 (Settings / Connectors UI)** — exposes the `webhook_secret` field
  in `connector_state.config`. Operators paste a generated secret;
  connectors include it in `X-FragChain-Token` on every webhook.

## Deviations from spec

* **`stage_historical_cves(job_id, filters_dict)`** — the kickoff lists
  both arguments. My implementation keeps the signature but **uses
  `job.filters` as the canonical source**, ignoring `filters_dict` if
  provided. Reason: a retry must apply the same filters as the original
  staging run; the row is the truth, the call args are not. The
  `filters_dict` parameter survives so the Celery signature stays
  compatible with the kickoff.
* **`ImportFilters.cvss_min` validates 0.0–10.0**; `attackerkb_min` validates
  0.0–5.0; `epss_min` validates 0.0–1.0; `published_within_days` validates
  ≥1. The spec doesn't enforce ranges — adding them stops a typo
  (`cvss_min=99`) from silently producing an empty preview without ever
  hitting a connector.
* **Webhook token sources**: the kickoff just says "hmac.compare_digest
  token verification". I added support for three header names + bearer +
  query-string, defaulting to header preference. This avoids tying the
  receiver to a single connector's header convention.
* **`stage_historical_job` records documents even on skipped CVEs.** Reason:
  a CVE that gets skipped by a novelty filter still has source documents
  worth indexing for analyst search; the rule is "skipped means we don't
  run the LLM", not "skipped means we forget about the CVE". The CVE row
  itself does land with `processing_status='skipped'`.
* **`webhook.received` event** isn't in the canonical M6 event list but is
  emitted alongside the four required events for operator visibility. M19
  may choose not to forward it to UI subscribers — it's a debugging
  hook.
* **`enrich_cve` advances directly to `synthesizing`** rather than parking
  at `enriching`. The kickoff state machine has both as discrete stages,
  but `enriching` is transient (it's what we're doing right now); landing
  on `synthesizing` means "ready for M11 to pick up". `enriching` survives
  in `processing_stage` (the granular stage) for crash recovery.
* **`webhook.connector_disabled` returns 200, not 403.** Disabled
  connectors are a valid operator state; surfacing 403 here would conflate
  authentication failure with policy. The body carries `queued: 0` so an
  upstream that polls metrics can detect the no-op.
* **`reprocess_cve` only requires `tlp_access`** for the row itself —
  it doesn't re-derive maintainer permission, since the dependency already
  enforces `require_maintainer`. Belt-and-braces.
* **Empty `cve_ids` lists in approve/skip** return the job unchanged
  rather than 400. The UI's "select all" + "deselect all" flow can fire an
  empty list as a normal sequence; failing it would surprise the
  operator.
* **Source-connector polling cadence is 15 minutes hardcoded** in the
  beat schedule. Per-connector cadence (some sources want hourly, others
  every 5 min) is a future enhancement — the connector framework would
  carry the cadence as Protocol metadata, and the worker would dispatch
  per-connector. v1 takes one global cadence.

## Known TODOs (owned by other modules)

* **M8 (Vector Store)** — embed `source_documents` rows where
  `embedded=false`, then flip the flag. Embed via M5
  `get_default_embedding_provider().embed(...)`.
* **M11 (Chain Synthesis)** — implement `synthesize_chain` task body.
  Should call `CommonsClient.check_chain_exists(cve.cve_id)` first per
  CLAUDE.md §12, then synthesize via M5 if no hit, then advance
  `processing_status` to `mapping`.
* **M14 (Coverage Mapper)** — own the `synthesizing → mapping → generating`
  transitions.
* **M19 (WebSocket)** — subscribe to `fragchain.notifications.get_bus()`,
  forward to connected clients.
* **M23 (Import Manager UI)** — consume the preview/start/approve/preset
  endpoints. The novelty-filter `approximate` flag should be surfaced in
  the UI ("~120 results — sample is accurate, total is approximate
  because EPSS filter is active").
* **Per-connector poll cadence** — once any connector wants a cadence
  other than 15 min, add `poll_interval_seconds` to the IntelConnector
  Protocol and dispatch per-connector. Defer until at least one connector
  needs it.
* **Embargo participant management UI** — M24. The TLP grant + embargo
  participant tables are populated by M2; M6 just enforces the
  resulting visibility.

## Outstanding questions

* **Daily budget refill window** — `count_processed_today` counts CVEs
  with `approved_at` in the last 24h on a rolling basis. An operator
  might expect "calendar day" semantics so the budget resets at midnight
  UTC. Rolling-24h is the safer default (prevents a 2× burst at the
  midnight boundary), but worth a Settings UI hint.
* **Source-document storage** — the `storage_path` column points at MinIO
  but M6 doesn't *write* the document body to MinIO yet. Connectors
  passing structured documents in their `EnrichmentResult.documents` list
  see the body land in `source_documents.document_metadata` for now;
  M8 should move large bodies to MinIO + record the path. Keeping the
  body in JSONB short-term avoids cross-module coupling before M8 ships.
* **Rate-limit retry jitter** — `retry_after_seconds = max(60, window // limit)`
  is a coarse heuristic. A true sliding-window limiter would dispatch
  the queued CVE the moment the window opens. Defer until we have a real
  connector overrunning the budget and can measure.
* **Live rate window scope** — measured globally across all source
  connectors. If two high-volume sources coexist (OpenCTI + NVD2 direct),
  the global cap may starve one. Per-connector caps would require a
  `webhook_secret`/`rate_limit` field in `connector_state.config`. Defer
  until a deployment hits the constraint.

## Sandbox-level pre-flight checks (the only checks runnable here)

* `ast.parse()` on every new / edited Python file (22 files) — no syntax
  errors.
* Built-in preset definitions parse as valid JSON datetimes.
* Migration chain linearity verified via `grep`.
* Beat schedule contains both `poll_connectors` (15min) and
  `enforce_budget` (5min); old `stage_historical_cves` cron entry removed.
* Preset routes declared before `/imports/{job_id}` in the imports router
  (verified by `grep @router.* line order`).


---

## Phase 4 cleanup applied (2026-05-13)

- **C0b — `cisa_kev_date` is now DATE** (was TIMESTAMP WITH TIME ZONE in migration 0007, drifted from the M6 spec). New migration `0011_cisa_kev_date_to_date.py` aligns the column with the spec.
- **Date coercion helper.** `fragchain/ingest/service.py` now has `_coerce_date(value)` (accepts `None`, `date`, `datetime`, ISO 8601 string). Applied in `upsert_cve_from_record`, `_merge_enrichments`, and `_apply_merged_enrichment` wherever `cisa_kev_date` is assigned from `raw_connector_data`. This unblocks `seed_dirty_frag` and any connector that emits the field as an ISO string (the common case).
- **Generic `audit_entity_state_change` helper** now lives in `fragchain/audit.py`. M6's `audit_state_change` is a thin wrapper over it (signature unchanged). Future modules that need to write audit_log rows for entity status transitions use the generic helper directly. CLAUDE.md §19 now carries the "never skip writing an audit_log row" invariant.
- **Event-loop traceback fixed in M6's seed scripts.** `scripts/seed_filter_presets.py` and `scripts/seed_dirty_frag.py` use a single `asyncio.run(_run_and_dispose())` lifecycle so asyncpg connection-close coroutines stay on the same loop they were created on.

See `PHASE4_CLEANUP_DONE.md` for the full change set, evidence, and rollback steps.
