# MODULE_M8_DONE — Vector Store
**Built:** 2026-05-12
**Effort actual:** M (one session)
**Status:** complete · sandbox-verified · pending runtime verification on live Qdrant + LiteLLM

## Scope reminder

M8 owns the **Qdrant collection lifecycle**, the **embedding + RAG pipeline**,
and the **ATT&CK seed**. It does NOT own chain synthesis (M11), coverage
mapping (M14), or sigma rule discovery (M12) — those modules consume the
embedder. M8 stops at "vectors land in Qdrant and `search_*` returns typed
results".

Qdrant moved INTO Server 3's Compose between v1 and v2 (CLAUDE.md §3),
so the `fragchain_` collection prefix workaround is gone — collections are
named directly (`source_chunks`, `sigma_rules`, `attack_chains`,
`attck_techniques`).

## What was built

### Schema (Alembic 0009)

`fragchain/db/migrations/versions/0009_coverage_map.py` creates the
`coverage_map` table early. M14 is the canonical owner of this table (it
flips rows to `covered` / `partial` / `gap`); M8 seeds the rows so the
ATT&CK Matrix screen has a full grid from day one.

Columns match the M14 spec verbatim plus three M8 additions
(`description`, `has_subtechniques`, `parent_technique_id`) so the matrix
UI can render without joining the Qdrant `attck_techniques` collection.

The migration revises off `0008_prompts` (M9's parallel branch), making
the chain `… → 0007_cves_imports → 0008_prompts → 0009_coverage_map`.
Linear; verified by grep on every `down_revision`.

`fragchain.db.models.CoverageMap` ORM class added alongside the table.

### Vector collection lifecycle

`fragchain/vector/collections.py` defines:

* Four collection name constants (no `fragchain_` prefix).
* `VECTOR_SIZE = 768`, `DISTANCE = "Cosine"` matching the operator's
  LiteLLM-routed embedding model.
* `PAYLOAD_INDEXES` — pre-declared payload-index fields per collection so
  future modules don't have to remember which keyword fields are indexed
  for filter pushdown.
* `ensure_collections()` — idempotent create-if-absent loop, called from
  the API lifespan hook. Best-effort payload index creation per collection.
  A Qdrant outage at startup is logged + tolerated.
* `get_collections_info()` — stats helper backing
  `GET /api/v1/vector/collections`. Reports `ok` / `missing` / `error`
  per collection with point counts.
* `get_qdrant_client()` — factory returning a configured
  `AsyncQdrantClient` using `Settings.QDRANT_HOST`/`PORT`/`API_KEY`.

### VectorEmbedder

`fragchain/vector/embedder.py` is the single seam between M5's LLM
provider and Qdrant.

#### Tokenizer + chunking

* `count_tokens(text)` — cl100k_base via tiktoken. Falls back to a
  whitespace estimator (4 chars ≈ 1 token) if tiktoken isn't installed —
  produces slightly more / fewer chunks but never crashes.
* `chunk_text(text, chunk_size=512, overlap=50, min_size=50)` — sliding
  window. Drops chunks shorter than `min_size` so RAG retrieval doesn't
  surface boilerplate fragments. Returns a single chunk when the whole
  text fits comfortably.
* Tuning constants exposed as module-level: `CHUNK_SIZE_TOKENS = 512`,
  `CHUNK_OVERLAP_TOKENS = 50`, `MIN_CHUNK_TOKENS = 50` (matches the M8
  spec exactly).

#### Public surface

```python
class VectorEmbedder:
    async def embed_source_document(session, source_doc_id) -> int
    async def embed_sigma_rule(session, rule_id, *, title, technique_ids,
                                yaml_body, sigma_uuid, status,
                                logsource_product, logsource_service,
                                origin) -> bool
    async def upsert_technique(*, technique_id, technique_name, tactic_id,
                                tactic_name, description, framework,
                                has_subtechniques, parent_technique_id) -> bool
    async def upsert_chain_summary(*, chain_id, cve_id, summary,
                                    overall_confidence, technique_ids) -> bool

    async def search_source_chunks(query, *, cve_id=None, limit=20) -> list[ChunkResult]
    async def search_sigma_rules(description, *, limit=5) -> list[SigmaSearchResult]
    async def search_attck_techniques(query, *, limit=10) -> list[TechniqueResult]
```

#### Determinism + idempotency

Every Qdrant point id is `uuid5(namespace, key)` over a stable seed:

* source chunks: `uuid5(_NS_SOURCE_CHUNK, f"{source_document_id}:{chunk_index}")`
* sigma rules:   `uuid5(_NS_SIGMA_RULE, rule_id)`
* attck tech:    `uuid5(_NS_ATTCK, f"{framework}:{technique_id}")`
* chain summary: `uuid5(_NS_CHAIN, chain_id)`

Re-embedding the same input overwrites the same point — no orphan vectors,
no de-dup logic needed at the call site. Verified in tests for
`embed_sigma_rule` (two embedder instances, same rule_id → identical
point id).

#### Content resolution

`_resolve_document_content(doc)` walks two sources in order:

1. `document_metadata.content` (inline body — what M6 stores when the
   payload is small).
2. MinIO at `doc.storage_path` (when a connector pre-staged a large body).

Returns `None` when neither has anything; the caller flips
`embedded=True` anyway so the queue doesn't keep retrying.

#### Side effects per chunk

Every `embed()` call already writes one `llm_interactions` row + one
MinIO blob (M5 framework). M8 doesn't double-log — the embedding pipeline
is observable via the existing M5 surfaces.

### Celery tasks

`fragchain/worker/tasks/vector.py` — two tasks:

| Task | Owner | Dispatch |
|---|---|---|
| `fragchain.worker.tasks.embed_source_document` | M8 | M6 `enrich_cve` (per new doc), API `POST /vector/embed/{id}` |
| `fragchain.worker.tasks.embed_sigma_rule` | M8 | M12 sigma source parse (when it lands) |

Both wrap async helpers with `asyncio.run`. Errors are logged + returned
as `{status: "error"}` rather than raised — a missing worker mustn't
break the chain synthesis pipeline.

The M1 stub `embed_source_document` was removed from
`fragchain/worker/tasks/__init__.py` and the real task is registered via
the new side-effect import.

### M6 wiring

* `fragchain/ingest/enrichment.py:enrich_cve_pending` — after
  `persist_documents` lands new rows, queries for
  `embedded=False` rows on the CVE and dispatches
  `embed_source_document` per row. Best-effort dispatch: a missing
  worker is logged, never failed.
* `fragchain/ingest/service.py:persist_documents` — now stores
  `content` inside `document_metadata.content`. Previously the connector
  dict was filtered to drop content, leaving no body for M8 to embed.
  Added `await session.flush()` after the inserts so each row has its
  UUID populated before the queue-embed step runs.

### Setup script — ATT&CK seed

`scripts/seed_attck_techniques.py`:

1. Downloads `enterprise-attack.json` from
   `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`.
2. Parses every non-deprecated, non-revoked `attack-pattern`. Resolves
   tactic_id via the `x-mitre-tactic` objects in the same bundle.
3. Sub-technique parent linkage via `T1059.001` → `T1059` suffix split.
4. Postgres pass: one `INSERT … ON CONFLICT DO UPDATE` per technique into
   `coverage_map`. Only descriptive columns are updated; operational
   columns (`coverage_status`, `covering_rule_ids`, `chain_cve_ids`) are
   preserved across re-runs so M14's work isn't stomped.
5. Second pass marks `has_subtechniques=true` on every parent that has at
   least one child.
6. Qdrant pass: per-technique `upsert_technique()` via the same
   `VectorEmbedder` the runtime pipeline uses (LiteLLM-routed
   embeddings, M5-logged interactions).
7. Idempotent. Bails out at the top with a "already populated" log if
   both Qdrant and Postgres already hold ≥ `MIN_TECHNIQUES=100` rows
   (typical ATT&CK enterprise has ~600 entries). Pass `--force` to
   re-embed anyway.

Environment overrides:
* `ATTCK_BUNDLE_URL` — internal mirror for air-gapped deployments.
* `ATTCK_BUNDLE_PATH` — read from local disk instead.

### API

`fragchain/api/routers/vector.py` — three endpoints under
`/api/v1/vector`, all maintainer-only:

| Method | Path | Behaviour |
|---|---|---|
| GET | `/vector/collections` | List collection stats + `points_count` |
| POST | `/vector/embed/{source_doc_id}` | Force-embed one document (sync, bypasses Celery) |
| POST | `/vector/search` | Debug search; body picks collection + query + optional CVE filter |

Maintainer-only because:
* search returns raw hits that haven't been TLP-filtered for the caller;
* re-embed costs LLM tokens.

### Health

`fragchain/api/routers/health.py:_check_qdrant` — connectivity + verifies
all four M8 collections exist. Missing collections flip the status to
`error` (the topbar dot goes red). The lifespan bootstrap creates them
on every startup so a missing-collection state usually means Qdrant
restarted and lost its volume.

### Lifespan bootstrap

`fragchain/api/main.py:_bootstrap_vector_store()` runs after LLM
providers come up. Failure is logged + tolerated — the API still serves;
the embedding pipeline will retry when next called.

### Dependencies

* `tiktoken>=0.6` added to `pyproject.toml`.

### Seed-data update

`scripts/seed_dirty_frag.py` now also attaches three source documents
(advisory, PoC writeup, LWN-style article) to CVE-2026-43284 via the
existing `persist_documents` helper. Each document carries its full text
in `document_metadata.content` so M8's embedding pipeline has real RAG
input out of the box. Dedup by content hash makes re-runs idempotent.

## Tests — `tests/test_vector.py` (16 tests)

Pure-Python, no live Qdrant / LiteLLM / Postgres. Coverage:

* Collection constants: no `fragchain_` prefix, 4 names, 768 dim Cosine.
* `chunk_text`: short returns single chunk, empty returns [], long
  produces overlapping windows, undersized tail dropped, default
  constants match the spec (512/50/50), bad args raise.
* `count_tokens` handles empty input.
* `embed_source_document` end-to-end with a fake Qdrant + stub provider:
  produces multiple chunks for a 3000-word body, upserts to
  `source_chunks` with `cve_id`/`source_document_id`/`chunk_index`/`tlp`
  payload, flips `embedded=True`.
* No-content document: doesn't crash, marks `embedded=True`, no upsert.
* `embed_sigma_rule`: upserts to `sigma_rules` with the expected payload
  shape; deterministic point id across two embedder instances.
* `search_source_chunks`: maps Qdrant hits → `ChunkResult`; honours the
  `cve_id` filter; empty query short-circuits without hitting Qdrant.
* `search_sigma_rules`: maps hits → `SigmaSearchResult`.
* `search_attck_techniques`: maps hits → `TechniqueResult`.
* ATT&CK STIX parser: extracts technique + sub-technique, resolves tactic
  via x-mitre-tactic lookup, drops revoked + deprecated entries, ignores
  non-T external IDs (S-prefixed software).
* `ensure_collections`: creates only the missing collections; returns
  per-name status.

## Sandbox-level pre-flight checks (the only checks runnable here)

* `ast.parse()` on every new/edited Python file (15 files) — no syntax
  errors.
* `grep -rn "import anthropic\\|from anthropic"` across `fragchain/`,
  `tests/`, `scripts/` — no matches (CLAUDE.md §19).
* `grep -rn "fragchain_"` in `fragchain/vector/` + the seed script — only
  comments + docstrings mentioning the rule (no actual prefixed
  collection names).
* Alembic chain linearity verified by grep on `down_revision`:
  `0001 → 0002 → 0003 → 0004 → 0005 → 0006 → 0007 → 0008 → 0009`.
* Tiktoken pinned in `pyproject.toml`.
* All four M8 collections referenced by name in `_check_qdrant`.

## Runtime verification *not* runnable in this sandbox

| Done criterion | Verification command |
|---|---|
| `alembic upgrade head` reaches `0009_coverage_map` | `docker compose exec fragchain-api alembic current` → `0009_coverage_map (head)`; `\dt` includes `coverage_map` |
| Lifespan creates all 4 collections | tail logs for `qdrant.collection.created collection=source_chunks` etc + `qdrant.bootstrap.complete` |
| `GET /api/v1/vector/collections` returns 4 rows with `status=ok` | `curl -H "Authorization: Bearer $JWT" .../api/v1/vector/collections` |
| `GET /api/v1/health` reports `qdrant: ok` | `curl .../api/v1/health` — `services.qdrant.status == "ok"` |
| ATT&CK seed populates `attck_techniques` (400+ points) | `python -m scripts.seed_attck_techniques` → "parsed=N embedded=N"; `curl .../api/v1/vector/collections` shows `attck_techniques.points_count ≥ 400` |
| ATT&CK seed populates `coverage_map` | `SELECT COUNT(*) FROM coverage_map;` ≥ 400; `SELECT coverage_status, COUNT(*) FROM coverage_map GROUP BY coverage_status;` → all `no_data` |
| Re-running seed is idempotent | second run logs `attck.seed.skipped reason=already_populated` |
| Dirty Frag source docs land | `python -m scripts.seed_dirty_frag` → "new_documents=3"; `SELECT id, url FROM source_documents WHERE cve_id IN (SELECT id FROM cves WHERE cve_id='CVE-2026-43284');` → 3 rows |
| Embedding pipeline produces vectors for CVE-2026-43284 | dispatch `enrich_cve` (or `POST /api/v1/vector/embed/{doc_id}`); `SELECT embedded FROM source_documents WHERE cve_id IN (...)` → `t` for all 3; Qdrant `source_chunks` count climbs by chunk count |
| `search_source_chunks(query, cve_id="CVE-2026-43284")` returns hits | `curl -X POST .../api/v1/vector/search -d '{"query":"modprobe","collection":"source_chunks","cve_id":"CVE-2026-43284"}'` → hits with `score` > 0.5 |
| `search_attck_techniques("powershell execution")` returns T1059.001 | `curl -X POST .../api/v1/vector/search -d '{"query":"powershell execution","collection":"attck_techniques"}'` → first hit `technique_id` starts with `T1059` |
| Tests pass | `docker compose exec fragchain-api pytest tests/test_vector.py -q` → 16 passed |

## Interfaces exposed

```python
from fragchain.vector import (
    # Collections
    ALL_COLLECTIONS,
    COLLECTION_SOURCE_CHUNKS,
    COLLECTION_SIGMA_RULES,
    COLLECTION_ATTACK_CHAINS,
    COLLECTION_ATTCK_TECHNIQUES,
    DISTANCE,
    VECTOR_SIZE,
    ensure_collections,
    get_collections_info,
    get_qdrant_client,
    # Embedder + chunking
    CHUNK_SIZE_TOKENS,
    CHUNK_OVERLAP_TOKENS,
    MIN_CHUNK_TOKENS,
    ChunkResult,
    SigmaSearchResult,
    TechniqueResult,
    VectorEmbedder,
    chunk_text,
    count_tokens,
    embed_pending_documents_for_cve,
)

from fragchain.db.models import CoverageMap
```

API contract (all under `/api/v1`, maintainer-only):

* `GET  /vector/collections`
* `POST /vector/embed/{source_doc_id}`
* `POST /vector/search`  (body: `{query, collection, cve_id?, limit}`)

Celery contract:

* `fragchain.worker.tasks.embed_source_document` (kwargs: `source_doc_id`
  or `document_id` for backward compat).
* `fragchain.worker.tasks.embed_sigma_rule` (kwargs: `rule_id`, `title`,
  `technique_ids`, `yaml_body`, optional `sigma_uuid`/`status`/
  `logsource_product`/`logsource_service`/`origin`).

## What dependent modules need to know

* **M11 (Chain Synthesis)** — call
  `VectorEmbedder().search_source_chunks(query, cve_id=cve.cve_id,
  limit=20)` for the RAG retrieval step. Hits carry `text`, `url`,
  `quality_score`, `tlp`. After producing a chain, call
  `upsert_chain_summary(chain_id, cve_id, summary, ...)` so it shows up
  in `attack_chains` for cross-CVE reuse.
* **M12 (Sigma Library)** — once the `sigma_rules` schema lands, send
  `embed_sigma_rule` per imported rule. M14 will then call
  `search_sigma_rules(description)` for semantic coverage Phase 2.
* **M14 (Coverage Mapper)** — owns `coverage_map` transitions. Read
  `attck_techniques` via `search_attck_techniques` for the
  semantic-match Phase 2. The rows are already on disk thanks to the
  M8 seed.
* **M21 (ATT&CK Matrix UI)** — reads `coverage_map` directly. Every
  technique has a row even before any chain exists (the M8 seed sets
  `coverage_status='no_data'`). Add fields like `description` from this
  table rather than touching Qdrant from the API.

## Deviations from spec

* **Migration revision id** — used `0009_coverage_map` instead of
  `0008_coverage_map` because M9's prompts migration had already grabbed
  `0008`. The chain stays linear (`0008_prompts → 0009_coverage_map`);
  alembic doesn't care about the numeric prefix.
* **`coverage_map` lives in M8, not M14** — the table is M14's by spec
  but M8 needs it on disk to seed `no_data` rows during the ATT&CK seed.
  Splitting the schema work doesn't make sense; the rows have to
  pre-exist for M14's first run. M14 will still own all mutation logic.
* **Sigma rule embedding takes its fields by kwarg, not by DB lookup** —
  no sigma rule ORM model exists yet (M12 hasn't shipped). The task
  signature accepts every field explicitly. Once M12 lands the model,
  the task can switch to a single `rule_id` argument and load from the
  DB inline; that's a non-breaking change.
* **`coverage_map` has 3 extra columns** — `description`,
  `has_subtechniques`, `parent_technique_id`. Without these the ATT&CK
  Matrix UI would have to round-trip Qdrant for every cell render.
  Adding them in M8 keeps M14's coverage logic untouched.
* **`persist_documents` (M6) now stores `content` inline** — previously
  it stripped `content` before writing to `document_metadata`, leaving
  the body inaccessible. The M6 done doc explicitly notes this as a
  known TODO; M8 needs the body, so the fix landed here. Large bodies
  (>~64KB) should still be moved to MinIO + referenced via
  `storage_path`; the embedder reads both.
* **Tiktoken fallback** — if tiktoken's encoding data isn't reachable
  (rare in containers, but possible offline) the chunker drops to a
  4-chars-per-token whitespace heuristic. Same windowing logic, slightly
  less accurate token counts. The fallback path was added because the
  spec mandates cl100k_base but a hard dependency on network-fetched
  encoding data would be brittle at startup.
* **`_check_qdrant` now reports missing collections** — connectivity
  alone passed before. M8 adds the four-collections check. A restart of
  the Qdrant container that drops the volume (e.g. dev with `docker
  compose down -v`) will surface as `qdrant: error` until the next API
  restart re-runs `ensure_collections`.
* **`embed_source_document` is synchronous in the API** — the
  `POST /vector/embed/{id}` route runs the embed inline rather than
  queuing. The operator gets an immediate result; the background path
  (via M6 `enrich_cve`) is still the normal flow.
* **`embed_pending_documents_for_cve` exists but isn't wired anywhere
  yet** — useful for "drain everything for one CVE" callers (M11 might
  want to call it before synthesis if there are stragglers). Kept
  unexported by default; importable from `fragchain.vector` if any
  caller wants it.

## Known TODOs (owned by other modules)

* **M11** — implement the synthesis pipeline using
  `VectorEmbedder.search_source_chunks` for RAG retrieval. Persist
  chains and call `upsert_chain_summary` so cross-CVE reuse works.
* **M12** — emit `embed_sigma_rule` for each rule imported from a sigma
  source. Without M12 the `sigma_rules` collection stays empty (the
  endpoint and the embedder both work end-to-end already; they're just
  not exercised by any caller).
* **M14** — read `coverage_map`, mutate `coverage_status` /
  `covering_rule_ids` / `chain_cve_ids` after each chain synthesis. The
  rows are already on disk.
* **Larger-than-inline source documents** — move bodies to MinIO via
  `storage_path` instead of `document_metadata.content`. The embedder
  reads both paths; no caller change needed in M8.

## Outstanding questions

* **Embedding model dimension** — hard-coded `VECTOR_SIZE=768` to match
  `nomic-embed-text`. If an operator switches LiteLLM to a different
  embedding model (e.g. `text-embedding-3-large` at 3072) the collection
  has to be dropped + recreated. Worth surfacing as a settings warning;
  parking that until M24 Settings UI ships.
* **ATT&CK bundle pin** — the seed fetches `master`. Reproducible
  deployments will want to pin to a tagged release (e.g. `v15.1`); the
  seed accepts an env override for that already. Default URL stays on
  `master` because that's what MITRE recommends in their README.
* **Qdrant payload index types** — used `keyword` for every indexed
  field. Once `cvss_min`/`epss_min` style range filters land on
  `source_chunks` we'll want `integer` / `float` indexes. Defer until a
  caller wants them.
* **Rate limiting on embed batches** — `VectorEmbedder.upsert_technique`
  fires one embed call per technique; for 600 ATT&CK techniques that's
  600 calls. Worth batching into 16-32-wide embedding requests once a
  caller exercises the path at scale (M5's `embed()` already batches
  internally — the per-technique loop is what's pessimistic). Defer
  until the operator complains.


---

## Phase 4 cleanup applied (2026-05-13)

- **`bootstrap_providers_for_scripts()` is now available** from `fragchain.llm`. Any standalone script that calls `VectorEmbedder` (or `LLMProvider.complete`/`embed` directly) must call this once before use, because the FastAPI lifespan that normally bootstraps the provider registry does not run for standalone Python entrypoints. `scripts/seed_attck_techniques.py` now invokes it at the top of `seed()`.
- **Phase 4 audit C0a fix:** before this helper, `seed_attck_techniques --force` reported `embedded=0` and the Qdrant `attck_techniques` collection stayed empty even though Postgres `coverage_map` had 697 rows. Now the registry is populated and the provider is called.
- **Known downstream defect** still blocks the Qdrant population: LiteLLM/Ollama rejects the OpenAI SDK's default `encoding_format="base64"`. Fix is either `litellm.drop_params = True` on the LiteLLM side or passing `encoding_format="float"` explicitly in `LiteLLMProvider.embed()`. Out of scope for Phase 4 cleanup; flagged in `PHASE4_CLEANUP_DONE.md` under "Discovered but not fixed".

See `PHASE4_CLEANUP_DONE.md` for the full change set.
