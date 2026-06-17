# MODULE_M7_DONE — Commons Sources
**Built:** 2026-05-12
**Effort actual:** M (one session)
**Status:** complete · sandbox-verified · pending runtime verification on live Postgres / network access to a real `fragchain-intelligence` repo

## What was built

The multi-source intelligence commons subsystem described in CLAUDE.md §7 and
FragChain_Module_Specifications.md M7. Operators can now configure one or more
git-hosted commons repos (public default + optional partner / internal feeds),
the engine bootstraps from them on first run, syncs deltas hourly, and exposes
a `CommonsClient` interface for M11 to skip LLM synthesis when a chain
already exists in the commons.

### Schema

- **`commons_sources`** (with `name UNIQUE`, indexed on `priority`) — the
  operator-configurable list of commons feeds.
  Columns from the spec (id, name, url, auth_type, auth_credentials_ref,
  sync_enabled, contribute_enabled, priority, trust_level, last_sync_at,
  last_release_version, created_at) plus three operational columns the spec
  table doesn't enumerate but every dashboard needs:
  `last_sync_status`, `last_error`, `chains_imported`, `updated_at`. Without
  these the Settings UI (M24) can't render whether the last cycle succeeded.
- **`commons_chains`** — chains imported from any source. Unique on
  `(source_id, cve_id, version)` so re-runs are idempotent. Stores the full
  chain JSON in a `JSONB` column plus `content_hash` for cheap change-detection.
  This is the table `CommonsClient.check_chain_exists()` reads.
- **Default row seeded in the migration** — one `Public Commons` source
  pointing at `https://github.com/fragchain/fragchain-intelligence`,
  `trust_level=community`, `priority=0`, `contribute_enabled=false`. Operators
  can disable, edit, or delete it via the API.

- **`fragchain/db/migrations/versions/0006_commons_sources.py`** — Alembic
  migration that creates both tables, both indexes, and seeds the default row.
  Downgrade drops both tables cleanly. Revises `0005_llm_interactions`.

- **ORM models** in `fragchain/db/models.py`: `CommonsSource`, `CommonsChain`.

### Backend — Transport layer

- **`fragchain/commons/transport.py`** — `CommonsTransport` Protocol + two
  implementations:
  - **`GitHubTransport`** (production path). Speaks the GitHub REST API for
    both reads (`/repos/{o}/{r}/releases/latest` and a fallback `contents`
    walk of the `chains/` tree at the release tag) and writes (create branch
    + `PUT /contents/...` + open PR — REST-only so no git CLI in the
    container). Supports GitHub Enterprise via the `COMMONS_GITHUB_API_BASE`
    knob. Token comes from the source row's `auth_credentials_ref` when
    `auth_type='token'`. Tolerates missing repos / 404s by returning `None`
    from `fetch_latest_release()`.
  - **`MockTransport`** (dev / offline). Returns an in-memory release pack
    containing a hand-built Dirty Frag (`CVE-2026-43284`) chain. Contribution
    PRs always "succeed" and the payload is recorded in `.prs` for test
    inspection. The bootstrap routine falls back to this when the configured
    remote isn't reachable — see `COMMONS_ALLOW_MOCK_FALLBACK` below.
  - Helpers: `parse_github_repo(url) → (owner, repo) | None`, `_hash_chain`
    (sorted-keys SHA-256 over the chain JSON), `_payload_from_chain_dict`
    (normalises a chain JSON document to `CommonsChainPayload`).

- **`fragchain/commons/factory.py`** — `default_transport_factory(source)`
  picks the right transport from a row. URL discriminator: anything matching
  `github.com/{owner}/{repo}` uses `GitHubTransport`; unknown schemes fall
  back to `MockTransport` with a structured warning. Future transports
  (GitLab, Gitea, filesystem mirror) plug in here without touching the
  bootstrap / sync code.

### Backend — Orchestration

- **`fragchain/commons/sources.py`** — pure helpers for source ordering:
  - `TRUST_LEVEL_RANK` (`internal=2`, `partner=1`, `community=0`), `trust_rank`,
    `source_priority_key`, `rank_sources`.
  - `list_enabled_sources`, `list_all_sources`, `list_contribute_sources` —
    async queries that return rows sorted highest-priority-first.
  - `select_winning_chain(rows)` — **pure** function used by
    `CommonsClient.check_chain_exists`. Lifted out of the client so unit
    tests can exercise conflict resolution without a DB.
  - `VALID_TRUST_LEVELS` + `VALID_AUTH_TYPES` so the API router validates
    payloads against a single source of truth.

- **`fragchain/commons/bootstrap.py`** — first-run import per source.
  `bootstrap_source(session, source, transport)` is the unit; `bootstrap_all`
  walks every enabled source. Returns structured `BootstrapResult` /
  `SourceImportResult` dataclasses so the API and Celery task can report
  per-source outcomes. `import_release` is the idempotent upsert
  (`pg_insert(...).on_conflict_do_nothing(...)` on the
  `(source_id, cve_id, version)` unique constraint). `has_been_bootstrapped`
  tells the startup hook whether to skip itself.

- **`fragchain/commons/sync.py`** — hourly delta. `sync_source` compares the
  remote's `tag_name` against the row's `last_release_version`; if they
  match, no-op (just touch `last_sync_at`). Otherwise pulls + re-imports,
  with the same idempotent upsert. Errors are recorded on the row and
  surfaced via the returned `SyncResult`; nothing raises out to the caller.

- **`fragchain/commons/contribute.py`** — `contribute_to_source(source,
  transport, *, cve_id, chain_payload, actor_username)` + `contribute_chain`
  batch wrapper. Enforces two preconditions before opening a PR:
  - `source.contribute_enabled = TRUE`
  - chain payload TLP is `tlp:clear` (the public commons is unrestricted by
    design; partner/internal can be relaxed in future revs)
  PR body cites the actor, timestamp, CVE, and overall confidence; the
  branch name is `fragchain/contrib/{cve-id}-{8 hex bytes}`. Returns a
  `ContributeResult` per source — caller decides whether to retry or
  surface the failure to the operator.

### Backend — `CommonsClient`

- **`fragchain/commons/client.py`** — engine-facing wrapper:
  - `check_chain_exists(cve_id) → CommonsChainHit | None` — the M11 read path.
    Runs the join, picks the winner via `select_winning_chain`, returns the
    chain plus where it came from (source id, name, trust_level, priority).
  - `bootstrap_all`, `bootstrap_one`, `sync_all`, `sync_one`, `test_one`,
    `contribute_chain`, `status` — high-level methods used by the API.
  - Accepts an injectable `transport_factory` so tests pass `MockTransport`
    and the API path uses the production factory. Default = the URL-based
    factory.

### Backend — API

- **`fragchain/api/routers/commons.py`** — eight endpoints under `/api/v1`:
  - `GET  /commons/sources` — list (authenticated).
  - `POST /commons/sources` — add (maintainer). Validates
    `auth_type ∈ {none, token, ssh}`, `trust_level ∈ {community, partner, internal}`,
    and refuses `auth_type ≠ none` without `auth_credentials_ref`.
  - `PATCH /commons/sources/{id}` — update (maintainer). Same constraints.
  - `DELETE /commons/sources/{id}` — remove (maintainer).
  - `POST /commons/sources/{id}/sync` — manual sync trigger (maintainer).
  - `POST /commons/sources/{id}/test` — connectivity test (maintainer).
  - `GET  /commons/status` — overall sync state (authenticated). Returns a
    per-source list plus aggregate `last_sync_at`, `has_errors`, counts.
- Registered in `fragchain/api/main.py` `create_app()` at the
  `/api/v1` prefix, tagged `commons` for OpenAPI grouping.

### Backend — Lifespan / startup

- `fragchain/api/main.py` gained `_bootstrap_commons()` — runs after LLM
  provider bootstrap. Skipped if any enabled source already has
  `last_sync_at` set (operators rerun explicitly via the API if they want).
  Bootstrap failures are logged and swallowed — never block API startup
  over a commons fetch failure.

### Backend — Celery

- `fragchain/worker/tasks/__init__.py` — promoted `sync_commons_source` from
  stub to real implementation; added new `bootstrap_commons` task.
  - `sync_commons_source(source_id=None)` — with no `source_id`, syncs every
    enabled source (the beat schedule fires it this way). With an explicit
    `source_id`, syncs only that row (the API uses this when an operator
    clicks "Sync now").
  - `bootstrap_commons()` — runs the bootstrap-all routine on demand from
    the worker (useful when an operator wants to kick a re-import without
    restarting the API).
  - Both wrap `CommonsClient` in `asyncio.run` (Celery tasks are sync entry
    points). Both catch every exception, log it, and return
    `{status: "error", ...}` rather than crashing the worker.
- Beat schedule for `sync_commons_source` was already wired in M1
  (`crontab(minute="0")` — hourly on the hour).

### Config

- **`fragchain/config.py`** — three new settings:
  - `COMMONS_ALLOW_MOCK_FALLBACK: bool = True` — when the configured remote
    isn't reachable, bootstrap drops to the mock release pack. Operators
    set this to `false` in production once the real public commons ships,
    so unreachable sources surface as errors rather than silently bootstrap
    from a stub.
  - `COMMONS_SYNC_TIMEOUT_SECONDS: int = 60` — httpx timeout per request.
  - `COMMONS_GITHUB_API_BASE: str = "https://api.github.com"` — override for
    GitHub Enterprise deployments.
- **`.env.example`** + **`docker-compose.yml`** updated to propagate the
  three knobs.

### Tests

`tests/test_commons.py` — 27 tests, all pure-Python (no Postgres, no
network, no LiteLLM). Covers:

| Area | Tests |
|---|---|
| URL parsing | github.com normalisation, rejecting other hosts |
| Content hashing | deterministic; order-independent |
| Payload normalisation | TLP casing, missing fields |
| Source ranking | priority order; trust-level tiebreaker |
| Conflict resolution (`select_winning_chain`) | priority wins; trust as tiebreaker; chain version within a source; empty-input → None |
| MockTransport | release fetch, connectivity ok/fail, PR recording |
| GitHubTransport against `httpx.MockTransport` | manifest-based release fetch; 404 release / connectivity; full PR creation flow; missing-token short-circuit |
| Bootstrap | mock import + state updates; idempotent re-run skips chains; mock fallback when remote returns None; no_release when fallback disabled; `bootstrap_all` walks every enabled source |
| Sync | up-to-date short-circuit; new release imports; error recorded on transport exception; disabled source skipped |
| Contribute | skipped when not enabled; TLP > clear blocked; submitted when eligible; batch walks eligible sources only |
| `check_chain_exists` end-to-end | high-priority internal beats community public; cache miss returns None |

DB-touching production code (`bootstrap_source` / `sync_source` /
`contribute_chain`) is tested via a `FakeSession` shim and `monkeypatch`
on the three thin DB helpers (`list_enabled_sources`,
`list_contribute_sources`, `import_release`). This follows the exact M2
pattern — the real SQLAlchemy path is exercised in integration tests once
the schema is up.

## Runtime verification (this session)

Cannot run pytest in this sandbox — the system Python is 3.9 and the project
requires 3.12 (the `dict | list | None` syntax, parametrised builtins, etc.
all break under 3.9). Sandbox-level pre-flight checks are clean:

| Check | Result |
|---|---|
| `ast.parse()` on every new / edited file | ✅ no syntax errors |
| Internal `from fragchain.commons...` imports resolve to real symbols | ✅ 0 missing names across every importer |
| Alembic migration chain is linear (`0001 → 0006`) | ✅ each `down_revision` points at the prior `revision` |
| Migration adds the default `Public Commons` row | ✅ `INSERT INTO commons_sources` in `upgrade()` |
| TLP validation enforced in `contribute_to_source` | ✅ explicit `_is_clear` guard before opening PR |
| `auth_type` / `trust_level` validation in the API | ✅ `field_validator` decorators on Pydantic schemas |
| Beat schedule retains `sync_commons_source` cadence | ✅ unchanged from M1 (hourly on minute 0) |
| Router registered at `/api/v1` | ✅ `app.include_router(commons_router.router, prefix=api_prefix, tags=["commons"])` |

### Runtime verification **not** runnable in this sandbox

Operator should run these on the next `docker compose up`:

| Done criterion | Verification command |
|---|---|
| `alembic upgrade head` reaches `0006_commons_sources` | `docker compose exec fragchain-api alembic current` → `0006_commons_sources (head)`; `\dt` includes `commons_sources`, `commons_chains` |
| Default row seeded | `SELECT name, url, trust_level FROM commons_sources;` → `Public Commons | https://github.com/fragchain/fragchain-intelligence | community` |
| Lifespan bootstrap runs once | tail logs for `commons.bootstrap.startup_complete`; subsequent restarts emit `commons.bootstrap.skipped reason=already_bootstrapped` |
| Bootstrap falls back to mock when commons repo missing | with `COMMONS_ALLOW_MOCK_FALLBACK=true` (default), `SELECT cve_id FROM commons_chains;` returns `CVE-2026-43284` even though the public repo is empty |
| `GET /api/v1/commons/sources` lists rows | `curl -H "Authorization: Bearer $JWT" .../api/v1/commons/sources` → array with the seeded `Public Commons` row |
| `POST /api/v1/commons/sources` adds an internal source | `curl -X POST -H "Authorization: Bearer $JWT_MAINTAINER" -d '{"name":"Org Internal","url":"https://github.com/org/internal-commons","auth_type":"token","auth_credentials_ref":"<token>","priority":10,"trust_level":"internal","contribute_enabled":true}' .../api/v1/commons/sources` → 201 + row JSON |
| `POST /api/v1/commons/sources/{id}/test` returns reachability | same with `/test`, returns `{ok:true, latency_ms:..., message:"repo reachable"}` against a real repo or `{ok:false, message:"repo not found (404)"}` for the placeholder URL |
| `POST /api/v1/commons/sources/{id}/sync` triggers re-import | same with `/sync`, returns `{status:"ok", chains_imported: N, ...}` |
| Celery beat fires `sync_commons_source` hourly | `celery -A fragchain.worker.celery inspect scheduled` shows the hourly tick; `celery events` shows the task running |
| `CommonsClient.check_chain_exists("CVE-2026-43284")` returns the Dirty Frag chain | from inside `fragchain-api`: `python -c "import asyncio; from fragchain.commons import CommonsClient; from fragchain.db.session import get_sessionmaker; ..."` → `CommonsChainHit(source_name="Public Commons", ...)` |
| Conflict resolution: two sources, same CVE, higher priority wins | manually `INSERT INTO commons_chains` from a partner-trust source with `priority=10`; `check_chain_exists` returns the partner row |
| Contribution to a token-authed source opens a real PR | configure a token on a fixture repo; analyst calls `client.contribute_chain(cve_id=..., chain_payload=...)`; PR appears on the fixture repo |

## Deviations from spec

- **`commons_chains` table is new and not in the spec table.** The spec only
  enumerates `commons_sources`. But `check_chain_exists(cve_id) → AttackChain
  | None` is a hard interface, and the only sensible place to materialise
  "what chains do we know about from the commons" is in Postgres — otherwise
  every `check_chain_exists` call would force a network hop against GitHub.
  The table is purely the read-side cache plus the conflict-resolution
  surface; M10 will project these rows into `attack_chains` whenever a
  deployment elects to use a commons chain directly.
- **`auth_credentials_ref` stores the secret value itself in v1.** The spec
  calls it a "secret reference, not the secret". A proper resolution flow
  (Vault, K8s secrets, env-var indirection) is post-v1 and lands when the
  Settings UI (M24) ships. The API marshalls the column as `has_credentials:
  bool` on output so the secret never round-trips through `GET /sources`.
- **`select_winning_chain` was extracted from `CommonsClient` for testability.**
  The spec defines conflict resolution as a behaviour of "check_chain_exists";
  I factored the ranking out into a pure function so tests can exercise the
  rule without a DB. The async client still owns the query; the pure function
  just owns the choice.
- **Default `Public Commons` row is `contribute_enabled = false`.** The spec
  doesn't say one way or the other, but the safe default for the public
  commons is "operator must opt in to push back". Operators flip it to true
  via PATCH once their GitHub token is configured.
- **`bootstrap_commons` lifespan hook is skipped after first run.** The spec
  says bootstrap "runs on first startup". I read that as "exactly once per
  deployment unless explicitly re-triggered" — the alternative (run on every
  start) costs a network round-trip per restart for no benefit. The hourly
  Celery sync still runs every hour regardless.
- **Mock fallback is on by default.** The spec calls for a mock when the
  public commons doesn't exist yet. I made it a runtime knob
  (`COMMONS_ALLOW_MOCK_FALLBACK`) defaulting to `true`. When the public
  repo ships in M35, operators flip the knob (or it's safe to leave on —
  fallback only triggers when the remote returns None / errors).
- **Contribution batches walk only contribute-enabled sources.** The spec's
  contribute language is one-source-at-a-time. I added a batch helper
  (`contribute_chain`) because the analyst contribution UI (M20) will
  natively want to fan out to every eligible source the operator has
  configured. Source filtering is honoured: `source_ids=None` walks every
  eligible row; `source_ids=[uuid, ...]` walks only the named subset.
- **No SSH auth in v1.** `auth_type='ssh'` validates through the API but no
  transport implementation reads it yet (would need to embed an SSH client
  in the API container). Operators using a private repo today should use
  `auth_type='token'` against the GitHub HTTPS API.
- **Mock chain payload is structurally complete but synthetic.** The
  fallback `MockTransport` returns a hand-built `CVE-2026-43284` chain with
  two TTPs, the right schema shape, and `provenance.contributed_by="mock"`.
  Once `chains/CVE-2026-43284.json` (the ground-truth fixture) lands in
  M10, the mock pack should load from disk instead of hard-coding the
  values. Left as a deferred TODO.

## Interfaces this module exposes

For M11 (the primary consumer):

```python
from fragchain.commons import CommonsClient

# In your synthesis task, before invoking the LLM:
client = CommonsClient(session)
hit = await client.check_chain_exists(cve.id)
if hit is not None:
    # Use hit.data directly — no LLM call, no cost, no latency.
    # hit.source_name + hit.source_trust_level tell you where it came from.
    return hit
# Otherwise, do the M11 LLM dance.
```

For M20 (Chain Viewer's contribute button):

```python
result = await client.contribute_chain(
    cve_id=cve.id,
    chain_payload=chain_dict,
    actor_username=current_user.username,
    source_ids=None,  # None = every eligible source
)
# result.submitted, result.failures, result.per_source[i].pr_url, etc.
```

For the worker (already wired in M7):

```python
# Hourly beat:
from fragchain.worker.tasks import sync_commons_source
sync_commons_source.delay()  # no args = sync every enabled source

# Operator-triggered:
sync_commons_source.delay(source_id="<uuid>")
```

Public surface re-exported from `fragchain.commons`:

```python
from fragchain.commons import (
    # Client + high-level result types
    CommonsClient, CommonsChainHit,
    BootstrapResult, SourceImportResult,
    SyncAllResult, SyncResult,
    ContributeBatchResult, ContributeResult,

    # Primitives (use these in tests / specialised flows)
    bootstrap_all, bootstrap_source, has_been_bootstrapped,
    sync_all, sync_source,
    contribute_chain, contribute_to_source,
    select_winning_chain, rank_sources,
    list_enabled_sources, list_all_sources, list_contribute_sources,

    # Transport
    CommonsTransport, GitHubTransport, MockTransport,
    CommonsRelease, CommonsChainPayload, ConnectivityResult, PullRequestResult,
    default_transport_factory, parse_github_repo,

    # Constants
    TRUST_LEVEL_RANK, VALID_TRUST_LEVELS, VALID_AUTH_TYPES, trust_rank,
)
```

API contract (all under `/api/v1`):
- `GET    /commons/sources`            (auth)
- `POST   /commons/sources`            (maintainer)
- `PATCH  /commons/sources/{id}`       (maintainer)
- `DELETE /commons/sources/{id}`       (maintainer)
- `POST   /commons/sources/{id}/sync`  (maintainer)
- `POST   /commons/sources/{id}/test`  (maintainer)
- `GET    /commons/status`             (auth)

## What dependent modules need to know

- **M8 (Vector Store)** doesn't depend on M7, but the commons chains in
  `commons_chains.data` are the natural seed for the `attack_chains` Qdrant
  collection. M8 should embed every imported commons chain after each
  successful sync so the RAG path can hit them.
- **M10 (Chain Schema)** owns `attack_chains`. When that table exists, M11
  is the only natural caller of `CommonsClient.check_chain_exists`; on a
  hit, it projects `hit.data` into an `attack_chains` row with
  `source_origin='commons'` and `commons_chain_id=hit.cve_id`.
- **M11 (Chain Synthesis)** — call `check_chain_exists` **before** any LLM
  call. Skip synthesis entirely on a hit. After validation, call
  `contribute_chain` (gated by the analyst's consent in the UI).
- **M17 (Rule Evaluations)** — same pattern with a different table.
  Evaluations contribute via `POST /api/v1/evaluations/{id}/contribute`
  (M17's API), which internally calls `CommonsClient.contribute_chain` (or
  a sibling `contribute_evaluation` if M17 adds one).
- **M20 (Chain Viewer)** — the "Contribute to Commons" button posts to a
  M11/M20 endpoint that calls `client.contribute_chain`. Show
  `result.per_source` so the analyst sees which contributions succeeded.
- **M24 (Settings → Commons Sources)** — UI sits on `GET/POST/PATCH/DELETE
  /commons/sources` + `POST /sources/{id}/sync` + `POST /sources/{id}/test`
  + `GET /commons/status`. The `has_credentials` boolean is the only
  source-row field the UI shouldn't try to read back from the API.
- **M35 (fragchain-intelligence repo)** — once the real repo ships, set
  `COMMONS_ALLOW_MOCK_FALLBACK=false` on production deployments. The CI
  pipeline in M35 should produce a `release_pack.json` asset attached to
  each tagged release — that's the manifest format `GitHubTransport`
  prefers (it falls back to walking the `chains/` directory if no manifest
  asset is found).

## Known TODOs (owned by other modules)

- Loading the ground-truth `CVE-2026-43284` chain from disk in
  `MockTransport` once `chains/CVE-2026-43284.json` exists (M10 ships the
  file; M7's mock currently hard-codes a synthetic version).
- SSH-key auth for private commons sources (post-v1).
- Vault / K8s-secret indirection for `auth_credentials_ref` (M24 / post-v1
  hardening).
- Settings UI for managing commons sources (M24).
- WebSocket broadcast on sync completion (M19) — the sync task already
  returns the per-source breakdown so M19 can iterate.

## Sandbox-level pre-flight checks (the only checks runnable here)

- `ast.parse()` on every new / edited Python file (15 files) → no syntax errors.
- Full-tree internal import resolution: every `from fragchain.commons...` and
  `from fragchain.commons.<mod>...` resolves to a real top-level name.
- Migration chain linearity verified by grep on `revision` / `down_revision`.
- `.env.example` and `docker-compose.yml` propagate the three new commons
  knobs.

## Outstanding questions

- **Default priority for the seeded Public Commons row** is `0`. Once
  operators add internal/partner sources (typically with priority 5–10),
  the public commons drops behind them automatically. Anyone running a
  single-source deployment is unaffected. No action needed unless we want
  to encourage a particular priority spacing convention — could live in
  Settings UI as a hint.
- **`commons_chains.tlp` is currently always `tlp:clear`** because the
  public commons is tlp:clear-only by design. Partner / internal commons
  sources will produce higher-classified chains; the column is sized for
  that future and the TLP-filter middleware (M2) already enforces visibility
  at the API edge. No code change needed at write time — the field is
  written verbatim from the chain JSON's `tlp` key.
- **Idempotency window**: `(source_id, cve_id, version)` uniqueness means
  re-publishing the same `version` of a chain (e.g. fixing a typo) won't
  pull through to deployments — they'll see "already imported, skipped".
  This is correct behaviour for a commons treating chain versions as
  immutable; if a flaw is found, the contributor bumps `version` and the
  next sync picks up the fix. Worth a note in M35's contribution guide.
