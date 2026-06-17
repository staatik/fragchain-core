# MODULE_M4_DONE — Connector Framework
**Built:** 2026-05-12
**Effort actual:** M (one session)
**Status:** complete · 48/48 tests pass (18 new + 30 prior) · alembic 0004 verified up/down on Postgres 16 · live install-of-stub flow verified end-to-end against the running stack

## Scope reminder

M4 is the **framework only**. fragchain-core ships with zero hardcoded data sources and zero specific connectors — those live in their own packages (M25–M34) and register via Python entry points. This module:

1. defines the `IntelConnector` Protocol everyone implements,
2. discovers installed connector packages at startup,
3. orchestrates parallel enrichment with per-connector isolation,
4. exposes connector management over `/api/v1/connectors`,
5. persists connector state in the `connector_state` table,
6. fetches the fragchain-registry index so the UI can browse not-yet-installed connectors.

## What was built

### Protocol + dataclasses — `fragchain/connectors/base.py`
- `IntelConnector` **Protocol** (`@runtime_checkable`) with exactly the surface from CLAUDE.md §5: `name`, `version`, `type`, `output`, `requires_auth`, `rate_limit`, `max_output_tlp`, `default_output_tlp`, `supports_embargo`, `requires_verified_tier`, `description` + the six async methods (`health_check`, `initialize`, `shutdown`, `stream_new`, `get_cve`, `enrich_cve`, `bulk_enrich`).
- `ConnectorType` enum — `SOURCE_STREAM`, `ENRICHMENT`, `HYBRID`.
- `ConnectorOutput` enum — `STRUCTURED`, `DOCUMENTS`, `BOTH`.
- `HealthStatus` enum — `HEALTHY`, `DEGRADED`, `UNHEALTHY`, `UNKNOWN`.
- Dataclasses: `RateLimit`, `ConnectorHealth`, `ConnectorConfig`, `CVERecord`, `AttackPattern`, `EnrichmentResult`. Each one is the shape connector packages actually consume — kept minimal so connector packages don't need to import half the engine.

### Discovery — `fragchain/connectors/discovery.py`
- `discover_connectors()` walks the `fragchain.connectors` entry-point group via `importlib.metadata.entry_points()`, with a compatibility shim around the `select()` form.
- Failure-isolated: a broken `load()`, instantiation crash, or non-Protocol object logs and is skipped — the loader never crashes startup. Returns `[]` when no connectors are installed (the v1 baseline).
- Every successful load is logged: `connector.discovered` with `name`, `version`, `type`, `entry_point`.

### Orchestrator — `fragchain/connectors/orchestrator.py`
- `ConnectorOrchestrator` is the only thing that talks to connectors. Holds the in-memory registry, per-connector rate semaphore, sliding failure window, and the last-known health.
- `enrich_cve(cve_id, cve_data)` fans out **in parallel** via `asyncio.gather`. Each call is wrapped in `_safe_enrich`: per-connector rate semaphore → `asyncio.wait_for(timeout)` → try/except. Any exception logs `connector.enrich_failed`, records a failure timestamp, and returns `None` for that connector. **One failure never blocks the others.**
- `_SlidingWindow(window_seconds=600, threshold=3)` prunes old timestamps on every record. Crossing the threshold flips `entry.unhealthy = True` and sets a synthetic `ConnectorHealth(UNHEALTHY, "...")` so the API surfaces it. A clean `run_health_check()` clears the window and the unhealthy flag.
- `stream_new_cves(connector_name, ...)` yields from a SOURCE_STREAM connector with the same exception isolation as enrichment.
- `register()`, `unregister()`, `set_enabled()`, `update_config()`, `initialize_all()`, `shutdown_all()`, `run_health_check()`, `run_all_health_checks()`, `get_connectors(type=...)`, `sync_state_to_db()` — the surface the API router and lifespan event use.
- Process-wide singleton via `get_orchestrator()` + `reset_orchestrator()` (test hook). The lifespan event in `main.py` owns its life — created at startup, cleared at shutdown.

### Registry client — `fragchain/connectors/registry_client.py`
- `RegistryClient` fetches the fragchain-registry JSON over HTTPS (default URL `https://raw.githubusercontent.com/fragchain/fragchain-registry/main/registry.json`, overridable per-call), caches for 5 minutes, and falls back to a bundled JSON shipped under `scripts/fragchain_registry.json`. Operators can point at a `file://` URL for air-gapped deployments.
- Network or parse failure → fallback JSON. The UI must always render — the kickoff explicitly asks for a hardcoded JSON fallback for now.
- `RegistryEntry` dataclass with `from_dict` / `to_dict` round-trip. Parses the schema from FragChain_Ecosystem_Architecture.md §2.4.
- `scripts/fragchain_registry.json` ships with 12 official connector entries (opencti, nvd2, epss, ctid, kev, attackerkb, exploitdb, osssecurity, github, vendor-redhat, vendor-msrc, vendor-ubuntu) so the Settings UI has something to render on first boot.

### Schema + migration
- `ConnectorState` ORM model added to `fragchain/db/models.py` matching the spec schema exactly: `name` PK, `version`, `type`, `enabled`, `config` JSONB, `max_output_tlp`, `default_output_tlp` (default `tlp:clear`), `last_health_check`, `health_status`, `error_count` (default 0), `last_error`, `rate_limit_config` JSONB.
- **`fragchain/db/migrations/versions/0004_connector_state.py`** — `0003_identity → 0004_connector_state`. Creates the table + two indexes (`type`, `enabled`). Down-migration drops everything cleanly. Verified by running `alembic upgrade head` against the live Postgres 16 container.

### API router — `fragchain/api/routers/connectors.py`
Six endpoints, all under `/api/v1`:

| Method | Path | Auth | Behaviour |
|---|---|---|---|
| GET | `/connectors` | authenticated | List installed connectors with state + health |
| GET | `/connectors/registry` | authenticated | Browse the registry, marks already-installed entries |
| GET | `/connectors/{name}` | authenticated | Full detail including config + rate limit + last health |
| PATCH | `/connectors/{name}` | maintainer | Update connector config (JSON body `{config: {...}}`) |
| POST | `/connectors/{name}/enable` | maintainer | Flip enabled=true |
| POST | `/connectors/{name}/disable` | maintainer | Flip enabled=false |
| POST | `/connectors/{name}/health` | maintainer | Run health check now, persist to DB |

Route declaration order is `list_connectors → list_registry → get_connector`, so the literal `/connectors/registry` resolves before `/connectors/{name}` — verified with curl.

Mutating endpoints call `orchestrator.sync_state_to_db(db)` so the table stays in sync with in-memory state without any background sweep.

### Lifespan wiring — `fragchain/api/main.py`
- New `_bootstrap_connectors()` runs after the admin seed:
  1. `discover_connectors()` → instances
  2. Load existing `connector_state` rows so user-set `enabled` flags and `config` survive restarts
  3. `orch.register(c, config=...)` for each connector
  4. `orch.initialize_all()` (failure-isolated)
  5. `orch.sync_state_to_db(session)` writes the mirror
- Wrapped in try/except so a broken plugin can never take the API down.
- Shutdown event calls `orch.shutdown_all()` then `reset_orchestrator()`.

### Tests — `tests/test_connectors.py` (18 tests)
- Protocol shape check — stub class passes `isinstance(stub, IntelConnector)`.
- Dataclass surface check — `CVERecord`, `AttackPattern`, `EnrichmentResult`, `ConnectorHealth`, `ConnectorConfig`, `RateLimit` all importable and defaultable.
- `discover_connectors()` → `[]` when no entry points exist.
- Entry-point injection via monkeypatch — a stub class registered under `fragchain.connectors` is loaded.
- Broken entry point alongside a working one — the working one still loads.
- `ConnectorOrchestrator.enrich_cve(...)` runs N stubs in parallel, returns N results.
- One raising stub doesn't prevent N-1 successful results — `bad` result is `None`, others succeed.
- Timeout path: stub sleeping past the configured timeout yields `None` and increments error count.
- Three failures inside the window → `is_unhealthy` flips to `True`, `last_health.status == UNHEALTHY`.
- Two failures don't trip the threshold.
- A clean `run_health_check()` resets the failure window and clears `unhealthy`.
- Disabled connector is skipped by `enrich_cve`.
- `initialize_all` + `shutdown_all` reach every connector.
- `get_connectors(type=...)` filters correctly across SOURCE_STREAM / ENRICHMENT.
- `RegistryClient` parses bundled JSON, falls back when the URL is unreachable, and the in-memory cache survives subsequent fetches.
- The bundled `scripts/fragchain_registry.json` parses and contains the expected fields.

## Runtime verification (this session — Docker Desktop, fragchain-fragchain-api healthy)

| Done criterion | Result |
|---|---|
| `IntelConnector` Protocol importable, all methods defined | ✅ `from fragchain.connectors import IntelConnector` works; `isinstance(stub, IntelConnector)` returns True |
| `discover_connectors()` returns `[]` on clean install | ✅ live container logs `connector.discovery.empty` then `connector.bootstrap.complete loaded=0` |
| Installing a test stub package causes it to auto-register after restart | ✅ built ad-hoc `fragchain-connector-test-stub`, `pip install -e .` inside the API container, restart → logs show `connector.discovered name=test-stub`, `connector.registered`, `connector.initialized` |
| `connector_state` table reflects installed connectors | ✅ `SELECT name, version, type, enabled FROM connector_state` → one row for `test-stub` after install + restart |
| `GET /api/v1/connectors` returns the test stub | ✅ HTTP 200 with `{"connectors": [{"name": "test-stub", "version": "0.1.0", "type": "enrichment", ...}]}` |
| `GET /api/v1/connectors/{name}` returns detail + config | ✅ HTTP 200 with `rate_limit`, `config`, `last_health_check`, `last_error` |
| `PATCH /api/v1/connectors/{name}` updates config | ✅ `{"config": {"api_key": "test123", "endpoint": "..."}}` persists to DB; `SELECT config FROM connector_state` confirms |
| `POST /.../enable`, `/.../disable` flip state | ✅ verified both directions; DB column toggles |
| `POST /.../health` runs the check now | ✅ returns `{"name": "test-stub", "status": "healthy", "checked_at": "..."}`; `last_health_check` populated in DB |
| `GET /api/v1/connectors/registry` returns browseable list | ✅ HTTP 200 with 12 entries from the bundled fallback (live URL returns 404 because the public registry isn't up yet) |
| Three failures of test connector → marked unhealthy | ✅ `test_three_failures_mark_connector_unhealthy` unit test + verified via the orchestrator's `is_unhealthy`/`last_health` API |
| Orchestrator runs N connectors in parallel, returns N results even if one raises | ✅ `test_orchestrator_isolates_a_failing_connector` — `bad` returns `None`, `good1` + `good2` succeed |
| `fragchain-registry` index fetched | ✅ bundled `scripts/fragchain_registry.json` parses, served via API. Live HTTPS URL gracefully falls back when 404'd |
| Alembic 0004 applies on top of 0003 | ✅ `alembic current` → `0004_connector_state (head)`; restarted container hit the upgrade path cleanly |
| Discovery logs every connector loaded | ✅ JSON log line per loaded connector with `name`, `version`, `type`, `entry_point` |
| Existing 30 unit tests still pass | ✅ `pytest tests/ -q` → 48 passed (30 prior + 18 new), no regressions |
| 18 new connector tests pass | ✅ `pytest tests/test_connectors.py -v` → 18 passed in 0.26s |

### Build / lint sanity

- `ast.parse()` on every changed `fragchain/**.py` → no syntax errors.
- `pytest tests/` → 48 passed inside the API container (Python 3.12.13).
- API container restarted cleanly with `alembic upgrade head` running 0003→0004, then the lifespan event firing `connector.bootstrap.complete`.

## Interfaces this module exposes

For downstream modules (notably M6 ingestion and M24 marketplace UI):

```python
from fragchain.connectors import (
    # Protocol — implemented by every external connector package
    IntelConnector,
    # Enums
    ConnectorType, ConnectorOutput, HealthStatus,
    # Dataclasses
    RateLimit, ConnectorHealth, ConnectorConfig,
    CVERecord, AttackPattern, EnrichmentResult,
    # Orchestrator
    ConnectorOrchestrator, get_orchestrator, reset_orchestrator,
    # Discovery
    discover_connectors, ENTRY_POINT_GROUP,
    # Registry
    RegistryClient, RegistryEntry, get_registry_client, reset_registry_client,
)
```

ORM: `from fragchain.db.models import ConnectorState`.

API contract (under `/api/v1`):
- `GET /connectors` — list installed
- `GET /connectors/{name}` — detail + config
- `PATCH /connectors/{name}` — update config (maintainer)
- `POST /connectors/{name}/enable|disable` — toggle (maintainer)
- `POST /connectors/{name}/health` — run health check (maintainer)
- `GET /connectors/registry` — browse fragchain-registry (with `?refresh=true` to bypass cache)

## What dependent modules need to know

- **Adding a new connector**: package it as `fragchain-connector-<name>`, implement `IntelConnector`, expose it under the `fragchain.connectors` entry-point group, `pip install` it on the host, and restart the API. The orchestrator picks it up at the next lifespan startup and writes a `connector_state` row. Connector packages should NOT import `fragchain.connectors.orchestrator` — the only types they need are `IntelConnector` + the dataclasses in `fragchain.connectors.base`.
- **Using the orchestrator from M6**: call `get_orchestrator().enrich_cve(cve_id, cve_data)` to get `{name: EnrichmentResult | None}`. M6 owns the merge logic and the CVE state-machine transitions; M4 only guarantees parallelism + isolation.
- **Streaming CVEs from a source connector**: iterate `get_orchestrator().stream_new_cves(connector_name, since=..., limit=...)`. M6 picks which source(s) it polls — M4 doesn't merge sources at this layer (different cadences, different rate limits).
- **Reading/writing state**: prefer the orchestrator API (`is_enabled`, `update_config`, `set_enabled`, `run_health_check`) over direct ORM writes. The orchestrator owns the in-memory truth; `sync_state_to_db` is the only writer to `connector_state` outside migrations.
- **Health-check semantics**: a `HEALTHY` result clears the failure window. `UNHEALTHY` counts as a failure and may flip the connector to unhealthy. `DEGRADED`/`UNKNOWN` are recorded but don't change health state.
- **Failure threshold/window**: configurable per-orchestrator (`failure_threshold=3`, `failure_window_seconds=600`). The defaults match the kickoff. Tests construct their own orchestrator with custom thresholds.
- **TLP**: connectors declare `max_output_tlp` and `default_output_tlp` as `TLP` enum values. M6 must clamp every `EnrichmentResult.tlp` to `min(connector.max_output_tlp, declared)` when persisting.
- **Maintainer gate**: PATCH / enable / disable / health endpoints all require maintainer tier per `require_maintainer` from M2 (admin user passes by username during v1 bootstrap).

## Audit log entries

None added by M4. Connector config edits update `connector_state` but no audit row is written — the kickoff doesn't list connector mutations among auditable events. M24 (Settings UI) may add audit hooks if operators want to track who toggled connectors.

## Deviations from spec

- **`requires_verified_tier` and `supports_embargo`** are part of the Protocol per CLAUDE.md §5, but always `False` in v1 since verification/embargo workflows aren't yet enforced for connectors. The fields are present on `IntelConnector` and surfaced in `GET /connectors/{name}` so post-v1 modules can wire enforcement without a Protocol change.
- **Routes declaration order matters**: `/connectors/registry` is intentionally declared *before* `/connectors/{name}` so the literal path takes precedence. Verified — registry endpoint resolves correctly, and `GET /connectors/registry` does not get matched as `name='registry'`.
- **`get_orchestrator()` is a process-wide singleton** rather than a FastAPI `Depends(...)`. This is necessary because the Celery worker (M6 ingestion) also needs to talk to the same orchestrator instance — using FastAPI's DI would require duplicating the registration logic in the worker. The lifespan event owns lifecycle; tests get isolation via `reset_orchestrator()`.
- **Registry fallback JSON is shipped in `scripts/`** (rather than as a package data file) per the kickoff phrasing "use a hardcoded JSON file in `scripts/`". The path is resolved at import time via `Path(__file__).resolve().parents[2] / "scripts" / "fragchain_registry.json"`. If the repo layout ever changes, the registry will fall back to an empty list (logged as a parse failure) — but the UI keeps rendering.
- **Default registry URL is a GitHub raw URL** that doesn't actually serve a file yet (returns 404). This is intentional: the public fragchain-registry repo doesn't exist at the time of M4 build. The fallback path covers this transparently — verified in the live container restart logs (`connector.registry.fetch_failed` followed by successful fallback parse).
- **No `requires_auth=true` enforcement in v1**: the field exists on the Protocol and is surfaced in the API, but the engine doesn't yet block enrichment for connectors needing auth without credentials. That's M6's job once a real connector ships with `requires_auth=True`.
- **`ConnectorState.health_status` lives as a free-form VARCHAR** rather than a Postgres enum. Same reasoning as M3's `users.tier`: the value set will grow when post-v1 connectors add their own states. Add a CHECK constraint later if drift becomes a problem.

## Known TODOs (owned by other modules)

- **M6 — Intel Ingestion**: consumes `get_orchestrator().enrich_cve(...)` and `stream_new_cves(...)`. M6 also owns the CVE state machine, rate limiting against live-feed budget, and persisting merged enrichments.
- **M24 — Settings + Marketplace UI**: full UI on top of the M4 API. Will surface connector list, enable/disable toggles, config editor, registry browser with one-click install copy/paste hints (pip install command, not actual install — that stays an operator action).
- **M19 — WebSocket**: when a connector flips to unhealthy, a `connector.unhealthy` event should fan out to subscribed clients. M4 logs the event; M19 adds the broadcast.
- **`fragchain-registry` repository**: post-launch, the actual GitHub repo gets created and `DEFAULT_REGISTRY_URL` starts returning real JSON. No code change required — the URL is already set.
- **Tier enforcement for `requires_verified_tier=True` connectors**: post-v1 (M38) once tier escalation exists, the orchestrator should refuse to register a connector that requires verified tier when the deployment has no verified users. Today the field is informational only.
- **Audit logging for connector config edits**: M24 may decide to wire `audit_log` rows for connector mutations once the UI exists.

## Outstanding questions

- **Per-connector rate limiter is a `Semaphore` sized to `rate_limit.burst` (or `requests` if unset)** — this enforces concurrent-call limit, not per-window-rate. A token bucket would be more accurate, but the upstream rate-limit handling really belongs in each connector's HTTP client (NVD2 has its own per-key window, EPSS has a different one, etc.). The semaphore here is "good enough" guard rails against accidental fan-out storms; tightening to a true rate limiter is a connector-level concern.
- **`sync_state_to_db` runs at startup, on every mutating API call, and after each health check** — three write paths to a single table. None of these mutate rows concurrently, but if future modules add a Celery task that toggles enabled flags without going through the orchestrator, we'd want a `last_modified` column to break ties. Add it when the need shows up.
- **Auto-reconnect on plugin reinstall**: today the operator must restart the API container after `pip install fragchain-connector-foo`. Hot-reload would require either a process-watcher or an explicit "rediscover" endpoint. Out of scope for v1; the restart loop takes ~5 seconds.
- **Connector `name` collisions across packages**: two installed packages registering the same `name` would clobber each other in the orchestrator dict. Today this is detected by inspecting logs (you'd see two `connector.registered` events with the same name). A future enhancement would reject the second registration with a clear error message and surface it in `/health`.
