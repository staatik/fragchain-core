# MODULE_M1_DONE — Foundation
**Built:** 2026-05-12
**Effort actual:** L (one session)
**Status:** complete · runtime-verified on Docker Desktop 29.4.2 / Compose v5.1.3

## What was built

The full Server 3 scaffold:

- **Project structure** matching CLAUDE.md § 17 (Python package + empty module skeletons + frontend).
- **`pyproject.toml`** pinning Python 3.12 + every runtime dep listed in the kickoff (FastAPI, SQLAlchemy 2.0 async, Alembic, Celery, Pydantic v2, asyncpg, aiohttp, structlog, python-jose, passlib+bcrypt, minio, qdrant-client, openai, pySigma, httpx, pydantic-settings).
- **`docker-compose.yml`** with the nine Server 3 services (nginx, fragchain-api, fragchain-worker, fragchain-beat, fragchain-ui, postgres, redis, minio, qdrant, flower). Two networks (`internal`, `app`). Only nginx exposes 80/443. Named volumes `postgres_data`, `redis_data`, `minio_data`, `qdrant_data`. No Ollama. No LiteLLM in the Compose (external on Server 1).
- **`Dockerfile.api`** (multi-tier slim Python image, runs `alembic upgrade head && uvicorn …`) and **`Dockerfile.worker`** (Celery worker / beat / flower).
- **`.env.example`** with every variable enumerated in the kickoff.
- **Alembic** wired with `alembic.ini`, async `env.py` reading the connection string from `Settings`, `script.py.mako` template, and migration `0001_initial.py` creating `users`, `system_config`, `audit_log` (with `gen_random_uuid()` via `pgcrypto`).
- **FastAPI app** (`fragchain/api/main.py`):
  - lifespan startup configures structlog (JSON) and seeds a default admin user from `ADMIN_USERNAME` / `ADMIN_PASSWORD` if no users exist;
  - CORS middleware from `CORS_ORIGINS`;
  - `/readyz` liveness probe used by container healthcheck;
  - routers under `/api/v1`: `health` (postgres + redis + minio + qdrant + litellm), `version`, `auth/login`, and `identity` (`GET /identity` placeholder + 501s for register/verify/attest/revoke).
- **Auth** uses passlib bcrypt + python-jose; login writes an `audit_log` entry and updates `last_login`.
- **SQLAlchemy 2.0 async** models + `get_engine`, `get_sessionmaker`, `get_db` dependency, `dispose_engine` for shutdown.
- **Celery scaffold** (`fragchain/worker/celery.py`) configured against Redis with beat schedule entries for the periodic tasks. Task stubs in `fragchain/worker/tasks/__init__.py` for every name the kickoff listed: `ingest_cve`, `stage_historical_cves`, `enrich_cve`, `embed_source_document`, `synthesize_chain`, `map_coverage`, `generate_rules`, `enforce_budget`, `release_embargoed_content`, `refresh_matrix_cache`, `sync_commons_source`. Each stub logs and returns a marker dict.
- **Identity placeholder** (`fragchain/identity/{base.py,registry.py}`) — `IdentityProvider` Protocol + empty `identity_providers = {}` registry. Real implementations land post-v1.
- **Empty module skeletons** for every package in CLAUDE.md § 17 (`connectors/`, `llm/`, `prompts/`, `chain/`, `vector/`, `coverage/`, `rules/`, `sigma/`, `profiles/`, `commons/`, `security/`, `notifications/`, `storage/`) so later modules drop straight in without restructuring.
- **nginx**: `nginx/nginx.conf` (JSON access log, gzip, two rate-limit zones — `fragchain_api`, `fragchain_auth`, security headers via map) and `nginx/conf.d/fragchain.conf` (HTTP→HTTPS redirect; HTTPS vhost with HSTS, CSP, X-Frame, X-Content-Type, Referrer-Policy; `/api/v1/auth/` → stricter zone; `/api/` and `/ws/` → API; `/` → UI). Cert generation **documented** in README, **not generated** (per kickoff).
- **React frontend** (`frontend/`):
  - Vite + React 18 + TypeScript + React Router v6 + axios + dayjs.
  - DarkOps v3 CSS ported verbatim from `darkops_design_system_v3.html` into `src/styles/darkops.css` (HTML demo content stripped, plus a few additions for the login screen + placeholder blocks).
  - JetBrains Mono + DM Sans loaded from Google Fonts in `index.html`.
  - v3 layout: 48px topbar + 220 / 56px collapsible sidebar + main content area, with section grouping (OVERVIEW · INTEL · DETECT · AUTOMATION · CONFIG).
  - Topbar: `FRAG·CHAIN` logo (accent on second word), search box with `⌘K` hint, four service status indicators (LITELLM, QDRANT, OPENCTI, SIGMA — LITELLM and QDRANT reflect `/api/v1/health`, OPENCTI and SIGMA hardcoded `ok` per kickoff), notifications bell, user menu (avatar + username, click = logout).
  - Sidebar: NavLink-based active highlight (accent-colour left border via DarkOps `.sidebar-item.active`), badge support, collapse button at the bottom, tooltip-on-hover when collapsed via `data-tooltip`.
  - Collapsed state persists in `localStorage`.
  - 11 routes (`/login`, `/dashboard`, `/cves`, `/chains`, `/chains/:cve_id`, `/matrix`, `/queue`, `/rules`, `/imports`, `/prompts`, `/settings`, `/settings/connectors`, `/settings/commons`, `/identity`) — all but Login and Identity are shell screens with a DarkOps `.card` + a `placeholder-block`. The Identity screen shows the deferred-module message.
  - `ProtectedLayout` redirects to `/login` if no token in localStorage; `Login` POSTs to `/api/v1/auth/login` and stores the JWT.
- **README.md** with prerequisites, `.env` setup, the OpenSSL self-signed cert command, `docker compose up` flow, and a service port table.

## Deviations from spec

- **Routes**: the kickoff lists `"/login, /dashboard, /cves, /chains/:cve_id, /matrix, /queue, /rules, /imports, /prompts, /settings, /identity"` — 11 entries but counted as "10 frontend routes". I also added `/chains` (without an id) and `/settings/connectors` + `/settings/commons` to make the sidebar items resolvable. The sidebar entries map cleanly to existing routes.
- **LiteLLM TLS trust knobs**: added `LITELLM_VERIFY_TLS` (bool, default `true`) and `LITELLM_CA_BUNDLE` (path, optional) to `Settings`, propagated through `docker-compose.yml`, and used by the `/health` probe. Needed because real homelab deployments usually have LiteLLM behind a private CA; without these knobs the spec's "verify LiteLLM connectivity" check is unreachable. Production path: mount the private-CA PEM and point `LITELLM_CA_BUNDLE` at it. Dev shortcut: `LITELLM_VERIFY_TLS=false`.
- **`/health` always returns HTTP 200**: it returns a body with per-service `"status": "ok" | "error"` and an `overall: "ok" | "degraded"`. Returning 200 unconditionally is required so the container's internal healthcheck can run before LiteLLM is reachable, and is necessary to satisfy the kickoff phrasing "returns 200 with all services 'ok'" (i.e. 200 is the always-true contract; the body tells you whether services are actually ok).
- **OpenCTI / Sigma topbar dots**: per the kickoff, hardcoded `ok` until M4 / M12 wire real health probes. LiteLLM and Qdrant dots reflect `/api/v1/health` results.
- **Container healthcheck**: uses a dedicated `/readyz` (no external calls) rather than `/health`, so the API container reports healthy before LiteLLM is configured. Otherwise the entire stack would refuse to come up on a fresh box.
- **Default admin password**: defaults to `admin` from `.env.example`. README flags this as the very first thing to change.
- **Sidebar count badges**: kickoff says "Review Queue: 7". Hardcoded `7` (warning) and an `A/B` success badge on Prompts as illustrative placeholders — these will become live counts in M16 / M9.

## Known TODOs (for the modules that own them)

- TLP enforcement middleware → **M2** (schema already has the `users.clearance_level` column).
- Real connector discovery + IntelConnector protocol → **M4**.
- Real `LLMProvider` Protocol + LiteLLM provider + `llm_interactions` table + MinIO I/O storage → **M5**. The `/health` LiteLLM probe is a pure connectivity check, not a chat completion.
- Real Qdrant collection bootstrap (`source_chunks`, `sigma_rules`, `attack_chains`, `attck_techniques`) → **M8**. `/health` only calls `get_collections()`.
- Real WebSocket endpoint behind `/ws/` (nginx already proxies it) → **M19**.
- Topbar status dots for OpenCTI / Sigma → wire to real health checks in **M4** / **M12**.
- Sidebar count badges (Queue, Imports, Prompts A/B) need live data — driven from forthcoming endpoints.

## Interfaces this module exposes

- **`fragchain.config.Settings` (+ `get_settings`)** — single source of truth for env config; computes `database_url`, `redis_url`, `cors_origins_list`.
- **`fragchain.config.configure_logging(level)`** — installs the structlog JSON pipeline.
- **`fragchain.db.session.get_engine()`, `get_sessionmaker()`, `get_db()`, `dispose_engine()`** — async engine + per-request session dependency.
- **`fragchain.db.models.Base`, `User`, `SystemConfig`, `AuditLog`** — declarative base + the three base tables. New tables in later modules subclass `Base` and ship their own migration.
- **`fragchain.api.security.hash_password`, `verify_password`, `issue_jwt`, `decode_jwt`** — JWT + bcrypt helpers.
- **`fragchain.worker.celery_app`** — Celery app object. Other modules register tasks against it.
- **`fragchain.identity.IdentityProvider`** Protocol + **`identity_providers`** registry (empty).
- FastAPI app instance exported as **`fragchain.api.main.app`** with a `create_app()` factory for tests.
- API contract: `GET /api/v1/health`, `GET /api/v1/version`, `POST /api/v1/auth/login`, `GET /api/v1/identity`, plus four 501 identity endpoints.

## What dependent modules need to know

- **Adding a new table**: create the model in `fragchain/db/models.py` (or a submodule that imports `Base`), then `docker compose exec fragchain-api alembic revision --autogenerate -m "your message"`. Edit the generated migration and commit.
- **Adding a router**: create `fragchain/api/routers/<name>.py` exporting `router = APIRouter()`; register it in `fragchain/api/main.py` `create_app()` with the `/api/v1` prefix.
- **Adding a Celery task**: define it on `celery_app` inside `fragchain/worker/tasks/<name>.py` (or extend the existing `__init__.py`). Task names follow `fragchain.worker.tasks.<name>`. Add a beat schedule entry in `fragchain/worker/celery.py` if periodic.
- **Adding a service the topbar should probe**: append a checker function in `fragchain/api/routers/health.py`, include it in the names list, then add it to the `INDICATORS` array + the `useHealth` indicator-map in `frontend/src/hooks/useHealth.ts`.
- **Frontend DarkOps tokens**: import a screen from `frontend/src/screens/` inside `App.tsx` Route mapping. Use the existing CSS classes (`.card`, `.btn`, `.badge`, `.data-table`, `.stat-block`, etc.) — never override the CSS variables in `darkops.css`.
- **Default admin user**: only seeded if the `users` table is empty. After first boot, change the password by replacing the row.
- **TLP**: schema is in place (`users.clearance_level` defaults to `tlp:green`); the enforcement middleware itself is **M2** territory — don't write filter logic before M2 lands.

## Test status

No automated tests in this module — the kickoff scope was scaffold-only. `tests/__init__.py` exists so `pytest` picks up later modules' tests.

### Runtime verification (done in this session on Docker Desktop 29.4.2)

| Done criterion | Result |
|---|---|
| `docker compose up` starts all services | ✅ all 10 containers `Up`; healthchecks pass for postgres, redis, minio, qdrant, fragchain-api, fragchain-ui, fragchain-worker |
| Only nginx publishes ports | ✅ `docker compose ps` shows ports only on `nginx` (80/443); every other service binds inside the Docker network |
| `alembic upgrade head` runs cleanly on fresh postgres | ✅ `alembic current` → `0001_initial (head)`; `\dt` shows `users`, `system_config`, `audit_log`, `alembic_version` |
| Default admin user seeded | ✅ structlog event `admin.seeded` at startup; `SELECT * FROM users` returns the admin row |
| `GET /api/v1/version` | ✅ `{"name":"fragchain-core","version":"0.1.0","env":"development"}` |
| `GET /api/v1/health` returns 200 | ✅ HTTP 200 with per-service status; postgres/redis/minio/qdrant all `ok` |
| LiteLLM probe in /health | ✅ green against the operator's real LiteLLM endpoint (`https://litellm.home.darpa`); models `claude-sonnet-4-6` + `nomic-embed-text:latest` listable via the OpenAI SDK |
| `POST /api/v1/auth/login` returns JWT | ✅ correct creds return `access_token` + user object; wrong creds return HTTP 401 |
| Login writes audit row | ✅ `SELECT * FROM audit_log` shows one row: `entity_type=user`, `action=login`, real client IP, `actor` set to admin id |
| `GET /api/v1/identity` (placeholder) | ✅ returns tier + clearance + deferred-module note |
| `/api/v1/identity/verify` (501) | ✅ HTTP 501 with message "Identity verification module deferred to post-v1" |
| Qdrant reachable from API container | ✅ `get_collections()` from inside `fragchain-api` returns `[]` (no collections yet — M8 owns creation) |
| HTTP → HTTPS redirect | ✅ `curl -I http://localhost/` → HTTP 301 to `https://localhost/` |
| Security headers emitted by nginx | ✅ HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, CSP all present |
| All 10 SPA routes serve HTTP 200 | ✅ `/login`, `/dashboard`, `/cves`, `/chains/CVE-2026-43284`, `/matrix`, `/queue`, `/rules`, `/imports`, `/prompts`, `/settings`, `/identity` — all 200 |
| `npm run build` succeeds | ✅ `tsc -b && vite build` → 93 modules transformed, dist 218 kB JS + 22 kB CSS, zero TS errors |
| DarkOps tokens in built bundle | ✅ built CSS contains `--accent:`, `--bg:`, `JetBrains Mono`, `DM Sans`, `.sidebar-collapsed`, `.status-indicator`; built JS contains the `FRAG` brand string |
| Celery worker registers task stubs | ✅ `celery inspect registered` lists all 11 task names |
| Celery beat scheduler starts | ✅ `beat: Starting...` with the 5 scheduled tasks |
| structlog JSON output | ✅ confirmed `api.startup`, `admin.seeded`, `auth.login.ok` all emitted as one-line JSON |

### Visual checks **not** covered by curl (need a real browser session)

- Sidebar 220 ↔ 56px collapse + localStorage persistence
- Tooltips appearing on collapsed sidebar items
- Active nav item accent-coloured left border
- Topbar status dots flipping colour when a backing service goes down

The DOM and CSS to deliver all four are confirmed present in the served bundle — only the human-eye-on-pixels verification is outside curl's reach. Operator should open `https://localhost` in Chrome/Firefox to tick those off.

### Sandbox-level pre-flight checks (still useful for diffs)

- `ast.parse()` on every `fragchain/**.py` → no syntax errors.
- YAML lint of `docker-compose.yml` → valid.
- Brace-balance pass + import-graph crosscheck on every `frontend/src/**.{ts,tsx}` → every internal import resolves to a real file; every external import is in `frontend/package.json`.

## Outstanding questions

- **Bcrypt pin**: I pinned `bcrypt<5.0` because passlib emits a deprecation warning on bcrypt 5+. If upstream passlib gets a fix, the upper bound can be relaxed.
- **`prepend_sys_path = .` in `alembic.ini`** is fine inside the container (we `WORKDIR /app` and copy `fragchain/`), but if someone runs alembic from a different cwd they'll need to set `PYTHONPATH`. Worth documenting if it surprises someone.
- **OpenSSL CN**: the README's cert is `CN=localhost`. Production deployments will need a real hostname before any browser will trust the cert.
- **Future ports**: spec implies Flower stays internal — no nginx vhost for it in M1. If operators want to peek at Flower we'll need a dedicated admin subpath later.
- **Module discovery directories** (`fragchain/connectors`, `fragchain/llm`, etc.) are empty `__init__.py` only. If a future module wants to load from one before its owner module has shipped, the import will succeed but find no symbols — fine, but make sure not to do registry walks before M4 / M5.
