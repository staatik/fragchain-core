# MODULE_M2_DONE — TLP & Embargo
**Built:** 2026-05-12
**Effort actual:** M (one session)
**Status:** complete · 30/30 unit tests pass · alembic migration verified · embargo task verified end-to-end on Postgres 16

## What was built

### Backend — TLP primitives
- **`fragchain/security/tlp.py`** — single source of truth for TLP 2.0:
  - `TLP` `StrEnum` with all five levels (`tlp:clear`, `tlp:green`, `tlp:amber`, `tlp:amber+strict`, `tlp:red`).
  - `restriction_level` ordering encoded so propagation decisions stay consistent across the codebase.
  - `TLP.parse(value)` — coerces strings/enums/None into a level (case-insensitive). Raises on unknown values so callers can't silently inherit a bogus tag.
  - `max_tlp(*levels)` — most-restrictive winner. Accepts strings and enums mixed; empty input returns `CLEAR`.
  - `can_user_access(session, user, entity_tlp, entity_id, *, embargoed=False)` — async predicate that every endpoint applies before returning a TLP-bearing row. Honours all four propagation rules from `FragChain_TLP_and_Identity.md` §2.3.
  - `has_explicit_grant`, `is_embargo_participant` — DB-backed lookups (lazy ORM import keeps them out of the import graph at startup).
  - `filter_tlp_visible(items, user)` — synchronous fast-path for CLEAR/GREEN-only batches. Conservatively drops amber+ so a caller missing the async helper can't accidentally leak.
  - `is_anonymous(user)` — `None` user *or* `tier == "anonymous"` is the same thing.

### Backend — Embargo
- **`fragchain/security/embargo.py`** — embargo timer + auto-release:
  - `EmbargoedTable` dataclass + `register_embargoed_table()` registry. Other modules call this on import when they own a table that gets an `embargo_until` column (M6 will register `cves`/`source_documents`, M10 will register `attack_chains`). The registry stays empty in M2, so the Celery task is a no-op on fresh deployments — exactly the contract the spec asks for.
  - `effective_tlp(declared, embargo_until)` — Rule 3 from the TLP spec: while embargo is active, effective TLP is `RED` regardless of declaration. Accepts both `datetime` and ISO-8601 strings (the filter middleware sees strings inside dicts/JSON responses).
  - `is_embargoed(embargo_until)` — boolean shortcut.
  - `release_expired(session, actor=None)` — finds every expired embargo across registered tables, NULLs `embargo_until`, deletes participant rows, writes one `audit_log` row per release. Returns a `ReleaseResult` with counts + ids so callers can emit websocket events later (M19 task).
  - `release_one(session, entity_type, entity_id, actor, reason)` — maintainer-initiated early release. Same side-effects, audit row carries `actor` + `reason`.
  - `list_active(session)` — every entity currently held under embargo, with participant counts. Powers `GET /api/v1/embargo/active`.

### Backend — TLP filter middleware
- **`fragchain/api/middleware/tlp_filter.py`**:
  - `TLPRequestContextMiddleware` — Starlette HTTP middleware that decodes the bearer JWT (if any) and attaches a `RequestUser` to `request.state.user`. Anonymous requests get `None`. Registered in `create_app()`.
  - `RequestUser` dataclass — lightweight `id`/`username`/`tier`/`clearance_level` view assembled from JWT claims. Matches the `_UserLike` Protocol so TLP helpers accept it without an ORM round-trip.
  - `get_request_user(request)`, `require_authenticated(request)`, `require_maintainer(request)` — FastAPI request helpers. `require_maintainer` recognises `tier=='maintainer'`, `tlp:red` clearance, and the seeded `admin` user (so a fresh deployment isn't locked out before M3 wires tier upgrades).
  - `apply_tlp_filter(session, items, user)` — async list filter. Strips over-classified rows; embargoed entities require participant membership. Accepts dicts, Pydantic models, and ORM rows uniformly (reads `tlp`/`embargo_until`/`id` via `_read_tlp`/`_read_embargo`/`_read_entity_id`).
  - `enforce_tlp_access(session, item, user)` — single-entity gate. Raises `HTTPException(403)` with `"TLP classification forbids access"` if the caller can't read this row. Logs the denial with the user id + entity id + effective TLP.
  - `visible_to_user_sync(items, user)` — sync fast-path that drops amber+ entries (mirrors `filter_tlp_visible`).

### Backend — Admin embargo endpoints
- **`fragchain/api/routers/embargo.py`** wires two endpoints under `/api/v1`, both gated by `require_maintainer`:
  - `GET /api/v1/embargo/active` → `ActiveEmbargoesResponse` with `active[]` and `registered_types[]`.
  - `POST /api/v1/embargo/release/{entity_id}` with `{entity_type, reason}` body → `ReleaseResponse`. 404 if the entity isn't currently embargoed; 400 if `entity_type` isn't registered.

### Backend — Schema + migration
- New ORM models in `fragchain/db/models.py`:
  - `TLPAccessGrant` (table `tlp_access_grants`) — schema from M2 spec §Schema. FKs to `users(id)` with `CASCADE`/`SET NULL` as appropriate. NULL `expires_at` means a permanent grant.
  - `EmbargoParticipant` (table `embargo_participants`) — unique `(entity_type, entity_id, user_id)` so duplicate adds are a no-op rather than a duplicate-row bug.
- **`fragchain/db/migrations/versions/0002_tlp_embargo.py`** creates both tables with the right indexes (`entity_type+entity_id`, `granted_to_user_id`/`user_id`) and unique constraint. Verified by running `alembic upgrade head` against a fresh `postgres:16-alpine`.

### Backend — Celery task
- `fragchain/worker/tasks/__init__.py::release_embargoed_content` upgraded from stub to a real implementation. Wraps `release_expired` in `asyncio.run` (Celery tasks are sync entry points). Returns `{released_count, released[]}`; logs and returns `{status: "error"}` on failure rather than crashing the worker. The 5-minute beat schedule in `fragchain/worker/celery.py` was already in place from M1.

### Frontend
- **`frontend/src/components/TLPBadge.tsx`** — renders all five DarkOps `.badge.tlp-*` variants. Reads the level (e.g. `"tlp:amber+strict"`), maps to `tlp-clear`/`tlp-green`/`tlp-amber`/`tlp-amber-strict`/`tlp-red` CSS classes, displays uppercase `TLP:<LEVEL>`. Props: `level`, `showPrefix`, `className`, `title`.
- **`frontend/src/components/EmbargoIndicator.tsx`** — lock icon + live countdown. Updates every 30s (configurable via `tickMs`). Switches to a success-coloured "RELEASED" state when the timer crosses zero so the parent can refetch on next interaction. Returns `null` when `embargoUntil` is empty so it's safe to drop into any list cell. Hooks order is safe across all branches.
- **`frontend/src/components/TLPBadge.css`** — adds `.embargo-indicator` styles (pulsing lock animation, `released` colour swap, countdown number). The TLP badge classes themselves live in the existing `darkops.css`.
- **`frontend/src/screens/Identity.tsx`** — added M2 demo blocks rendering all five TLP badges and three embargo countdowns (days/hours/minutes granularities). Keeps the deferred-module placeholder for the actual identity workflow.

### Tests
- **`tests/test_tlp.py`** (21 tests) — covers `TLP` enum/levels/ordering, `TLP.parse` happy + sad paths, `max_tlp` for all combos, `can_user_access` for every (tier × level × grant) cell, embargo override, `is_embargoed`, and `filter_tlp_visible`. Uses a `FakeSession` + monkeypatched `has_explicit_grant`/`is_embargo_participant` so it's pure-Python.
- **`tests/test_tlp_filter.py`** (9 tests) — exercises `apply_tlp_filter` (anonymous, authenticated, amber-with-grant), `enforce_tlp_access` (403 rejection + 200 path), embargoed entity treated as RED, embargoed entity visible to participant, dicts + Pydantic input shapes, and `visible_to_user_sync` dropping amber.

## Runtime verification (this session)

| Done criterion | Result |
|---|---|
| `TLP` enum has all 5 levels in correct restriction-level order | ✅ unit test |
| `max_tlp()` returns the most restrictive level | ✅ unit test (incl. mixed string/enum) |
| `can_user_access()` denies over-classified content | ✅ unit tests across all five levels |
| TLP filter middleware rejects access to over-classified content | ✅ `test_enforce_tlp_access_rejects_with_403` (HTTP 403) |
| TLP filter strips amber+ for unauthenticated callers | ✅ `test_apply_tlp_filter_strips_over_classified_content_for_anonymous` |
| Embargo override flips effective TLP to RED | ✅ `test_embargo_overrides_clear_classification` + `test_embargoed_entity_treated_as_red` |
| Embargoed entity visible to participants only | ✅ `test_embargoed_entity_visible_to_participant` |
| Alembic migration applies on fresh postgres | ✅ `alembic upgrade head` runs `0001_initial -> 0002_tlp_embargo` cleanly |
| Embargo release task end-to-end | ✅ live Postgres run: 1 expired CVE released, 1 active retained, 1 audit row written, participant row cleared |
| `GET /api/v1/embargo/active` registered | ✅ shows in app route table |
| `POST /api/v1/embargo/release/{entity_id}` registered | ✅ shows in app route table |
| Celery `release_embargoed_content` re-registers (task name unchanged) | ✅ import verified, task name `fragchain.worker.tasks.release_embargoed_content` |
| `TLPBadge` renders all 5 variants matching DarkOps v3 | ✅ uses existing `.badge.tlp-*` classes from `darkops.css`; verified in built bundle |
| `EmbargoIndicator` shows correct countdown | ✅ `formatRemaining` exercised on days/hours/minutes/seconds inputs; demo on Identity screen |
| Frontend builds clean | ✅ `tsc -b && vite build` → 96 modules, dist 222 kB JS + 22 kB CSS, zero TS errors |
| 30 unit tests pass | ✅ `pytest tests/test_tlp.py tests/test_tlp_filter.py -v` → 30 passed |

## Audit log entries

The audit log gains two new actions:

- `embargo.released` — written by `release_expired` (auto-release; `actor=NULL`, `after={released_at, auto: true}`) and by `release_one` (manual; `actor=<user>`, `after={released_at, auto: false, reason}`).
- The TLP-change action (`tlp.changed`) is reserved for the modules that own the entities (M6 onward) — M2 only exposes the primitives. The propagation function is here; the call sites land alongside the tables that have a `tlp` column.

## Interfaces this module exposes

For downstream modules:

- `from fragchain.security import TLP, max_tlp, can_user_access, filter_tlp_visible, has_explicit_grant, is_embargo_participant, is_anonymous`
- `from fragchain.security import register_embargoed_table, EmbargoedTable, release_expired, release_one, list_active, effective_tlp, is_embargoed`
- `from fragchain.api.middleware import TLPRequestContextMiddleware, RequestUser, get_request_user, require_authenticated, require_maintainer, apply_tlp_filter, enforce_tlp_access`
- ORM models `TLPAccessGrant` and `EmbargoParticipant` in `fragchain.db.models`.
- Audit actions: `embargo.released`.

## What dependent modules need to know

- **Adding `embargo_until` to a table**: M6 (cves, source_documents), M10 (attack_chains), M12 (sigma_rules — optional) add the column in their own migrations, then call `register_embargoed_table(EmbargoedTable(table=…, entity_type=…))` at module import. The Celery task picks them up automatically — no central wiring change.
- **Filtering an endpoint response**: pull the user via `get_request_user(request)` (or accept it as a `Depends(require_authenticated)`), then `await apply_tlp_filter(session, rows, user)` before returning. Single-entity endpoints call `await enforce_tlp_access(session, row, user)` to either pass or raise 403.
- **Storing a chain with sources**: chain TLP = `max_tlp(chain.declared_tlp, *[s.tlp for s in chain.sources])`. Do this at write time, not just on read.
- **Maintainer gate**: until M3 ships full tier management, `require_maintainer` accepts (a) `tier == "maintainer"`, (b) `clearance_level == "tlp:red"`, (c) the seeded `admin` user by name. Operators promoting users will replace the third clause once M3 exposes tier mutation.
- **Embargo overrides**: never read raw `tlp` — always call `effective_tlp(declared, embargo_until)`. The filter middleware does this for you, but DB-direct callers (Celery tasks, reports) must do it themselves.

## Known TODOs (owned by other modules)

- TLP columns on entity tables (`cves`, `source_documents`, `attack_chains`, `sigma_rules`) — added per-module from M6 onward. M2 is the framework.
- WebSocket `embargo_released` event broadcast — wired in M19 once the WebSocket bus exists. `release_expired` already returns the released IDs so the broadcaster can iterate.
- Settings UI for TLP grants and embargo participant management — M24 (Settings + Marketplace UI).
- TLP propagation on chain write — M10 / M11 (chain schema + synthesis call `max_tlp` over `sources_used`).

## Deviations from spec

- **`require_maintainer` accepts the seeded `admin` user by username** as a temporary bridge. Without it, a fresh deployment has no way to call `/api/v1/embargo/release/*` until M3 ships tier escalation. Replaced cleanly when M3 (or later) wires real tier management.
- **Embargo task registry is empty until other modules register**. The kickoff describes the task as releasing expired content; in M2 that's a no-op because there are no embargoeable tables yet. This is intentional — `release_expired` walks the registry, so it scales to whatever the codebase registers without M2 needing to know about the future tables. Verified end-to-end against an ad-hoc table.
- **Audit-log `before`/`after` are JSONB**, so the `embargo.released` rows store `{"released_at": iso, "auto": bool, "reason"?: str}` in `after`. No `before` snapshot because the only state change is "embargo_until cleared" — there's nothing meaningful to capture.
- **`EmbargoIndicator` uses emoji lock icons (🔒 / 🔓)** to match the existing topbar pattern (which already uses 🔔 and ☰). Replacing with SVG icons is purely cosmetic; the styling and animation hooks are in place.

## Outstanding questions

- **TLP downgrade audit**: the spec says only the original contributor can downgrade, recorded with reason. The primitives are here (`max_tlp`, audit hooks), but the actual downgrade endpoint belongs with the entity-owning modules. Worth a note in their kickoffs.
- **`require_maintainer` fallback to `tlp:red` clearance** assumes any user explicitly cleared for RED is trusted enough to release embargoes. That's a defensible default but should be revisited once M3 ships proper tier management — it's the kind of permission you probably want to be explicit about.
- **Embargo participant cascade**: on `release_one`, we delete every participant row for the entity. If a maintainer ever wants to *preserve* the participant list (e.g. so participants get a notification on next view), we'd need a `released_at` column on `embargo_participants` rather than DELETE. Defer until M19 (notifications) tells us whether that's needed.
