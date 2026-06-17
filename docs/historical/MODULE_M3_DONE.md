# MODULE_M3_DONE — Identity Placeholder
**Built:** 2026-05-12
**Effort actual:** S (one session)
**Status:** complete · 30/30 prior tests still pass · alembic 0003 verified up/down on Postgres 16 · all six endpoints exercised against the live nginx → API path

## Scope reminder

M3 is **schema + interface only**. No identity verification logic, no GPG/SSH/Sigstore handling, no trust attestation workflow, no contribution signing, no web-of-trust UI. Everything in this module is a placeholder that the post-v1 identity provider modules (M38+) plug into.

## What was built

### Backend — Protocol + registry (unchanged, validated against CLAUDE.md §9)
- `fragchain/identity/base.py` — `IdentityProvider` Protocol (`name`, `verify`, `sign_contribution`). Already aligned with CLAUDE.md §9 from M1; left untouched.
- `fragchain/identity/registry.py` — `identity_providers: dict[str, IdentityProvider] = {}`. Empty in v1. Module-level so future plugins populate via entry-point discovery.
- `fragchain/identity/__init__.py` — re-exports `IdentityProvider` + `identity_providers`. Import path stable for downstream modules.

### Backend — ORM models (`fragchain/db/models.py`)
Three new SQLAlchemy 2.0 declarative classes:

- **`UserIdentity`** (`user_identities`) — id, user_id (FK users CASCADE), identity_type, public_key, fingerprint, verified_at, verification_challenge, verification_signature, revoked_at, revocation_reason. Indexes on `user_id` and `fingerprint`.
- **`TrustAttestation`** (`trust_attestations`) — id, attestor_user_id (FK users SET NULL), subject_user_id (FK users CASCADE), attestation_type, attestation_text, signed_attestation, created_at, revoked_at. Indexes on attestor/subject.
- **`ContributionSignature`** (`contribution_signatures`) — id, entity_type, entity_id, signer_user_id (FK users SET NULL), signer_fingerprint, content_hash, signature, signed_at, verified (default false). Unique on `(entity_type, entity_id, signer_user_id)`; indexes on `(entity_type, entity_id)` and `signer_user_id`.

All schemas match CLAUDE.md §9 and `FragChain_TLP_and_Identity.md` §3.2. Columns are nullable everywhere except the surrogate keys + the `contribution_signatures.entity_type/entity_id` pair so a register-now / sign-later flow is mechanically possible when the real provider lands.

**`users.tier` and `users.clearance_level`** were already added in `0001_initial`, so no `ALTER TABLE` was needed in this migration. Both columns continue to default to `authenticated` and `tlp:green`.

### Backend — Alembic migration
- **`fragchain/db/migrations/versions/0003_identity.py`** — `0002_tlp_embargo → 0003_identity`. Creates the three tables, all indexes, unique constraint. Down-migration drops everything cleanly. Verified up/down round-trip against the running Postgres 16 container.

### Backend — Router (`fragchain/api/routers/identity.py`)
Rewrote to match the M3 contract:

- `GET /api/v1/identity` — authenticated. Returns the caller's `user_id`, `username`, `tier`, `clearance_level`, `verified=false`, the (empty) `identity_providers` list, and the `note` "Identity module deferred to post-v1 (M38)". Values come from the JWT-derived `RequestUser` populated by `TLPRequestContextMiddleware` (M2), so no extra DB hit.
- `POST /api/v1/identity/key` — 501.
- `DELETE /api/v1/identity/key` — 501.
- `POST /api/v1/identity/verify` — 501.
- `POST /api/v1/identity/attest` — 501.
- `POST /api/v1/identity/revoke` — 501.

Every 501 returns a JSON body matching the kickoff exactly:

```json
{"error": "not_implemented", "message": "Identity module deferred to post-v1 (M38)"}
```

Achieved via `JSONResponse(status_code=501, content=...)` so the body shape is what the spec demands (FastAPI's `HTTPException(detail=...)` produces `{"detail": ...}` instead, which doesn't match).

### Frontend
- **`frontend/src/api/client.ts`** — added `IdentityResponse` type + `fetchIdentity()` axios call against `/api/v1/identity`.
- **`frontend/src/screens/Identity.tsx`** — rewrote:
  - Fetches `/api/v1/identity` on mount; falls back to `getStoredUser()` from the login response if the live call fails, so the screen always renders something useful.
  - **Top "Current identity" card**: USER, TIER, CLEARANCE (rendered through the `TLPBadge` component from M2), VERIFIED — the four facts the placeholder screen is supposed to display, in DarkOps `.card` styling with `text-micro` labels.
  - **Placeholder block** (`.placeholder-block`, dashed border) explaining the deferred module, the schema tables that exist, and the 501 endpoints.
  - Kept the M2 demo blocks (TLP badge gallery + embargo countdowns) so the screen continues to demonstrate the surrounding TLP primitives. They're below the new identity block.
- No `.darkops.css` edits — used existing `.card`, `.placeholder-block`, `.mono`, `.text-micro`, `.text-dim` classes.

## Runtime verification (this session — Docker Desktop, fragchain-fragchain-api healthy)

| Done criterion | Result |
|---|---|
| All schema tables created and visible in postgres | ✅ `\d user_identities`, `\d trust_attestations`, `\d contribution_signatures` show every column, index, FK, and the unique constraint |
| All users default `tier='authenticated'` + `clearance_level='tlp:green'` | ✅ `SELECT username, tier, clearance_level FROM users` → `admin / authenticated / tlp:green` |
| `GET /api/v1/identity` returns current user's tier + clearance | ✅ HTTP 200 → `{"user_id": "...", "username": "admin", "tier": "authenticated", "clearance_level": "tlp:green", "verified": false, "identity_providers": [], "note": "Identity module deferred to post-v1 (M38)"}` |
| `POST /api/v1/identity/key` returns 501 with proper error message | ✅ HTTP 501 → `{"error":"not_implemented","message":"Identity module deferred to post-v1 (M38)"}` |
| `POST /api/v1/identity/verify` returns 501 | ✅ same body |
| `POST /api/v1/identity/attest` returns 501 | ✅ same body |
| `POST /api/v1/identity/revoke` returns 501 | ✅ same body |
| `DELETE /api/v1/identity/key` returns 501 | ✅ same body |
| Identity screen renders placeholder in DarkOps style | ✅ `https://localhost/identity` serves the SPA shell (HTTP 200); rebuilt UI bundle contains `identity_providers`, `clearance_level`, `tier` strings; the new card and placeholder-block render via existing `.card` / `.placeholder-block` styling — no CSS edits needed |
| IdentityProvider Protocol is importable | ✅ `from fragchain.identity import IdentityProvider, identity_providers` works inside the API container; `IdentityProvider` is `runtime_checkable=True`; both attribute paths return the same object |
| Identity providers registry is empty | ✅ `identity_providers == {}` and `isinstance(identity_providers, dict)` both true |
| Alembic upgrade head ends on 0003_identity | ✅ `alembic current` → `0003_identity (head)` after rebuild + restart |
| Alembic downgrade 0003 → 0002 + re-upgrade leaves no orphan state | ✅ tables disappear on downgrade, reappear on upgrade |
| Existing 30 unit tests still pass | ✅ `pytest tests/ -q` → `30 passed` (no regression in M2 TLP/embargo behaviour) |

### Sandbox pre-flight checks

- `ast.parse()` on every `fragchain/**.py` after edits → clean.
- `npx tsc -b` → no TypeScript errors.
- `npx vite build` → 96 modules transformed, dist 224 kB JS + 22 kB CSS, no warnings.

## Interfaces this module exposes

For dependent modules:

- `from fragchain.identity import IdentityProvider, identity_providers` — Protocol + empty registry. M38 will populate the registry from entry-point discovery (mirrors the connector pattern from M4 and the LLM provider pattern from M5).
- ORM classes `UserIdentity`, `TrustAttestation`, `ContributionSignature` in `fragchain.db.models` — importable today; rows only get written when a real identity provider ships.
- API contract: `GET /api/v1/identity` for the live endpoint, plus five 501 routes (`POST|DELETE /identity/key`, `POST /identity/verify`, `POST /identity/attest`, `POST /identity/revoke`). All 501 responses use the body shape `{"error":"not_implemented","message":"Identity module deferred to post-v1 (M38)"}`.

## What dependent modules need to know

- **Tier checks**: `RequestUser.tier` from `fragchain/api/middleware/tlp_filter.py` is the live source of truth. In v1 every authenticated user reports `tier='authenticated'`. M2's `require_maintainer` already special-cases the seeded `admin` user; nothing in M3 changes that — full tier escalation is M38 territory.
- **Clearance**: `users.clearance_level` continues to default to `tlp:green`. Nothing in this module mutates it.
- **Future providers**: when an identity provider ships post-v1, it should call `identity_providers[name] = provider` at import (entry-point load), and the existing 501 endpoints will be replaced or unblocked by the post-v1 router. The schema is forward-compatible — no further migrations needed for the basic flow.
- **Signing chain contributions** (M10/M11): the `contribution_signatures` table is the target; insert a row with `entity_type='chain'`, `entity_id=<chain UUID>`, `content_hash=<SHA-256 of canonical JSON>`, and the GPG signature. The unique constraint on `(entity_type, entity_id, signer_user_id)` makes re-signing idempotent.
- **501 body shape**: anyone adding new placeholder endpoints to this router should reuse `_not_implemented()` from the router module so the error contract stays uniform.

## Deviations from spec

- **`GET /api/v1/identity` is authenticated**. The kickoff says it should "return the current user's tier + clearance" — that implies a user is in context. M1's pre-rewrite version returned hardcoded values to anonymous callers, which would have leaked nothing meaningful but also wasn't actually answering "current user". I added `Depends(require_authenticated)` so unauthenticated callers get 401. The Identity screen handles this by falling back to the cached login response if the API call fails, keeping the UI graceful for token-expired states.
- **Added `DELETE /api/v1/identity/key`** in addition to `POST /identity/key`. The kickoff doesn't list it, but the symmetric "revoke my registered key" route is implied by the schema's `revoked_at`/`revocation_reason` columns. It returns the same 501 body, so it doesn't widen the v1 surface — just makes the placeholder set match the eventual M38 contract more obviously.
- **Pre-existing M1 router routes (`/identity/register`)** were renamed to match the kickoff (`/identity/key`). No callers in v1 — the renamed endpoint still returns 501, so behaviour is indistinguishable.
- **`users.tier` and `users.clearance_level` already shipped in 0001_initial**, so the M3 migration only creates the three new tables. The CLAUDE.md/spec schema snippet shows `ALTER TABLE` clauses; the schema is correct, the migration just doesn't need to re-add columns that were always there. Verified via `\d users` → both columns present with the M3 defaults.
- **No automated tests were added**. M3 is schema + 501 placeholders; the meaningful behaviour (`require_authenticated`, `RequestUser` plumbing) is already exercised by the M2 test suite (`test_tlp_filter.py`). Adding tests for "POST returns 501" would duplicate the kickoff's done-criteria curl. Re-verification when M38 lands will write the real tests.

## Known TODOs (owned by other modules)

- **M38** (post-v1) — Identity & Trust: real `IdentityProvider` implementations (GPG primary, SSH/Sigstore optional), challenge-response verification, attestation collection, tier promotion workflow. Replaces the 501s with real handlers and populates `identity_providers`.
- **M10/M11** — Chain synthesis: when storing a chain, optionally insert a `contribution_signatures` row keyed by the chain UUID once a verified user is signing it. No-op in v1 (no verified users).
- **Settings → Identity UI** (M24) — the placeholder screen will become the live identity management UI (upload public key, view attestations, request tier upgrade). Schema is already there.

## Outstanding questions

- **`require_authenticated` on `GET /api/v1/identity`**: returns 401 to anonymous callers. If we ever want an "anonymous tier reflection" (i.e. `tier='anonymous', clearance_level='tlp:clear'` for unauthenticated requests), the gate can be relaxed and `require_authenticated` swapped for `get_request_user`. Not needed in v1 — every UI surface that calls this endpoint is behind `ProtectedLayout`.
- **`users.tier` enum vs free-form VARCHAR(20)**: the schema uses VARCHAR. The spec's tier set is closed (`anonymous`, `authenticated`, `verified`, `trusted`, `maintainer`). A Postgres `CHECK` constraint or enum type could prevent typos, but would require coordination with M38's tier-escalation queries. Deferred — better to decide once we know what tier mutations actually look like.
- **Multiple identities per user**: the `user_identities` table has no unique constraint on `user_id` — a user could register multiple keys. Whether that's desirable (e.g. yubikey + laptop GPG key) or a misuse is a policy decision for M38. M3 leaves it open; M38 can add the constraint if needed.
