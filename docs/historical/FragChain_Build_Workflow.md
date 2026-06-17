> **Historical — preserved for context.** This is the original M1–M37 build workflow from the pre-assessment-centric era. Active build guidance lives in [`CLAUDE.md`](../../CLAUDE.md) and the per-feature plans under [`docs/superpowers/plans/`](../superpowers/plans/). See [`docs/historical/README.md`](README.md) for what else lives in this folder.

---

# FragChain — Build Workflow Guide
**Purpose:** How to drive Claude Code sessions to build FragChain module by module.  
**Companion to:** `CLAUDE.md` (operational reference) + `FragChain_Module_Specifications.md` (canonical scope).

---

## The Core Workflow

```
ONE MODULE = ONE CLAUDE CODE SESSION (usually)
```

Larger modules (L effort, ~8-14 days) may take 2 sessions with a checkpoint between.
Smaller modules (S effort, ~1-3 days) can sometimes be combined if closely related.

### Session Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│  1. OPEN session in a fresh Claude Code conversation        │
│  2. PASTE the opening prompt (template below)                │
│  3. CLAUDE reads context, plans, asks clarifying questions   │
│  4. WORK begins — Claude Code builds the module              │
│  5. REVIEW intermediate checkpoints as needed                │
│  6. CLAUDE writes MODULE_N_DONE.md before closing            │
│  7. CLOSE session, commit code, move to next module          │
└─────────────────────────────────────────────────────────────┘
```

**Why one module per session:** Context stays focused, you can review and commit per module, and if a session goes wrong you only lose one module's worth of work.

---

## The Opening Prompt Template

Paste this at the start of every module session, with `{N}` and `{NAME}` filled in:

```
Read the following files fully before doing anything else:

1. CLAUDE.md — the operational reference (MUST read entirely)
2. FragChain_Module_Specifications.md — focus on Module M{N} ({NAME})
3. Any MODULE_X_DONE.md files for modules M{N} depends on
   (check the dependency graph in the specs)

We are building Module M{N}: {NAME}.

Scope is exactly what's defined in the module spec — no more, no less.
Do not implement features that belong to other modules.
Do not skip steps in the done criteria.

Before you start writing code:
1. Confirm you've read CLAUDE.md and the relevant section of the module spec
2. List the schema additions this module makes
3. List the API endpoints this module exposes
4. List the interfaces this module exposes to other modules
5. Note any clarifying questions before you begin

When you finish:
1. Run through the done criteria one by one and verify each
2. Write MODULE_{N}_DONE.md with: what was built, deviations from spec,
   known TODOs, what dependent modules need to know
3. Stop. Do not start the next module.
```

---

## The MODULE_N_DONE.md Template

Every module session must end by writing this file:

```markdown
# MODULE_M{N}_DONE — {NAME}
**Built:** {date}
**Effort actual:** {S/M/L}, {hours spent}
**Status:** complete | partial | blocked

## What was built

{Brief paragraph: what now exists that didn't before}

## Deviations from spec

{Any places where what was built differs from the module spec, and why.
If none, write "None."}

## Known TODOs

{List any deferred work, future improvements, or things explicitly left
for follow-up modules}

## Interfaces this module exposes

{Copy from spec — confirm these are real and callable}

## What dependent modules need to know

{Key things for the next module's session: file paths, function signatures,
schema fields, gotchas}

## Test status

{What's tested, what isn't, what test files exist}

## Outstanding questions

{Anything that came up during build that needs human decision later}
```

This file is a contract handoff between sessions. The next session reads it to understand what it can rely on.

---

## Recommended Module Build Order

For a solo or small-team build, follow the critical path:

### Week 1-2 — Foundation (Phase 1)
- **Session 1:** M1 Foundation (L effort, may need 2 sessions)
- **Session 2:** M2 TLP & Embargo + M3 Identity Placeholder (combine — both small, both touch users table)
- **Session 3:** M4 Connector Framework
- **Session 4:** M5 LLM Provider Framework

✅ **Checkpoint:** Platform boots, plugin discovery works, LiteLLM connection healthy.

### Week 3-4 — Data In (Phase 2)
- **Session 5:** M6 Intel Ingestion (L, may need 2 sessions for live + historical paths)
- **Session 6:** M7 Commons Sources

✅ **Checkpoint:** CVE webhook works, historical import works, commons can be configured.

### Week 5-6 — AI Infrastructure (Phase 3)
- **Session 7:** M8 Vector Store
- **Session 8:** M9 Prompt Management

✅ **Checkpoint:** Qdrant collections seeded, prompts manageable via API.

### Week 7-8 — Synthesis (Phase 4)
- **Session 9:** M10 Chain Schema & Ground Truth (small, can combine with start of M11)
- **Session 10:** M11 Chain Synthesis (L, may need 2 sessions)

✅ **Checkpoint:** CVE-2026-43284 generates a chain matching ≥80% of ground truth.

### Week 9-11 — Coverage & Rules (Phase 5)
- **Session 11:** M12 Sigma Integration
- **Session 12:** M13 Logsource Profiles (small, combine with M12 if time allows)
- **Session 13:** M14 Coverage Mapper
- **Session 14:** M15 Rule Generator
- **Session 15:** M16 Review Queue + M17 Rule Evaluations

✅ **Checkpoint:** Generated rules in queue, approval creates Git PR.

### Week 12-13 — Frontend Core (Phase 6, first half)
- **Session 16:** M18 Frontend Core
- **Session 17:** M19 Dashboard
- **Session 18:** M20 CVE Explorer + Chain Viewer

### Week 14-15 — Frontend Polish (Phase 6, second half)
- **Session 19:** M21 ATT&CK Matrix UI (L)
- **Session 20:** M22 Sigma Library + Review Queue UI
- **Session 21:** M23 Import Manager UI
- **Session 22:** M24 Settings + Marketplace UI

✅ **Checkpoint:** Full end-to-end UI works.

### Week 16+ — Ecosystem (Phase 7-8)
Connectors (M25-M34) build in **separate repos** — one session per connector. These can be done in parallel by different people or AI agents since they're independent packages.

Then M35 (Commons Repo), M36 (Notifications), M37 (Documentation).

---

## Parallelization Tips

Once M4 (Connector Framework) and M5 (LLM Provider) are done, you can split tracks:

```
Track A (Backend pipeline):  M6 → M7 → M8 → M11 → M14 → M15 → M16
Track B (UI):                M18 → M19 → M20 → M21 → M22 → M23 → M24
Track C (Connectors):        M25–M34 (one session each, separate repos)
```

If you have multiple Claude Code sessions running on different machines/projects, you can work tracks in parallel. Just maintain a shared `MODULE_*_DONE.md` directory so each track sees the others' contracts.

---

## Managing Long Modules (L effort)

For modules estimated 8-14 days of effort, one session may not be enough. Strategy:

**Session A:** Build the backbone — schema, core protocols, basic implementation.
End with MODULE_N_PARTIAL.md noting what's done and what's next.

**Session B (fresh session):** Read PARTIAL file, read CLAUDE.md, continue with second half.
End with MODULE_N_DONE.md.

Larger modules in this spec: M1 (Foundation), M6 (Intel Ingestion), M9 (Prompt Management), M11 (Chain Synthesis), M14 (Coverage Mapper), M15 (Rule Generator), M21 (ATT&CK Matrix UI), M22 (Sigma Library + Queue).

---

## Common Pitfalls (And How to Avoid Them)

**Pitfall: Claude Code builds too much.**
Symptom: You asked for M2 but it also started implementing M4.
Fix: The opening prompt explicitly says "do not implement features that belong to other modules." If it happens anyway, stop the session and start over.

**Pitfall: Schema drift between sessions.**
Symptom: Module N expected a field that Module M-1 didn't add.
Fix: Module spec is the source of truth for schema. Both modules' specs must agree before either builds. If they don't, update the spec doc first, then build.

**Pitfall: Done criteria not actually checked.**
Symptom: MODULE_N_DONE.md says complete but something doesn't work.
Fix: The closing prompt requires Claude to walk through done criteria one by one. If it just writes "done" without proof, push back: "Show me the test output for each done criterion."

**Pitfall: Hardcoded values that should be configurable.**
Symptom: Module M11 has `commons_url = "github.com/fragchain/..."` hardcoded.
Fix: CLAUDE.md's "Never Do List" forbids hardcoding sources. If you spot it, fix it before closing the session.

**Pitfall: DarkOps drift.**
Symptom: UI module uses inline styles instead of DarkOps tokens.
Fix: M18 sets the pattern. All later UI modules reference DarkOps CSS variables only.

---

## When to Update the Specs

If during a build session you discover the spec is wrong, incomplete, or conflicts with reality:

**Stop building. Update the spec first.** Then resume the session with the updated spec.

The spec is the source of truth. Code that diverges from the spec creates technical debt and breaks future sessions.

Updates to the spec should be small commits with clear messages:
- `spec: M6 ingestion - add missing webhook retry logic`
- `spec: M11 synthesis - clarify commons-check priority order`

---

## M1 KICKOFF PROMPT (READY TO PASTE)

Copy everything in the code block below and paste it into a fresh Claude Code session. Make sure `CLAUDE.md` and `FragChain_Module_Specifications.md` are in the project root before you start.

````
Read the following files fully before doing anything else:

1. CLAUDE.md — the operational reference (MUST read entirely)
2. FragChain_Module_Specifications.md — focus on Module M1 (Foundation)
   No predecessor module to consult.

We are building Module M1: Foundation.

Scope is exactly what's defined in the M1 spec — project scaffold, base
schema, Alembic, FastAPI app shell, React app shell with DarkOps integration,
Docker Compose for Server 3 (including Qdrant local), and the auth scaffolding.

Specifically build:

PROJECT SCAFFOLD
- Full directory structure per CLAUDE.md Section 17
- pyproject.toml (Python 3.12, FastAPI, SQLAlchemy 2.0 async, Alembic,
  Celery, Pydantic v2, asyncpg, aiohttp, structlog, python-jose, passlib,
  minio, qdrant-client, openai, pySigma)
- package.json (React 18, TypeScript, Vite, React Router, axios, dayjs)

DOCKER COMPOSE (Server 3 — includes Qdrant now)
- Services: nginx, fragchain-api, fragchain-worker, fragchain-beat,
  fragchain-ui, postgres, redis, minio, qdrant, flower
- Networks: internal (everything except nginx), app (nginx + api + ui)
- Only nginx exposes ports 80/443
- Named volumes: postgres_data, redis_data, minio_data, qdrant_data
- IMPORTANT: NO Ollama, NO LiteLLM in this Compose — those are external on Server 1

.ENV.EXAMPLE
- All variables from CLAUDE.md Section 4 plus:
  - APP_ENV, APP_SECRET_KEY, APP_HOST
  - POSTGRES_*, REDIS_PASSWORD, MINIO_*
  - JWT_SECRET, JWT_EXPIRY_HOURS
  - LITELLM_BASE_URL, LITELLM_API_KEY, LITELLM_CHAT_MODEL, LITELLM_EMBEDDING_MODEL
  - QDRANT_HOST (= "qdrant"), QDRANT_PORT, QDRANT_API_KEY
  - MAX_LIVE_CVE_PER_HOUR, MAX_HISTORICAL_CVE_PER_DAY, AUTO_PROCESS_KEV

ALEMBIC MIGRATIONS
Single initial migration with these tables (base — others added by their modules):
  - system_config (key, value JSONB, description, updated_by, updated_at)
  - audit_log (id, entity_type, entity_id, action, actor, before/after JSONB, ip, timestamp)
  - users (id, username, email, hashed_password, tier='authenticated',
           clearance_level='tlp:green', created_at, last_login)
Migration must run cleanly: `alembic upgrade head`

FASTAPI APPLICATION
- fragchain/config.py: pydantic-settings reading .env
- fragchain/api/main.py: app init, CORS, lifespan, router registration
- fragchain/db/models.py: SQLAlchemy 2.0 async models for above tables
- fragchain/db/session.py: async session factory
- Routers:
  - GET /api/v1/health — checks postgres, redis, minio, qdrant, litellm
  - GET /api/v1/version
  - POST /api/v1/auth/login — JWT issue using passlib bcrypt + python-jose
- Structured logging via structlog (JSON output)

CELERY SCAFFOLD
- fragchain/worker/celery.py: Celery app, Redis broker, beat schedule
- Task stubs (just log + return) for: ingest_cve, stage_historical_cves,
  enrich_cve, embed_source_document, synthesize_chain, map_coverage,
  generate_rules, enforce_budget, release_embargoed_content,
  refresh_matrix_cache, sync_commons_source

REACT FRONTEND
- Copy ALL CSS from the DarkOps v3 design system into
  frontend/src/styles/darkops.css (strip HTML demo content, keep CSS)
- Import JetBrains Mono + DM Sans from Google Fonts in index.html
- Implement the v3 layout pattern: slim 48px topbar + collapsible 220px sidebar
- App.tsx with React Router covering all 10 screen routes:
  /login, /dashboard, /cves, /chains/:cve_id, /matrix, /queue,
  /rules, /imports, /prompts, /settings, /identity
- Topbar component with:
  - FRAGCHAIN logo (mono, accent on second word)
  - Global search input with ⌘K hint
  - Service status indicators (LiteLLM, Qdrant, OpenCTI, Sigma)
    - These show health-colored dots (green/amber/red)
    - For v1 stub: hardcode as ok states, real health checks come later
  - Notifications bell icon (placeholder)
  - User menu (avatar + name + logout)
- Sidebar component with section grouping per CLAUDE.md Section 16:
  - OVERVIEW: Dashboard
  - INTEL: CVEs, Chains, ATT&CK Matrix
  - DETECT: Review Queue, Sigma Library
  - AUTOMATION: Imports, Prompts
  - CONFIG: Connectors, Commons, Settings, Identity
  - Collapse button at the bottom
  - Active item highlights with accent-colored left border
  - Count badges supported on nav items (e.g., Review Queue: 7)
- Sidebar collapsible state persists in localStorage
- Identity screen shows the 501-style placeholder message
- All screens render shell only (correct DarkOps layout, placeholder content)

NGINX
- nginx/nginx.conf with security headers, gzip, rate limit zones
- nginx/conf.d/fragchain.conf: HTTPS vhost
  - /api/ → fragchain-api:8000
  - /ws/ → fragchain-api:8000 (WebSocket headers)
  - / → fragchain-ui:3000
- Self-signed cert generation documented in README.md (do NOT generate, just document)

README.md
- Prerequisites, .env setup, SSL cert generation command,
  `docker compose up` instructions

DO NOT BUILD in this module:
- Any data ingestion logic, OpenCTI integration
- Any LLM calls
- Any Qdrant operations beyond verifying connectivity in /health
- Any business logic for chains, rules, coverage, sigma
- Any frontend data fetching — screens are shell only
- Identity verification logic — endpoints exist but return 501
- TLP enforcement middleware — schema is ready for it, middleware itself is M2
- Connector discovery — that's M4

DONE CRITERIA (verify each before writing docs/MODULE_M1_DONE.md):
- `docker compose up` starts all services with no errors
- All container health checks pass
- `GET /api/v1/health` returns 200 with all services "ok"
- `POST /api/v1/auth/login` with seeded admin user returns JWT
- `alembic upgrade head` runs cleanly on fresh postgres
- All 10 frontend routes load at https://localhost
- Topbar renders: FRAGCHAIN logo, search box, 4 service status indicators,
  notifications bell, user menu
- Sidebar renders 5 sections (OVERVIEW, INTEL, DETECT, AUTOMATION, CONFIG)
  with nav items grouped under each
- Sidebar collapse button toggles between 220px and 56px width
- Collapsed sidebar shows icons only with tooltips on hover
- Active nav item shows accent-colored left border
- DarkOps styling visible (dark bg, cyan accents, JetBrains Mono on monospace data)
- `npm run build` succeeds with no TypeScript errors
- Qdrant container is reachable from fragchain-api container
- LiteLLM connection test in /health works against Server 1
- Service status indicators in topbar reflect actual /health response

When done, write docs/MODULE_M1_DONE.md as specified in the build workflow guide.

Begin by confirming you've read CLAUDE.md and the M1 module spec, then list
the schema, API surface, and any clarifying questions before writing code.
````

---

## After M1 Lands

You'll have a working scaffold. The next session is M2 (TLP & Embargo) — start a fresh Claude Code conversation, paste the M2 kickoff prompt (adapt the template above), and continue.

The pattern repeats for every module. The opening prompt is generic; only the module number and specific scope notes change between sessions.

---

## Final Tips

**Commit between every module.** A clean git commit per module makes rollback easy if something goes wrong later.

**Read MODULE_N_DONE.md files when starting dependent modules.** They contain real handoff information your next session needs.

**If a module starts going sideways, stop and start over.** Better to lose 2 hours and restart cleanly than to inherit confused code.

**Use the Module Specifications doc as the bible.** When in doubt, the spec wins. Update the spec if it's wrong; don't deviate silently.

**Don't skip the done criteria check.** "Looks done" is not "verified done." Run every check.

---

*This document is your operating manual. Keep it open during build sessions.*
