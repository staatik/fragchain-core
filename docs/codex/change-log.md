# Codex Change Log

## 2026-06-11 — Wave 1b — frontend credibility

### Changed

Eight root-caused fixes from the 2026-06-10 platform-architecture review
(Appendix C) and product-viability review (Appendix B), one commit each.
Frontend-only; no backend, schema, or endpoint changes.

- **API client unification:** `frontend/src/api/assessments.ts` had defected
  to native fetch and lost the global 401→/login redirect, the 15s timeout,
  and the `detailFromError` error shape. It now routes through the shared
  axios `api` instance; exported signatures/return types unchanged;
  `getDetectability`/`getArtifactPlan` keep null-on-404 via an
  `axios.isAxiosError` guard. `CreateAssessmentRequest.cve_id` tightened
  from `?: string | null` to required `string` to match the backend
  contract (`AssessmentCreateRequest.cve_id: uuid.UUID`).
- **Error surfacing:** runLoop, gate override, generateArtifact (Generate +
  Retry), and closeAssessment previously swallowed rejections silently. The
  workspace now toasts failures via the ReviewQueue idiom (`useToast` +
  `detailFromError`); close no longer navigates away on failure.
- **Bug — dead empty-state link:** the Assessments empty state linked to
  `/assessments/new`, which fell into the `:id` route and rendered "not
  found". It now opens the same `CreateAssessmentModal` as the header button.
- **Bug — gate-recovery label lie:** "Add intel & re-run Loop 2" only
  focused the paste textarea. Split into "Add intel" (focus only) and
  "Re-run Loop 2" (invokes the loop-2 run). The `document.querySelector`
  focus reach replaced with a ref threaded through SourcesCard →
  PasteSourceForm.
- **Bug — create-modal CVE contract:** the "CVE ID" field's placeholder was
  a UUID, the Explorer pre-filled the textual form, and kind=cve_id made
  the analyst type the CVE twice. The modal now takes the textual CVE once,
  resolves it to the row UUID via `GET /cves/{id}` (helpful guidance on
  404), derives the cve_id trigger value from it, and labels ticket/PSIRT
  trigger fields per kind.
- **Fake affordances removed:** hardcoded sidebar badges (Review Queue "7",
  Prompts "A/B") and the handler-less topbar search input + ⌘K hint. The
  queue badge now shows the real pending count (`listQueue` status=pending
  limit=1 → `total`; fetch failure → no badge); search is hidden until it
  exists.
- **Failed-run diagnostics:** a failed loop run now renders its `error`
  field in a `role="alert"` block (GeneratedArtifactsCard's failed-row
  pattern). Also fixed the stale version selection: LoopCard snaps to the
  newest run when a new version lands, preserving explicit older-version
  picks across refetches that don't change the newest run.
- **Status visibility:** the workspace header renders `wsState` as a
  Dashboard-style status dot ("live" / "connecting" / "polling"); a running
  LoopCard shows a Spinner, ticking elapsed seconds, and "typically
  1–2 min" copy.

### Tests

- 24 new/updated vitest cases across `api/assessments.test.ts` (rewritten
  from fetch-spying to axios-instance spying), `AssessmentWorkspace.test.tsx`
  (toasts, WS indicator, focus ref), `AssessmentsList.test.tsx` (modal not
  navigation), `GateBanner.test.tsx` / `LoopCard.test.tsx` (honest buttons,
  failed-run alert, version selection, running indicator),
  `CreateAssessmentModal.test.tsx` (payload shape per trigger kind, 404
  guidance), `Sidebar.test.tsx` (live count, graceful failure, no fakes),
  and new `Topbar.test.tsx` (search absent). Full suite: 24 files /
  114 tests green; `tsc --noEmit` clean.

### Risks / known limitations

- Error messages now flow through axios shapes; code that read
  `Error.message` from the old fetch-thrown errors gets axios's generic
  message unless it uses `detailFromError` (workspace + modal updated; the
  hook's workspace-level `error` string is now the axios message).
- The sidebar queue count fetches once per Sidebar mount — it does not
  live-update on queue changes; a future queue WS event surface can wire it.
- The create modal still uses a native `<select>` for trigger kind and the
  workspace cards remain unstyled — §16 conformance (review action 3) is
  out of this wave's scope.

### Integration-review fixes (follow-up commit)

- **detailFromError at degraded sites:** `PasteSourceForm`, `ExistingChainOffer`,
  `useAssessment` (refetchAll), and `useAssessments` still used
  `e instanceof Error ? e.message : String(e)`, which rendered axios's generic
  "Request failed with status code NNN" instead of the backend `detail`. All
  four now import and use `detailFromError` from `api/client`.
- **Delete-source failure feedback:** `SourcesCard.onDelete` was wired directly
  to `a.deleteSource` with no error handling. The workspace now wraps it in
  `handleDeleteSource` using the same toast + `detailFromError` idiom as the
  other handlers.
- **Gate banner re-run gating:** `GateBanner`'s "Re-run Loop 2" button was
  always clickable even on closed assessments (while the card's Run button was
  disabled). A new optional `rerunDisabled` prop on `GateBanner` (defaulting
  `false`) is set to `!props.runnable` in `LoopCard`, so the banner respects
  the same runnable state as the header button.
- 3 new vitest cases: PasteSourceForm shows backend detail on axios-shaped 409;
  workspace toasts backend detail on rejected deleteSource; LoopCard gate-banner
  Re-run is disabled when `runnable=false`. Suite: 25 files / 117 tests green;
  `tsc --noEmit` clean.

### Next

- Doc-sync: any doc quoting the old two-field create modal, the
  `/assessments/new` link, or the sidebar placeholder-badge note
  (`Sidebar.tsx` M1 comment) is stale; `CreateAssessmentRequest.cve_id` is
  now documented as required.
## 2026-06-11 — Wave 1a — backend reliability (P0/P1)

### Changed

Nine fixes from the platform architecture review, on branch
`claude/wave1a-backend-reliability` (T1–T9):

- **T1 — `GATE_MIN_CATEGORIES` is now a real setting.** CLAUDE.md §12.1
  documented it, but it existed only as hardcoded `=3` constructor defaults
  that neither factory passed. Now in `fragchain/config.py` + `.env.example`
  and propagated through both the API and worker orchestrator factories to
  the detectability gate and Loop 2's gap-pass threshold.
- **T2 — Loop 2 per-pass timeout configurable.** The hardcoded
  `_PASS_TIMEOUT_S = 60.0` fired before the configurable
  `LLM_STRUCTURED_TIMEOUT_SECONDS` (120s) ever applied, silently defeating
  the Plan A timeout fix — the live cause of observed loop timeouts on slow
  backends. New setting `LOOP2_PASS_TIMEOUT_SECONDS` (default 150s; must
  exceed the structured timeout so the inner timeout + repair budget
  governs).
- **T3 — one active loop run per (assessment, loop) enforced in the DB.**
  Migration `0026` resolves existing duplicates (keep highest version
  active, demote the rest to `superseded`) and replaces the non-unique
  partial index from `0017` with unique `uq_assessment_loop_run_active`;
  also declared in the ORM so `create_all` test DBs match prod metadata.
- **T4 — failed loop runs no longer advance assessment state.**
  `execute_run` previously assigned `next_state_after_loop` unconditionally,
  so a failed Loop 1 reached `loop1_done` with no output and a failed Loop 3
  reached `loop3_done` (which `can_close` accepts). State now advances only
  on `succeeded` / `gate_failed`.
- **T5 — supersede-at-success.** `begin_run` previously demoted the prior
  active row and invalidated downstream runs BEFORE execution, so a
  transient LLM failure orphaned the prior good output and broke the active
  detectability/plan joins. New runs start `is_active=false`; demotion +
  activation + downstream invalidation happen only when the run finalizes
  with real output. The already-running guard keys on `status='running'`.
- **T6 — stale in-flight reaper.** Both 202 endpoints commit the in-flight
  row then dispatch; a lost broker message left `assessment_loop_run`
  `'running'` / `generated_artifacts` `'generating'` forever, 409-blocking
  the assessment. Beat task `assessment.reap_stale_inflight` (every 5 min,
  `fragchain/worker/tasks/reaper.py`) fails rows older than
  `STALE_INFLIGHT_MAX_SECONDS` (default 1800s) with the
  only-flip-if-still-in-flight discipline and emits the completion events.
- **T7 — Redis pub/sub event bridge (worker → API WS).** The EventBus is
  per-process and the worker owns nearly the entire assessment event
  surface, so browser WS subscribers never received worker events.
  `emit_event` now also publishes each event to Redis channel
  `fragchain.events` (sync redis-py client, best-effort, never raises, 30s
  circuit breaker → warn-once local-only degradation when Redis is down),
  tagged with a per-process `origin`. A new `EventBridge` subscriber
  (`fragchain/notifications/bridge.py`), started/stopped in the API
  lifespan, re-emits foreign-origin events into the local bus — skipping
  its own origin and going straight to `bus.emit` (never back through
  `emit_event`) so events can't ping-pong between processes; reconnects
  with capped exponential backoff and cancels cleanly on shutdown. Events
  deliberately keep their existing shape (no tlp/entity typing added —
  owner decision pending on REST-vs-WS access asymmetry).
- **T8 — cost visibility repair.** (a) `structured_complete` now
  accumulates per-call cost from `LLMResponse.usage.cost_usd` into
  `StructuredResult.cost_usd` — across repair attempts and across voted
  samples (failed-validation attempts count; they cost real money).
  (b) `AssessmentLoopRun.model` / `cost_usd` are written at finalize: loops
  surface an `_llm` block (model + summed cost) in their output — Loop 1
  from its StructuredResult, Loop 2 summed over bulk + gap passes, Loop 3
  from new `GenerationReport.model` / `cost_usd` (RuleGenerator accumulates
  per-attempt cost in `_call_with_retries`, per-rule in
  `GeneratedRule.cost_usd`) — and the orchestrator copies it onto the run
  columns. (c) `LiteLLMProvider._record_interaction` mirrors `entity_id`
  into the previously-dead `llm_interactions.assessment_id` FK column when
  `entity_type == 'coverage_assessment'`.
- **T9 — worker startup task-registration assertion.** On `worker_ready`
  (fires exactly once, after the `include` imports ran) the worker asserts
  `EXPECTED_TASKS` (`assessment.run_loop`, `assessment.embed_source`,
  `assessment.generate_artifact`, `assessment.reap_stale_inflight`) ⊆
  registered task names, logging `worker.tasks.registration_missing` and
  shutting down via `celery.exceptions.WorkerShutdown` (a `SystemExit`
  subclass that Celery's signal dispatch cannot swallow) when expected
  tasks are missing — a half-registered worker now refuses to start
  instead of silently rejecting dispatches (the Phase 2b registration-gap
  failure mode).
- **Integration-review fixes (post-T1–T9):** (1) the T9 assertion now
  raises `WorkerShutdown` instead of `RuntimeError` — Celery's
  `Signal.send` wraps receivers in `except Exception`, so the original
  raise was logged and swallowed; (2) the T6 reaper flips rows via atomic
  conditional UPDATEs (`WHERE status='running'`/`'generating'`) and only
  counts/emits for rows actually flipped, closing a lost-update race that
  could clobber a concurrently finalized `succeeded`/`gate_failed` row to
  `failed`; (3) `use_as_start` demotes any existing active Loop 1 row
  (flush, then insert) so the 0026 partial unique index no longer 500s
  `POST /assessments/{id}/use-existing-chain` on double-click or after a
  real Loop 1 run.

### Tests

- T1–T6: gate-settings, loop2 timeout, migration-0026 backfill,
  no-state-advance, supersede-at-success, and reaper suites added with the
  original commits (`tests/assessments/test_gate_settings.py`,
  `tests/assessments/test_models.py` for the 0026 migration tests,
  `tests/worker/test_reaper.py`, plus orchestrator additions).
- T7: `tests/test_event_bridge.py` (7 tests — publish-on-emit carries
  origin + classification fields, emit never raises when Redis is down,
  self-origin skipped, foreign-origin re-emitted with tlp/entity restored,
  malformed messages dropped, re-emit never republishes, lifespan
  start/stop task lifecycle with mocked redis).
- T8: 3 structured cost tests, `_llm` metadata tests for all three loops,
  generator cost/model accumulation test, 2 orchestrator finalize tests,
  2 provider `assessment_id` wiring tests.
- T9: 3 unit tests on the `worker_ready` handler (missing task raises,
  full registry passes, expected-set coverage).
- Full suite: 1076 passed, 8 failed — exactly the 8 known pre-existing
  failures (5 in `tests/api/test_ws_tickets.py` + `test_ws_tlp_filter.py`,
  3 in `tests/test_vector.py`). No new failures.

### Risks / known limitations

- T7 publishes synchronously inline in `emit_event` (1s socket timeouts);
  a Redis outage costs at most ~1s once per 30s backoff window per
  process. Bridged events restore tlp/entity_id so F-010 WS filtering
  still applies, but event payloads remain untyped by design.
- T8 cost columns are advisory: Loop 3 calls whose rule was ultimately
  skipped or raised mid-generation are not counted in the report sum, and
  providers that report no per-call cost yield 0.0/NULL.
- T9's `EXPECTED_TASKS` list is hardcoded by design — adding a new
  assessment task requires extending it (regression-guarded by
  `tests/worker/test_task_registration.py`).
- T8 attribution gap: Loop 3 rule-generation LLM interactions are logged
  with `entity_type='chain_ttp'`, so the `llm_interactions.assessment_id`
  mirror (which keys on `entity_type='coverage_assessment'`) misses them —
  the run's `cost_usd` column does capture them. Follow-up: thread the
  assessment id through `RuleGenerator`.

### Next

- CLAUDE.md §12.1/§12.2 updates for the new settings
  (`GATE_MIN_CATEGORIES` wiring, `LOOP2_PASS_TIMEOUT_SECONDS`,
  `STALE_INFLIGHT_MAX_SECONDS`), migration `0026`, supersede-at-success
  semantics, the event bridge, cost-visibility columns, and the worker
  startup assertion — deferred to the owner per workstream rules.
## 2026-06-10 — Wave 1c — documentation truth + mechanical-truth guards

### Changed

- **Behavior before:** the docs made checkably false claims (platform-review
  Appendix D): `docs/litellm-setup.md` was referenced by README + CLAUDE.md
  §4.1 but didn't exist; CLAUDE.md §17 described a pre-pivot tree (no
  `fragchain/assessments/`, nonexistent `api/routers/matrix.py`,
  `api/middleware/auth.py`, `notifications/channels.py`); §15 claimed 3
  seeded prompts (actual: 10); §12.2 claimed `ChainGenerator` had "no caller
  in the active flow" while `POST /cves/manual` (live ManualCveAdd screen),
  `POST /cves/{id}/resynthesize`, and `ingest/enrichment.py` all dispatch
  `synthesize_chain`; §18 listed unused `aiohttp`; six architecture docs
  referenced moved/never-created paths. Nothing enforced any of it.
- **Behavior after (no runtime behavior change):** CLAUDE.md bumped to
  **2.9** with all of the above corrected; `docs/litellm-setup.md` written
  (env vars verified against `fragchain/config.py` / `.env.example`; worked
  Ollama/OpenAI/Anthropic LiteLLM examples; health-check curl); the six
  architecture-doc path references fixed with minimal edits. Two new
  mechanical-truth guards: `scripts/verify_doc_claims.py` (verifies every
  backtick/href repo-path reference in CLAUDE.md + `docs/architecture/*.md`
  exists and every backticked ALL-CAPS settings name in CLAUDE.md is real,
  with visible commented allowlists; exit 0/1) and
  `tests/test_dormancy_claims.py` (grep-level assertions that each §12.2
  dormancy claim still matches the wiring — e.g. `synthesize_chain` dispatch
  sites are exactly the documented set).
- Dead code removed (each re-verified by grep before removal): Python deps
  `aiohttp`, `email-validator`, `python-multipart`; npm dep
  `@codemirror/merge` (+ lockfile); 11 dead frontend API client functions
  (`getChain`, `validateChain`, `rejectChain`, `contributeChain`,
  `fetchCommonsStatus`, `reprocessCve`, `usePreset`, `getImport`,
  `recomputeMatrix`, `getProfile`, `assignQueueItem`). Deleting
  `contributeChain`/`validateChain` makes explicit that the CLAUDE.md §7
  "Contribute to Commons" UI flow does not exist yet — the backend
  validate/reject/contribute endpoints remain live.

### Tests

- New: `tests/test_verify_doc_claims.py` (runs the guard script via
  subprocess, asserts exit 0) and `tests/test_dormancy_claims.py` (9 static
  assertions; failure messages say "§12.2 claim drifted — update CLAUDE.md
  §12.2 or this test, deliberately").

### Risks / known limitations

- The doc guard checks path existence and settings names only — it cannot
  verify prose semantics; the dormancy guard covers the §12.2 allowlist, not
  every doc claim.
- `GATE_MIN_CATEGORIES` sits in the guard's settings allowlist because a
  parallel Wave-1 backend workstream is promoting it to a real setting;
  remove the allowlist entry once that lands. CLAUDE.md §12.1's
  GATE_MIN_CATEGORIES sentence was deliberately left untouched, and the new
  backend work is intentionally undocumented here (doc-sync happens at the
  merge train).
- `frontend/node_modules` was absent in this worktree, so the frontend
  deletions were verified by grep (zero non-test callers; kept shared types
  confirmed still used) rather than `tsc` — the W1 merge train runs the
  frontend suite.

### Next

- Phase 2c flip evidence gathering continues unchanged; consider wiring
  `scripts/verify_doc_claims.py` into CI alongside the test hook.

## 2026-06-10 — CVE Explorer: assessment badging + analysis read access

### Changed

- **Behavior before:** the CVE Explorer's Assessment and Detectability columns
  were absent; the Rules column rendered an always-empty field because
  `rule_count` was never populated; clicking a CVE revealed no assessment
  summary.
- **Behavior after:** `GET /cves` now embeds a per-row `assessment` summary
  (`CveAssessmentSummary`: assessment_id, state, detectability class +
  confidence, active artifact counts by status) assembled by the new advisory
  helper `fragchain/assessments/cve_summary.py` in batched queries over the
  returned page only. `rule_count` is keyed by `sigma_rules.cve_id`, excluding
  deprecated rules. The Explorer gains two new columns (Assessment state badge,
  color-coded Detectability badge); the CVE side panel gains a read-only
  `CveAssessmentSection` (state + rationale + active artifacts + "Open
  assessment →" link) via lazy advisory fetches over the existing per-assessment
  endpoints. Shared display maps extracted to
  `frontend/src/components/assessments/display.ts` so Explorer badges and
  workspace cards cannot drift. No new endpoints, no migrations, no WS
  dependency.
- Access filter F-002: inaccessible assessments render exactly like unassessed
  CVEs — no data leakage. Failures in the advisory helper degrade to no badges,
  never a 500.

### Tests

- New backend: 8 helper unit tests (`tests/assessments/test_cve_summary.py` —
  batch assembly, F-002 filter, advisory degradation, rule-count grouping),
  3 router tests (`tests/test_cves_list_assessment_summary.py` — summary
  injected per row, null/zero without assessment, page-only computation) —
  11 new backend tests (mock-based; SQL filter semantics such as
  deprecated-rule exclusion are asserted at the statement level only).
- New frontend: 6 badge render tests + 4 section render tests — 10 new
  vitest cases.

### Risks / known limitations

- Advisory degradation is silent: a backend error in `cve_summary` hides
  badges without any UI indicator — consistent with the detectability/artifact
  pattern but means operator monitoring (structlog events) is the only signal.
- Four extra batched queries per CVE list page (assessments, detectability
  join, artifact counts, sigma-rule counts) plus per-row access checks for
  non-owned assessments; acceptable at typical page sizes, worth revisiting
  if list pages grow large.
- Practical visibility (final-review finding): `_check_access` has no
  general TLP read path for non-embargoed rows, so badges show only for
  the assessment's creator and admin-tier users today. Fine for the
  current single-team deployment; widening visibility is a follow-up
  decision (recorded in the spec).

### Next

- None — feature complete. Lands on PR #76.

## 2026-06-10 — Phase 2b: On-demand non-Sigma artifact generation

### Changed

- **Behavior before:** the router recommended `mitigation_plan` /
  `analyst_research_task` / `telemetry_contract`, but nothing could generate
  them — the recommendations were display-only on `ArtifactPlanCard`.
- **Behavior after:** each of the three non-Sigma types is generatable on
  demand. `POST /assessments/{id}/artifacts` runs a sync precheck
  (`begin_generation`: supersession, plan provenance via the shared
  `active_plan_stmt`, 409-mapped already-generating guard), commits a
  `status='generating'` row, dispatches the Celery task
  `assessment.generate_artifact`, and returns **202** + the row;
  `GET /assessments/{id}/artifacts` lists all rows newest-first. Generation
  is **not** gated on assessment state or on the plan — `plan_recommended`
  records the advisory signal (spec decision 6); compatibility mode and
  Loop 3 are unchanged.
- New table `generated_artifacts` (migration `0025_generated_artifacts`):
  one ACTIVE row per `(assessment_id, artifact_type)` (partial unique index
  `uq_generated_artifacts_active`); regenerate supersedes (deactivate prior
  active, insert `version=max+1`); `content` is schema-validated JSONB
  (`GeneratedArtifactContent`: title/summary/headed sections +
  assumptions/limitations/references/confidence, strict `extra='forbid'`);
  `validation_status` defaults `not_validated` (Phase 3 territory).
- `ArtifactGenerator.generate` (`fragchain/assessments/artifact_generation.py`)
  is headless-callable: bounded context from active Loop 1/2 outputs +
  detectability classification + artifact plan, one `structured_complete`
  call; advisory — marks its own row `failed`, never raises. The worker task
  is idempotent on non-`generating` rows with a fresh-session
  finalize-failed backstop, and emits `assessment.artifact.generated`.
- **Celery registration fix (affects Plan A):** review found
  `fragchain/worker/tasks/__init__.py` never imported the assessment task
  modules, so `run_assessment_loop`, `embed_assessment_source` (and the new
  `generate_artifact`) were **never registered with the Celery worker** —
  dispatched messages were rejected as unregistered. The package now
  side-effect-imports all assessment tasks; regression-guarded by
  `tests/worker/test_task_registration.py` (subprocess-isolated so a stale
  in-process registry can't mask it).
- New: three seeded prompt task_types
  (`prompts/{mitigation_plan,analyst_research_task,telemetry_contract}_v1.{system,user}.txt`
  + `scripts/seed_prompts.py` DEFAULTS), three new `InteractionType`
  members, Generate/Re-generate buttons on recommended non-Sigma artifacts
  in `ArtifactPlanCard`, `GeneratedArtifactsCard` below it (plain React text
  nodes only — no markdown rendering), `useAssessment` artifacts state +
  `generateArtifact` + WS refetch on `assessment.artifact.generated` +
  polling fallback while `generating`.

### Tests

- New backend: `tests/assessments/test_artifact_generation_schemas.py` (9),
  `tests/assessments/test_artifact_generation.py` (16 — begin_generation
  supersession/guard/provenance, generator context/failure-advisory),
  `tests/worker/test_generate_artifact.py` (5 — idempotency, backstop,
  event), `tests/worker/test_task_registration.py` (1, subprocess), plus 9
  added across `test_models.py` / `test_router.py` /
  `test_notifications_event_types.py` — 38 new backend tests.
- New frontend: 12 vitest cases across the artifacts api client,
  `useAssessment`, `ArtifactPlanCard`, `GeneratedArtifactsCard`, and
  workspace integration.

### Risks / known limitations

- A concurrent duplicate `POST /assessments/{id}/artifacts` race surfaces as
  a 500 `IntegrityError` instead of a 409 — correctness is preserved by the
  partial unique index; the same gap exists in the loop-run endpoint.
- No "generation started" WS event — only completion (the spec defined a
  single event); the UI relies on the 202 response + polling for the
  in-flight state.
- `.delay()` raising **after** commit (broker down) strands a `generating`
  row — same accepted exposure as Plan A loop dispatch.

### Next

- Deploy: rebuild containers, `alembic upgrade head` (0025), re-run
  `scripts/seed_prompts.py` for the three new task_types.
- Collect router divergence data on real assessments; then Phase 2c (active
  gating) / Phase 3 (validation states) per ADR-0004 §5.

## 2026-06-10 — Plan A: Async loop execution + configurable LLM timeouts

### Root cause (investigated, not assumed)

Live loop runs 504'd. Measured the real layers: the LiteLLM gateway has ~7–8s
baseline latency + ~40 output tok/s, so a Loop-1-shaped structured call
(≈2500 output tokens) takes ~60s. Three stacked timeouts: `structured_complete`'s
`asyncio.wait_for` (30s, fired first), httpx client (60s), nginx `/api/`
`proxy_read_timeout` (60s → the 504). `rule_generation` survived only because it
calls `provider.complete` directly (no 30s `wait_for`) and emits fewer tokens.
The frontend was already built for async (polls `status='running'`, refetches on
the WS completion event) but the backend never produced a `'running'` status and
the API ran loops inline.

### Changed

- **Behavior before:** `POST /assessments/{id}/loops/{n}/run` ran the loop inline
  (LLM call on the request path) and returned the completed run; the
  `run_assessment_loop` Celery task existed but had no caller.
- **Behavior after:** the endpoint runs a cheap synchronous precheck
  (`begin_run`), creates a `status='running'` row, commits, dispatches the worker,
  and returns **202** + the running row. The worker calls `execute_run(run_id)`
  (LLM work + post-loop hooks + finalize). No request ever blocks on the model.
- `LoopOrchestrator.run_loop` split into `begin_run` (sync) + `execute_run`
  (worker); `run_loop` kept as a `begin_run`+`execute_run` wrapper so every
  existing test and the deterministic chain pass unchanged. `execute_run` no-ops
  on a non-`running` row (Celery-delivery idempotency).
- New settings `LLM_STRUCTURED_TIMEOUT_SECONDS` / `LITELLM_HTTP_TIMEOUT_SECONDS`
  (default 120); the loops pass the structured timeout to `structured_complete`;
  the provider uses the httpx timeout. No migration (`'running'` is a new value of
  the existing `status` column).
- Frontend `runLoop` dispatches and returns the running row; `LoopCard` disables
  Run and shows "Running…" while a running row exists.

### Tests (validation = automated only; no live-gateway runs)

- New: config timeout defaults; provider httpx-timeout-from-setting; loop passes
  configured timeout; `begin_run` (running row / illegal transition / already-
  running 409); `execute_run` (finalizes / terminal no-op) + `run_loop`-still-does-
  both; worker calls `execute_run(run_id)`; endpoint 202 dispatch + 409; frontend
  runLoop-returns-running.
- Full suite: **969 passed, 9 failed — all 9 the known pre-existing set** (5
  websocket + 3 vector + the `_RUNNABLE` `test_run_loop2_invalidates_loop3`).
  Frontend: `tsc` clean, 63/63 vitest. The `run_loop` split was verified by the
  24 existing behavioral run_loop tests passing through begin+execute, plus a
  code-quality review (approved; one Minor test-helper-comment applied).

### Failure handling (hardened after the final integration review)

- The final integration review found that an exception **after** the loop body
  in `execute_run` (a non-`ChainSynthesisError` DB error in a post-loop hook, or
  the final `commit()`) would escape, roll back the worker session, and leave the
  row stuck at `status='running'` — which `begin_run`'s already-running 409 then
  blocks from re-dispatch, a hard dead-end. **Fixed:** the worker (`_run`) now
  catches any escape from `execute_run` and finalizes the row to `'failed'` in a
  **fresh** session (`_finalize_failed`, only flips a still-`running` row), which
  restores the re-dispatch recovery path. Covered by
  `test_run_finalizes_row_failed_when_execute_raises` +
  `test_finalize_failed_leaves_terminal_row_untouched`.

### Risks / known limitations

- No stale-`running` reaper for the narrow case of a worker **process death**
  (SIGKILL/OOM) between `begin_run` and finalize — that leaves the row `running`
  with no exception to catch. Mitigation is operational (the analyst waits /
  re-dispatch is still blocked until a reaper exists). A reaper is out of scope
  for Plan A; tracked as follow-up. (A clean exception, the common case, is now
  always finalized — see above.)
- nginx `proxy_read_timeout` left at 60s — irrelevant now that the request
  returns immediately.
- Frontend polling fallback (WS-down only) restarts its interval on each `runs`
  refresh, so its effective cadence is ~30s rather than the documented 3s — a
  Minor follow-up; the WS path (the normal case) is unaffected.

### Next

- Plan B: Phase 2b non-Sigma artifact generation, on this async foundation.

## 2026-06-09 — Phase 2: Artifact Router (compatibility mode)

### Changed

- **Behavior before:** the Phase 1 classifier recommended/skipped artifacts,
  but nothing consumed that output; Loop 3 generated Sigma for every TTP gap
  × profile with no plan and no record of whether that matched the
  classification.
- **Behavior after:** a deterministic `ArtifactRouter`
  (`fragchain/assessments/artifact_router.py`) chains off every successful
  classification: pure policy v1 (`build_plan`) over the classifier's
  artifact lists with guardrails (class-based force-skips,
  `ROUTER_MIN_CONFIDENCE` floor, gate-failed prerequisite), persisted to the
  new `artifact_plans` table (migration `0024`). After Loop 3 succeeds, the
  router records `observed` (rules generated vs `sigma_planned`) and emits
  `assessment.artifact_plan.diverged` on mismatch. **Generation is not
  gated** — compatibility mode per ADR-0004 §3; divergence records are the
  evidence for the Phase 2c flip.
- Every guardrail override of the classifier is recorded in
  `plan.policy_adjustments` — conflicts are visible, never silent.
- New: `GET /assessments/{id}/artifact-plan`, `ArtifactPlanCard` UI below
  the detectability card (mode chip, recommendations with prerequisites,
  skips with reasons, policy adjustments, divergence badge), events
  `assessment.artifact_plan.created` / `assessment.artifact_plan.diverged`,
  setting `ROUTER_MIN_CONFIDENCE` (default 0.4).
- Design decision: **no second LLM call** — the classifier already reasoned
  about artifacts; the router is versioned deterministic policy
  (`POLICY_VERSION = "v1"`), mirroring the chain-synthesis bridge pattern.

### Tests

- New: `tests/assessments/test_artifact_router_policy.py` (15 tests — full
  class matrix, guardrail overrides recorded, confidence floor, gate-failed
  prerequisite, determinism, sigma-never-in-both-lists),
  `test_artifact_router_service.py` (persistence flattening, advisory
  failure swallow, divergence true/false, no-plan no-op), orchestrator
  chaining tests (plans after classification, skipped when classifier
  absent/None, observes Loop 3 rule count), router endpoint tests (200/404),
  frontend suites for card + api client.
- Also fixed in passing: the test-local `_FakeLoop3` stub in
  `test_orchestrator.py` was missing the `low_detectability_override` kwarg
  (same stale-stub class as the Phase 1 production-stub fix).

### Post-implementation review fixes (same day)

A high-effort review pass before deployment found and fixed: (1) a
**production-breaking flush bug** — the plan row was keyed to the classifier
row's id before any flush assigned it, so the NOT NULL FK would fail at
commit outside the advisory wrapper and take the whole loop run down
(`ArtifactRouter._plan` now flushes first; regression test pins it);
(2) divergence semantics — "planned Sigma, zero rules, zero gaps" is now
correctly NOT divergence (`gaps_processed` surfaced from Loop 3 and stored
in `observed`); (3) dual-listed non-sigma artifacts from the classifier are
reconciled (skip wins, recorded) instead of silently failing plan
validation; (4) `artifact_plans.loop_run_id` is now UNIQUE (indexed CASCADE
FK, one plan per run); (5) event name unified to
`assessment.artifact_plan.created`; (6) the UI mode chip renders from
`data.mode` instead of hardcoding; plus docstring/trace-semantics
clarifications. All fixes test-covered.

### Risks / known issues

- Compatibility mode means Sigma remains over-generated while skip decisions
  are advisory — by design until divergence data is reviewed.
- Policy guardrails can override classifier reasoning (recorded in
  `policy_adjustments`); if real-world plans show the guardrails are too
  aggressive, tune policy v2 rather than editing v1 in place.
- Non-Sigma artifact generation (Phase 2b) still blocked on the
  markdown-artifact storage decision (open question).

### Next

- Review divergence data on real assessments; then Phase 2b (markdown
  artifact generation) and Phase 2c (active gating) or Phase 3 (validation
  states), per ADR-0004 §5.

## 2026-06-09 — Phase 1: Detectability Classifier (advisory)

### Changed

- **Behavior before:** after Loop 2, the only detectability signal was the
  deterministic pass/fail category gate; Sigma was generated for every TTP
  gap × profile once the gate passed, with no classification and no
  recommended/skipped artifact reasoning.
- **Behavior after:** an advisory `DetectabilityClassifier` runs after every
  Loop 2 (on `succeeded` and `gate_failed`), producing a 5-class
  `DetectabilityAssessment` (class, rationale, confidence, telemetry,
  blind spots, recommended/skipped artifacts with reasons) persisted to the
  new `detectability_assessments` table and shown in the workspace UI.
  **Nothing gates yet** — Loop 3 behavior is unchanged (ADR-0004 Phase 1).
- New: `fragchain/assessments/detectability.py` (schemas + service),
  `DetectabilityAssessmentRow` + migration `0023`,
  `InteractionType.DETECTABILITY_CLASSIFICATION`, seeded prompt task_type
  `detectability_classification`, orchestrator post-Loop-2 hook, wiring in
  both orchestrator factories (worker + API),
  `GET /assessments/{id}/detectability`, `DetectabilityCard` UI between the
  Loop 2 and Loop 3 cards.
- Fix: `StubLoop3.run()` grew the `low_detectability_override` kwarg the
  orchestrator has passed since the override plumbing landed (pre-existing
  red test at HEAD).

### Tests

- New: `tests/assessments/test_detectability_schemas.py` (all 5 classes,
  Sigma-skip validity, sigma-justification validator, missing-telemetry
  representation, `extra='forbid'`),
  `tests/assessments/test_detectability_classifier.py` (persist, advisory
  failure, prompt summary bounds), orchestrator hook tests (loop-2-only,
  gate-failed included, status untouched), router endpoint tests (200/404),
  frontend vitest suites (card render, api 200/404, hook mocks).
- Backend: assessments + api suites green except two **pre-existing**
  failures documented below. Frontend: `tsc --noEmit` clean, 54 tests pass.

### Risks / known issues found

- Full-suite run: **926 passed, 9 failed — all 9 verified pre-existing at
  the Phase 0 baseline commit** (re-run in a clean worktree at `3c51514`):
  - `test_orchestrator.py::test_run_loop2_invalidates_loop3` —
    `state_machine._RUNNABLE` forbids re-running Loop 2 from `loop3_done`,
    contradicting CLAUDE.md §12.1 re-run semantics (flagged as a separate
    task).
  - `tests/api/test_ws_tickets.py` (2) + `tests/api/test_ws_tlp_filter.py`
    (3) + `tests/test_vector.py` (3) — fail identically at baseline in a
    fresh unpinned venv; suspected dependency drift (no lockfile; pytest 9
    / newer starlette / qdrant-client). Need a pinned dev environment.
  - `test_assessments_router_uses_real_loops.py` — order-dependent (passes
    alone; fails after `tests/assessments`, also at baseline): test_router.py
    rebinds module-level service factories without restoring them.
- Phase 1 *improved* suite health: fixed `StubLoop3` kwarg (stale stub),
  fixed `tests/worker` full-suite collection (module-level sys.modules
  pollution in test_e2e), fixed `test_source_service` order-dependence
  (same root cause). Zero new failures introduced.
- Classifier quality is untested against real LLM output — prompt
  evaluation against ground-truth CVEs is future work.

### Next

- Phase 2: ArtifactPlan router in compatibility mode (harness Prompts 6–7),
  consuming the classifier's recommended/skipped artifacts.

## 2026-06-09 — Phase 0: Reconciliation Baseline (docs only)

### Changed

- Filled `docs/architecture/001-current-architecture.md` with the real baseline
  (replaces the generic placeholder): three-loop assessment engine, active vs.
  dormant flows, validation/review/export as shipped, recommended first refactor
  target.
- Completed `docs/architecture/002-domain-model.md`: 11 target objects mapped — 7
  exist under assessment-era names; `DetectabilityAssessment` and `ArtifactPlan`
  are the genuinely new ones.
- Completed `docs/architecture/003-pipeline-contract.md`: 11-stage target mapped
  onto the shipped engine with per-stage contracts.
- Marked ADR-0003 (schema-first pipeline) **Accepted** — shipped loops already
  comply.
- Added **ADR-0004** (staged adoption): CLAUDE.md stays authoritative / AGENTS.md
  defers; classifier runs alongside (not replacing) the deterministic gate; router
  ships in compatibility mode first; v1 artifact scope = sigma_rule,
  analyst_research_task, mitigation_plan, telemetry_contract, no-reliable-detection.
- `AGENTS.md`: added Authority and Precedence section; domain-object list now
  points at the 002 mapping instead of asking for one.
- `CLAUDE.md` bumped to v2.4: direction note in §1, adoption summary in the header,
  new references in §21. No behavior contract changed.
- Answered the answerable entries in `docs/codex/open-questions.md`; corrected
  `docs/codex/known-risks.md` against the actual codebase (the
  "unstructured text blobs" guess did not apply).

### Tests

- Not applicable — documentation only, no behavior change.

### Risks

- See updated `docs/codex/known-risks.md` (notably: review-state changes ripple
  into the dormant flow; migration 0017 backfill check before Phase 1 migrations).

### Next

- Phase 1: DetectabilityAssessment implementation plan (harness Prompt 4), then
  implementation (Prompt 5).

## 2026-05-31 — Codex Control Pack Added

### Changed

- Added baseline Codex governance files.
- Added FragChain agent instructions.
- Added reusable skills for architecture review, domain modeling, pipeline stages, detectability analysis, artifact routing, validation, documentation, code quality, and LLM hardening.
- Added prompt harness for staged Codex execution.
- Added baseline architecture documentation placeholders.
- Added initial ADRs.

### Tests

- Not applicable. Documentation-only control pack.

### Docs

- Created `AGENTS.md`.
- Created `docs/codex/skills/`.
- Created `docs/codex/harness/`.
- Created `docs/architecture/`.
- Created `docs/architecture/adr/`.

### Risks

- Files are generic until Codex maps them to the actual FragChain codebase.
- Architecture placeholders require repo-specific completion.

### Next

- Run Prompt 0 from `docs/codex/harness/fragchain-prompt-harness.md`.
