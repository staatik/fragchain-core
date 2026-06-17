# Platform Architecture Review — 2026-06-10

**Method:** four parallel specialist reviews (backend content engine, platform/infra
layer, frontend, dead/stale-code audit) over the post-PR-#76 main, synthesized by
the controlling session. Full per-review reports are preserved as appendices A–D.
Companion document: [2026-06-10-product-viability-review.md](2026-06-10-product-viability-review.md).
This review is the code-evidence half of the input to the rebuild question
([008-rebuild-decision-log.md](008-rebuild-decision-log.md)).

## Executive synthesis

The codebase is unusually disciplined for its age — consistent auth gating, real
secret validation, idempotent workers, schema-validated LLM boundaries, almost no
genuinely dead code (15 small items). The problems are systemic rather than local,
and they cluster into five themes:

**1. The process boundary is the platform's structural weakness.** Three
process-local singletons break the worker↔API and multi-replica stories: the
in-process EventBus (the worker owns nearly the entire assessment event surface,
so the browser-facing WS channel mostly carries nothing — production UX is
polling-only), the prompt cache (**live bug today**: a prompt activated via the
API never reaches the long-lived worker process until restart), and WS tickets.
One Redis-backed fix family addresses all three.

**2. In-flight row lifecycle is not automation-safe.** No stale-row reaper
(broker blip ⇒ permanently 409-blocked assessment); assessment state advances
even when a run **fails**; `begin_run` destructively supersedes the prior good
run *before* execution, so a transient LLM failure demotes good data (active
detectability/plan rows become unreachable). Tolerable with a human watching;
correctness-critical the moment the pipeline runs unattended.

**3. Cost visibility does not exist.** `structured_complete` never accumulates
cost (every `cost_usd` it persists is 0.0); `assessment_loop_run.model/cost_usd`
are never written; `llm_interactions.assessment_id` is a dead column. The
documented per-assessment cost roll-up — a prerequisite for budgeted automation —
is fiction today.

**4. One live timeout bug.** Loop 2's hardcoded `_PASS_TIMEOUT_S = 60.0` fires
before the configurable `LLM_STRUCTURED_TIMEOUT_SECONDS=120` ever applies —
silently defeating the Plan A timeout fix and the prime suspect for the observed
"slow backend times out loops" pain. One-line fix.

**5. Idiom drift taxes every new phase.** Supersession/versioning is hand-rolled
four different ways; advisory-failure ownership has three styles; the
orchestrator's `execute_run` is a ~280-line god-method whose per-loop branches
absorb every new pipeline stage; the orchestrator wiring is duplicated
byte-for-byte between API and worker; the frontend split into two generations
(class-driven legacy screens vs. inline-styled assessment track that bypasses the
design system, with silent failures on its primary actions).

### Priority actions

**P0 — live bugs (fix this week):**
1. Loop 2 pass timeout derives from settings (`loops/loop2.py:34`).
2. Cross-process prompt-cache invalidation or short TTL (`fragchain/prompts/store.py`).
3. `unique=True` on the `assessment_loop_run` active partial index + declare in ORM.
4. Stop advancing assessment state on `status='failed'`; reconsider
   supersede-at-success instead of supersede-at-begin.

**P1 — automation prerequisites:**
5. Redis pub/sub bridge for `emit_event` (worker→API WS); type events with
   `tlp`/`entity_id` while at it.
6. Beat-scheduled stale `running`/`generating` reaper (reuses finalize-failed
   semantics).
7. Cost-visibility repair (one coherent change: accumulate in
   `structured_complete`, write loop-run `model`/`cost_usd`, wire
   `llm_interactions.assessment_id`).
8. Extract the orchestrator's post-loop branches into per-loop hooks; unify the
   duplicated API/worker factory wiring; loop chaining driver (on-succeeded →
   dispatch next) for the automated pipeline.

**P2 — debt to schedule:**
9. Frontend: route `api/assessments.ts` through the shared axios client; surface
   errors on all workspace actions; replace native selects; `.btn`/`Badge`
   adoption (restores focus rings); ReviewQueue tests before Phase 3.
10. Shared "versioned active row" helper before Phase 3 adds a fifth supersession
    variant; split `models.py` by domain; A/B routing parity across task types.
11. Dead-code cleanups (appendix D top-5): §12.2 ChainGenerator-reachability
    drift (manual-CVE-add drives the "dormant" LLM chain path today), missing
    `docs/litellm-setup.md`, 3 unused Python deps + 1 npm dep, CLAUDE.md §17
    rewrite, 11 dead frontend API functions.

### Cross-review corroboration

Independent reviewers converged on the same root causes without shared context:
the EventBus gap (platform + frontend + backend reviews), the missing reaper
(backend + platform), the §16 conformance breaks concentrated in the assessment
track (frontend + usability evaluation in the companion doc), and CLAUDE.md
§17/§12.2 staleness (dead-code + backend). Convergence raises confidence that
these are the real load-bearing issues.

---

## Appendix A — Backend content engine review (verbatim)

*(Scope: fragchain/assessments, llm, prompts, chain, rules, coverage, vector.)*

### Executive summary (10 lines)

1. The assessment engine is well-layered overall: pure policy modules (`state_machine.py`, `artifact_router.build_plan`), small loop implementations, and a consistently applied begin/execute split with idempotency guards and fresh-session failure backstops.
2. `LoopOrchestrator.execute_run` is the god-object risk realized: a ~280-line method owning loop dispatch, gating, chain synthesis, supersession, classification, routing, coverage dispatch, state, audit, and commit.
3. Two confirmed dead-data bugs: `structured_complete` never accumulates cost (every `cost_usd` persisted through it is 0.0), and `AssessmentLoopRun.model`/`cost_usd` plus `llm_interactions.assessment_id` are never written — the documented per-assessment cost roll-up does not exist.
4. State advances even when a loop run **fails** (`orchestrator.py:409`), and `begin_run` destructively supersedes the prior good run before execution — a failed re-run orphans the previous output and its detectability/plan rows.
5. Transaction ownership is scattered: the mapper and rule generator commit mid-`execute_run`, so the orchestrator's end-commit is not a real boundary.
6. Loop 2's hardcoded 60s pass timeout silently defeats the configurable 120s `LLM_STRUCTURED_TIMEOUT_SECONDS` — likely the live cause of the "slow backend times out loops" pain.
7. Consistency gaps: A/B prompt routing only on the rule-generation path, three different failure-ownership styles among advisory collaborators, inconsistent `get_active` None handling.
8. For automation: services are headless-callable and generation is un-gated (good), but there is **no loop chaining** — sequencing lives entirely in analyst clicks — and dispatch-after-commit with no stale-row sweeper can wedge an unattended pipeline permanently.
9. Adding a 4th loop is shotgun surgery across ~7 sites; adding an artifact type is contained (enum-driven).
10. Doc/config drift: `GATE_MIN_CATEGORIES` (CLAUDE.md §12.1) does not exist anywhere in code; the threshold is a hardcoded constructor default.

### 1. Architecture quality

**[strength] Begin/execute idiom is cleanly mirrored.** `begin_run`/`execute_run` (`fragchain/assessments/orchestrator.py:85,157`) and `begin_generation`/`ArtifactGenerator.generate` (`fragchain/assessments/artifact_generation.py:94,233`) share the same shape: sync precheck, 409 guard, commit, dispatch, idempotent no-op on non-running rows, fresh-session `_finalize_failed` backstop (`fragchain/worker/tasks/run_assessment_loop.py:136`, `generate_artifact.py:52`). This is the strongest pattern in the codebase and directly supports the automation goal.

**[risk] `execute_run` is a god-method.** `orchestrator.py:157–437` interleaves: source load, loop dispatch, gate evaluation, chain synthesis (Loop 2 branch), rule supersession (Loop 3 branch), plan observation (Loop 3), coverage dispatch (Loop 3), detectability + router (Loop 2), state advance, audit, commit. There are four separate `if loop_number == LoopNumber.THREE` blocks and two `== TWO` blocks. Post-loop behavior is encoded as orchestrator branches rather than hooks on the Loop objects or a declarative post-hook list — every new pipeline stage (Phase 2c gating, Phase 3 validation) lands as another branch here.

**[risk] State advances on failure.** `orchestrator.py:406–410` computes `next_state_after_loop` and assigns it **unconditionally** — including `status='failed'`. A failed Loop 1 puts the assessment at `loop1_done` with no active Loop 1 output (the prior active row was already superseded in `begin_run`), making Loop 2 runnable only to fail on missing `detection_questions` (`loop2.py:66`). A failed Loop 3 reaches `loop3_done`, which `can_close` accepts (`state_machine.py:65`). No test in `tests/assessments/test_orchestrator.py` asserts state-after-failed.

**[risk] Destructive precheck.** `begin_run` supersedes prior active rows and invalidates downstream **before** execution (`orchestrator.py:125–126`). If the worker run then fails or times out, the failed row is the only `is_active=true` row; `active_detectability_stmt`/`active_plan_stmt` (which join on the active Loop 2 run) now return nothing, so `GET /detectability` 404s and artifact provenance degrades — the previous good run's data is silently demoted by a transient LLM failure. Defensible for downstream invalidation, questionable for the same-loop row.

**[risk] Transaction ownership is scattered.** The orchestrator commits at the end (`orchestrator.py:427`), but Loop 3's call chain commits twice mid-flight: `CoverageMapper.map_coverage` (`fragchain/coverage/mapper.py:438`) and `RuleGenerator.generate_all_gaps` (`fragchain/rules/generator.py:583`) — both inside `execute_run`. A failure after those commits persists rules/coverage against a loop run that finalizes `failed`. Meanwhile `DetectabilityClassifier` adds without committing, `ArtifactGenerator` commits itself (`artifact_generation.py:324`), and `ArtifactRouter._plan` flushes defensively because of this ambiguity (`artifact_router.py:309` — the comment documents a near-miss where an unflushed FK would have escaped the advisory wrapper).

**[debt] Duplicated orchestrator construction.** `_orchestrator_factory` (`fragchain/api/routers/assessments.py:139–183`) and `_make_orchestrator` (`run_assessment_loop.py:58–119`) are byte-for-byte the same wiring, acknowledged by a "Touch both when changing" comment. `_EmbedderShim` exists three times (`assessments.py:186`, `run_assessment_loop.py:42`, `embed_assessment_source.py:~47`), each reaching into the private `VectorEmbedder._embed_texts` with a `# noqa: SLF001` — the missing public `embed(texts)` on `VectorEmbedder` is the real gap.

**[debt] One layering inversion.** `fragchain/assessments/access.py:40` imports `RequestUser` from `fragchain.api.middleware.tlp_filter` — a service module depending on the API layer. Not circular today (tlp_filter doesn't import assessments), but it's the only place the service layer points upward; the type belongs in `security/` or a shared module. Otherwise layering is clean: API constructs services, services never import routers, loops never import the orchestrator.

**[strength] Pure cores.** `state_machine.py`, `artifact_router.build_plan` (pure function with an append-only `policy_adjustments` trace), `mapping._normalize` (longest-first word-boundary synonyms with a documented acronym guard), `token_budget.py`, and `chain_synthesis._validate_chain` are all DB-free and synchronous. The shared `active_plan_stmt`/`active_detectability_stmt` statements (`artifact_router.py:48`, `detectability.py:101`) prevent reader drift between the API and the generator — a nice idiom.

### 2. Consistency

**[debt] Three failure-ownership styles among "advisory" collaborators.** `DetectabilityClassifier.classify` swallows and returns None (`detectability.py:160–181`); `ArtifactGenerator.generate` swallows, marks its own row failed, and has a worker backstop; `ArtifactRouter` swallows in both methods; but `ChainSynthesizer` **raises** and fails the loop (`orchestrator.py:260`), and `RuleSuperseder` failures are caught per-rule by the orchestrator, not the service (`orchestrator.py:299`). Whether a collaborator owns its own failure or the orchestrator does varies per collaborator — pick one (the artifact-generation style is the most robust).

**[debt] A/B testing silently bypassed on the active path.** `RuleGenerator._select_prompt` routes through `ABTestRouter.select_variant` (`rules/generator.py:802–825`), as does the dormant `ChainGenerator`. Loop 1, Loop 2, the detectability classifier, and the artifact generator call `PromptStore.get_active` directly. The §15 A/B framework therefore covers only `rule_generation` in the active engine; an operator setting up an A/B test on `vuln_analysis` would see 0% traffic to variant B with no warning.

**[debt] `get_active` None handling.** `artifact_generation.py:285–288` raises an explicit `RuntimeError("no active prompt template…")`; `loop1.py:59`, `loop2.py:80`, and `detectability.py:191` dereference `selection.user_template` unchecked, surfacing a missing prompt as `AttributeError: 'NoneType'` in the run error — same failure, much worse diagnostics.

**[debt] Two repair-loop implementations.** `structured_complete` (`fragchain/llm/structured.py:100–184`) and `RuleGenerator._call_with_retries` (`rules/generator.py:917–1021`). The YAML/pySigma case legitimately can't use Pydantic validation, but the rule path also has **no asyncio timeout at all** (it relies only on the httpx-level `LITELLM_HTTP_TIMEOUT_SECONDS`), no timeout-vs-validation budget separation, and differently-shaped repair prompts. Extracting a shared `call-validate-repair` engine parameterized by validator would converge them.

**[debt] Test-indirection idioms differ by layer.** The router uses module-level rebindable callables (`_begin_generation`, `_load_assessment_for_read`, `assessments.py:119–124`); services use constructor injection (`Loop2(rag_searcher=...)`, `RuleGenerator(similarity_searcher=...)`). Two mechanisms for one purpose; the module-level pattern is router-only, so it's contained but worth noting.

### 3. Tech debt + risk hot spots

**[debt] Cost tracking through `structured_complete` is dead code.** `cost_total = 0.0` at `structured.py:129` is never incremented from `resp.usage`; `_voted` hardcodes `cost_usd=0.0` (`structured.py:246`). Consequently `detectability_assessments.cost_usd` (`detectability.py:243`) and `generated_artifacts.cost_usd` (`artifact_generation.py:321`) always persist 0. Per-call costs land only in `llm_interactions`.

**[debt] `AssessmentLoopRun.model` / `cost_usd` never written.** The API serializes them (`assessments.py:243–244`) but `execute_run` never sets them — always NULL in every response.

**[debt] `llm_interactions.assessment_id` is a dead column.** Added by migration 0017 for "per-assessment cost roll-up" (CLAUDE.md §12.1), present on the model (`fragchain/db/models.py:273`), but `LiteLLMProvider._record_interaction` (`litellm_provider.py:699–722`) has no parameter for it and no code writes or queries it. The loops pass `entity_type="coverage_assessment"`/`entity_id` instead, which works as a proxy but isn't the documented contract. These three findings together mean per-assessment cost visibility — a prerequisite for an automated pipeline with budgets — doesn't actually exist.

**[debt] `GATE_MIN_CATEGORIES` doesn't exist.** CLAUDE.md §12.1 documents it as a setting; `grep` finds no occurrence in `fragchain/` or `.env.example`. The threshold is a hardcoded `=3` default on `LoopOrchestrator.__init__` and `Loop2.__init__`, and neither factory passes it.

**[risk] Loop 2's hardcoded pass timeout defeats the v2.7 timeout fix.** `_PASS_TIMEOUT_S = 60.0` (`loop2.py:34`) wraps `_call`, whose inner `structured_complete` uses `LLM_STRUCTURED_TIMEOUT_SECONDS` (default **120**, `config.py:187`). The outer 60s always fires first: on a slow backend the bulk pass raises `TimeoutError` out of `run()` and fails the loop before the configured timeout (or its repair budget) is ever exercised. Given the recorded env quirk ("slow LLM backend times out loops"), this is the prime suspect and a one-line fix (derive the pass timeout from settings).

**[debt] Supersession/versioning logic is hand-rolled four ways.** Loop runs (`orchestrator.py:500–525`, demote + `version=max+1`), chains (`chain_synthesis._supersede_prior_active`, timestamp-based), rules (`rule_supersession.py`, status-based), artifacts (`begin_generation`, flag-based with a flush ordering subtlety documented at `artifact_generation.py:144–150`). Each has its own active-marker (`is_active` vs `superseded_at` vs `deprecated_*`) and its own partial-unique-index dance. Phase 3 (validation states, review alignment) will add a fifth unless a shared "versioned active row" helper is extracted.

**[debt] Adding a 4th loop is shotgun surgery.** Touch points: `LoopNumber` + `AssessmentState` enums (`schemas.py`), `_RUNNABLE`/`next_state_after_loop` maps (`state_machine.py:20–47`), orchestrator `__init__` dict + six loop-number branches in `execute_run`, both factories, `Path(..., le=3)` on two endpoints (`assessments.py:442,485`), `stubs.py`, and the frontend. The branches are the avoidable part — gate/synthesis/supersession behavior could be declared per-Loop instead of per-loop-number in the orchestrator.

**[debt] `rules/generator.py` (1455 lines) and `coverage/mapper.py` (1185) are the two monoliths.** The rule generator mixes YAML normalization, mandatory-tag enforcement, prompt rendering, retry, persistence, dedup, similarity flagging, supersession plumbing, events, and matrix cache invalidation. Both predate the assessment engine and both commit internally (see §1).

**[debt] Loop 1 truncation ordering is inoperative.** `LoopContext.source_contents` is `list[str]` (`loops/base.py:24`), so `loop1.py:75` fabricates `pasted_at=datetime(2026, 1, 1)` and `injection_risk_score=None` for every source — the documented "highest injection risk, then oldest first" drop order (`token_budget.py` docstring) degenerates to list order. Carry `AssessmentSource` metadata into the context.

**[debt] Divergence evidence buried in JSONB.** `artifact_plans.observed.diverged` is the Phase 2c flip evidence, but it's an unindexed JSONB key (`artifact_router.py:395–401`); measuring divergence rates — the stated purpose — requires JSONB extraction over all rows. `sigma_planned` got flattened to a column; `diverged` deserves the same.

### 4. Extensibility vs the automated-pipeline direction

**[strength] Headless-callable everywhere that matters.** `begin_run`/`execute_run`, `begin_generation`/`ArtifactGenerator.generate`, `ChainSynthesizer`, `RuleGenerator` all take a session + ids with zero HTTP coupling. Artifact generation is deliberately not state-gated (`artifact_generation.py:333–342` degrades context to "(none)" markers). `validation_status` already exists on `generated_artifacts` defaulting `not_validated` — Phase 3 has a landing pad.

**[blocker-for-automation] No loop chaining exists.** Nothing dispatches Loop 2 when Loop 1 succeeds: sequencing lives exclusively in the analyst clicking `POST /loops/{n}/run`. `EVENT_ASSESSMENT_LOOP_RUN_COMPLETED` is emitted (`run_assessment_loop.py:184`) but no consumer advances the pipeline. The automated CVE→artifacts goal needs a driver — either a Celery chain/canvas, or a policy hook in `execute_run`'s finalize ("on succeeded, dispatch next"). The begin/execute split makes this cheap to add; the unconditional-state-advance and destructive-precheck issues (§1) become correctness-critical the moment no human is watching.

**[blocker-for-automation] Stuck rows have no recovery path without a human.** Both 202 endpoints commit the in-flight row **then** call `.delay()` (`assessments.py:462–468, 606–612`). If the broker is down, `.delay()` raises after commit: the loop row stays `running` (blocking re-dispatch via the already-running guard, `orchestrator.py:107`) and the artifact row stays `generating` (blocking via `ArtifactAlreadyGeneratingError`) — forever. No stale-row sweeper exists anywhere in `fragchain/worker/`. An unattended pipeline that hits one broker blip wedges that assessment permanently. A periodic "fail rows running > N minutes" beat task is the missing piece.

**[blocker-for-automation] Source acquisition is human-only.** Loop 1 consumes analyst-pasted sources; embedding is dispatched per-source from the source-create endpoint. Automation needs a source-acquisition stage (the dormant connector track) plus auto-embed-then-run sequencing; `LoopContext` is already agnostic about where `source_contents` came from, which helps.

**[risk] Gate-failed override is inherently interactive.** `begin_run` demands `override_rationale` for Loop 3 after a gate failure (`orchestrator.py:112–123`) — correct today, but the automation design must decide whether the pipeline stops there (and the router's gate-failed prerequisite, `artifact_router.py:238–242`, becomes the machine-readable stop signal) or auto-overrides under policy.

**[strength] The router/classifier separation fits Phase 2c.** Because `build_plan` is pure and the plan is persisted before Loop 3, flipping to gating is a read of `sigma_planned` in `begin_run` — no restructuring needed. The divergence observation (`observe_loop3` distinguishing "zero gaps" from "generated nothing", `artifact_router.py:388–394`) is exactly the right evidence shape.

### 5. Scalability / cost

**[risk] Worst-case serial LLM fan-out in Loop 3.** `generate_all_gaps` iterates gaps × profiles **serially** (`rules/generator.py:538–581`), each with up to `MAX_VALIDATION_RETRIES+1` calls and no per-call asyncio timeout. Six TTPs × 2 profiles × 3 attempts = up to 36 sequential LLM calls inside one Celery task holding one DB session. No cap on gap count, no concurrency. This is the cost/latency hot spot for an automated pipeline.

**[risk] Timeout-cancel doesn't stop billing, and may lose the log.** `structured_complete` wraps `provider.complete` in `asyncio.wait_for` (`structured.py:136–147`); cancellation abandons the HTTP call but the gateway-side completion still bills, and the timeout-retry budget (3) re-issues the full prompt — worst case ~6 minutes and 3 billed calls per structured call at default settings. Additionally, `_record_interaction` runs in `finally` (`litellm_provider.py:244`); on cancellation its awaits (MinIO + fresh DB session) can themselves be cancelled, so timed-out calls may not be logged at all.

**[strength] Loop 2 RAG is properly bounded** (≤8 calls, 2 passes, 60s/pass, hit dedup, `loop2.py:33–34,164–191`), and the embedding-first coverage default eliminates chat-LLM verify entirely (`mapper.py:322,343` honoring `COVERAGE_LLM_VERIFY_ENABLED=False`), with the opt-in path capped by `COVERAGE_VERIFY_MAX_CALLS`.

**[debt] Embedder lifecycle churn.** `_EmbedderShim.embed` constructs and tears down a full `VectorEmbedder` (new httpx-backed client context) **per batch call** — Loop 2 makes up to 8 RAG queries, each one shim call (`run_assessment_loop.py:52–55`, `rag.py:31`). Each `provider.complete` also opens a fresh DB session + MinIO write for logging. Both are fine at current volume, wasteful under automation throughput.

**[risk] Latent statefulness in Loop 2.** `run()` caches the per-assessment `RagSearcher` on `self._rag` (`loop2.py:76–78`). Safe today only because both factories build fresh Loop2 instances per request/task; any future move to shared/long-lived orchestrators would silently pin the first assessment's Qdrant filter onto later runs.

**[strength] Worker session discipline is right:** session-per-task, fresh-session failure finalizers, `worker_process_init` provider bootstrap honored via `resolve_chat_provider`'s registry fallback (`loops/base.py:47–63`), and Qdrant filtering is server-side (assessment-scoped `query_points`, `rag.py:34–51`).

### Top 5 actionable items by leverage

1. Fix `structured_complete` cost accumulation + populate `AssessmentLoopRun.model/cost_usd` + wire `llm_interactions.assessment_id` (one coherent cost-visibility change).
2. Make Loop 2's pass timeout derive from `LLM_STRUCTURED_TIMEOUT_SECONDS` (or exceed it) — `loop2.py:34`.
3. Stop advancing state on `status='failed'` and reconsider superseding the same-loop active row in `begin_run` vs at successful finalize.
4. Add a stale `running`/`generating` sweeper (beat task) — prerequisite for unattended operation.
5. Extract the orchestrator's post-loop branches into per-loop hooks before adding Phase 2c gating, and unify the two factory wirings into one shared builder.

---

## Appendix B — Platform/infra review (verbatim)

*(Scope: api, worker, db, notifications, security, sigma, commons, connectors, ingest, storage, config, deployment.)*

### Executive summary

1. The platform layer is unusually disciplined for its age: consistent auth gating, real secret validation, idempotent tasks, and audited state transitions.
2. The deepest structural problem is the **in-process EventBus**: nearly all assessment lifecycle events are emitted in the worker process, where there are zero WS subscribers — the "WS + polling fallback" UX is effectively polling-only in production.
3. **Access-control drift in `access.py` is real but points the safe way**: the code is stricter than the module docstring; the hazard is a future "fix" toward the docstring, plus WS events using a more permissive model than REST.
4. The **no stale-in-flight reaper** gap is partially mitigated (acks_late, finalize-failed backstops, Redis AOF) but a lost broker message still bricks a loop/artifact behind a permanent 409.
5. The partial-unique supersession idiom is applied in 4 places but **missing on `assessment_loop_run`**, the one table where a race is most plausible.
6. Two API replicas break three process-local stores: WS tickets, the EventBus, and the **prompt cache, which already has a cross-process staleness bug today** (worker never sees prompt activations).
7. `models.py` (1826 lines, ~38 tables) and inline router schemas are tolerable debt, not urgent.
8. Migration discipline is good (26/26 downgrades, 0017 backfill present) with one naming wart (duplicate `0011_` prefixes).
9. Deployment hardening (nginx F-007, compose `${VAR:?}`, F-001 validator) is a genuine strength; missing persistent volume for `SIGMA_REPOS_DIR` is an ops gap.
10. Highest-leverage fixes, in order: Redis-bridge the EventBus; add a stale-run reaper; make the prompt cache TTL/cross-process; add the loop-run partial unique index.

### 1. API design

**[strength] Uniform per-endpoint auth.** Every data-bearing router gates with `require_authenticated`/`require_maintainer`; gate counts meet or exceed endpoint counts in all 20 routers (verified by count). The only ungated routes are deliberate: `auth.py` (login), `version.py`, `webhooks.py` (HMAC token via `verify_webhook_token`, `api/routers/webhooks.py:138`), `identity.py` (501s). The middleware (`api/middleware/tlp_filter.py:79-90`) only attaches identity; enforcement is explicit per endpoint. No endpoint missing access control was found.

**[risk] Auth is opt-in per endpoint with no structural guard.** A new endpoint that omits the `Depends(require_authenticated)` fails open. There is no route-walk test asserting every route carries an auth dependency. Cheap to add; worth it given the per-endpoint pattern.

**[risk] `require_maintainer` username fallback.** `tlp_filter.py:118-121` grants maintainer to any user whose `username == "admin"`. Reasonable bootstrap crutch, but it makes a username a privilege boundary; should be retired when tier upgrades land (M3).

**[debt] Schema placement is split-brain.** Assessments correctly centralize response schemas in `fragchain/assessments/schemas.py`; meanwhile `queue.py` declares 15 inline `BaseModel`s, `sigma.py` 12, `prompts.py` 11. `queue.py` (659 lines) is one-third schema definitions. Verdict: the assessments pattern is the right one — inline schemas make cross-router reuse (e.g., the queue projection of assessment fields) copy-paste-prone. Not urgent, but new routers should follow the schemas-module pattern.

**[strength] Error mapping is consistent.** Domain exceptions map uniformly: `*NotFoundError`→404, `Duplicate*/StateTransition/InvalidLoopTransition/AlreadyGenerating`→409, `InvalidTrigger`→400, content size→413 (`api/routers/assessments.py:290-293, 363-364, 386-393, 609-610`). The F-002 "404-not-403" rule is applied consistently (`assessments/access.py:174-181`).

**[debt] The F-002 module-level-indirection test pattern is fragile, not yet unsustainable.** `assessments.py:119-124` rebinds `_load_assessment_for_read = load_assessment_for_read` (and `_begin_generation`) so tests monkeypatch module globals. Two failure modes: (a) both the real name and the alias are imported into the module namespace — a future endpoint calling `load_assessment_for_read` directly compiles, works, and silently escapes the test seam; (b) tests that rebind the alias to a no-op `MagicMock` can mask a *missing* access check (the test passes whether or not the endpoint calls the helper). The same pattern repeats in `worker/tasks/embed_assessment_source.py:31-57`. FastAPI `dependency_overrides` would give the same testability with the access check expressed as a dependency the router can't forget per-endpoint. Judge: acceptable now; migrate before the router count grows.

**[strength] WS auth design.** The F-003 single-use ticket scheme (`api/ws_tickets.py`, `routers/websocket.py:154-196`) plus nginx `json_safe` logging on `/ws/` (`nginx/conf.d/fragchain.conf:117-121`) is a thorough fix for the JWT-in-querystring leak.

### 2. Worker architecture

**[strength, residual risk] Task registration.** The fix is sound: `include=["fragchain.worker.tasks"]` (`worker/celery.py:21`) + side-effect imports in `worker/tasks/__init__.py:25-59`, regression-guarded. Residual fragility: every new task module must be manually added to `__init__.py` — the same omission class can recur. Also, `Dockerfile.worker` CMD uses `-A fragchain.worker.celery_app` while docker-compose overrides with `-A fragchain.worker`; two spellings, one of which is never exercised in the composed deployment. A startup assertion ("expected task names ⊆ registered") would close this permanently.

**[strength → debt-at-scale] `run_async_task`** (`worker/celery.py:69-96`). The create-loop-then-dispose-engine-per-task pattern correctly kills the "Future attached to a different loop" class, and the `worker_process_init` hook (`celery.py:99-157`) even disposes the bootstrap-loop engine — careful work. Cost: every task pays full engine + pool construction. Fine at current volume; at automation-pipeline volume a persistent per-process event loop is the right replacement.

**[strength] Idempotency discipline is genuinely consistent.** `run_assessment_loop`: `execute_run` no-ops on non-`running` rows; fresh-session `_finalize_failed` flips only still-`running` rows (`worker/tasks/run_assessment_loop.py:136-166`). `generate_artifact`: identical pattern + skip on non-`generating` (`generate_artifact.py:104-110, 52-81`). `embed_assessment_source`: short-circuits `embedded` rows, deterministic uuid5 point ids so retries overwrite (`embed_assessment_source.py:88-103, 113-116`). Beat tasks are naturally idempotent. `task_acks_late` + `task_reject_on_worker_lost` (`celery.py:26-27`) make redelivery the recovery path for worker crashes — and the row-status guards make redelivery safe.

**[risk] No stale-in-flight reaper — the remaining hole is broker message loss, not worker crash.** Worker crash → redelivery (acks_late). But if the Celery message is lost (Redis data loss despite AOF, queue purge, dispatch succeeding after an API crash window), the `running`/`generating` row is permanent: `begin_run`'s already-running guard and `ArtifactAlreadyGeneratingError` (`api/routers/assessments.py:465-466, 609-610`) then 409 forever, with no operator-facing unstick path short of SQL. A beat task that fails rows `running` longer than N×`LLM_STRUCTURED_TIMEOUT_SECONDS` would close this cheaply and fits the existing finalize-failed semantics.

**[blocker-for-scale] In-process EventBus — the problem runs deeper than "some events are missed."** `EventBus` is a per-process singleton (`notifications/events.py:170-177`). WS subscribers exist only in the API process. But the emit census shows the *worker* owns nearly the entire assessment event surface: `assessment.loop.run.completed` (`run_assessment_loop.py:184`), `artifact.generated` (`generate_artifact.py:134`), `source.embedded` (`embed_assessment_source.py:145,164`), `chain.synthesized`/`rule.superseded` (orchestrator hooks, `assessments/orchestrator.py:248,312`), `artifact_plan.created/diverged` (`artifact_router.py:335,410`), coverage events (`coverage/mapper.py:963,989`). The only browser-visible events today are API-process emissions: `loop.run.started` (`assessments.py:470`), `import_job.created`, `webhook.received`, queue actions. Consequences: (a) the documented "refetch on WS completion event" never fires — the UI's polling fallback is the *primary* mechanism; (b) the F-010 per-event TLP filter (`events.py:82-120`) protects a channel that mostly carries nothing; (c) the recent "poll in-flight work regardless of WS state" commit (3d9a133) is treating the symptom. This needs a Redis pub/sub bridge (emit → Redis channel → API-side fan-out) before Phase 3, and it is also the prerequisite for any multi-replica API.

**[risk] Untyped events broadcast assessment metadata to all authenticated WS subscribers.** No emitter passes `tlp=`/`entity_id=`, so every event is "untyped" and `Event.visible_to` returns True unconditionally (`events.py:104-105`). `loop.run.started` carries `assessment_id` — visible to any authenticated subscriber, while the REST surface 404s the same user. Inconsistent with F-002's enumeration hardening; today low-severity (mostly UUIDs), but worth fixing when the bus is bridged.

### 3. Data layer

**[debt] `models.py` at 1826 lines / ~38 tables.** Pure declarative, no logic, well-commented — readable, but past the threshold where a domain split (`models/assessment.py`, `models/sigma.py`, `models/intel.py`, re-exported from `models/__init__.py`) pays for itself in merge-conflict avoidance. Not urgent.

**[strength] Migration discipline.** 26 files, 26 real `downgrade()`s (only `0015` is a justified data-cleanup `pass`). `0017` correctly backfills `superseded_at` *before* creating `uq_attack_chains_active_per_cve` (`0017_assessment_centric.py:240-265`) — the non-fresh-DB failure flagged in project memory is addressed in tree. One wart: duplicate `0011_` prefixes (`0011_cisa_kev_date_to_date`, `0011_sigma`, both off `0010`, merged by `0012`'s tuple `down_revision`) — numbering no longer encodes topology; fine for Alembic, confusing for humans.

**[debt] The supersession idiom is inconsistently enforced.** Partial unique indexes back it in four places: `prompt_templates` (`models.py:568`), `attack_chains` (`:817`), `review_queue` pending (`:1177`), `generated_artifacts` (`:1824`). But `assessment_loop_run` — whose docstring states the same one-active invariant (`models.py:1550-1557`) — has only a *non-unique* partial index, created in the migration (`0017:203-208`) and **absent from the ORM `__table_args__`** (metadata/migration drift; `create_all`-based test DBs diverge from prod). The invariant rests solely on `begin_run`'s app-level guard; a concurrent double-dispatch race can mint two active rows. Add `unique=True` (it's the only table in the idiom without it).

**[strength] JSONB-vs-relational choices are right.** Versioned LLM outputs (`assessment_loop_run.output`, `detectability payload`, `plans`, `generated_artifacts.content`) as JSONB with strict Pydantic validation at the boundary is correct — these are write-once blobs, not query targets, and flattened hot columns (`detectability_class`, `sigma_planned`, `gate_passed`) are pulled out where filtering matters. The one smell is `attack_chains.chain` JSONB + `chain_ttps` relational dual-write (legacy column populated from the serialized TTP list) — two sources of truth held consistent only by the bridge code.

**[strength] Index coverage on hot paths.** `0020` retro-fixed the missing assessment FK indexes; `generated_artifacts.assessment_id` indexed at creation (`models.py:1779`); `assessment_source` has a purpose-built partial index for the embedding poll (`0017:133-138`).

### 4. Known-debt depth assessment

**Access-control drift (`assessments/access.py`).** Confirmed: the module docstring (lines 5-17) promises path 4, "effective TLP … under `can_user_access`", but `_check_access` (lines 81-158) implements creator / elevated / embargo-participant / explicit-grant only, and its *own* docstring (lines 102-107) documents the deny-by-default policy that contradicts the module header. Depth: the code direction is safe (stricter than documented — assessments are private workspaces). The risks are (a) a future maintainer "fixing" the code toward the header and opening every `tlp:clear`/`green` assessment to all authenticated users, and (b) the asymmetry with the WS bus, which *does* use the TLP path (`events.py:114-120`) — the two access models will diverge visibly the moment emitters start passing `tlp=`. Fix is a docstring edit plus one sentence in the WS module; do it before Phase 3 touches sharing semantics.

**Shared `review_queue`.** Coexistence is engineered, not accidental: `assessment_id`/`low_detectability_override`/`superseded_by_assessment_id` columns are projected by the queue router (`queue.py:86-88, 236-241`), the F-009 check gates the `?assessment_id=` filter behind assessment read access (`queue.py:400-435`), and the pending-rule partial unique (`models.py:1177`) prevents duplicate pendings across pipelines, with `RuleSuperseder` deprecating live-feed rules deterministically. Depth: shallow today (dormant path has no traffic). It becomes real debt at ADR-0004 Phase 3, when review states for non-Sigma artifacts must align — decide then whether the queue stays unified or splits per artifact kind.

**`cves.processing_status` dual state machines.** Depth: cosmetic-to-confusing, not corrupting. The assessment flow never touches `processing_status` (zero references under `fragchain/assessments/`), so assessment-driven CVEs sit at whatever default the row got while `coverage_assessment.state` does the real work. `ingest/state.py` keeps the dormant machine fully audited, so revival is clean. Cost today: the CVE Explorer's status column lies for assessment-era CVEs. Cheapest fix: a `source='assessment'`-aware display, not a state-machine merge.

### 5. Deployment / ops

**[strength] Secrets handling is a model.** Compose `${VAR:?}` required-substitution for every credential (docker-compose.yml header block), the F-001 production validator with placeholder/length/exact-match checks (`config.py:221-317`), admin/admin refusal in both validator and seeder (`api/main.py:60-77`), prod docs/openapi disabled (`main.py:287-288`), TLS-verify enforcement against LiteLLM.

**[strength] nginx layer.** Host-header catch-all 444, canonical-host redirect, Upgrade stripped outside `/ws/`, per-zone rate limits, full security-header set, ticket-safe WS logging (`nginx/conf.d/fragchain.conf`).

**What breaks at 2 API replicas** (all process-local, all confirmed):
- **WS tickets** (`ws_tickets.py:31-35`, self-acknowledged): ticket issued by replica A is unredeemable at replica B → intermittent WS connect failures behind a round-robin proxy.
- **EventBus**: each replica fans out only its own emissions; subscribers see a random subset. (Same root cause as the worker gap — one Redis bridge fixes both.)
- **Prompt cache** (`fragchain/prompts/store.py:84-129`): no TTL; `invalidate()` is called only in the activating process (`store.py:257,311`). **This is broken at 1 replica today**: a prompt activated via the API never reaches a long-lived worker process — the worker serves the stale template until restart. Cross-process invalidation (Redis key version or short TTL) is needed regardless of replica count.

**At 2 workers:** mostly safe — row-status guards + idempotent tasks hold; beat is a separate singleton service. The missing loop-run unique index (above) is the one DB-level race. Each container re-clones sigma repos independently because **no volume backs `SIGMA_REPOS_DIR`** in docker-compose (volumes: postgres/redis/minio/qdrant only) — contradicting CLAUDE.md §13's "mount on a persistent volume"; refreshes degrade to full re-clones on every container recreate.

**[debt] Misleading network name.** The compose network `internal` has `internal: false` — necessary (worker needs egress to LiteLLM on Server 1) but the name promises an isolation the config doesn't deliver; deserves an inline comment. No service ports are published except nginx 80/443 — §19 honored.

**Three-server realism:** sound. LiteLLM-as-mandatory is enforced at config validation; OpenCTI is genuinely optional; Redis AOF enabled; healthchecks and dependency ordering throughout; `proxy_read_timeout 60s` on `/api/` is now safe for loops (202-async) but remains a tripwire for any future slow synchronous endpoint.

### Priority recommendations

1. Redis-bridge `emit_event` (worker→API WS); type assessment events with `tlp`/`entity_id` while at it.
2. Beat-scheduled stale-`running`/`generating` reaper using the existing finalize-failed semantics.
3. Cross-process prompt-cache invalidation (or short TTL) — live correctness bug.
4. `unique=True` on `idx_assessment_loop_run_active` + declare it in `models.py`.
5. Fix the `access.py` module docstring; add a route-walk auth test; volume-mount `SIGMA_REPOS_DIR`.

---

## Appendix C — Frontend review (verbatim)

*(Scope: frontend/src — screens, components, api, hooks, styles.)*

### Executive Summary (10 lines)

1. The codebase splits cleanly into two generations: a polished "legacy" track (Dashboard, ImportManager, ReviewQueue — DarkOps classes, Toast, Badge/DataTable) and a newer assessment track built almost entirely from raw HTML + inline styles, bypassing the design system it sits inside.
2. `useAssessment` is a well-documented single source of truth for the workspace, and its WS+polling hybrid is honest about the cross-process EventBus gap — but it fires ~7 HTTP requests every 3s while anything runs, and recreates its interval every tick.
3. The axios/fetch split is deliberate but now incoherent: one file (`api/assessments.ts`) opted out of the shared client and lost the global 401-redirect, timeout, and error-shape conventions with it.
4. Error handling is bimodal: legacy screens uniformly toast via `detailFromError`; the assessment track silently swallows rejections from `runLoop`, `generateArtifact`, gate override, and close.
5. §16 conformance violations are concentrated in the new code: four native `<select>`s, zero `.btn` classes (so zero focus rings, since darkops.css has no element-level button style), hand-rolled badges duplicating `Badge`.
6. Test coverage is inverted relative to risk for Phase 3: the assessment track is well-tested (24 test files), while all 13 legacy screens — including ReviewQueue, the Phase 3 centerpiece — have zero tests.
7. ImportManager.tsx (2,249 lines, 26 functions) is the real outlier, not CVEExplorer; five screens exceed 850 lines.
8. There is no shared WebSocket: each consumer (Dashboard, ImportManager, ChainViewer, useAssessment) opens its own socket + ticket POST — fine today, a tax on every future live surface.
9. No code-splitting (all 16 screens statically imported in App.tsx), no react-query/SWR — cache, dedup, and invalidation are all hand-rolled per screen.
10. For an automation-first future, the biggest structural gap is that data-freshness logic lives inside one per-assessment hook; fleet-level pipeline monitoring will require either a shared event/cache layer or a rewrite of the polling pattern.

### 1. Architecture

**[strength] Layering is legible.** `api/` (typed clients) → `hooks/` (`useAssessment`, `useAssessments`, `useHealth`, `useWebSocket`) → `components/` (shared primitives + `components/assessments/` feature folder) → `screens/`. The barrel (`src/components/index.ts`) gives a single import surface. Routing (`src/App.tsx:20-53`) is flat and readable.

**[debt] The api/ layer is leaky.** 18 of 21 screens import the raw axios `api` from `api/client.ts` directly (e.g. `screens/Dashboard.tsx`, `screens/ReviewQueue.tsx`, all of `screens/settings/*`). `client.ts:3-5` blesses this for "one-off calls", but at 18/21 it's the norm, not the exception — endpoint knowledge is smeared across screens, which will hurt when Phase 3 adds/changes review endpoints.

**[strength] `useAssessment` (hooks/useAssessment.ts, 248 lines) is the best-engineered file in the tree.** Six entities, advisory data correctly fails soft (lines 91-119), optimistic surfacing of `running`/`generating` rows (lines 213, 231), and an unusually honest comment about why polling exists (lines 170-175).

**[risk] The polling loop is correct but wasteful and self-churning.** `hooks/useAssessment.ts:176-192`: the effect depends on `runs` and `artifacts`, which the interval itself replaces with fresh array identities every tick — so the interval is torn down and recreated every 3s, and each tick issues 7 requests regardless of *which* thing is in flight. For one analyst on one workspace this is fine. For the automation-first trajectory (many assessments running unattended, a dashboard watching them), this pattern cannot be replicated per-row — you'd need either a backend that broadcasts worker events cross-process (Redis pub/sub behind the WS bus) or a batched "in-flight status" endpoint.

**[debt] One WebSocket per consumer.** `useWebSocket` (hooks/useWebSocket.ts) is solid in isolation (exponential backoff lines 149-157, clean unmount 162-171, one-shot ticket auth 101-113), but there's no shared connection/provider — Dashboard, ImportManager, ChainViewer, and every open `useAssessment` each open their own socket and POST `/ws/ticket`. Every new live surface adds a connection; a fleet-monitoring screen would multiply this.

**[debt] No code-splitting.** `App.tsx:1-17` statically imports all screens, including heavyweights pulling `@xyflow/react` + `dagre` (ChainViewer) and CodeMirror (Prompts, ReviewQueue). One bundle carries everything to the login page.

**[strength] State management fits current scale.** No Redux/zustand is the right call for v1: server state dominates, and the custom hooks centralize it. But invalidation is already manual and ad-hoc (`refetchX` fan-out at `useAssessment.ts:152-168` mirrors the polling fan-out at 183-189 — two hand-maintained lists of "what to refresh when"). React-query would collapse both into cache invalidation and give request dedup for free; worth adopting *before* Phase 3 multiplies the entity graph.

### 2. Consistency

**[debt] axios vs fetch: one file defected, and lost guarantees doing it.** `api/assessments.ts:2-5` uses native fetch explicitly so tests can `vi.spyOn(global, "fetch")` — a testing-tail wagging an architecture-dog. Consequences: (a) no global 401→`/login` redirect (axios interceptor only, `api/client.ts:44-59`), so an expired session in the workspace surfaces as raw `HTTP 401` strings; (b) no 15s timeout (`client.ts:28`); (c) a second error-shape (`Error(detail)`) vs `detailFromError`; (d) duplicate auth-header logic. Worse, the file is internally inconsistent: `getDetectability`/`getArtifactPlan` (lines 336, 348) bypass its own `apiFetch` helper with raw `fetch`. This split should be healed toward the axios client.

**[debt] Inline styles: 224 `style={{` vs 1,384 `className=` (~14%), but the distribution is the story.** Legacy screens are class-driven (ImportManager: 2 inline styles in 2,249 lines). The assessment track is inline-style-driven: GeneratedArtifactsCard (22), ArtifactPlanCard (21), DetectabilityCard (19). Tokens are respected, but darkops.css's components (`.btn`, `.card`, badge classes) are unused there.

**[debt] Component reuse skipped by the new track.** Badge is used in 18 files, Dropdown in 11, Modal in 11 — yet `GeneratedArtifactsCard.tsx:75-90` and `DetectabilityCard.tsx:30-40` hand-roll bordered-span badges instead of `Badge`; `VersionDiffView` uses native selects instead of `Dropdown`; `AssessmentWorkspace.tsx:41-55` hand-rolls a header instead of using the context-bar pattern other chromeless screens use. `StatBlock` (2 uses) and `EmbargoIndicator` (1 use) are near-dead.

**[risk] Error handling is uniform in legacy, absent in the new track.** Legacy: `useToast` in 17 screens + `detailFromError` everywhere. Assessment track: no toast usage at all, and several swallowed rejections where the only UX on failure is *nothing*: `AssessmentWorkspace.tsx:71` → `LoopCard.tsx:49` (`onRun` discards the promise — a 409 or 400 is an unhandled rejection); `AssessmentWorkspace.tsx:50` (`closeAssessment` no `.catch`); `ArtifactPlanCard.tsx:80` (`void onGenerate`); `GateBanner.tsx:29-36` (`try/finally` with no `catch`). PasteSourceForm (lines 36-41) is the one assessment component that does it right.

### 3. Tech Debt

**[debt] Large files:** ImportManager.tsx **2,249**, ATTACKMatrix.tsx 1,152, SigmaLibrary.tsx 1,074, Prompts.tsx 1,034, ReviewQueue.tsx 883, Dashboard.tsx 867, CVEExplorer.tsx 778, ChainViewer.tsx 767. ImportManager is 26 functions/sub-components in one file. ReviewQueue at 883 lines is the one that matters: Phase 3 grows exactly this screen.

**[debt] Duplicated helpers:** `fmtDate`/`fmtDateTime`/`cvssBadgeVariant`/`statusBadgeVariant` exist independently in ImportManager.tsx:123-168 and CVEExplorer.tsx:58-110. No shared `format.ts`. Meanwhile `components/assessments/display.ts` shows the team knows the right pattern.

**[strength] TODO hygiene:** zero TODO/FIXME/HACK markers in `frontend/src`. Zero `window.alert/confirm`.

**[risk] Accessibility is partial.** Good: `role="alert"`/`role="status"` in the right places, 31 `aria-label`s, Dropdown has listbox/option roles, matrix cells have `:focus-visible`. Bad: **darkops.css styles focus only on `.btn:focus-visible` (line 590) and `.input:focus` (634) — and the assessment-track components use no classes at all**, so every button in LoopCard, GateBanner, SourcesCard, ArtifactPlanCard, GeneratedArtifactsCard, AssessmentWorkspace renders with browser-default chrome and no DarkOps focus ring, directly against §16. `Modal.tsx:29` handles Escape but has no focus trap; `Dropdown.tsx:62` has no arrow-key navigation; `DataTable.tsx` has no keyboard semantics. `AssessmentWorkspace.tsx:73-76` reaches into the DOM with `document.querySelector`.

**[risk] Test coverage is inverted for what's coming.** All 24 test files cover the assessment track plus Sidebar and ProfilesSection. **Zero tests**: ReviewQueue, ImportManager, Dashboard, CVEExplorer, ChainViewer, ChainsList, SigmaLibrary, Prompts, ATTACKMatrix, Login, ManualCveAdd, Identity, and 7 of 9 settings sections. Phase 3 will modify ReviewQueue — currently 883 untested lines.

**[debt] Stale version selection in LoopCard.** `LoopCard.tsx:26-27`: `selectedId` is captured once; after a re-run completes, the card silently keeps displaying the superseded output until the user manually switches versions.

### 4. Design-System Conformance (§16)

- **[risk] Native `<select>` (explicit §16 violation):** `AssessmentsList.tsx:84`, `CreateAssessmentModal.tsx:117`, `VersionDropdown.tsx:11`, `VersionDiffView.tsx:21,26`. All four are assessment-track; `components/Dropdown.tsx` exists and is used by 11 legacy files.
- **[risk] Focus rings missing** on all unclassed assessment-track controls — §16 requires focus rings on form controls.
- **[debt] Hardcoded hex:** `ChainViewer.tsx:70-74` re-declares `#38bdf8/#818cf8/#fbbf24/#f87171` (because @xyflow node fills can't take `var()` — defensible but will drift) and `:466` hardcodes `#1e2d45`. Everything else samples clean.
- **[strength] Tactic colors** match the §16 mapping; **TLP badges** centralized in `TLPBadge.tsx`, used in 9 files.
- **[strength] font-display discipline** is good even in inline-style land.

### 5. Fit for What's Coming

**Phase 3 (validation states + review workflow):** `validation_status` is already typed and rendered — the data plumbing is ready. The hard part: review *actions* on artifacts will need the error-surfacing the assessment track currently lacks, plus alignment with ReviewQueue's interaction patterns — an untested 883-line file. Recommend extracting ReviewQueue's action-bar/detail-panel pattern into shared components *before* bolting artifact review onto it. A `validation_status` badge will be the fifth hand-rolled badge variant; consolidate on `Badge` first.

**Automation-first future:** the biggest blocker is data freshness architecture: `useAssessment` is built around *one* assessment being actively driven; a "pipeline monitor" needs many assessments' in-flight status cheaply. Per-row polling at 7 req/3s doesn't scale; per-row sockets don't either. The fix is mostly backend (cross-process event fan-out, or a bulk status endpoint), but the frontend should prepare by (a) a single shared WS provider with client-side topic dispatch, and (b) a query cache so invalidation-by-event is one line. The Generate/Run buttons are appropriately thin wrappers over 202-dispatch endpoints — the click layer will peel off easily. `canRunLoop` (`AssessmentWorkspace.tsx:17-22`) hand-mirrors the backend state machine — a drift hazard; the API should expose runnable affordances.

**Top 5 actions, in order:** (1) route `api/assessments.ts` through the shared axios client; (2) add error surfacing to runLoop/generateArtifact/override/close paths; (3) replace the four native selects and adopt `.btn`/`Badge` in assessment components; (4) add ReviewQueue tests before Phase 3; (5) introduce a shared WS provider + query cache as the foundation for fleet monitoring.

---

## Appendix D — Dead/stale-code audit (verbatim)

Method: import-graph analysis over `fragchain/` (absolute, relative, and `__init__` re-export patterns), grep-verified per finding; frontend export-vs-caller analysis; doc path-existence checks; migration DAG reconstruction.

### 1. Dormant-allowlisted (§12.2) — verification of each claim

All seven entries verified **wired but dormant** — imported, registered, and router-included; nothing has rotted into unreachability. One drift finding.

| Entry | Verification | Classification |
|---|---|---|
| `fragchain/chain/generator.py::ChainGenerator` | Imported by `chain/__init__.py`, `worker/tasks/synthesize.py`, `scripts/eval_chain.py`. **DRIFT:** §12.2 says "no caller in the active flow," but `POST /cves/manual` (`fragchain/api/routers/cves.py:346,497`) — the live **ManualCveAdd UI screen** (`frontend/src/screens/ManualCveAdd.tsx:113`) — dispatches `synthesize_chain`, as does a regenerate endpoint in `routers/chains.py:556`. ChainGenerator is reachable from the active UI today, not merely dormant. | DORMANT-ALLOWLISTED (claim partially stale) |
| `fragchain/worker/tasks/synthesize.py` | Registered task; dispatched from 3 prod sites (above + `ingest/enrichment.py:159`). | DORMANT-ALLOWLISTED |
| `fragchain/ingest/webhooks.py` + `api/routers/webhooks.py` | Router included at `api/main.py:329`; `security/webhook_hardening.py` consumed only by it. Wired, traffic-less. | DORMANT-ALLOWLISTED |
| `fragchain/ingest/rate_limit.py` + `MAX_LIVE_CVE_PER_HOUR` | Imported by 7 prod modules. Live import graph. | DORMANT-ALLOWLISTED |
| `api/routers/imports.py` + budget settings | Router included; frontend `ImportManager` routed at `/imports`. UI-reachable, dormant in practice. | DORMANT-ALLOWLISTED |
| `cves.processing_status` machine (`ingest/state.py`) | Imported by 10 prod modules incl. active-path `worker/tasks/coverage.py`. | DORMANT-ALLOWLISTED |
| `connectors/orchestrator.py` | Re-exported via `connectors/__init__.py`; consumed by `ingest/enrichment.py` and beat task `poll_connectors` (runs every 15 min — it *executes*, just finds no connectors). | DORMANT-ALLOWLISTED |

Celery beat schedule (`worker/celery.py:37-66`): all 7 entries resolve to registered task names — no dead beat entries.

### 2. Python — dead / test-only / placeholder

- **`StubLoop1/2/3`** (`fragchain/assessments/loops/stubs.py:27,63,90`) — zero prod importers; only tests. The module's fourth member, `evaluate_detectability_gate` (line 111), IS production (imported by `orchestrator.py:29`). Production gate logic living in a file named `stubs.py` is a misleading-location smell. → **TEST-ONLY** (the three classes)
- **`fragchain/identity/`** — `identity_providers` dict empty, consumed only by the 501-returning router; matches §9 exactly. → **PLACEHOLDER-BY-DESIGN**
- **Unused pyproject dependencies** (verified zero imports in `fragchain/`, `scripts/`, `tests/`): `aiohttp` (also stale in §18 conventions list), `email-validator`, `python-multipart`. → **DEAD** (3)
- Verified live (not dead): `python-jose`, `passlib`, `tiktoken`, `gitpython` (lazy `import git` in `sigma/sources.py:145,513`), `minio`, `pysigma`, `fragchain/prompts/ab.py` (`ABTestRouter.select_variant` called from `rules/generator.py:814` — active Loop 3 path), `fragchain/prompts/eval.py`, `evaluations/store.py`, `connectors/registry_client.py`, `commons/{sync,contribute,factory}.py`, `coverage/benchmark.py`, all 24 routers, all 50 config settings.

### 3. Frontend

**Dead API client functions** (zero callers outside their own file + tests, grep-verified): `api/chains.ts` — `getChain`, `validateChain`, `rejectChain`, `contributeChain` (notable: the §7 "Contribute to Commons" UI flow has no living frontend caller; backend endpoints exist); `api/commons.ts` — `fetchCommonsStatus`; `api/cves.ts` — `reprocessCve`; `api/imports.ts` — `usePreset`, `getImport`; `api/matrix.ts` — `recomputeMatrix`; `api/profiles.ts` — `getProfile`; `api/queue.ts` — `assignQueueItem`. → **DEAD** (11)

**Dead npm dependency:** `@codemirror/merge` — zero imports; `VersionDiffView.tsx` renders diffs without it. → **DEAD**

**Components:** all barrel exports have ≥1 non-test consumer (lowest: `EmbargoIndicator`, 1). All 18 screens are routed. No orphan screens.

**CVEExplorer client-side chains join** (`screens/CVEExplorer.tsx:178-191`, `listChains({limit:500})`): **still required** — `CVEOut` embeds `rule_count` + `assessment` summary but **no** chain confidence field. Not dead, but the `limit: 500` join is a scalability wart worth a backend embed eventually.

### 4. Docs staleness (excluding docs/historical/)

- **`docs/litellm-setup.md` does not exist** — referenced by `README.md` and **CLAUDE.md §4.1**. → **STALE-DOC**
- **CLAUDE.md §17 file structure**: lists `api/routers/matrix.py` (doesn't exist; §12.1 itself says matrix lives in `coverage.py` — internal contradiction), `api/middleware/auth.py` (doesn't exist), `notifications/channels.py` (actual: `events.py`), `hooks/useWebSocket.ts` only (7 hooks exist), omits the entire `fragchain/assessments/` package — the active flow. → **STALE-DOC**
- **CLAUDE.md §15** "Default Prompts Seeded: 3" — `scripts/seed_prompts.py` seeds **10** task_types. → **STALE-DOC**
- **CLAUDE.md §12.1** `GATE_MIN_CATEGORIES=3` presented as a setting; it's a hardcoded default (`stubs.py:114`, `orchestrator.py:70`), not in `config.py` or `.env.example`. → **STALE-DOC** (minor)
- **§12.1 sampled claims verified TRUE (10/12)** — the two misses are GATE_MIN_CATEGORIES and the §12.2 ChainGenerator reachability drift.
- **`docs/architecture/001-current-architecture.md:18`** — references a nonexistent `auth.py` middleware module. → **STALE-DOC**
- **`ASSESSMENT_CENTRIC_ARCHITECTURE_DESIGN.md`** — references the pre-move `loops/loop1.py` location (actual: `fragchain/assessments/loops/loop1.py`). → **STALE-DOC**
- **`ASSESSMENT_WORKSPACE_FRONTEND_DESIGN.md`** — references a nonexistent `ws_events.py` module and `components/assessments/__tests__/` (tests are co-located). → **STALE-DOC**
- **`platform_review_diagrams.md`** — references the TLP-and-Identity doc at its pre-move location (now under `docs/historical/`). → **STALE-DOC**
- **`PHASE_A_STATUS_AUDIT.md` + `COVERAGE_VERIFICATION_DESIGN.md`** — referenced the deleted backfill_content_hash script. → **STALE-DOC**
- `006`/`007` correctly self-mark "Draft target behavior"; `COVERAGE_VERIFICATION_DESIGN.md` correctly bannered; `AGENTS.md` clean.

### 5. Scripts

All 11 scripts import only existing modules (AST-verified). All runnable/relevant; `scripts/eval_chain.py` drives the dormant `ChainGenerator` — dormant-adjacent but not broken. No dead scripts.

### 6. DB

- **`user_identities`, `trust_attestations`, `contribution_signatures`**: zero references outside models/migrations — exactly the §9 contract. → **PLACEHOLDER-BY-DESIGN** (3)
- **`prompt_evaluations` / `prompt_ab_tests`**: written AND read. Not dead.
- All other sampled models have prod readers.
- **Migrations**: DAG reconstructed — dual `0011_*` files are an intentional branch + merge; single true head `0025_generated_artifacts`. Consistent.

### Counts

| Classification | Count |
|---|---|
| DORMANT-ALLOWLISTED | 7 (all verified wired; 1 with claim drift) |
| DEAD | 15 (11 frontend API fns, 3 Python deps, 1 npm dep) |
| STALE-DOC | 11 distinct findings |
| TEST-ONLY | 1 (StubLoop1/2/3 trio) |
| PLACEHOLDER-BY-DESIGN | 2 groups (identity code; 3 identity tables) |
| UNCERTAIN | 1 (backend chains validate/reject/contribute + `/cves/{id}/reprocess` endpoints — live code, zero UI callers; possibly awaiting UI) |

### Top 5 highest-value cleanups

1. **Fix the §12.2 ChainGenerator drift**: either document that `POST /cves/manual` (a live UI screen) drives `synthesize_chain`, or stop dispatching synthesis from that endpoint — right now the "dormant" LLM-only chain path is one click away in production.
2. **Restore or delete the `docs/litellm-setup.md` reference** (README + CLAUDE.md §4.1) — broken operator-onboarding link.
3. **Remove 3 unused Python deps** (`aiohttp`, `email-validator`, `python-multipart`) + `@codemirror/merge` — shrinks install/attack surface; also fix §18's `aiohttp` mention.
4. **Rewrite CLAUDE.md §17 file structure** — it predates the assessment pivot and contradicts §12.1.
5. **Delete or annotate the 11 dead frontend API functions** — especially `contributeChain`/`validateChain`, which silently mask that the §7 commons-contribute UI flow doesn't exist.
