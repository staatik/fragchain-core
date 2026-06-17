# Async Loop Execution + Timeout Config (Design — Plan A)

**Status:** Approved (2026-06-10). Prerequisite for Phase 2b
(`2026-06-10-phase-2b-artifact-generation-design.md`).
**Validation:** automated tests only (TDD). No reliance on live runs against the
slow gateway.

## Problem (root-caused 2026-06-10)

Assessment loops run **inline in the API request**
(`assessments.py::run_loop` → `_orchestrator_factory(session).run_loop(...)`).
A real Loop-1 LLM call takes ~60s through the deployment's gateway
(measured: ~7–8s baseline + ~40 output tok/s; Loop-1 ≈ 2,500 tokens ≈ 60s).
Three stacked timeouts kill it:

1. `structured_complete`'s `asyncio.wait_for(timeout=30.0)` — fires first, at 30s.
2. httpx client timeout 60s (in `litellm_provider.initialize`).
3. nginx `/api/` `proxy_read_timeout 60s` — returns 504 to the client.

`rule_generation` survives only because it calls `provider.complete()` directly
(no 30s `wait_for`, just the 60s httpx) and emits fewer tokens (12–24s).

The frontend was **already built for async** — `useAssessment` polls
`while any loop run is in 'running' state` and refetches on the
`assessment.loop.run.completed` WS event — but the backend has **no `'running'`
status** and never dispatches the (existing, currently uncalled)
`run_assessment_loop` Celery task. This plan completes that half-built feature
and removes the synchronous LLM call from the request path.

## Decisions

1. **Move loop execution to the worker.** The API endpoint does a cheap
   synchronous precheck, creates a `'running'` run row, dispatches the existing
   `run_assessment_loop` Celery task, and returns 202 + the running row. No LLM
   call on the request path → no 504.
2. **Add a `'running'` status** to `assessment_loop_run` (no migration needed —
   `status` is a free String column; the value is new, the schema isn't).
3. **Split the orchestrator** into `begin_run` (sync, fast) and `execute_run`
   (worker, slow). Keep `run_loop` as `begin_run` + `execute_run` inline so every
   existing orchestrator test and the deterministic Phase-2 chain keep passing
   unchanged.
4. **Timeout config, not hardcoded.** New settings
   `LLM_STRUCTURED_TIMEOUT_SECONDS` (default 120) and
   `LITELLM_HTTP_TIMEOUT_SECONDS` (default 120); the loops pass the structured
   timeout explicitly, the provider reads the httpx timeout at init. nginx is
   left at 60s — irrelevant now that the request returns immediately.

## Lifecycle

```
POST /assessments/{id}/loops/{n}/run
  └─ begin_run (SYNC, no LLM):
       - can_run_loop(state, n)         → 409 if illegal transition
       - reject if an active 'running' row already exists for (assessment, n) → 409
       - Loop-3 gate-override precondition check → 409
       - supersede prior active rows for loop n; invalidate downstream loops
       - INSERT assessment_loop_run(status='running', is_active, version=max+1)
       - commit; return the row
  └─ run_assessment_loop.delay(run_id)   (dispatch)
  └─ 202 + running row
        ↓ (worker)
  execute_run(run_id):
       - load the running row + assessment + sources + prior outputs
       - run the loop impl (LLM work, the slow part)
       - gate eval (Loop 2); post-loop hooks (classifier, router, chain
         synthesis, rule supersession, coverage dispatch, plan observe)
       - UPDATE the row: status = succeeded|failed|gate_failed, output,
         gate_result, latency, error, completed_at
       - advance assessment state (next_state_after_loop) — as today,
         regardless of status
       - audit; emit assessment.loop.run.completed
        ↓
  frontend WS handler / polling fallback refetches → cards populate
```

State is **not** advanced at `begin_run` (the assessment stays at its current
state while the row is `running`); it advances only at `execute_run`, preserving
today's behavior. The post-loop hooks key off the already-created `run_id`, which
is cleaner than today's add-then-flush-for-id dance.

## Components

| Unit | Change |
|---|---|
| `fragchain/config.py` | `LLM_STRUCTURED_TIMEOUT_SECONDS=120.0`, `LITELLM_HTTP_TIMEOUT_SECONDS=120.0` |
| `fragchain/llm/litellm_provider.py` | httpx timeout from setting |
| loop callers (`loop1`, `loop2`, `detectability`) | pass `timeout_seconds=settings.LLM_STRUCTURED_TIMEOUT_SECONDS` to `structured_complete` |
| `fragchain/assessments/orchestrator.py` | `begin_run` + `execute_run`; `run_loop` = both inline (back-compat) |
| `fragchain/assessments/schemas.py` | add `running` to status doc; no schema change |
| `fragchain/worker/tasks/run_assessment_loop.py` | task body calls `execute_run(run_id)` instead of `run_loop(...)`; takes `run_id` |
| `fragchain/api/routers/assessments.py` | endpoint: `begin_run` (sync) → `.delay(run_id)` → 202 + running row |
| `frontend/src/hooks/useAssessment.ts` | `runLoop` dispatches & returns the running row; existing WS + polling already finish it |
| `frontend/src/components/assessments/LoopCard.tsx` | disable Run while a `running` row exists for that loop (status already renders) |

## Idempotency / failure

- The Celery task is keyed on `run_id`; a retry re-runs `execute_run` on the same
  row (which re-executes the loop — acceptable, the row is overwritten). Guard:
  `execute_run` no-ops if the row is already in a terminal status, so a duplicate
  delivery doesn't double-run.
- If the worker dies mid-run, the row stays `running`; the frontend polling keeps
  waiting. A stale-running reaper is **out of scope** (documented limitation) —
  the analyst can re-dispatch, which supersedes the stuck row.
- Worker provider bootstrap (`worker_process_init`, CLAUDE.md §19) already exists;
  this plan only adds a new caller, not new worker lifecycle.

## Testing (automated only)

- Orchestrator: `begin_run` creates a `running` row, supersedes prior active,
  rejects illegal transitions (409) and concurrent running rows (409), does not
  advance state; `execute_run` finalizes status/output/state and runs post-loop
  hooks; `execute_run` no-ops on an already-terminal row; `run_loop` still does
  both (existing tests stay green).
- Timeout: loop callers pass the configured timeout to `structured_complete`
  (assert via the patched-`structured_complete` kwargs); provider init uses the
  configured httpx timeout.
- API: endpoint returns 202 + a `running` row and calls `.delay(run_id)` (patched
  Celery), 404/409 paths preserved.
- Worker: task calls `execute_run(run_id)`; idempotent re-delivery.
- Frontend: `runLoop` returns the running row without awaiting completion; WS
  `completed` + polling drive the refetch; Run disabled while running.

## Scope boundaries (YAGNI)

- No stale-running reaper / timeout-sweeper (documented limitation).
- nginx config unchanged.
- No retry/backoff tuning on the Celery task beyond default.
- The known `_RUNNABLE` "re-run Loop 2 from loop3_done" inconsistency is **not**
  addressed here (separate flagged task); `begin_run` uses the same
  `can_run_loop`, so behavior is unchanged.
