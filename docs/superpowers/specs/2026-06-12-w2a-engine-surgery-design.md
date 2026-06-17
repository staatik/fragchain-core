# W2a — Engine Surgery: Design

**Date:** 2026-06-12
**Status:** Approved (design), pending implementation plan
**Scope:** Wave 2a of the agentic rebuild program ([2026-06-10-agentic-rebuild-proposal.md](../../../architecture/2026-06-10-agentic-rebuild-proposal.md) §5).
**Branch:** `claude/wave2a-engine-surgery` off main `51f7daa`.

## Goal

Refactor `LoopOrchestrator.execute_run` for maintainability and lay the
mechanism for the automated CVE→artifacts pipeline, **without changing any
existing behavior** except the addition of a new opt-in loop-chaining driver.

Four sub-pieces, all from the platform review's Appendix A / proposal §5:

1. Extract the `execute_run` post-loop **god-method** into an ordered hook pipeline.
2. Unify the **duplicated API/worker orchestrator factory** wiring.
3. Extract a shared **versioned-active-row helper** (before Phase 3 adds a 5th supersession variant).
4. Add a **loop-chaining driver** (on-succeeded → dispatch next loop under policy; gate-fail/failed/loop3-done = machine-readable stop).

## Current state (what we're operating on)

- `fragchain/assessments/orchestrator.py::LoopOrchestrator.execute_run`
  (~lines 167–483) runs the loop impl then inlines ~8 post-loop hooks, each
  guarded by scattered `if loop_number == X and status == Y` conditionals and
  its own try/except: **gate** (L2, can flip status→`gate_failed`) → **chain
  synthesis** (L2 gate-passed, can flip status→`failed`) → **rule
  supersession** (L3) → **observe-loop3** (L3 artifact-plan reconciliation) →
  **coverage dispatch** (L3) → persist/cost → **supersede+activate+invalidate**
  → **detectability classification + artifact plan** (L2, runs *after* the row
  is flushed/activated because it joins on `run.id`) → state advance → audit →
  commit.
- The orchestrator is constructed by two near-byte-identical factories:
  `api/routers/assessments.py::_orchestrator_factory` and
  `worker/tasks/run_assessment_loop.py::_make_orchestrator`. The API factory's
  docstring explicitly warns "Touch both when changing the construction." The
  `_EmbedderShim` adapter is also duplicated across both modules.
- The versioned-active-row idiom — `max(version)+1` then *demote prior active
  rows → flush → activate new row* under a partial unique index — is
  copy-pasted across `assessment_loop_run` (orchestrator), `attack_chains`
  (`chain_synthesis.py`, added in #81), and `generated_artifacts`
  (`artifact_generation.py::begin_generation`). ADR-0004 Phase 3 will add a 5th
  (validation states).
- Today there is **no loop chaining**: each loop is dispatched manually
  (`POST /assessments/{id}/loops/{n}/run`). Appendix A flagged the absence as a
  prerequisite for the automation product bet.

## Design

### A. Post-loop hook pipeline

New module `fragchain/assessments/loops/post_loop.py`:

- **`LoopExecution`** — mutable dataclass threaded through the hooks, carrying
  what hooks read and produce: `ctx` (LoopContext), `run` (AssessmentLoopRun),
  `loop_number`, `status`, `output`, `gate_result`, `assessment`, `prior_outputs`,
  and accumulators (`synth_meta`, `supersession_totals`). Hooks mutate it in
  place; `status` mutations are how the gate and chain-synthesis hooks signal
  `gate_failed` / `failed`.
- **`PostLoopHook` protocol** — `name: str`, `should_run(ex) -> bool`,
  `async run(ex) -> None`. Each hook owns its own try/except + event emission,
  preserving today's **advisory-swallow** semantics exactly (detectability,
  router, supersession, coverage all swallow their own errors today; the gate
  and chain-synthesis hooks are the only two allowed to flip `status`).
- **Concrete hooks**, one per current inline block:
  - `GateHook` (L2, succeeded) — evaluate detectability gate; may set `status=gate_failed`.
  - `ChainSynthesisHook` (L2, gate-passed) — synthesize chain; may set `status=failed`; emits `assessment.chain.synthesized`.
  - `RuleSupersessionHook` (L3, succeeded) — supersede prior rules per (cve, technique, profile); emits `assessment.rule.superseded`.
  - `ObserveLoop3Hook` (L3, succeeded) — artifact-router `observe_loop3` reconciliation.
  - `CoverageDispatchHook` (L3, succeeded) — fire `map_coverage` task.
  - `DetectabilityHook` (L2, succeeded|gate_failed) — classify, then chain the artifact-plan; **runs post-finalize** (needs `run.id`).
- **Two ordered lists**, because today's code has a hard split around the
  finalize: `PRE_FINALIZE_HOOKS` (gate, chain-synth, rule-supersession,
  observe-loop3, coverage-dispatch) run before persist/activate;
  `POST_FINALIZE_HOOKS` (detectability+plan) run after the row is
  flushed/activated. Order within each list is load-bearing and explicit.
- The pipeline runner is a trivial `for hook in hooks: if hook.should_run(ex): await hook.run(ex)`.

`execute_run` becomes: idempotency check → build context → run the loop impl →
build `LoopExecution` → run `PRE_FINALIZE_HOOKS` → `_finalize_run(ex)` → run
`POST_FINALIZE_HOOKS` → return run. Target: ~60 lines. `execute_run` does NOT
invoke the chaining driver — it returns the finalized run, and the worker task
calls the driver after the transaction commits (see D).

**Phase 3 validation lands as one new hook** appended to a list — no
`execute_run` edit.

### B. Finalize + versioned-active-row helper

- **`_finalize_run(ex)`** (orchestrator method) — extracts the persist tail:
  write output/gate/cost/error/latency/embedding_warned onto `run`; the
  supersede-at-success block (`demote prior active → flush → activate →
  invalidate downstream`), but ONLY for `succeeded`/`gate_failed`; state
  advance (succeeded/gate_failed only); audit; commit; refresh; log. Behavior
  identical to today — extracted and named, not changed.
- **`fragchain/assessments/active_rows.py`** — two focused helpers:
  ```python
  async def next_version(session, model, *scope_clauses) -> int:
      # max(version) over the scope + 1

  async def supersede_active(session, model, *scope_clauses) -> list:
      # demote every is_active row matching scope (is_active=False,
      # status="superseded" where the model has a status col); return them
  ```
  `scope_clauses` are SQLAlchemy filter expressions so all current scopes work:
  `(assessment_id, loop_number)`, `(cve_id,)`, `(assessment_id, artifact_type)`.
  **Conservative boundary:** the helper shares only the duplicated *queries*.
  The flush-between-demote-and-activate ordering stays in each caller, because
  it is tied to each model's specific partial unique index and is checked
  per-statement. Replaces the copy-pasted query idiom in the orchestrator,
  `chain_synthesis.py`, and `artifact_generation.py`.

### C. Factory unification

New `fragchain/assessments/orchestrator_factory.py::build_orchestrator(session)
-> LoopOrchestrator` holding the wiring currently duplicated across the two
factories (loop construction, prompt store, embedder shim, RAG builder, gate
min, all collaborators). The duplicated `_EmbedderShim` moves here too. Both
`api/routers/assessments.py::_orchestrator_factory` and
`worker/.../run_assessment_loop.py::_make_orchestrator` collapse to a one-line
delegation (kept as thin named wrappers so existing test rebind-points still
work). The coverage-dispatch closure is built inside the shared factory with
the lazy `map_coverage` import (the only real difference between the two
factories today was import timing, which the lazy import already handles).

### D. Loop-chaining driver + schema

- **Migration `0027`** — add `coverage_assessment.auto_advance BOOLEAN NOT NULL
  DEFAULT false`. Surfaced read-only in the assessment response schema.
- **`LoopChainDriver`** (`fragchain/assessments/loop_chain.py`) — after
  `execute_run` finalizes, `maybe_dispatch_next(run, assessment, dispatch)`
  decides:
  - `status == "succeeded"` **and** `assessment.auto_advance` **and** a next
    loop exists (1→2 or 2→3) → dispatch the next loop (begin_run for the next
    loop + enqueue its worker task). Never auto-runs the Loop 3 override path
    (a gate-failed L2 requires an analyst rationale, so it cannot be reached
    under auto-advance).
  - `gate_failed` / `failed` / loop 3 succeeded → **stop**, emitting
    `assessment.loop.chain.stopped` with a machine-readable `reason`
    (`gate_failed` | `loop_failed` | `chain_complete`). Gate-fail is the
    documented analyst-decision point; the machine halts and waits.
- **Invocation site:** the **worker task** (`run_assessment_loop._run`), after
  `execute_run` returns and its transaction has committed — NOT inside
  `execute_run`. This keeps the orchestrator transaction pure and the
  next-loop dispatch outside the committed unit, mirroring how the API endpoint
  dispatches the first loop. The driver only ever *enqueues* the next loop's
  begin+execute; it never runs LLM work itself.
- **Default off** → today's manual stepping is byte-for-byte the current
  behavior. W3a headless mode creates assessments with `auto_advance=true` and
  triggers the first Loop 1; the chain then runs 1→2→3 (or halts at a gate
  fail) on its own.

## Testing

- **Per-hook unit tests** — each hook tested in isolation against a
  `LoopExecution` fixture (the entire point of the extraction). Includes the
  status-flip hooks (gate→gate_failed, chain-synth error→failed) and the
  advisory-swallow hooks (an internal error leaves status untouched).
- **Pipeline ordering test** — asserts the documented order and the
  pre/post-finalize split.
- **`active_rows` helper tests** — `next_version` over each scope shape;
  `supersede_active` demotes only matching active rows.
- **Driver tests** — succeeded+flag→dispatches next; succeeded+flag-off→no
  dispatch; gate_failed→stop+event; failed→stop+event; loop3 succeeded→stop
  (chain_complete); never dispatches the override path.
- **Factory equivalence test** — both call sites produce orchestrators with the
  same collaborator set.
- **Regression safety net:** the existing orchestrator test suite
  (`tests/assessments/test_orchestrator*.py`, the worker task tests) must stay
  **green unchanged** — they are the proof the refactor preserved behavior. The
  `run_loop` convenience wrapper is unchanged.

## Scope boundaries

- **In:** the four sub-pieces above; migration `0027`; the opt-in driver
  (default off).
- **Out:** progress UI / failed-run rendering (W2b); the *first-loop* trigger
  for headless mode (W3a); the Phase 3 validation hook (leave the pipeline seam
  only). No change to CLAUDE.md §19 invariants or the §12.2 dormant allowlist.
- **One migration** (`0027`), additive, backward-compatible.

## Risks

- The refactor is behavior-preserving by contract; the existing suite is the
  guard. The main risk is a subtle reordering of the pre/post-finalize hooks —
  mitigated by making the two lists explicit and testing the order.
- The driver introduces a new dispatch path; default-off keeps it inert until
  W3a, and the stop-policy is unit-tested for every terminal status.
