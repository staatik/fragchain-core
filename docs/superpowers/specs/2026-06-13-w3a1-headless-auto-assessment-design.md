# W3a-1 — Headless Auto-Assessment (Given Sources): Design

**Date:** 2026-06-13
**Status:** Approved (design), pending implementation plan
**Scope:** Wave 3a, stage 1 — owner-approved per the [W3a memo](../../architecture/2026-06-13-w3a-headless-auto-assessment-memo.md) + [008 ledger](../../architecture/008-rebuild-decision-log.md) entry #2.
**Branch:** `claude/wave3a-scoping-memo` off main `f3b6e7d` (already carries the memo + ledger).

## Goal

A programmatic trigger that runs a full coverage assessment **unattended** —
given a CVE and caller-supplied source material — by reusing W2a's
loop-chaining driver, with a density safety that structurally cannot reproduce
the thin-input failure (viability review #1). **No §12.2 revival, no source
auto-fetch** (that is W3a-2, deferred to its own memo).

W3a-1 is orchestration glue + one guard + one setter. It adds **no** new loop
logic and **no** migration (`coverage_assessment.auto_advance` already exists
from W2a).

## Current state (verified)

- `AssessmentService.create(req, *, creator_id)` (`fragchain/assessments/service.py`)
  creates a `coverage_assessment` row (state `created`); raises
  `DuplicateAssessmentError` if a CVE already has one. The create request has no
  `auto_advance` field.
- `SourceService.add` attaches `kind=free_text` sources (limits: ≤100KB/source,
  ≤2MB total; per `fragchain/assessments/content.py`).
- `LoopOrchestrator.begin_run(assessment_id, LoopNumber.ONE)` + the API endpoint
  dispatch `run_assessment_loop.delay(run_id)` after committing the running row.
- W2a's `LoopChainDriver` (`fragchain/assessments/loop_chain.py`): when
  `coverage_assessment.auto_advance` is true, a succeeded loop dispatches the
  next; `gate_failed` / `failed` / loop-3-done **stop** the chain.
- `LoopOrchestrator.begin_run` for Loop 3 raises `InvalidLoopTransitionError`
  when the latest Loop 2 finalized `gate_failed` and no `override_rationale` is
  supplied — i.e. **the gate is already enforced**; a headless caller that never
  supplies an override simply cannot push a thin assessment into Loop 3.
- `coverage_assessment.auto_advance` column exists (migration 0027); **no code
  writes it `true`** today (no setter).

## Design

### A. Reusable service core — `fragchain/assessments/headless.py`

```python
@dataclass
class AutoAssessResult:
    status: Literal["started", "rejected_thin_sources", "duplicate"]
    assessment_id: uuid.UUID | None
    loop1_run_id: uuid.UUID | None
    detail: str | None = None

async def auto_assess(
    session: AsyncSession,
    *,
    cve_id: uuid.UUID,
    cve_textual_id: str,
    sources: list[HeadlessSource],   # [{title, content}]
    creator_id: uuid.UUID,
    dispatch: Callable[[str], None] = run_assessment_loop.delay,
) -> AutoAssessResult
```

Flow:
1. **Density precheck (pre-spend guard):** total bytes of `sources` content must
   be ≥ `HEADLESS_MIN_SOURCE_BYTES` (config; default 500) and there must be ≥1
   source. Below the floor → return `rejected_thin_sources` (no assessment
   created, no LLM spend). This is a cheap spend-guard, **not** the density
   judge — the gate is.
2. **Create** the assessment via `AssessmentService.create` (trigger
   `{kind: cve_id, value: cve_textual_id}`). `DuplicateAssessmentError` →
   return `duplicate`.
3. **Attach** each source via `SourceService.add` (existing `free_text` path,
   inheriting its size limits — a source over the limit surfaces the service's
   existing error).
4. **Set `auto_advance=true`** via the setter (§C).
5. **Dispatch Loop 1:** `orchestrator.begin_run(assessment_id, LoopNumber.ONE)`
   (no `override_rationale` — ever), commit, `dispatch(str(run.id))`. Return
   `started` with the assessment + loop-1 run ids.

The function is dependency-injected on `dispatch` so tests assert the dispatch
without Celery. It **never** passes `override_rationale` anywhere — the
no-auto-override invariant lives here.

### B. Density safety — two layers, the real one already free

1. **The gate (existing, the mechanism):** because `auto_assess` never supplies
   an override, a Loop 2 that fails `GATE_MIN_CATEGORIES` finalizes `gate_failed`
   and W2a's driver **stops the chain** at `loop2_done`. The assessment ends with
   a detectability classification (a valid "insufficient / no reliable detection"
   output per the defense-engineering direction) — never a thin-input Loop 3.
   W3a-1 changes none of this; it relies on it.
2. **The pre-Loop-1 min-source guard (new, §A.1):** avoids spending Loop 1 on
   empty/near-empty input. A floor, not the judge.

### C. `auto_advance` setter — `AssessmentService.set_auto_advance`

```python
async def set_auto_advance(self, assessment_id: uuid.UUID, value: bool) -> None:
    # load row, set auto_advance, commit; raises AssessmentNotFoundError if absent
```

A small, testable method on the existing service (rather than an inline update in
`headless.py`), so the write path is unit-coverable and reusable. This is the
only writer of `auto_advance=true`.

### D. CLI — `scripts/auto_assess.py`

Thin wrapper (mirrors `scripts/eval_chain.py`'s session-open pattern):
- args: `--cve-id <textual CVE id>` (resolves/creates the CVE row — see note),
  `--source-file PATH` (repeatable) and/or `--source-stdin`, `--title`.
- opens a session, resolves the CVE row id, reads source files, calls
  `auto_assess`, prints the `AutoAssessResult` (status + ids) as JSON.
- **CVE-row resolution:** the CLI requires the CVE row to exist (by textual id);
  if absent it errors with a clear message (creating CVE rows from external data
  is auto-fetch territory = W3a-2). For W3a-1 the operator seeds the CVE row (the
  same precondition the manual workspace has today).

Not an API endpoint — headless runs as the operator via CLI/cron, matching the
script pattern and keeping the authenticated API surface unchanged.

### E. Config

`HEADLESS_MIN_SOURCE_BYTES: int = 500` in `fragchain/config.py` — the pre-Loop-1
floor. Documented as a spend-guard, not the density gate.

### F. Tests

- `auto_assess` **happy path**: creates assessment, attaches sources, sets
  `auto_advance=true`, calls `begin_run(loop=1)`, invokes `dispatch` with the run
  id; result `started`. (Mock/inject `dispatch`; in-memory session or mocked
  services per the repo's existing assessment-test pattern.)
- **density guard**: zero sources and below-floor total → `rejected_thin_sources`,
  **no** assessment created, **no** dispatch.
- **duplicate**: a CVE with an existing assessment → `duplicate`.
- **never auto-overrides**: assert no `override_rationale` is passed to
  `begin_run` (spy/inspect). (The gate-stop behavior itself is already covered by
  W2a's driver tests — reference, don't duplicate.)
- `set_auto_advance`: flips the column; `AssessmentNotFoundError` on a missing id.
- **CLI smoke**: `--help` parses; a `--source-file` round-trip builds the right
  `HeadlessSource` list (no LLM, no DB — or a path-based import test mirroring
  `scripts/` test convention).

## Scope boundaries

- **In:** `headless.py::auto_assess` + `AutoAssessResult`/`HeadlessSource`; the
  `set_auto_advance` service method; the `HEADLESS_MIN_SOURCE_BYTES` config; the
  `scripts/auto_assess.py` CLI; tests.
- **Out:** source auto-fetch / NVD-KEV connector / §12.2 revival / KEV-watch
  daemon (all W3a-2); any new API endpoint; any change to the gate, driver, or
  override semantics (reused unchanged); CVE-row creation from external data; any
  migration.

## Risks

- **Operator triggers a thin-source CVE anyway.** Mitigated by the gate (stops at
  `loop2_done`) + the min-source floor (rejects empties). The worst case is a
  cheap Loop 1+2 that correctly concludes "insufficient information" — the
  designed-for outcome, not a generic-rule leak.
- **Unattended cost.** Each `started` assessment runs Loop 1+2 (+3 + artifacts if
  the gate passes), ~$0.50–2.50. The operator controls how many CVEs they
  trigger; there is no daemon auto-triggering in W3a-1.
- **`auto_advance` left true after completion.** Harmless — the driver stops at
  loop-3-done / completed regardless; the flag only affects in-flight chaining.
