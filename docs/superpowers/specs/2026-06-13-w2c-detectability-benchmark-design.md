# W2c — Detectability Classifier Benchmark (30-case pilot): Design

**Date:** 2026-06-13
**Status:** Approved (design), pending implementation plan
**Scope:** Wave 2c of the agentic rebuild program ([2026-06-10-agentic-rebuild-proposal.md](../../../architecture/2026-06-10-agentic-rebuild-proposal.md) §5; viability-review ranking #4).
**Branch:** `claude/wave2c-detectability-benchmark` off main `f3b6e7d`.

## Goal

Stand up a **standalone** benchmark that scores the `DetectabilityClassifier`
(5-class) against owner-adjudicated ground-truth labels and persists the
metrics into the existing `prompt_evaluations` framework — establishing the
evidence base that a future Phase 2c gating decision will rest on.

Two findings shape the design:
- The classifier reads only from a `loop2_output` dict + `gate_result` dict +
  `ctx.prior_outputs[1]` (the Loop 1 vuln_profile). It can therefore be
  benchmarked on **hand-curated inputs without running Loop 1/2** — the
  expensive part of the original cost estimate is avoided.
- Ground-truth labels are **owner-adjudicated**, not LLM-generated (proposal
  §6: LLM-labeling an LLM classifier is circular). The agent drafts proposed
  labels; the owner reviews/corrects them before the scored run is meaningful.

**Cost:** the build (harness + 30 fixtures) is **zero LLM spend**. The scored
run is ~30 classifier calls × a few iterations ≈ **~$5** on the deployed
`claude-sonnet-4-6`. This runs only after label adjudication.

## Phasing

1. **Build (no spend, this branch):** the `predict()` refactor + metrics module
   + 30-case fixture + runner + tests + the adjudication review doc.
2. **Owner gate:** owner adjudicates the 30 draft `expected.detectability_class`
   labels (edits the fixture JSON; the review doc aids scanning).
3. **Scored run (~$5, deployed env):** run the benchmark against the live
   classifier; persist a `prompt_evaluations` row; report accuracy / confusion
   matrix / calibration.

This spec + plan cover **Phase 1 only**. Phases 2–3 are owner-gated follow-ups.

## Current state (verified)

- `prompt_evaluations` columns: `prompt_template_id`, `benchmark_set` (str,
  indexed), `technique_overlap`/`ordering_consistency` (Numeric 3,2),
  `hallucination_count` (int), `cost_per_run` (Numeric 8,4), `avg_latency_ms`
  (int), `sample_outputs` (JSONB), `evaluated_at`, `evaluated_by`. The three
  chain metrics are chain-shaped; `cost_per_run`/`avg_latency_ms`/
  `benchmark_set`/`sample_outputs`/`evaluated_*` are generic.
- `PromptEvaluator.run` (`fragchain/prompts/eval.py`) is hard-coupled to chain
  generation (`_run_case` drives the chain generator). It is NOT reused — the
  classifier benchmark gets its own runner.
- `DetectabilityClassifier.classify` (`fragchain/assessments/detectability.py`)
  → `_classify` does `structured_complete(...)` then builds a
  `DetectabilityAssessmentRow` and `session.add(row)` — prediction and
  persistence are intertwined.
- Benchmark precedent: `benchmarks/dirty_frag_groundtruth.json` (fixture JSON
  shape) + `scripts/eval_chain.py` (runner pattern).

## Design

### A. `predict()` extraction (behavior-preserving classifier refactor)

Split the LLM prediction from persistence in `DetectabilityClassifier`:
- New `async def predict(self, *, ctx, loop2_output, gate_result) ->
  DetectabilityAssessment | None`: builds the prompt, calls
  `structured_complete`, validates into the `DetectabilityAssessment` pydantic,
  and **returns it** (no DB write, no `loop_run_id` needed). Returns `None` on
  failure, preserving the classifier's advisory swallow.
- `_classify(...)` is refactored to call `predict(...)` then build + `session.add`
  the `DetectabilityAssessmentRow` from the returned model (unchanged outward
  behavior). The cost/latency metadata `predict` surfaces is what `_classify`
  already records.
- The benchmark calls `predict()`; it never persists assessment rows.
- Existing detectability tests (`tests/assessments/test_detectability_classifier.py`)
  stay green unchanged — they are the regression net for this refactor.

### B. Fixture — `benchmarks/detectability_pilot_v1.json`

30 agent-drafted cases, ~6 per class (so the 5×5 confusion matrix is
populated). Shape:
```json
{
  "name": "detectability_pilot_v1",
  "description": "30-case pilot for the detectability classifier; labels owner-adjudicated.",
  "cases": [
    {
      "id": "case-07-proxylogon",
      "cve": { "cve_id": "CVE-2021-26855", "title": "...", "description": "..." },
      "vuln_profile": { "vuln_class": "ssrf", "...": "..." },
      "loop2_output": {
        "indicators": { "network": [ { "value": "..." } ], "process": [ ... ] },
        "unanswered_questions": [ "..." ]
      },
      "gate_result": { "passed": true, "filled_categories": ["network","process"], "empty_categories": ["registry"], "threshold": 3 },
      "expected": { "detectability_class": "directly_detectable", "notes": "owner-review: why this class" }
    }
  ]
}
```
- `loop2_output.indicators` keys are the 7 `ObservableCategory` values
  (process / command_line / file / network / registry / parent_child /
  api_call) — match the real Loop 2 output shape exactly.
- `vuln_profile` matches the Loop 1 output shape the classifier reads from
  `ctx.prior_outputs[1]`.
- Cases span the 5 classes including the hard ones: sparse-indicator →
  `insufficient_information`; mitigation/config-only → `control_only`;
  env-conditional telemetry → `environment_dependent`.
- **Synthetic-but-realistic:** inputs are curated by the agent from public CVE
  knowledge; they do not require real pasted source material. The `expected`
  label is a *draft* the owner adjudicates.

### C. Metrics — `fragchain/evaluations/detectability_metrics.py`

Pure functions, no LLM, no DB — fully unit-testable. Public entry:
`compute_metrics(results: list[CaseOutcome]) -> dict` where `CaseOutcome`
carries `(case_id, expected, predicted, confidence, correct)`. Returns:
- `accuracy` — overall correct / total.
- `per_class` — for each of the 5 classes: precision, recall, f1, support.
- `macro_f1` — unweighted mean F1 across classes.
- `confusion_matrix` — 5×5, rows = expected, cols = predicted, with the class
  order recorded.
- `calibration` — mean confidence overall, mean confidence on correct vs
  incorrect predictions (a large correct-vs-incorrect gap = well-calibrated;
  high confidence on wrong answers = over-confident).
- `n` — case count.
All numbers rounded to a fixed precision; division-by-zero guarded (a class
with zero support → precision/recall reported as `null`, not a crash).

### D. Runner — `scripts/run_detectability_benchmark.py`

- Loads `benchmarks/detectability_pilot_v1.json`.
- For each case: build a synthetic `LoopContext` (a throwaway `assessment_id`
  uuid, `cve_textual_id` from `cve.cve_id`, `prior_outputs={1: vuln_profile}`,
  `cve_id`/source fields as the classifier needs), call
  `classifier.predict(ctx=..., loop2_output=case.loop2_output,
  gate_result=case.gate_result)`, record predicted class + confidence + the
  call's cost + latency.
- Compute metrics via module C.
- Persist ONE `PromptEvaluation` row: `benchmark_set="detectability_pilot_v1"`,
  `sample_outputs` = the full report (summary metrics + per-case rows),
  `cost_per_run` = mean per-case cost, `avg_latency_ms` = mean latency,
  `evaluated_by` from a `--evaluated-by` arg; the chain numeric columns left
  NULL. The active `detectability_classification` template id is recorded as
  `prompt_template_id` (resolved via the prompt store).
- Print a summary table (accuracy, macro-F1, confusion matrix, calibration).
- **`--dry-run`**: validate every fixture case (schema, valid class strings,
  indicator categories) and run module C against the *expected* labels as a
  self-check — **no LLM calls, no DB writes**. This is what CI/tests exercise.
- `--no-store` runs the real classifier but skips persistence (for a quick
  look without a DB row).

### E. Adjudication artifact — `docs/superpowers/specs/detectability_pilot_labels.md`

A generated, readable table: case id · CVE · one-line indicator summary ·
**proposed class** · rationale. Lets the owner scan all 30 proposed labels
quickly. Corrections flow back into `benchmarks/detectability_pilot_v1.json`
(`expected.detectability_class`) — the JSON is the source of truth; the doc is
a review aid. The plan generates this doc from the fixture so the two cannot
drift.

### F. Tests

- **Metrics module** (`tests/evaluations/test_detectability_metrics.py`):
  deterministic accuracy, per-class P/R/F1, confusion matrix, calibration,
  zero-support guard. No LLM.
- **Fixture validation** (`tests/evaluations/test_detectability_fixture.py`):
  the 30 cases parse; every `expected.detectability_class` is a valid
  `DetectabilityClass`; every indicator key is a valid `ObservableCategory`;
  every case has the required fields; counts span all 5 classes.
- **`predict()` refactor**
  (`tests/assessments/test_detectability_classifier.py`): existing tests stay
  green; add one asserting `predict()` returns a `DetectabilityAssessment` and
  performs no `session.add`.
- **Runner dry-run** (`tests/test_detectability_benchmark_dryrun.py` or under
  `tests/`): `--dry-run` loads + validates the fixture and emits a metrics dict
  with zero LLM calls (mock/skip the provider) — guards the harness wiring.

## Scope boundaries

- **In (Phase 1):** the `predict()` refactor; the metrics module; the 30-case
  fixture with drafted labels; the runner (incl. `--dry-run`); the adjudication
  doc; the tests above.
- **Out:** the scored run (Phase 3, owner-gated, ~$5); label adjudication
  (Phase 2, owner); the Phase 2c gating flip (separate owner decision); any
  schema migration (JSONB-only); scaling past 30 cases; real-CVE-sourced inputs.

## Risks

- **Fixture realism.** Synthetic `loop2_output` sets must resemble real Loop 2
  output or the benchmark tests the classifier on out-of-distribution inputs.
  Mitigation: model each case's indicators on the public detection guidance for
  a real CVE; the owner's adjudication pass is also a realism check.
- **`predict()` refactor regressions.** Mitigated by keeping the existing
  detectability tests green as the contract.
- **Label quality.** The drafted labels are the agent's best guess; they are
  explicitly *draft* until the owner adjudicates (Phase 2). The benchmark
  numbers are only as good as the adjudicated labels — the spec treats Phase 1
  output as un-adjudicated.
