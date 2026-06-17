# Detectability Pilot — Scored Benchmark Results (W2c Phase 3)

**Run date:** 2026-06-14 · **Fixture:** `benchmarks/detectability_pilot_v1.json` (30 cases, owner-adjudicated, accepted as drafted)
**Classifier:** deployed `DetectabilityClassifier`, model `claude-sonnet-4-6`, seeded `detectability_classification` v1 prompt
**Persisted:** `prompt_evaluations` row `56fec4fd-0848-4cdc-956f-4cd9036379e9` (`evaluated_by=owner-adjudicated-pilot-2026-06-13`)
**Runner:** `python scripts/run_detectability_benchmark.py` (standalone path, after the provider-bootstrap fix)

## Headline

**`indirectly_detectable` recall = 0/6 (0%).** The classifier never emitted this
class for any case — the entire `indirectly_detectable` prediction column is zero.
This quantifies, on adjudicated ground truth, the blind spot the 2026-06-13 live
runs hinted at (0/4). The 6 indirectly-detectable cases collapse to the two poles:
3 → `directly_detectable`, 3 → `environment_dependent`.

## Aggregate

| Metric | Value |
|---|---|
| n | 30 |
| accuracy | **0.60** |
| macro F1 | **0.539** |
| mean latency / case | ~39 s (every case pays a `priority` repair-retry — see Operational notes) |
| mean cost / case | 0.0 (LiteLLM proxy returns no per-call cost; tokens are captured) |

## Per-class

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| `directly_detectable` | 0.625 | 0.833 | 0.714 | 6 |
| `indirectly_detectable` | — (never predicted) | **0.000** | **0.000** | 6 |
| `environment_dependent` | 0.400 | 1.000 | 0.571 | 6 |
| `control_only` | 1.000 | 0.333 | 0.500 | 6 |
| `insufficient_information` | 1.000 | 0.833 | 0.909 | 6 |

## Confusion matrix (rows = expected, cols = predicted)

| expected ↓ / predicted → | direct | indirect | env | control | insuf |
|---|---|---|---|---|---|
| directly_detectable | **5** | 0 | 1 | 0 | 0 |
| indirectly_detectable | 3 | **0** | 3 | 0 | 0 |
| environment_dependent | 0 | 0 | **6** | 0 | 0 |
| control_only | 0 | 0 | 4 | **2** | 0 |
| insufficient_information | 0 | 0 | 1 | 0 | **5** |

## Per-case misses (6 of 30)

| Case | Expected | Predicted | Conf |
|---|---|---|---|
| case-05-zerologon | directly_detectable | environment_dependent | 0.62 |
| case-07-proxylogon | indirectly_detectable | directly_detectable | 0.87 |
| case-08-citrix-adc | indirectly_detectable | environment_dependent | 0.62 |
| case-09-fortios-traversal | indirectly_detectable | environment_dependent | 0.62 |
| case-10-f5-icontrol | indirectly_detectable | directly_detectable | 0.88 |
| case-11-vcenter-upload | indirectly_detectable | directly_detectable | 0.85 |
| case-12-bluekeep | indirectly_detectable | environment_dependent | 0.62 |
| case-20-openssl-punycode | control_only | environment_dependent | 0.35 |
| case-22-heartbleed | control_only | environment_dependent | 0.72 |
| case-23-libwebp | control_only | environment_dependent | 0.62 |
| case-24-cisco-asa-read | control_only | environment_dependent | 0.45 |
| case-29-http2-reset | insufficient_information | environment_dependent | 0.62 |

(12 misses → accuracy 0.60. The two reliable poles — `directly_detectable` and
`insufficient_information` — account for only 2 of the 12.)

## Findings

1. **`indirectly_detectable` is unusable (0% recall, never predicted).** The v1
   prompt has no working notion of "a signal exists but it's secondary / noisy /
   you detect the consequence not the exploit." Every such case is forced to a
   pole.
2. **`environment_dependent` is an uncertainty sink (recall 1.0, precision 0.40).**
   It absorbed 1 directly, 3 indirectly, 4 control_only, and 1 insufficient case —
   9 false positives against 6 true. Most land at a near-constant `conf≈0.62`,
   reading like a default "not sure" bucket.
3. **`control_only` recall is weak (2/6).** 4 of 6 "patch is the only defense"
   cases were called `environment_dependent` — the classifier conflates "no
   reliable detection" with "needs special telemetry." (Precision is 1.0: when it
   *does* say control_only it's right.)
4. **The two reliable poles are `directly_detectable` (R 0.83) and
   `insufficient_information` (R 0.83, P 1.0).** `insufficient_information` is also
   well-calibrated — its predictions carry very low confidence (0.02–0.12).
5. **Calibration is inverted in aggregate:** mean confidence on *incorrect*
   predictions (0.653) exceeds that on correct ones (0.552), driven by the
   over-confident `environment_dependent` false positives. A confidence threshold
   would not cleanly separate right from wrong — except for the very-low-confidence
   `insufficient_information` signals.

## Implications for ADR-0004 Phase 2c (gating flip)

- **Do not gate generation on `indirectly_detectable`** — the classifier cannot
  produce it. Either improve the v1 prompt to distinguish the middle class (add
  explicit guidance + worked examples: reliable post-exploit consequence in common
  telemetry ⇒ indirect, vs. the two poles) or drop the class from the gating
  vocabulary.
- **`environment_dependent` cannot be trusted as a skip signal** — its 40%
  precision means gating "skip Sigma when environment_dependent" would wrongly
  skip genuinely directly/indirectly-detectable vulns.
- **Safe-to-gate today:** `directly_detectable` (proceed) and
  `insufficient_information` (decline) are reliable and, for the latter,
  well-calibrated.
- **Re-run this benchmark after any v1-prompt change** to measure movement on
  `indirectly_detectable` recall and `environment_dependent` precision before
  flipping gating on.

## Operational notes

- **Every case triggered a `priority`-field repair-retry.** The classifier prompt
  emits `recommended_artifacts[].priority` as a string (`"high"`/`"medium"`/`"low"`)
  but `DetectabilityAssessment` requires an int, so `structured_complete` does one
  repair round-trip per call — ~2 LLM calls/case, ~39 s mean latency, and extra
  spend. Fixing the prompt (or relaxing the schema to accept the string enum) would
  roughly halve benchmark latency/cost. Pre-existing; first seen in the Wave 1 live QA.
- **Best-effort `llm_interactions` FK noise.** The benchmark scores standalone with
  synthetic `assessment_id`s, so each call's best-effort `llm_interactions` write
  fails the `assessment_id` FK (logged `llm.io.db_write_failed`, non-fatal per
  CLAUDE.md §6). Predictions and metrics are unaffected; the per-interaction cost
  rows simply aren't written for benchmark runs.
