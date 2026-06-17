# Phase 2c Gating — Revisited After Adjudication (ADR-0004)

**Date:** 2026-06-14 · **Gate:** owner-required (gating-behavior change) · **Status:** recommendation, awaiting owner decision
**Supersedes:** [2026-06-14-phase-2c-gating-decision.md](2026-06-14-phase-2c-gating-decision.md) (HOLD)

## What changed

The original Phase 2c decision was **HOLD the full flip**, on two load-bearing
facts: `indirectly_detectable` was unproducible (0% recall) and
`environment_dependent` was a 0.40-precision uncertainty sink. The
[label adjudication](../superpowers/specs/2026-06-14-detectability-adjudicated-results.md)
**resolved both**: on the adjudicated pilot, `indirectly_detectable` F1
0.0→0.769 (recall 5/6) and `environment_dependent` precision 0.40→0.857.
Aggregate accuracy 0.60→0.833, macro-F1 0.539→0.839; every class F1 ≥ 0.77; all
residual errors are adjacent-class confusions on the 5 kept borderline cases.

"HOLD everything" is therefore no longer the right answer. But the same
adjudication did **not** refresh calibration (still inverted), and the headline
0.833 was recomputed **offline** by re-scoring the existing v2 predictions
against 3 owner-flipped labels — the only *fresh* scored v2 number is 0.733, and
a fresh confirmation run is required. This decision was stress-tested by a
4-perspective + adversarial-verification analysis (full-flip advocate,
partial-flip advocate, adversarial skeptic, mechanism analyst → synthesis →
verifier); all four perspectives converged on the recommendation below.

## Recommendation: approve-and-build a narrow, config-reversible gate; flip after the confirmation run

**Do not "flip Phase 2c" as a wide switch.** Build a per-class, config-reversible
gate and enable only the parts the evidence and the router's own failure
asymmetry make safe. The governing principle (verified against the inviolable
§19 human review gate): **a false-_generate_ is caught by human review (a
low-value draft a reviewer rejects); a false-_skip_ is silent, produces no
review-queue entry, and is the only irreversible harm.** So gate hard only where
the false-suppression rate — the per-class _precision_ — is at the ceiling.

### Per-class gating to enable (after confirmation)

| Class | Router action | Adjudicated P / R | Safe because |
|---|---|---|---|
| `insufficient_information` | **skip Sigma** → research task | 1.00 / 1.00 | Precision 1.0 → zero false-suppression on the pilot; best-classified class. |
| `control_only` | **skip Sigma** → mitigation plan | 1.00 / 0.667 | Precision 1.0 → skip-when-fired is always right; low recall is benign (a missed control case just keeps generating Sigma, the safe default). |
| `environment_dependent` | **prerequisite** on Sigma (flag "verify telemetry") + telemetry contract | 0.857 / 0.857 | Soft action — Sigma still generates, so even a misroute does **not** suppress a detection. |
| `directly_detectable` | passthrough (generate) | 0.714 / 0.833 | Pure passthrough — zero suppression possible. |
| `indirectly_detectable` | passthrough (generate) | 0.714 / 0.833 | Passthrough — the formerly-dead class is producible and its action can't suppress. The frequent direct↔indirect adjacency swap is operationally inert (both generate). |

### Disable the confidence floor as a gate

The `ROUTER_MIN_CONFIDENCE` (default 0.4) skip branch
(`artifact_router.py:226-236`) **must not prevent generation.** Calibration is
**anti-predictive** (correct preds avg confidence 0.702 vs incorrect 0.848 on the
adjudicated set; 0.552 vs 0.653 at v1 — inverted in both runs). The floor *fails
open*: wrong-but-confident classifications sail over 0.4 untouched, while the
demote branch fires preferentially on the low-confidence outputs that are
disproportionately **correct**. It would not have caught a single one of the
pilot's actual errors. Keep the branch advisory (it still records its demotion on
the persisted plan for telemetry), but the new generation gate must read **only**
the class-derived skip set. Re-enabling it is conditioned on a recalibration
(temperature-scaling / reliability curve) measuring confidence non-inverted.

## Prerequisites before flipping

1. **This is new control-flow wiring, not a config toggle.** Verified: the plan /
   `sigma_planned` is consumed only by the read API (`assessments.py:507`) and
   divergence observation (`observe_loop3`); Loop 3's generation decision
   (`orchestrator.py:214-225`) keys solely on `low_detectability_override` and
   calls the generator unconditionally. There is no per-class gating switch today.
   Add a decision point that, before invoking `RuleGenerator`, loads the active
   plan's **class-derived** skip set and suppresses generation for
   `insufficient_information`/`control_only` **while persisting the recommended
   fallback artifact** so the assessment completes with "no reliable detection
   exists" as a successful, human-visible outcome — never a silent dead end.
2. **⚠ The `sigma_planned` trap (loudest implementation note).** The confidence-floor
   demote sets `sigma_planned=False` on the persisted plan. So the natural wiring
   `if not plan.sigma_planned: skip` would **silently re-enable the anti-predictive
   floor as a gate** — exactly what §"Disable the confidence floor" forbids. The new
   gate must **not** read `plan.sigma_planned`; it must recompute the class-only
   skip set (or read a separate persisted class-derived field). Add a regression
   test asserting a **low-confidence `directly`/`indirectly` case still generates**.
3. **Per-class config** (`ROUTER_GATING_SKIP_CLASSES`, default
   `insufficient_information,control_only`) so the flip is reversible to full
   compatibility mode **without a code change** — a bad flip must not be a one-way door.
4. **Confirmation scored run** against the adjudicated fixture (in flight). Require:
   `insufficient_information` precision = 1.0 and `control_only` precision = 1.0
   (precision is the load-bearing property for a skip gate), a minimum count of
   cases *predicted into* each skip class (control_only precision rests on only
   ~2-4 predictions, not its 6-case support), **no** `X→insufficient`/`X→control`
   confusion off-sample, and a refreshed calibration report. **If control_only
   precision drops below 1.0, narrow the flip to `insufficient_information` only**
   (the single 1.0/1.0 class whose skip direction is self-correcting).
5. **Fallback-artifact path must reach a human.** A hard skip produces no
   review-queue Sigma draft, so §19 cannot catch a wrong skip — the
   research-task/mitigation-plan fallback is the only backstop and must surface to
   an analyst (queue entry or equivalent).
6. **Divergence telemetry + kill-switch.** Keep `observe_loop3` recording
   skip-but-would-have-generated cases post-flip; instrument the rate of "analyst
   overrode a gated skip and generated a useful rule" (the false-skip ledger) and
   pre-commit to a config revert if that rate exceeds a threshold on early
   production cases.

## Confirmation run results — PASSED (2026-06-14)

A fresh scored run against the **adjudicated** fixture (deployed v2 prompt;
`prompt_evaluations.evaluated_by = w2c-adjudicated-fresh-2026-06-14`) reproduced
the offline-recomputed metrics and cleared every precondition for the two skip
classes:

| Class | P | R | F1 | predicted-into-class |
|---|---|---|---|---|
| `insufficient_information` | **1.0** | 1.0 | 1.0 | 5 (all correct) |
| `control_only` | **1.0** | 0.667 | 0.8 | 4 (all correct) |
| `environment_dependent` | 0.857 | 0.857 | 0.857 | — |
| `directly_detectable` | 0.714 | 0.833 | 0.769 | — |
| `indirectly_detectable` | 0.714 | 0.833 | 0.769 | — |

- **Stability:** accuracy **0.833** / macro-F1 **0.839** — identical to the offline
  recompute; the confusion matrix matched exactly. Run-to-run variance on this
  fixture is negligible.
- **Skip-class safety (the load-bearing check):** both skip classes reproduce
  **P=1.0** with a **clean column** — zero `X→insufficient` / `X→control`
  off-sample confusion, i.e. no detectable case is misfiled into a skip bucket on
  the pilot. `control_only`'s precision rests on 4 predicted-into-class cases (its
  0.667 recall means 2 of 6 still generate — the benign miss direction).
- **Calibration is STILL inverted** (correct 0.700 vs incorrect 0.852) — confirms
  the confidence floor must remain disabled as a gate; re-enabling it still
  requires a recalibration.

**Verdict:** the **evidence** precondition for the partial flip is **met**. What
remains before generation is actually gated is the implementation work
(prerequisites 1–3, 5–6) and the owner's sign-off — not more evidence. Standing
caveat: still an N=30 synthetic-fixture pilot, so the divergence ledger + the
kill-switch (prereq 6) cover the live-distribution unknown.

## Residual risks

- **N=30 single-run pilot**, ~5-6 support per skip class, no CIs; P=1.0 at that N
  is "not-yet-contradicted," not "proven safe." Run-to-run variance unquantified.
- **False-skip is silent and irreversible** under §19; all-adjacent error shape
  is a property of this dataset, not a guarantee — an off-adjacent `detectable→skip`
  error at this N would be invisible. The override-recovery path is a weak backstop
  (it asks the analyst to doubt a "no detection" verdict), which is why the
  kill-switch and fallback-artifact prerequisites exist.
- **Fixture realism:** the pilot uses curated `loop2_output`, not real pasted Loop
  2 evidence; the confirmation run is still synthetic-fixture. The live
  distribution may route differently (thin-source assessments may land
  disproportionately in `insufficient_information`).
- **Adjudication circularity:** 3 of 30 labels were owner-flipped after seeing the
  v2 predictions — none touch the two skip classes' precision, which limits
  exposure, but the fresh run is what breaks the circularity.

## Non-goals / unchanged

- The deterministic `GATE_MIN_CATEGORIES` gate and the inviolable §19 human
  review/approve gate are untouched. Gating decides only whether Loop 3 **generates
  a draft**, never whether a rule ships.
- The §12.2 dormant allowlist is untouched.
