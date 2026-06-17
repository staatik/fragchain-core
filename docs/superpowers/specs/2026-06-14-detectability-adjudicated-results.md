# Detectability Pilot — Adjudicated v2 Results

**Date:** 2026-06-14 · **Status:** owner-adjudicated; informs the ADR-0004 Phase 2c decision

Combines two changes against the W2c pilot:
1. The **v2 detectability prompt** (abstract-pattern rewrite — explicit
   indirectly_detectable decision procedure + integer `priority`; no
   benchmark-CVE names) deployed as `detectability_classification` v2 and scored
   at accuracy **0.733** (`prompt_evaluations` row tagged
   `w2c-phase3-promptfix-v2`).
2. **Three owner-adjudicated label flips** — the v2 run surfaced that several
   "errors" were debatable labels where the model's call is more defensible.

## The three flips

| Case | Old label | New label | Rationale |
|---|---|---|---|
| `case-04-printnightmare-rce` | directly_detectable | **indirectly_detectable** | The reliable signal is the `spoolsv.exe` child / DLL-load *consequence*, not the RPC exploit itself. |
| `case-09-fortios-traversal` | indirectly_detectable | **directly_detectable** | The `/../` traversal URI is itself a high-fidelity, matchable signature in HTTP access logs. |
| `case-29-http2-reset` | insufficient_information | **environment_dependent** | A rate-based signal *does* exist; it needs special rate-monitoring telemetry rather than being unclassifiable. |

The four other borderline cases (`02` shellshock, `10` f5-icontrol, `18`
sysmon-imageload, `22` heartbleed) and `24` cisco-asa were reviewed and **kept**
as-is — their model-vs-label disagreement is genuine detection-engineering
judgment, not classifier failure.

## Adjudicated metrics

Recomputed **offline** by re-scoring the existing v2 predictions against the
flipped labels — no re-run, no LLM spend.

**Accuracy 0.833 · macro-F1 0.839** (v1 baseline: 0.60 / 0.539).

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| `directly_detectable` | 0.714 | 0.833 | 0.769 | 6 |
| `indirectly_detectable` | 0.714 | 0.833 | 0.769 | 6 |
| `environment_dependent` | 0.857 | 0.857 | 0.857 | 7 |
| `control_only` | 1.000 | 0.667 | 0.800 | 6 |
| `insufficient_information` | 1.000 | 1.000 | 1.000 | 5 |

Every class now has F1 ≥ 0.77. The two v1 failure modes are resolved:
- **`indirectly_detectable`: 0.0 → 0.769** (recall 0/6 → 5/6). The blind spot is gone.
- **`environment_dependent` precision: 0.40 → 0.857** — no longer an uncertainty sink.

Remaining 5 misses are the kept borderline cases (`02`, `10`, `18`, `22`, `24`).

## Implication for ADR-0004 Phase 2c

The [Phase 2c HOLD decision](../../architecture/2026-06-14-phase-2c-gating-decision.md)
rested on two facts that no longer hold:
- `indirectly_detectable` was unproducible (0% recall) → now recall 0.833.
- `environment_dependent` was a 0.40-precision sink → now 0.857.

**Recommendation:** revisit the Phase 2c gating decision with these numbers. The
classifier is now balanced across all five classes (F1 0.77–1.0). The narrow
partial flip (gate the precision-1.0 decline classes) is still the safest first
step, but a broader flip is now defensible — pending a confirmation re-run of the
scored benchmark against the **adjudicated** fixture (this writeup used the
existing v2 predictions re-scored offline; a fresh scored run would also refresh
calibration, which was inverted at v1).
