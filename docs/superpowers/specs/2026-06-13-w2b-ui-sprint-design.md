# W2b — UI Sprint Remainder: Design

**Date:** 2026-06-13
**Status:** Approved (design), pending implementation plan
**Scope:** Wave 2b of the agentic rebuild program ([2026-06-10-agentic-rebuild-proposal.md](../../../architecture/2026-06-10-agentic-rebuild-proposal.md) §5).
**Branch:** `claude/wave2b-ui` off main `f3b6e7d` (W2a merged).

## Goal

Close the assessment-workspace UI gaps before ADR-0004 Phase 3: surface the
`low_detectability_override` safety signal in the Review Queue, give analysts a
Loop 3 → Review Queue handoff, bring the workspace cards into §16 DarkOps v3
conformance, and add the missing ReviewQueue tests. **Frontend-only** — no
backend, schema, or migration changes.

## Scope reduction (recorded)

The proposal §5 listed five W2b items; two are **already shipped** (W1b) and are
out of scope:

- **Progress UI for 60s+ runs** — `RunningIndicator` in
  `frontend/src/components/assessments/LoopCard.tsx` (lines ~27-50) already
  renders a spinner + live elapsed-time counter (1s tick off `run.started_at`)
  + a "typically 1–2 min" hint while a run is `status='running'`.
- **Failed-run error rendering** — `LoopCard.tsx` (~99-106) renders a
  `role="alert"` block with `run.error ?? "run failed (no error detail
  recorded)"`, and `AssessmentWorkspace.tsx` already calls
  `toast.error(detailFromError(err), "Loop N run failed")` on failure.

W2b therefore covers the remaining three: the safety badge + handoff, §16
conformance, and ReviewQueue tests.

## Current state (verified)

- The backend `QueueItemOut` (`fragchain/api/routers/queue.py:86-88`) already
  projects `assessment_id`, `low_detectability_override` (default `False`), and
  `superseded_by_assessment_id`. The list endpoint accepts `?assessment_id=`
  (line ~400) with a server-side read-access check on that assessment
  (F-009/S-001). **No backend change is needed.**
- The frontend `QueueItem` type (`frontend/src/api/queue.ts`, ~lines 4-26) does
  NOT yet carry those three fields, and `ReviewQueue.tsx` (883 lines) renders no
  override indicator anywhere — the §12.1 "safety gap."
- `ReviewQueue.tsx` already uses `useSearchParams` and reads `?id=` to focus an
  item; `listQueue(params)` passes params straight through to `GET /queue`.
- The app's button convention is `className="btn ..."` with variants
  (`sm`/`ghost`/`danger`/`active`) across 24 files; there is NO `<Button>`
  component and zero `<Button>` usages. §16 conformance = apply the classes.
- Frontend tests: Vitest + `@testing-library/react`, `vi.mock` for hooks/api.
  Card tests exist (LoopCard/SourcesCard/ArtifactPlanCard/GeneratedArtifactsCard
  `.test.tsx`); **ReviewQueue has no test.**

## Design

### A. Safety signal + Loop 3 → Review Queue handoff

1. **Types** (`frontend/src/api/queue.ts`):
   - Add to `QueueItem`: `low_detectability_override: boolean`,
     `assessment_id: string | null`, `superseded_by_assessment_id: string | null`.
   - Add to `QueueListParams`: `assessment_id?: string`.
2. **Row badge** (`ReviewQueue.tsx`, item-row map): when
   `item.low_detectability_override` is true, render a red
   `<span class="badge danger">LOW-DETECTABILITY OVERRIDE</span>` chip in the row.
3. **Detail callout** (expanded-item body): when the flag is set, render a
   `.badge.danger`-weighted callout: "This rule was generated from an assessment
   whose detectability gate failed; an analyst overrode the gate. Validate the
   detection logic carefully before approving." Hidden when the flag is false.
4. **Assessment filter:** read `?assessment_id=` from `useSearchParams`; pass it
   into `listQueue({ assessment_id })`. When set, show a small "Filtered to
   assessment ✕" indicator whose ✕ clears the param (and refetches the full
   queue). The endpoint's read-access check is already enforced server-side.
5. **Workspace handoff** (`AssessmentWorkspace.tsx`): once Loop 3 has a
   `succeeded` active run that generated rules, render an affordance below the
   loop cards — an anchor/`Link` styled `className="btn"` reading
   "N detection rules ready for review →" that navigates to
   `/review-queue?assessment_id=<assessmentId>`. The rule count `N` comes from
   the Loop 3 run output already in workspace state (the `rules` array length /
   the existing loop-3 run summary). When no Loop 3 success exists, the
   affordance is absent.

### B. §16 DarkOps conformance of the assessment cards

Apply the established convention; behavior-preserving markup swaps.

- **Raw `<button>` → `.btn`:**
  - `LoopCard.tsx`: Run/Re-run → `className="btn"`; Compare-versions → `className="btn sm ghost"`.
  - `SourcesCard.tsx`: Delete-source → `className="btn sm ghost danger"`.
  - `ArtifactPlanCard.tsx`: Generate → `className="btn sm"`.
  - `GeneratedArtifactsCard.tsx`: Retry → `className="btn sm ghost"`.
  - Focus rings are inherited from `darkops.css` `.btn:focus` (`var(--shadow-focus)`) — no per-element work.
- **Inline badge styles → `.badge.{variant}`:**
  - `DetectabilityCard.tsx`: the detectability-class chip's inline
    `style={{ border…, color… }}` → an appropriate `.badge` variant
    (e.g. `.badge.accent2` for the class label).
  - `ArtifactPlanCard.tsx`: the recommended/skipped chips' inline border styles →
    `.badge` variants (recommended → `.badge.accent3`/`accent`, skipped →
    `.badge` plain/`text-dim`).
- Do NOT override DarkOps tokens (§16) — only consume existing classes/vars.

### C. Tests

Vitest + testing-library, matching existing `*.test.tsx`.

- **New `ReviewQueue.test.tsx`** (YAGNI scope — the new behavior + a smoke):
  - Row badge renders when an item has `low_detectability_override: true`;
    absent when `false`.
  - Detail callout appears for an overridden item on expand; absent for a normal item.
  - `?assessment_id=` in the URL is read and forwarded to `listQueue` (assert the
    mock was called with `{ assessment_id }`); the "Filtered" indicator renders.
  - Smoke: list renders rows from a mocked `listQueue`; selecting a row shows its detail.
- **`AssessmentWorkspace.test.tsx`** (extend): the handoff link renders with
  `href`/`to` = `/review-queue?assessment_id=<id>` after a Loop 3 success;
  absent when there is no Loop 3 success.
- **Card tests:** update LoopCard/SourcesCard/ArtifactPlanCard/
  GeneratedArtifactsCard tests where an assertion matched a raw element so they
  match the `.btn`/`.badge` markup; all card tests stay green.

## Scope boundaries

- **In:** the three areas above; frontend only.
- **Out:** backend/schema/migration (none needed); the dormant W2a auto-advance
  UI (no setter yet — W3a); progress UI + failed-run rendering (already shipped);
  exhaustive ReviewQueue coverage (test the new behavior + smoke, not all 883
  lines). No DarkOps token changes.

## Risks

- ReviewQueue is large and untested; edits there risk regressions. Mitigation:
  keep changes additive (badge + callout + filter wiring), and the new test
  smoke covers the touched render paths.
- The handoff rule-count source must match what the workspace already has in
  state; if the Loop 3 run summary doesn't expose a count, fall back to a static
  "Rules ready for review →" without a number rather than fetching extra data.
