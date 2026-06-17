# Assessment Workspace (Plan B) — Frontend Design Note

**Status:** **Reconciled 2026-05-19** — Plan B shipped. All 17 expected files are in tree under `frontend/src/screens/Assessments*.tsx`, `frontend/src/components/assessments/`, `frontend/src/hooks/useAssessment*.ts`, and `frontend/src/api/assessments.ts`. The three backend WS event types (`assessment.loop.run.started`, `assessment.loop.run.completed`, `assessment.source.embedded`) are wired in `fragchain/worker/tasks/run_assessment_loop.py` and `fragchain/worker/tasks/embed_assessment_source.py`. The design below is preserved as the rationale-of-record; no material divergence from the shipped code.

**Status (original):** Draft for review
**Date:** 2026-05-18
**Author:** Elie M (drafted with Claude)
**Decides:** the frontend Assessment Workspace screen — sidebar placement, list + workspace screens, create flow, per-loop card behavior, source paste UX, version compare, gate-failure interactive flow, and component decomposition. Also documents the small backend dependency (three new WebSocket event types) that Plan B requires.

---

## 1. Problem

[Plan A](../superpowers/plans/2026-05-17-assessment-foundation.md) landed the assessment-centric backend ([fragchain/assessments/](../../fragchain/assessments/) + the `/api/v1/assessments` router) but no UI surface drives it. An analyst can only exercise the new workflow via `curl`. Without a screen, the platform's new primary workflow is inaccessible to its intended users.

---

## 2. Goals / non-goals

**Goals (v1):**

- New `/assessments` (list) and `/assessments/:id` (workspace) screens.
- Sidebar entry under DETECT next to Review Queue.
- Modal-based create flow with two entry points: the list screen "+ New" button, and a "Start Assessment" CTA on each CVE Explorer row.
- Stacked-section workspace layout: Sources, Loop 1, Loop 2, Loop 3 cards always visible.
- Per-loop versioning with a version dropdown; "Compare v1 ↔ v2" modal.
- Gate-failure interactive surface for Loop 2 (paste-more-intel-and-re-run + override-with-rationale).
- Existing-chain offer inline in the create modal when backend reports a candidate.
- Live updates via the existing `/ws/events` WebSocket channel; polling fallback when WS is unavailable.
- Component-decomposed implementation: workspace shell + focused components + two resource hooks.
- Three new WebSocket event types (`assessment.loop.run.started`, `assessment.loop.run.completed`, `assessment.source.embedded`) published from existing Celery tasks. Documented as independent prerequisite tasks in the implementation plan.

**Non-goals (deferred):**

- URL ingest, document upload, screenshot upload (spec §4.3 — Phase 2 of assessment workflow).
- Multi-user roles, role-based UI gating, read-only viewer mode. Single-admin assumption (matches the platform's current Identity-placeholder posture per CLAUDE.md §9).
- Multi-analyst collaboration on one assessment.
- Auto-progression toggle (run all three loops on one click).
- Prompt-injection score badge UI.
- TLP per-source UI control.
- Templated assessments.
- PDF export / JIRA back-write.
- Slack / email notifications on state transitions.
- Bulk operations on the list screen.
- Streaming preview of Loop 3 rule generation.
- Mobile / responsive (desktop ≥ 1280px only).
- New shared component-library primitives (everything reuses the existing [frontend/src/components/](../../frontend/src/components/) library).

---

## 3. Architecture overview

```
┌─────────────────────────────────────────────────────────────────┐
│                       Sidebar (DETECT section)                   │
│   Review Queue                                                   │
│   Assessments  ← NEW (list + workspace behind one entry)         │
│   Sigma Library                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
       ┌──────────────────────┴──────────────────────┐
       ▼                                              ▼
┌──────────────┐                              ┌──────────────────┐
│ /assessments │                              │ /assessments/:id │
│ (list)       │   ← "+ New" opens modal      │ (workspace)      │
│              │   ← CVE Explorer "Start      │                  │
│   filters,   │     Assessment" CTA opens    │                  │
│   columns,   │     same modal               │                  │
│   click to   │   ← on submit, redirect      │                  │
│   workspace  │     to workspace             │                  │
└──────────────┘                              └────────┬─────────┘
                                                        │
                                                        ▼
                                          ┌─────────────────────────┐
                                          │ Workspace shell         │
                                          │  ┌─ SourcesCard         │
                                          │  ├─ LoopCard (Loop 1)   │
                                          │  ├─ LoopCard (Loop 2)   │  ← GateBanner on fail
                                          │  └─ LoopCard (Loop 3)   │
                                          │                          │
                                          │ State: useAssessment(id) │
                                          │ Live updates: WS sub     │
                                          │ Mutations via callbacks  │
                                          └─────────────────────────┘
```

---

## 4. File structure

### 4.1 New files

```
frontend/src/
├── screens/
│   ├── AssessmentsList.tsx              (~200 lines) — list + filters + create CTA
│   └── AssessmentWorkspace.tsx          (~250 lines) — shell, orchestrates cards
├── components/assessments/              (new subdirectory)
│   ├── CreateAssessmentModal.tsx        (~180 lines) — modal form
│   ├── ExistingChainOffer.tsx           (~120 lines) — "use as start / start fresh" inline
│   ├── SourcesCard.tsx                  (~200 lines) — pasted source list + add UI
│   ├── PasteSourceForm.tsx              (~150 lines) — textarea + title + size meter
│   ├── LoopCard.tsx                     (~240 lines) — reused for Loop 1/2/3 via props
│   ├── LoopOutputRenderer.tsx           (~180 lines) — dispatches to per-loop renderers
│   ├── VulnProfileView.tsx              (~120 lines) — Loop 1 output
│   ├── IndicatorTable.tsx               (~140 lines) — Loop 2 indicators by category
│   ├── GateBanner.tsx                   (~100 lines) — Loop 2 gate-fail surface
│   ├── RuleList.tsx                     (~140 lines) — Loop 3 generated rules
│   ├── VersionDropdown.tsx              (~80 lines)  — switches between loop run versions
│   └── VersionDiffView.tsx              (~180 lines) — modal for "Compare v1 ↔ v2"
├── hooks/
│   ├── useAssessment.ts                 (~200 lines) — workspace data + selective refetch + WS sub
│   └── useAssessments.ts                (~80 lines)  — list + filters
└── api/
    └── assessments.ts                   (~200 lines) — typed client matching backend router
```

**Total:** 17 new files, ~2,500 lines of new TypeScript. Average file ~145 lines. Largest single file ~250 lines (workspace shell).

### 4.2 Modified files (additive only)

| Path | Modification |
|---|---|
| [frontend/src/components/Sidebar.tsx](../../frontend/src/components/Sidebar.tsx) | One new `NavItem` under the `Detect` section: `{ to: "/assessments", label: "Assessments", Icon: ClipboardCheck }` inserted between Review Queue and Sigma Library. |
| [frontend/src/App.tsx](../../frontend/src/App.tsx) | Two new `<Route>` entries: `/assessments` and `/assessments/:id`. The route table is the `<Routes>` block in this file. |
| [frontend/src/screens/CVEExplorer.tsx](../../frontend/src/screens/CVEExplorer.tsx) | Add a "Start Assessment" button to each row's action area. Clicking it opens the shared `<CreateAssessmentModal />` with `cveId` pre-filled. |

No other existing files modified. No new components added to the shared component library — all new components are assessment-domain-specific and live under `components/assessments/`.

### 4.3 Backend additions (prerequisite to Plan B)

Three new WebSocket event types must be published by existing Celery tasks. Documented as **independent prerequisite tasks** in the implementation plan (not bundled with frontend work).

| Event type | Published by | Payload |
|---|---|---|
| `assessment.loop.run.started` | [fragchain/worker/tasks/run_assessment_loop.py](../../fragchain/worker/tasks/run_assessment_loop.py) on task entry | `{assessment_id, loop_number, version}` |
| `assessment.loop.run.completed` | Same task, on success/failure/gate_failed before returning | `{assessment_id, loop_number, version, status}` |
| `assessment.source.embedded` | [fragchain/worker/tasks/embed_assessment_source.py](../../fragchain/worker/tasks/embed_assessment_source.py) on success or failure | `{assessment_id, source_id, status}` (status: `'embedded'` or `'failed'`) |

Plus one shared module: `fragchain/notifications/events.py` (where `emit_event` lives — as built) gains a constants block for the three new event-type strings so the frontend and backend share the same names.

Total backend touch: ~6 lines added to two Celery tasks + ~5 lines of constants. Three small tasks in the implementation plan.

---

## 5. State management & data flow

### 5.1 Hook contracts

**`useAssessment(id: string)`** — workspace data orchestrator. Fires three fetches in parallel on mount (assessment detail, sources list, loop runs for all three loops). Owns the WebSocket subscription. Exposes selective refetch.

```typescript
export function useAssessment(id: string): {
  assessment: Assessment | null;
  sources: AssessmentSource[];
  runs: { 1: LoopRun[]; 2: LoopRun[]; 3: LoopRun[] };  // each list ordered version DESC
  state: "loading" | "ready" | "error";
  error: string | null;

  refetchAssessment: () => Promise<void>;
  refetchSources: () => Promise<void>;
  refetchRuns: (loop?: 1 | 2 | 3) => Promise<void>;
  refetchAll: () => Promise<void>;

  // Mutations
  addSource: (req: SourceCreateRequest) => Promise<AssessmentSource>;
  deleteSource: (sourceId: string, rationale: string) => Promise<void>;
  runLoop: (loop: 1 | 2 | 3, opts?: { overrideRationale?: string }) => Promise<LoopRun>;
  useExistingChain: (chainId: string) => Promise<LoopRun>;
  closeAssessment: (note?: string) => Promise<void>;
};
```

**`useAssessments(filters)`** — list screen. Simple fetch + filters.

```typescript
export function useAssessments(filters: {
  state?: AssessmentState;
  creatorId?: string;
  search?: string;
}): {
  data: Assessment[];
  state: "loading" | "ready" | "error";
  refetch: () => Promise<void>;
};
```

### 5.2 WebSocket subscription

The `useAssessment` hook subscribes to `/ws/events` filtered by `msg.type.startsWith("assessment.") && msg.payload.assessment_id === id`. Event handling rules:

| Event | Action |
|---|---|
| `assessment.loop.run.started` | `refetchRuns(loop_number)` — picks up the new active row |
| `assessment.loop.run.completed` | `refetchRuns(loop_number)` + `refetchAssessment()` (state machine may have advanced) |
| `assessment.source.embedded` | `refetchSources()` — picks up new `embedding_status` |

### 5.3 Polling fallback

If `useWebSocket`'s state stays `"error"` or `"closed"` for > 30 seconds, the workspace falls back to polling every 3 seconds while any loop run is `'running'` in the local state. The topbar shows a small "live updates paused" indicator. WS reconnect cancels polling.

### 5.4 Optimistic updates

For the click-to-run flow:

1. User clicks "Run Loop N" → component calls `runLoop(n)`.
2. Hook immediately appends a synthetic in-progress run entry to local state (status `'running'`, version derived from existing max + 1).
3. POST `/loops/{n}/run` returns the real run id + version. Hook reconciles.
4. WS event `assessment.loop.run.completed` arrives → `refetchRuns(n)` → status flips to terminal.
5. If the POST errors (e.g., 409), rollback the optimistic entry and surface a toast.

### 5.5 Error handling

Match existing screen pattern. Per response code:

| Code | Behavior |
|---|---|
| 400 / 409 / 413 | `useToast({type:"error", message: detailFromError(e)})` then stay on screen |
| 404 | `navigate("/assessments")` (workspace) or stay (list) |
| 500 | toast + `console.error`; screen stays usable with stale data |

---

## 6. Screens

### 6.1 List screen (`AssessmentsList.tsx`)

**Layout:** AppShell + content area with header row (filters + "+ New Assessment" button) + DataTable.

**Filters (left-to-right):**

- State dropdown: All / Created / Loop 1 Done / Loop 2 Done / Loop 3 Done / Completed
- Creator dropdown (populated from existing user list endpoint if available; single-admin until roles land, so collapses to one option)
- Search input: CVE ID substring match (debounced 250ms)

**Columns:**

| Column | Source | Notes |
|---|---|---|
| CVE ID | `assessment.initial_trigger.value` | Click → workspace |
| Title | join from `cves` table (existing API) | Truncate at 60 chars |
| State | `assessment.state` | Rendered as `<Badge>` with semantic variants |
| Creator | `assessment.creator_id` → user display name | Avatar + name; "—" if not resolvable |
| Created | `assessment.created_at` | `dayjs` relative ("3h ago") |
| Last Activity | computed from latest non-superseded loop run's `started_at` | "—" if no runs yet |
| Cost ($) | sum of `cost_usd` across runs | "$0.00" if no runs |

Sort: default by Created DESC. Sortable on Created and Last Activity. Empty state: `<EmptyState>` with "Start your first coverage assessment" + CTA button opening the create modal.

### 6.2 Workspace screen (`AssessmentWorkspace.tsx`)

**Sticky topbar** (below the global Topbar):

```
[CVE-2026-1234]  Apache Log4j2 RCE — Disclosed 2026-04-15      [State: loop2_done]  $0.41  [⋮]
```

`[⋮]` kebab menu opens dropdown:
- Close assessment (opens close confirmation; disabled if `state` not in `loop2_done|loop3_done`)

(An "Audit log" menu item is *intentionally omitted* — there is no audit-log screen in the frontend yet. Backend audit rows are written but not surfaced; when a generic audit-log screen lands, the kebab menu gains a "View audit log" entry then.)

**Body:** stacked cards in fixed order:

1. **SourcesCard** — always at top, expanded by default. Header: "Sources (N) · X.X KB total". Body: pasted source list (title, size, embedding status badge, delete icon) + inline `PasteSourceForm` at bottom.
2. **LoopCard for Loop 1** — header: "Loop 1 · Vulnerability Analysis". Active version dropdown. Run/Re-run button.
3. **LoopCard for Loop 2** — same shape; if active version is `gate_failed`, the `GateBanner` is inlined above the indicators table.
4. **LoopCard for Loop 3** — same shape; output renders as `RuleList`.

Cards 2–4 are visibly disabled (lower opacity, button greyed) when the state machine forbids running them. Tooltip explains why (e.g., "Run Loop 1 first").

**Read-only mode:** when `assessment.state === 'completed'`, the topbar shows a "Closed" banner and all action buttons across all cards are disabled. Source list is read-only. Version dropdowns still work for browsing history.

### 6.3 Create modal (`CreateAssessmentModal.tsx`)

Triggered by:

- `/assessments` "+ New Assessment" button
- CVE Explorer row "Start Assessment" button (pre-fills CVE-ID)

**Fields:**

| Field | Input | Required | Notes |
|---|---|---|---|
| CVE-ID | UUID search/autocomplete from `/api/v1/cves` | yes | Pre-filled when launched from CVE Explorer |
| Trigger kind | Dropdown: CVE ID / Ticket / PSIRT URL | yes | Default: "CVE ID" |
| Trigger value | Text input | yes | Validation: CVE format if `kind=cve_id`, https if `kind=psirt_url`, any non-empty if `kind=ticket` |
| Context note | Textarea (max 2000 chars) | no | "Why are we assessing this?" |

**Submit behavior:**

1. POST `/api/v1/assessments` with `{trigger, cve_id, context_note}`.
2. Response includes `assessment` + optional `existing_chain` candidate.
3. **If `existing_chain` is null:** navigate to `/assessments/{id}`.
4. **If `existing_chain` is present:** modal body replaced with `<ExistingChainOffer>` showing the chain summary + two buttons: **"Use as starting point"** (primary, calls `useExistingChain(chainId)` then navigates) and **"Start fresh"** (secondary, just navigates — workspace will show Loop 1 not yet run).

### 6.4 Version diff modal (`VersionDiffView.tsx`)

Triggered by "Compare v1 ↔ v2" button on any LoopCard with ≥2 versions.

**Layout:** large Modal (90vw) with two side-by-side panes (left = older, right = newer). Selector row at top lets analyst pick which two versions to compare (defaults: newest two).

**Rendering per loop:**

- **Loop 1** (vuln_profile + detection_questions): key-by-key field comparison. Added/removed/changed fields highlighted in red/green/yellow.
- **Loop 2** (indicators by category): per-category indicator list comparison. Added indicators highlighted green, removed red.
- **Loop 3** (Sigma rule list): per-rule YAML diff. The project already uses CodeMirror (via `@uiw/react-codemirror` + `@codemirror/lang-yaml`) in [frontend/src/screens/ReviewQueue.tsx](../../frontend/src/screens/ReviewQueue.tsx) as a regular editor — there is no diff extension in the project today. Implementation pick at task time: either add `@codemirror/merge` as a new dependency (preferred — same editor stack, native diff view) or use a small text-diff library. Rules added/removed shown as full-block highlights. The exact diff library is an open question (§12).

---

## 7. Edge cases & failure modes

| Case | Behavior |
|---|---|
| Non-existent assessment ID in URL | Workspace renders 404 toast then navigates to `/assessments` |
| Embedding still pending when user runs Loop | Yellow banner in SourcesCard ("Embedding N source(s)…"). Loop run still allowed. Resulting run carries `embedding_warned=true`, surfaced as a small warning chip on the LoopCard. |
| Loop 2 gate failed, user clicks "Run Loop 3" | API returns 409. Inline rationale textarea expands beneath the disabled button (50-char min). On submit, POST with `override_rationale`. Resulting rules carry `low_detectability_override` flag — visually marked on RuleList with a warning badge. |
| Stale workspace (closed elsewhere) | First WS event or interaction triggers refetch. If `state==='completed'`, screen renders read-only with banner. |
| Paste fails guardrails (size, charset, dedup) | 400/413/409 → inline error in PasteSourceForm (no toast since the form is right there). |
| Source soft-deleted mid-run | Optimistic remove from list, POST delete. Worker removes Qdrant vector. Subsequent loop runs won't see that source. |
| WebSocket connection drops | `useWebSocket` reconnects with exponential backoff. After 30s of failed state, falls back to polling every 3s. Topbar shows "live updates paused" indicator. |
| Loop run takes > 60 seconds | UI keeps showing the spinner. No client-side timeout — the backend's own timeout determines failure. |
| Compare v1 ↔ v2 across loops with version mismatch | Each loop's "Compare" button only shows when that loop has ≥2 versions. No cross-loop compare. |

---

## 8. Testing strategy

**Component tests** — React Testing Library, co-located per component as `frontend/src/components/assessments/*.test.tsx` (as built — no separate `__tests__/` directory):

- `LoopCard` renders all statuses (running, succeeded, failed, gate_failed); version dropdown selection changes output; action buttons emit correct callbacks; disabled when state machine forbids.
- `SourcesCard` paste form validation, embedding status banner, soft-delete optimistic flow.
- `GateBanner` renders correct empty categories, override and re-run buttons emit callbacks.
- `VersionDropdown` version list, current selection highlight, version-count display.
- `IndicatorTable` per-category grouping, source-ref tooltip on hover.
- `CreateAssessmentModal` form validation, existing-chain inline flow (mocked response).
- `ExistingChainOffer` use-as-start vs start-fresh button behavior.
- `RuleList` renders generated rules with low-detectability-override warning badge.

**Hook tests** — `renderHook` with mocked API client:

- `useAssessment(id)` parallel fetch on mount, selective refetch, optimistic run + rollback, WS event triggers correct refetch.
- `useAssessments(filters)` filter changes trigger refetch.

**Integration test** for the workspace: mount the workspace with mocked hooks + deterministic WS event stream, assert state machine progression after each event (created → loop1_done → loop2_done(gate_failed) → loop2_done(override) → loop3_done → completed).

**Backend prerequisite tests:** the three new WS event publishes are covered by adding event-emission assertions to the existing `tests/worker/test_run_assessment_loop.py` and `tests/worker/test_embed_assessment_source.py`. No new test files required.

---

## 9. Sequencing

Listed in dependency order. Tasks 1–3 are the backend prerequisites; the rest are frontend.

| # | Task | Depends on | Output |
|---|---|---|---|
| 1 | Backend: define WS event-type constants in `fragchain/notifications/events.py` (as built). | — | one new constants module / additions |
| 2 | Backend: publish `assessment.loop.run.started` + `assessment.loop.run.completed` from `run_assessment_loop` Celery task. Update existing task test. | 1 | task edit + test edit |
| 3 | Backend: publish `assessment.source.embedded` from `embed_assessment_source` Celery task. Update existing task test. | 1 | task edit + test edit |
| 4 | Frontend: `api/assessments.ts` typed client matching the backend router. | — (independent of 1–3) | new file + client unit tests |
| 5 | Frontend: `useAssessments` hook for the list screen. | 4 | new hook + test |
| 6 | Frontend: `useAssessment` hook for the workspace. | 4 | new hook + test (heaviest hook test) |
| 7 | Frontend: `AssessmentsList` screen + integration into the router and sidebar. | 5 | new screen + screen test |
| 8 | Frontend: `CreateAssessmentModal` + `ExistingChainOffer` components. Wire to list "+ New Assessment" and to a new "Start Assessment" button on CVE Explorer rows. | 4 | 2 new components + tests + CVE Explorer edit |
| 9 | Frontend: `SourcesCard` + `PasteSourceForm` components. | 6 | 2 components + tests |
| 10 | Frontend: `LoopCard` + `VersionDropdown` + `LoopOutputRenderer` + per-loop renderers (`VulnProfileView`, `IndicatorTable`, `GateBanner`, `RuleList`). | 6 | 6 components + tests |
| 11 | Frontend: `VersionDiffView` modal. | 10 | component + test |
| 12 | Frontend: `AssessmentWorkspace` screen — shell wiring all cards together, sticky topbar, kebab menu, read-only mode for completed assessments. | 6, 9, 10, 11 | new screen + integration test |
| 13 | Frontend: workspace-level integration test (mounted screen + deterministic WS event stream + assertion on full state-machine progression). | 12 | integration test |
| 14 | Frontend: polish — empty states, loading skeletons, copy review, accessibility pass (keyboard nav on the workspace). | 12 | small edits |

Plan B closes after task 14. Plan C (real Loop 1/2/3 implementations + review queue integration + rule supersession) becomes the natural follow-up — when those land, this UI starts producing real chains and rules instead of stub outputs.

---

## 10. Decisions (locked from brainstorming)

| # | Question | Decision |
|---|---|---|
| 1 | Sidebar placement | New "Assessments" item under DETECT, between Review Queue and Sigma Library. |
| 2 | List vs workspace screens | Two screens: list (with filters) + workspace (single assessment). Matches CVEs and Chains pattern. |
| 3 | Workspace layout | Stacked sections (Sources + 3 loops) all always visible. |
| 4 | Create flow | Modal triggered from list "+ New Assessment" button AND from CVE Explorer row "Start Assessment" CTA. Same modal, different pre-fill. |
| 5 | Existing-chain offer | Inline in the create modal after submit, with Use-as-start vs Start-fresh buttons. |
| 6 | Loop card structure | Header (title + version dropdown + status badge), output detail, action buttons. Used for Loop 1/2/3 via prop variation. |
| 7 | Loop 2 gate-failure UI | Inline banner with empty-category grid + 3 actions: "Add intel & re-run", "Override gate · continue", "Compare versions". |
| 8 | Version diff | Modal with side-by-side panes per output type (key diff for L1, category diff for L2, YAML diff for L3). |
| 9 | Implementation shape | Decomposed: shell + focused components + 2 resource hooks (workspace + list). 17 new files. |
| 10 | Hook granularity | 2 hooks: `useAssessment(id)` orchestrates workspace data; `useAssessments(filters)` for list. |
| 11 | Live updates | WebSocket subscription via existing `/ws/events` channel with polling fallback after 30s WS failure. |
| 12 | Backend dependency | Three new WS event types published from existing Celery tasks. Documented as independent prerequisite tasks in the implementation plan (tasks 1–3 of the sequencing). |
| 13 | Loop 3 streaming | No streaming. Wait for completion, then render rule list. |
| 14 | Role-based UI gating | Out of scope. Single-admin assumption in v1; matches existing Identity placeholder posture. All authenticated users have full access. |
| 15 | Read-only viewer mode | Removed (was a v1 over-engineer). Only `state==='completed'` triggers read-only UI. |
| 16 | TLP per-source picker | Out of scope. Sources inherit assessment TLP. |
| 17 | URL ingest / document upload | Out of scope (deferred to a later phase). Free-text paste only in v1. |
| 18 | Mobile / responsive | Out of scope. Desktop ≥ 1280px only. |

---

## 11. Out of scope (explicit — won't drift in)

- URL ingest and document upload UI.
- Multi-user roles, role-based UI gating, read-only viewer mode for non-creators.
- Multi-analyst collaboration on one assessment.
- Auto-progression toggle through loops.
- Prompt-injection score badge.
- TLP per-source UI control.
- Templated assessments.
- PDF export and JIRA back-write.
- State-transition notifications (Slack, email).
- Bulk operations on the list screen.
- Streaming preview of Loop 3 rule generation.
- Mobile / responsive layouts.
- New shared component-library primitives.
- Frontend changes to existing screens beyond two: one new sidebar entry, one new "Start Assessment" button on CVE Explorer rows.

---

## 12. Open questions

- **List screen columns** — current proposal: `CVE ID | Title | State | Creator | Created | Last Activity | Cost`. Acceptable defaults, revisit during implementation if any are noisy.
- **Workspace topbar kebab menu** — current item: "Close assessment". An "Audit log" entry is omitted in v1 because no audit-log screen exists in the frontend yet (backend rows are written though). Add the menu entry when that screen lands.
- **WS reconnect threshold** — 30 seconds before polling fallback. Acceptable, tune if WS proves flaky.
- **Polling interval** — 3 seconds during active run. Acceptable, tune based on observed run duration.
- **Loop run timeout from the UI side** — no client-side timeout; spinner stays until backend reports terminal state. Acceptable, no obvious reason to add one.
- **YAML diff library for Loop 3 version compare** — pick at implementation time. Preferred: add `@codemirror/merge` dependency (same editor stack as ReviewQueue's YAML viewer). Alternative: a small `react-diff-viewer`-style library. Default to `@codemirror/merge` unless installation friction makes it worse.
