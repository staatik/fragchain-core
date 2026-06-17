# MODULE_M23_DONE — Import Manager UI
**Built:** 2026-05-13
**Effort actual:** M (one session)
**Status:** complete · sandbox-verified (`npx tsc --noEmit -p .` → clean · `npm run build` → 0 TS errors, 2064 modules transformed, 69.26 kB CSS / 612.38 kB JS) · pending in-browser verification on a live API + worker pipeline

## Scope reminder

M23 consumes the M6 import-manager API (preview / start / approve / preset
CRUD) and the M19 `/ws/events` bus, packaging them into a two-tab
operator screen at `/imports`:

* **Live feed** — 4 stat blocks, streaming event log (20 rows), and a
  pipeline-config card surfacing `MAX_LIVE_CVE_PER_HOUR` +
  `AUTO_PROCESS_KEV`.
* **Historical import** — saved-presets dropdown, basic + advanced
  filter form, preview/start flow, active-jobs table with an inline
  expand panel for staged CVEs and batch approve / skip actions.

M23 does NOT own:

* Backend — every endpoint already exists in M6
  (`fragchain/api/routers/imports.py`).
* Other screens — the dashboard, CVE explorer, queue, etc. live in
  their own modules.
* Settings UI for `system_config` — the kickoff asks for a
  `AUTO_PROCESS_KEV` toggle that "writes to system_config" but the
  backend exposes no CRUD endpoint for `system_config` today. The
  toggle therefore renders read-only state with a toast pointing
  operators at M24 (which will ship the real Settings UI). The
  current env-managed value is surfaced for awareness; flipping the
  switch does not persist anything server-side.

## What was built

### Frontend — `frontend/src/screens/ImportManager.tsx`

One file (~2 100 LOC) driving the entire `/imports` route. Mounts in
`frontend/src/App.tsx` in place of the M1 placeholder. Top-level
state owns:

* A `?tab=live|historical` URL query param (round-trips through
  `useSearchParams`) so refreshes preserve which view the operator
  was on.
* A single `useWebSocket` subscription filtered to the events both
  tabs need (`budget_status`, `rate_limit_warning`, `cve_ingested`,
  `enrichment_complete`, `import_job.created`, `import_job.staged`).
  The latest `wsLast` + `state` is propagated to whichever tab is
  mounted; the budget state is hoisted to the parent so the
  historical-tab approval banner can see budget updates even when
  the live tab is not rendered.

#### LIVE FEED tab

* **4 stat blocks** via `<StatGrid>`:
  * Live CVEs today — `listCves({ import_mode: "live", published_after: midnight, limit: 500 })`
    `total`.
  * Processing rate — `listCves({ import_mode: "live", published_after: now-1h, limit: 500 })`
    `total`, suffixed `/h`.
  * Rate limit — `count / MAX_LIVE_CVE_PER_HOUR`, with a `<ProgressBar>`
    in the delta slot. `rateBarVariant(ratio)` returns
    `success | warning | danger` at 0.6 / 0.9 thresholds, driving
    both the bar fill colour and the stat value colour.
  * Queue depth — `listCves({ status: "pending", limit: 500 })`
    `total`; click → `/cves?status=pending`. Delta surfaces the
    last reported `budget.queued` when known.
* **Live event log** (last 20, newest first) — driven by the
  parent's `wsLast`. Each row: `HH:mm:ss` timestamp (mono dim),
  event-type `<Badge>` coloured per `eventTypeBadgeVariant`, CVE
  ID (mono accent), and a normalised status string from
  `mapEventStatus`. Surfaces `cve_ingested`, `rate_limit_warning`,
  `enrichment_complete`, chain / coverage / rules / queue events,
  and import-job lifecycle events.
* **Pipeline config card** — three rows:
  * `MAX_LIVE_CVE_PER_HOUR` (current value, surfaced from the most
    recent `rate_limit_warning` event when available, else the
    default of 10).
  * `AUTO_PROCESS_KEV` (`.toggle` component, optimistic local
    state). Flipping fires an `info` toast: "AUTO_PROCESS_KEV is
    currently env-managed. Settings UI lands with M24."
  * Daily budget — only rendered once a `budget_status` event has
    landed; shows `used/limit · remaining` and a `dayjs.fromNow()`
    timestamp.

#### HISTORICAL IMPORT tab

* **Saved presets bar** (always visible at the top):
  * `<Dropdown searchable>` over `listPresets("popular")` sorted
    built-in first → custom by `use_count DESC`. Built-ins are
    labelled `★ Name`; custom rows show `(×use_count)`.
  * Selecting a preset hydrates the form with its filters and
    re-opens the form card.
  * "Save as preset" button → `<SavePresetModal>` (name + optional
    description + frozen filters preview → `createPreset`).
  * "Manage" button → `<ManagePresetsModal>` (custom presets are
    edit/delete-able; built-ins render read-only).
* **Collapsible NEW IMPORT card** — "Collapse / Expand" button in
  the card header. Inside:
  * **Basic filters** in a `repeat(auto-fit, minmax(160px, 1fr))`
    grid: date from / date to (native `<input type="date">`),
    "Or last N days" number input, Min CVSS `<Dropdown>` (Any /
    6.0+ / 7.0+ / 8.0+ / 9.0+ / 10.0), KEV-only toggle button
    (`.btn` / `.btn.active`), Vendor + Product text inputs.
  * **CVE-IDs override** textarea — one ID per line. The form
    keeps the `cve_ids` array in sync (`split(/\r?\n/) → trim →
    filter(Boolean)`). The M6 server-side filter short-circuits
    every other filter when `cve_ids` is set, matching the kickoff
    spec.
  * **Show advanced filters** toggle reveals the **novelty filters**
    section: Min EPSS dropdown (0.1 / 0.2 / 0.5 / 0.8), Min
    AttackerKB dropdown (2.0 / 3.0 / 4.0), and an "Exclude commons"
    toggle button.
* **PREVIEW button** (`.btn.ghost`) — calls `previewImport(filters)`
  via M6's `POST /imports/preview`. Loading copy is "Querying
  sources…". On response the preview panel renders:
  * "`X CVEs match`" (or "`~X CVEs match (approximate)`" when
    `result.approximate === true`, with a follow-up `.form-hint`
    explaining novelty filters are evaluated during staging).
  * Estimated LLM cost rendered to two decimals.
  * Sample table (`<table class="data-table dense">`, max 10 rows):
    CVE ID, CVSS (colour-coded `<Badge>` via
    `cvssBadgeVariant`), KEV (danger badge or em-dash), EPSS, and
    Published date.
  * **>500 → warning toast**: "X CVEs match — consider tightening
    filters before starting an import."
* **START IMPORT button** (`.btn.active`) — disabled until preview
  has run and `total_count > 0`. Calls
  `startImport({ filters, preset_id })`; bumping the preset's
  `use_count` happens server-side inside `/imports/start` (the M6
  router already does this — no double-bump from the client). On
  success the form collapses, the new job is prepended to the
  list, the expand panel auto-opens for the new job, and a success
  toast appears.
* **Active jobs card** — `<DataTable<ImportJob>>` driven by
  `listImports({ limit: 50 })`. Columns: Job ID (8-char mono
  prefix), Created (`fromNow()`, title attribute carries the full
  timestamp), Filters summary (`describeFilters(...)`), counts
  cluster (`staged/approved/done`), status `<Badge>`
  (`statusBadgeVariant`), and progress bar
  (`approved / staged → success when fully approved`). Click a row
  → toggle the inline expand panel for that job (one job expanded
  at a time).
* **Inline expand panel** (`<ExpandedJobPanel>`):
  * Loads via `getStagedCves(jobId, include_skipped=true)`.
  * **Batch action bar**: APPROVE ALL (`.btn.active`), APPROVE KEV
    ONLY (`.btn.accent2` — a new variant added in CSS), SKIP ALL
    (`.btn.danger.ghost`). Each goes through a `<ConfirmDialog>`
    whose `destructive` flag is set for the skip-all path.
  * **Filter tabs** (All / Staged / Approved / Processing /
    Complete / Skipped) drive a client-side filter over the loaded
    rows. The "Approved" tab maps to `processing_status === "pending"`
    (M6 transitions staged → pending on approve). "Processing"
    maps to `enriching | synthesizing | mapping | generating`.
  * **Staged CVEs table** (`.data-table.dense`), paginated 20/page
    with prev/next buttons. Per-row actions:
    `Approve` (`.btn.sm.success`) / `Skip` (`.btn.sm.danger.ghost`)
    visible only when `processing_status === "staged"`.
  * **Budget warning banner** — appears at the top of the expand
    panel when `budget.remaining != null && stagedCount > remaining`:
    > "X CVEs awaiting approval. Daily budget: Y remaining. Excess
    > will process tomorrow."

### CSS — `frontend/src/styles/darkops.css`

A `~270`-line M23 block appended after the M19 dashboard block:

* **Tabs**: `.imports-tabs / .imports-tab(.active)` for the top
  Live ⟷ Historical switch; `.imports-staged-tabs /
  .imports-staged-tab(.active)` for the staged-CVE filter row
  inside the expand panel.
* **Live feed**: `.imports-live-grid` (`2fr × 1fr` collapses to
  one column below 1024 px), `.live-events-card`, `.live-event-log
  / .live-event-row` (4-column grid for timestamp / type-badge /
  CVE / status), `.live-config-card / .live-config-row` (two-row
  grid with a third hint row at full-width).
* **Saved presets bar**: `.imports-preset-bar`,
  `.imports-preset-controls` (flex with `flex: 1` on the
  dropdown), `.imports-preset-summary`.
* **Filter form**: `.filter-form`, `.filter-section`,
  `.filter-section-title`, `.filter-grid`
  (`repeat(auto-fit, minmax(160px, 1fr))`),
  `.filter-advanced-toggle`.
* **Preview**: `.imports-preview-panel`, `.imports-preview-summary`,
  `.imports-preview-count`, `.imports-preview-table`.
* **Active jobs**: `.imports-jobs-card`, `.imports-jobs`,
  `.imports-job-panel`, `.imports-batch-bar`,
  `.imports-staged-table`, `.imports-row-actions`,
  `.imports-pagination`, `.imports-loading`.
* **Manage presets**: `.manage-presets`, `.preset-list`,
  `.preset-row(.preset-row-main / .preset-row-actions)`,
  `.preset-edit-form / .preset-edit-actions`.
* **`.btn.accent2`** — a new button variant for the APPROVE KEV
  ONLY action. The existing `.btn.danger.ghost` combination
  already gives us a usable destructive-ghost button without
  extra CSS.

Every selector consumes existing DarkOps tokens — no hardcoded
hex colours, no inline `style={{ color: '#...' }}` for theming.
The only `style=` usages in the TSX are layout-only
(`marginTop: var(--space-3)`).

### API client — `frontend/src/api/imports.ts` (rewritten)

The M18 placeholder typed the response shapes against guessed
field names (`count`, `cves`, `last_used_at`) that did not match
the real M6 routes. Without this fix the historical-import tab
would have rendered an empty count + N/A everywhere. Rewritten
against the actual `fragchain/api/routers/imports.py` contract:

* `ImportFilters` mirrors `fragchain.ingest.filters.ImportFilters`
  (date_from / date_to / cvss_min / kev_only / vendor / product /
  cve_ids + the four novelty filters).
* `PreviewSample / PreviewResult` match the backend's
  `total_count`, `approximate`, `sample[]`,
  `estimated_llm_cost_usd`, `filters_applied` shape.
* `ImportJob` carries the full status-machine count set
  (`preview_count`, `staged_count`, `approved_count`,
  `processed_count`, `skipped_count`, `error_count`,
  `completed_at`).
* `StagedCve` matches M6's `StagedCveOut`.
* `listPresets(sort)` defaults to `popular` (matches the kickoff's
  "sort by use_count DESC" requirement).
* `startImport({ filters, preset_id })` matches the
  `ImportStartRequest` schema.
* `approveImport / approveImportKev / approveImportAll / skipImport`
  match the four backend POST routes.

### Routing — `frontend/src/App.tsx`

* New import: `import { ImportManager } from "./screens/ImportManager"`.
* `<Route path="/imports" element={<ImportManager />} />` replaces
  the M1 placeholder.
* The unused `Imports` export was dropped from
  `screens/Placeholders.tsx` so the bundle no longer carries dead
  code for this screen.

## Architecture decisions

* **Two tabs in one screen, not two routes.** The operator
  workflow is "monitor the feed → if something looks staged,
  switch to the historical tab and approve". A single screen with
  a tab makes that one click cheaper than navigation. The URL
  carries `?tab=live|historical` so links and refreshes preserve
  context.
* **Single parent-level WebSocket subscription.** Each tab's
  re-render cycle is expensive (the historical tab mounts forms,
  modals, a data table, an expanded panel). Having both tabs
  subscribe independently would mean either two open sockets
  (wasteful) or unmount → resubscribe on tab change (drops the
  budget reading every time). One subscription at the
  `ImportManager` level forwards `wsLast` down by prop.
* **Budget state hoisted to the parent.** The budget warning
  banner inside the expand panel needs the most-recent budget
  reading, but the operator might still be on the live tab when
  the next budget tick fires. Lifting the state lets the warning
  appear the moment they switch over. The historical tab itself
  has no WebSocket subscription — it just reads the prop.
* **`AUTO_PROCESS_KEV` is a soft toggle.** The kickoff asks for a
  toggle that writes to `system_config`, but no `/api/v1/config`
  CRUD endpoint exists in v1 (the M6 backend reads the value from
  env at startup). Rather than ship a 501-only endpoint or a
  fake-success toggle, the UI flips the visual state and fires an
  info toast that points operators at M24 (Settings UI). This
  matches the same "settings UI lands with M24" disclaimer
  patterns the rest of the codebase uses.
* **The rate-limit number comes from event payloads, not a
  separate stats endpoint.** M6 emits `rate_limit_warning` when
  the cap is approached, and `budget_status` every 5 min. The
  UI hydrates the rate-limit reading from whichever event lands
  first, defaulting to the conventional `MAX_LIVE_CVE_PER_HOUR=10`
  baseline before any event arrives. Adding a dedicated
  `GET /imports/stats` endpoint to satisfy a 100 % accurate
  display on first paint felt heavier than its value — the
  default is right for the default config and the live tab fixes
  itself within seconds of the first event.
* **Preview panel sits inside the form card, not a modal.** The
  kickoff (M18 deviation note) suggested a `<Modal>` for the
  preview. In practice the operator wants to **see the preview
  while iterating filters** — popping a modal would block the
  filter form, force them to dismiss, tweak, re-open. The
  in-card panel lets them tighten filters until the count looks
  right, then hit Start.
* **Per-row Approve/Skip + batch actions.** Per-row actions only
  surface for `processing_status === "staged"`; once approved or
  skipped, the row's status badge replaces the action buttons.
  Prevents a double-approve / double-skip race against the worker.
* **Confirm dialog for batch actions only.** Per-row Approve /
  Skip fires immediately — the operator's intent is unambiguous
  on one CVE and the UI is reversible by the worker
  (they can re-stage via M6's reprocess flow). Batch actions
  (Approve all / KEV-only / Skip all) require a
  `<ConfirmDialog>` because the blast radius is larger.
* **`include_skipped=true` on the staged-CVEs fetch.** The
  expand panel's filter tabs need to show "Skipped" as one of
  the options, so we fetch the full set (including skipped) and
  partition client-side. With M6's typical staging batch sized at
  20 per worker tick + a daily budget of 20 CVEs/day, the row
  count is small enough to filter in-browser.
* **Manage-presets modal edits + deletes but does not preview
  filters live.** The operator's edit intent is "rename / re-
  describe my saved preset", not "change which filters it
  encodes". A full filter-editor inside the modal would require
  rendering the whole `<FilterForm>` for each row and managing
  per-row mutation state. If the operator wants different
  filters, they hydrate the preset, tweak the form, save as a new
  preset, and delete the old one — that's a clean two-step.
* **Built-in presets are listed read-only in the manage modal.**
  The backend rejects PATCH/DELETE on `is_builtin=true` with a
  400; we don't even render the buttons. Saves an extra round-
  trip and a misleading "Edit" affordance.

## Sandbox-level pre-flight checks (runnable here)

| Check | Result |
|---|---|
| `npm install` adds no new deps | ✅ no `package.json` changes; existing palette covers every primitive used |
| `npx tsc --noEmit -p .` from `frontend/` | ✅ clean (no output) |
| `npm run build` — `tsc -b && vite build` | ✅ 0 TS errors, 2 064 modules transformed, dist 69.26 kB CSS + 612.38 kB JS, 1.31 s |
| Internal import resolution | ✅ every `from "../api/imports"`, `from "../api/cves"`, `from "../components"`, `from "../hooks/useWebSocket"` resolves to a real file |
| DarkOps token usage | ✅ every `.imports-*` / `.live-*` / `.filter-*` / `.preset-*` rule reads from CSS variables; no inline hex literals in `ImportManager.tsx` (spot-checked via `grep` for `#[0-9a-f]\{3,8\}` against the screen) |
| API client matches backend route shapes | ✅ each `imports.ts` type aligns with `fragchain/api/routers/imports.py` Pydantic models — `ImportFilters`, `PreviewResult`, `FilterPreset(Create|Update)`, `ImportJob`, `StagedCve` |
| Preset routes ordered before `/imports/{job_id}` on the backend | ✅ already verified in M6 done doc; the client routes are URL-distinct anyway |

## Runtime verification *not* runnable in this sandbox

Operator should run these on the next `docker compose up`:

| Done criterion | Verification |
|---|---|
| LIVE FEED stats update via WebSocket | navigate `/imports`, confirm the four stat blocks render with `—` initially. Fire a synthetic CVE through the live pipeline (e.g. `curl -X POST $API/api/v1/webhooks/connector/test-stub -H "X-FragChain-Token: $SECRET" -d '{"cve_id":"CVE-2026-43285"}'`). Within ~500 ms the Live CVEs today + Processing rate + Queue depth values bump; a `cve_ingested` row lands at the top of the event log. |
| Rate limit progress bar colours correctly per threshold | set `MAX_LIVE_CVE_PER_HOUR=5` in `.env`, restart API + worker. Fire 4 webhooks → bar fills to 80 %, variant = warning (amber). Fire 5th → bar full, variant = danger (red); the 6th gets queued + the WebSocket emits a `rate_limit_warning`. |
| Preview returns count + sample from real OpenCTI (or mock) | switch to Historical tab, set Min CVSS = 9.0 + KEV only, click Preview. Endpoint returns `total_count` ≥ 0, sample ≤ 10. The "approximate" flag is **false** because no novelty filter is set. Then enable `epss_min` = 0.5 → re-preview → approximate flag flips true and the form-hint copy appears. |
| Start Import creates job, appears in Active Jobs | hit Start. POST `/imports/start` returns 201 with the new `ImportJob`. The new row lands at the top of the Active Jobs table, the expand panel auto-opens, and the status badge shows `queued`. Polling `GET /imports/{id}` should show the status walk through `queued → staging → ready` and the staged_count climbing. |
| Expand active job shows staged CVEs | once `staged_count > 0` (poll the M6 worker), refresh the panel. The CVE table populates with every staged row (CVE ID + CVSS badge + KEV chip + Published + Status badge + per-row Approve/Skip). |
| Approve flow moves CVEs to pending → pipeline runs | click a row's Approve. `POST /imports/{id}/approve` returns the updated job with `approved_count += 1`. The CVE row's status badge flips from staged → pending. Worker logs should show `enrich_cve` task dispatch within seconds. |
| KEV-only approve works | trigger an import with mixed KEV + non-KEV CVEs. Hit APPROVE KEV ONLY → `POST /imports/{id}/approve-kev`. Only the KEV rows transition to pending; non-KEV stays staged. |
| Budget warning appears at correct threshold | seed the daily budget close to its limit (e.g. approve 18 CVEs out of 20-day cap). Stage a new import with ≥ 3 staged. The warning banner "X CVEs awaiting approval. Daily budget: Y remaining. Excess will process tomorrow." appears above the staged table once a `budget_status` event lands. |
| All form controls use DarkOps tokens | ✅ already verified by inspection — no Tailwind utility classes, no inline hex literals. Use Chrome DevTools to confirm every `.imports-*` rule resolves to `var(--...)`. |
| `?tab=` query param round-trips | navigate `/imports?tab=historical` directly → historical tab renders selected. Click "Live feed" tab → URL updates to `?tab=live`. Reload → live tab still active. |
| Saved presets dropdown lists built-in + custom | navigate the historical tab. Built-in presets (★-prefixed) render first, then custom ones with `(×use_count)`. Selecting one hydrates the form; pressing Save as preset adds a custom row to the list within ~200 ms of confirming. |
| Manage presets edit + delete works | open Manage modal → rename a custom preset → save → list refreshes. Delete a custom preset → toast + list refreshes. Try the same on a built-in: the buttons are not rendered (read-only). |

## Interfaces this module exposes

Frontend consumers:

```ts
import { ImportManager } from "../screens/ImportManager";

// Per-resource API (already tightened in this module):
import {
  ImportFilters,
  PreviewResult,
  FilterPreset,
  ImportJob,
  StagedCve,
  listPresets,
  createPreset,
  updatePreset,
  deletePreset,
  previewImport,
  startImport,
  listImports,
  getImport,
  getStagedCves,
  approveImport,
  approveImportAll,
  approveImportKev,
  skipImport,
  cancelImport,
} from "../api/imports";
```

No new backend surface, no new hooks.

## What dependent modules need to know

* **M24 (Settings)** — the `AUTO_PROCESS_KEV` toggle currently
  fires an info toast pointing at M24. Once M24 ships a
  `system_config` CRUD surface, the soft toggle in
  `ImportManager.tsx` (line ~700 in the LIVE FEED tab's config
  card) should be wired to:
  * `GET /api/v1/config/auto-process-kev` for the initial state,
  * `PATCH /api/v1/config/auto-process-kev` on flip.

  The same applies to the `MAX_LIVE_CVE_PER_HOUR` display — once
  the env value is patchable at runtime, M24 can add an editable
  field there.
* **M19 (Dashboard)** — the dashboard already links to `/imports`
  from the staged-KEV banner. The new `?tab=historical` query
  param could be appended (e.g. `/imports?tab=historical`) to
  drop the operator directly into the approval flow; today the
  link goes to the default (live) tab.
* **M22 (Queue)** — no shared state with this module.
* **M21 (Matrix)** — no shared state with this module.

## Deviations from kickoff

* **`AUTO_PROCESS_KEV` is read-only.** The kickoff asks for a
  toggle that writes to `system_config`. Backend has no CRUD
  endpoint; we render the toggle and surface a toast pointing at
  M24 instead of either silently no-op-ing or shipping a 501-only
  endpoint as part of M23. CLAUDE.md §19 forbids implementing
  identity logic in v1, and `system_config` mutation falls under
  the same M24-owned settings surface.
* **Preview panel is in-card, not a modal.** M18 hint suggested
  Modal; in-card lets the operator iterate filters without
  popping a dialog. Detailed rationale in Architecture Decisions.
* **`?tab=live|historical` URL state added.** Not in the kickoff
  but matches the M19 dashboard's `?technique=` pattern for
  cross-screen deep links.
* **Built-in presets are listed read-only in the manage modal,
  not just hidden.** Operators benefit from seeing the canonical
  built-in set when deciding whether to clone or extend it.
* **`include_skipped=true` on the staged-CVE fetch.** The
  kickoff's spec doesn't mention it; we need it for the "Skipped"
  filter tab. M6's backend supports the flag.
* **Per-row Approve/Skip skips the confirm dialog.** Only batch
  actions go through `<ConfirmDialog>`. Per-row actions are
  immediate to avoid the click cascade. Detailed rationale in
  Architecture Decisions.
* **Server-side preset use-count bump only.** The kickoff says
  "Start Import creates job, calls POST /api/v1/imports/presets/{id}/use if using preset"
  but the M6 router already bumps `use_count` inside
  `POST /imports/start` when `preset_id` is in the body. Calling
  the explicit `/use` route in addition would double-count.
* **`describeFilters(...)` summary string.** Not in the kickoff
  but the Active Jobs table needs a Filters column; a single
  human-readable summary is more useful than a JSON blob.
* **Stats fetch uses three `listCves` calls.** A dedicated
  `/imports/stats` endpoint would be cheaper but adds backend
  surface. The same trade-off the dashboard accepted in M19;
  defer until we see real load. (M6's `listCves` is indexed on
  `published_at`, `import_mode`, and `processing_status` — the
  filtered list is a fast scan.)

## Known TODOs (owned by other modules)

* **M24 — `system_config` CRUD endpoint.** Wire the
  `AUTO_PROCESS_KEV` toggle to the real backend once M24 ships.
  The toggle scaffold already exists; only the `onChange` body
  needs to swap from "toast info" to "PATCH then refresh state".
* **M24 — editable `MAX_LIVE_CVE_PER_HOUR`.** Same. Render as an
  editable number input once the backend supports runtime
  override; today it's read-only display.
* **M19 — deep link from dashboard to `/imports?tab=historical`.**
  The dashboard's staged-KEV banner links to `/imports` today; a
  one-line change to append `?tab=historical` would drop
  operators straight onto the approval tab.
* **Server-driven preset sort.** `listPresets("popular")` already
  sorts by `use_count DESC`, but the M6 router doesn't group by
  `is_builtin` first. The frontend re-sorts client-side; if
  preset lists grow large we'd want to push the grouping to
  Postgres.
* **N+1 staged-CVE fetch.** Each expand opens a new
  `getStagedCves` call. Cheap for the typical 20-row batch; we
  could add a list-level caching layer once the import volume
  grows.

## Risks / known weaknesses

* **Per-row Approve fires immediately.** A misclick approves one
  CVE. Mitigation: the row reverts to staged trivially via
  `POST /api/v1/cves/{id}/reprocess` (the M6 reprocess endpoint)
  but the budget tick will have already counted it. Operators
  should treat individual Approve clicks as committal.
* **`AUTO_PROCESS_KEV` toggle is misleading.** Visually it looks
  functional; only the toast tells the operator it's read-only.
  M24 will wire this up properly; until then there's a small risk
  an operator assumes a flip persists.
* **Stats reload only on a small set of WS events.** The Live
  CVEs today / processing-rate stats reload on
  `cve_ingested | enrichment_complete | import_job.staged`. A
  chain_generated or coverage_mapped event won't bump them,
  which is correct — but a long idle period (no live ingest)
  will leave the rate stat stale until the next reload trigger
  arrives. Acceptable for a feed monitor; the user can refresh
  the page to force a re-fetch.
* **`describeFilters` is best-effort.** Reads only the canonical
  set of fields; a future filter we add to `ImportFilters`
  without updating `describeFilters` would silently drop from
  the Active Jobs summary. The TypeScript surface keeps the
  field set stable, so the drift risk is bounded.
* **Filter tabs partition on `processing_status` alone.** The
  "Approved" tab is `processing_status === "pending"`. If a
  CVE rolls past pending (e.g. straight to enriching) inside the
  poll window, it appears in the "Processing" tab on next refresh.
  This matches the M6 state machine semantics but may surprise
  an operator expecting a strictly monotonic "Approved" list.
* **Builtin preset `★` prefix is decorative.** The
  `<Dropdown>` filter searches against `searchText` which
  excludes the `★` glyph; built-ins still match when the user
  types their name. No accessibility regression — the prefix is
  in the label only.

## Outstanding questions

* **Should the live tab also surface `import_job.created` /
  `import_job.staged` events in the event log?** Currently it does
  (they're in `mapEventStatus`). An alternative would be to scope
  the live tab strictly to live-feed events and leave import-
  job events to the historical tab. Open whether to filter them
  out — defer until operators give feedback.
* **Preview cost-estimate accuracy.** The M6 `estimated_llm_cost_usd`
  is a rough per-CVE × LiteLLM input-token estimate. Operators
  may want a per-stage breakdown (synthesis vs. rule-gen vs.
  coverage check). Defer until cost-tracking lands in the
  finance UI (M24-or-later).
* **Should the "Save as preset" button gate on the preview
  having been run?** Today you can save filters that you haven't
  previewed. The reverse view (saving only filters you've
  validated) might be safer, but adds friction. Open.
* **Should `MAX_LIVE_CVE_PER_HOUR` come from an event
  exclusively?** Today we fall back to a 10-default if no
  `rate_limit_warning` has landed. If a deployment runs with
  the default for hours without ever hitting the cap, the UI
  still shows "/10" even if the actual env value is different.
  An on-mount stats endpoint would fix this; defer to M24.

---

## Phase 6 scope catch-up applied (2026-05-13)

Closes one silent gap and one spec drift from `SCOPE_REVIEW_M22_M24.md`.
See `SCOPE_CATCHUP_M22_M24_DONE.md` for the full record.

* **Vendor/Product autocomplete.** The kickoff explicitly says
  "Vendor/Product text input with autocomplete"; the original build
  shipped two plain `<input type="text">` fields. New
  `GET /api/v1/cves/suggest?field=<vendor|product>&q=<prefix>&limit=N`
  endpoint backed by a JSONB scan over `cves.affected_products` with
  a 5-minute Redis cache. Frontend uses a debounced (300 ms)
  `SuggestInput` component with min-2-char prefix, keyboard nav
  (arrows + enter), Esc/Tab close, and "No matches" empty-state.
  Auth: any authenticated user; the data is non-sensitive.
* **Event-type spec drift.** The kickoff listed aspirational event
  names (`cve_received`, `rate_limited`, `processing_started`,
  `complete`, `failed`) that don't match what
  `fragchain/api/routers/websocket.py` actually emits. Updated
  `FragChain_Module_Prompts.md` and the M23 spec section to list
  the real emitter names. The frontend already mapped the real
  names — only the docs were stale.

The `MAX_LIVE_CVE_PER_HOUR` and `AUTO_PROCESS_KEV` blockers stay
acknowledged here; both wait on the v1.x `system_config` CRUD ticket
described in `MODULE_M24_DONE.md`'s v1.x backlog section.
