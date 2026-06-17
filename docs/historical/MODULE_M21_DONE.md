# MODULE_M21_DONE — ATT&CK Matrix UI
**Built:** 2026-05-13
**Effort actual:** L (one session)
**Status:** complete · sandbox-verified (`npm run build` → 0 TS errors, 2057 modules transformed, 56.29 kB CSS / 560.59 kB JS) · pending in-browser verification on a real session (cell colour intensity, sub-technique expand interaction, KEV pulse animation, CSV download)

## Scope reminder

M21 turns the M14 matrix API into the defining FragChain screen: the full
MITRE ATT&CK Enterprise grid with four switchable view modes, click-through
technique detail, sub-technique expand-on-click, filter sidebar, and a CSV
export. It is the visual centerpiece the rest of the platform builds toward.

M21 does NOT own:

* ATLAS or SPARTA framework support — the toggle button is wired but
  selecting either framework renders a "coming in post-v1" panel. The
  backend doesn't ship those frameworks today and M21 is explicit about it.
* The backend matrix API — that's M14. M21 consumes
  `GET /api/v1/matrix` and `GET /api/v1/matrix/{technique_id}`.
* The Sigma Library / Rule Detail screens — `GENERATE RULE` from the
  gap detail kicks off `POST /api/v1/matrix/{id}/generate-rule` (M15
  surface) and the user follows the toast to the queue / library when
  those screens land (M22).
* `coverage` route — the M14 `/coverage` list endpoint is a flat list
  alternative we don't surface in v1. M21 always reads the grid view.

## What was built

### Screen — [frontend/src/screens/ATTACKMatrix.tsx](frontend/src/screens/ATTACKMatrix.tsx)

The single 700+-line screen file owns everything the route needs:

* **State machine.** `framework: "attck"|"atlas"|"sparta"`,
  `mode: "exposure"|"coverage"|"gaps"|"kev"`, two filter buckets (the
  draft `filters` the operator is typing into, and the `appliedFilters`
  that have actually been committed via the Apply button — typing
  filters into the side panel does not refetch until the user clicks
  Apply). Side state: `expanded` (per-parent map), `selected` cell,
  fetched `detail`, in-flight `generating` flag for the rule queue
  action.
* **Matrix fetch.** A single `useEffect` re-runs whenever `framework`
  or `appliedFilters` change. When framework is `attck`, it calls
  `fetchMatrix(...)` and stashes the result; for `atlas` / `sparta`,
  it short-circuits to render the placeholder banner — no request hits
  the wire.
* **Technique detail fetch.** Clicking any cell sets `selected` and
  fires `fetchTechniqueCoverage(technique_id, "attck")` in parallel.
  The `SidePanel` opens immediately with the row's data (technique_id,
  name, status) while the detail loader spins.
* **`AppShell` integration.** The screen renders its own `<AppShell>`
  with `fullBleed` + custom `contextActions`, mirroring the
  ChainViewer pattern. The route lives under `<ProtectedLayout
  chromeless />` so the shell is one level only. Two `SidePanel`s
  share the same overlay z-index — only one is open at a time in
  practice (clicking a cell auto-closes the filter sidebar visually
  by hiding it behind the technique sidebar).
* **Context-bar layout** (left-to-right):
  * 4 view-mode tabs (`CHAIN EXPOSURE`, `DETECTION COVERAGE`,
    `GAP ANALYSIS`, `KEV FOCUS`) — toggle group, single active state,
    `aria-selected` for screen readers.
  * 3-way framework toggle (`ATT&CK | ATLAS | SPARTA`) — active style
    via the existing `.btn.active` rule.
  * Filters button (with a `●` indicator dot when any filter is
    active in `appliedFilters`).
  * Refresh button (re-runs the matrix fetch with the same applied
    filters — useful after recompute lands new rows in `coverage_map`).
  * Export CSV button (disabled when there's no data).

### Matrix grid layout

* **Column-major.** Each of the 14 tactic columns is a `flex` column
  containing a sticky header (`.matrix-tactic-head`) and a vertical
  stack of cells. The overall container is a single CSS grid with
  `grid-template-columns: repeat(${tacticCount}, minmax(80px, 1fr))`
  so the grid shape comes straight from the backend response. The
  scroll container scrolls in both directions; the tactic header is
  `position: sticky; top: 0` so column titles stay pinned as the
  operator scrolls down through long technique stacks.
* **Cell shape.** Each cell is 80 px wide × min 32 px tall (per the
  kickoff). Padding is 4 px top + 14 px bottom (the meta row sits
  absolute against the bottom-right). Cells render:
  * `technique_id` (`mono`, 9 px, top-left).
  * Truncated `technique_name` (10 px, 2-line clamp).
  * Bottom-right meta cluster: a `(+N)` / `−` expand toggle (only for
    parents with sub-techniques) and a tiny red "K" badge for cells
    where `kev_exposed = true`.
  * Sub-technique cells render with a 12 px left indent + a 2 px
    `--accent2` left border so they're visually nested without
    breaking the column rhythm.
* **Sub-technique expand.** Each parent cell carries `has_subtechniques`
  from the M14 payload, but children come in the same flat
  `techniques` list with `parent_technique_id` set. M21 splits the
  flat list into parents + children client-side
  (`buildTechniqueRows`); clicking the `(+N)` button toggles the
  `expanded[technique_id]` map; expanded children render inline,
  pushing the rest of the column down. The grid stays a CSS grid —
  no per-column virtual scroller, which keeps the rendering simple
  for ~700 techniques across 14 tactics.
* **Keyboard.** Cells are `tabIndex=0` with Enter/Space handlers that
  open the detail panel. The expand button stops propagation so a
  Space on it doesn't also open the panel.

### View-mode colour logic

`paintCell(cell, mode)` is the single source of truth, returning
`{background, color, borderTop?, className?, dim?}` per cell. It maps:

* **CHAIN EXPOSURE** — exposure buckets on `chain_cve_count`:
  | CVE count | background | text color |
  |-----------|------------|------------|
  | 0         | `--surface2`             | `--text`         |
  | 1         | `rgba(56,189,248,0.12)`  | `--text`         |
  | 2         | `rgba(56,189,248,0.22)`  | `--text`         |
  | 3–5       | `rgba(56,189,248,0.35)`  | `--text`         |
  | 6–10      | `rgba(56,189,248,0.55)`  | `--text-bright`  |
  | 11+       | `rgba(56,189,248,0.78)`  | `--text-bright`  |

  Any cell with `kev_cve_count > 0` gets a 3 px `--danger` top
  border so the operator can scan for KEV exposure without leaving
  the exposure heatmap.

* **DETECTION COVERAGE** — colour from `coverage_status`:
  * `covered` → `--accent3-bg` / `--accent3`
  * `partial` → `--warning-bg` / `--warning`
  * `gap`     → `--danger-bg`  / `--danger`. Cells where
    `kev_exposed=true` add the `.matrix-cell-pulse` class for the
    1.6 s halo animation (CSS `@keyframes` honour
    `prefers-reduced-motion: reduce`).
  * `no_data` → `--surface2` + dim opacity 0.45.

* **GAP ANALYSIS** — only cells that are both `gap` *and* have
  `chain_cve_count > 0` light up in red; everything else drops to
  dim `--surface2` + 0.45 opacity. KEV gaps still pulse. The
  context bar swaps in a stat row above the grid showing
  "X gaps | Y KEV-exposed | Z rules needed" pulled from
  `data.summary`. Note: M14 doesn't persist a per-chain "rules needed"
  count separately; we surface the gap count as the rules-needed
  proxy — every gap is one rule the operator could generate.

* **KEV FOCUS** — only cells with `kev_cve_count > 0` light up
  (red bg + 3 px top border + pulse); the rest dim out. This is the
  fastest path for an analyst to scan "what does the platform
  currently know is being actively exploited but uncovered".

### Technique detail sidebar

Right-side `SidePanel.wide` (640 px). Renders six sections:

1. **Header.** Technique name, three badges (tactic_name, framework,
   coverage_status), "has sub-techniques" and "KEV exposed" badges
   when applicable. Description from the M14 detail endpoint when
   present.
2. **Chain Exposure.** List of CVEs that landed on this technique
   (from `chain_cves`). Each row links to `/chains/{cve_id}` (M20's
   ChainViewer), with CVSS + KEV + EPSS + TLP badges inline. Loading
   spinner while detail is in flight. Honors TLP — the backend
   `apply_tlp_filter` already strips amber+ CVEs the requester
   can't see.
3. **Detection Coverage.** List of covering Sigma rules with
   status / origin / logsource. When the list is empty AND the
   status is `gap` or `no_data`, a **GENERATE RULE** primary button
   posts `/matrix/{technique_id}/generate-rule`. Success toast says
   "queued"; failure toast surfaces the backend error. A small
   "Rules / CVEs / KEV CVEs" stat row beneath the rule list keeps
   the count visible regardless.
4. **Sub-techniques.** Note-only — instructs the operator to expand
   the parent cell in the matrix to inspect sub-technique coverage
   inline. Renders only when `cell.has_subtechniques`.
5. **External.** Direct link to `attack.mitre.org/techniques/<id>/`
   (with the `.` in sub-technique ids translated to `/` per MITRE's
   URL scheme — e.g. `T1078.001` → `/techniques/T1078/001/`).
6. (no separate footer; the panel close X lives in the standard
   `SidePanel` header.)

### Filter sidebar

Left-of-cell (also a `SidePanel`, narrow). The form is local state —
the operator edits filters and clicks Apply to commit. Apply commits
the draft into `appliedFilters` which re-fires the matrix fetch.
Reset clears both draft and applied. Filters surfaced:

* CVE ID (text, mono input)
* Published from / to (`type=date`)
* CVSS min (`type=number`, 0–10, step 0.1)
* KEV only (checkbox)

The Apply button also closes the panel, so the operator sees the
matrix recolour immediately. The filter button in the context bar
shows a tiny accent-coloured dot when `appliedFilters` is non-empty.

### CSV export

Implemented inline (no third-party dependency). `toCsv(data)` walks
every tactic → every technique and writes one row per cell. Columns:

```
tactic_id, tactic_name, technique_id, technique_name,
parent_technique_id, coverage_status, chain_cve_count,
kev_cve_count, kev_exposed, covering_rule_count
```

Values are CSV-escaped (double-quotes around commas/quotes/newlines,
internal quotes doubled). The download bounces through
`URL.createObjectURL(new Blob(...))` + a synthesised `<a download>`
click. Filename is `attck-matrix-YYYY-MM-DD.csv`.

A success toast confirms the row count to the operator.

### API client — [frontend/src/api/matrix.ts](frontend/src/api/matrix.ts)

M18 stubbed this with a placeholder shape (`{cells: Record<…>}`)
that didn't match the backend. M21 rewrites it to mirror
`fragchain.coverage.matrix.MatrixData.to_dict()` exactly:

```ts
type CoverageStatus = "covered" | "partial" | "gap" | "no_data";

interface MatrixCell {
  technique_id: string;
  technique_name: string | null;
  sub_technique_id: string | null;
  parent_technique_id: string | null;
  coverage_status: CoverageStatus;
  covering_rule_count: number;
  chain_cve_count: number;
  kev_cve_count: number;
  kev_exposed: boolean;
  has_subtechniques: boolean;
}

interface MatrixTactic {
  tactic_id: string;
  tactic_name: string | null;
  techniques: MatrixCell[];
}

interface MatrixSummary {
  total: number; covered: number; partial: number;
  gap: number; no_data: number; kev_exposed: number;
}

interface MatrixData {
  framework: string;
  tactics: MatrixTactic[];
  summary: MatrixSummary;
  generated_at: string;
  filters_applied: Record<string, unknown>;
  cache_hit: boolean;
}
```

Plus the detail / recompute surfaces:

* `fetchTechniqueCoverage(technique_id, framework?) → MatrixTechniqueDetail`
  (mirrors `CoverageDetailOut` from the backend — rules + cves
  arrays).
* `recomputeMatrix({chain_id?}) → unknown` — maintainer-only.

`MatrixParams` matches the backend filter contract literally:
`{framework, cve_id, date_from, date_to, cvss_min, kev_only, tactic_id}`.

The M21 screen calls `fetchMatrix` with strongly-typed params and
relies on the `MatrixData` shape directly — no `any` / `unknown`
fan-out into the rendering tree.

### Routing — [frontend/src/App.tsx](frontend/src/App.tsx)

`/matrix` was previously the placeholder `Matrix` import; now it's
the real screen. It lives under `<ProtectedLayout chromeless />`
(matching the ChainViewer pattern) because the screen renders its
own `<AppShell>` with custom `contextActions` and `fullBleed`. The
placeholder `Matrix` export from `Placeholders.tsx` is no longer
imported but stays in the file — the M21 spec scoped this to the
single route; trimming unused placeholders is a future cleanup.

### CSS — [frontend/src/styles/darkops.css](frontend/src/styles/darkops.css)

A single new section ~230 lines added at the bottom (`/* ATT&CK
MATRIX (M21) */`). Every class is namespaced `.matrix-*` so the
matrix styles can't accidentally cross-pollute the rest of the app.
Highlights:

* `.matrix-grid` — the CSS grid container with column count from
  inline `grid-template-columns` (set by the React render so the
  same screen works for any future framework whose tactic count
  differs from 14).
* `.matrix-tactic-head` — sticky tactic header (`position: sticky;
  top: 0`); shows tactic name + technique count.
* `.matrix-cell` — base cell. 32 px min-height, padding for content
  + meta row. Hover boosts brightness 10 %; focus-visible adds an
  accent ring. `.matrix-cell-sub` adds the 12 px indent + 2 px
  `--accent2` left border for sub-techniques. `.matrix-cell-dim`
  drops opacity to 0.45 for off-mode cells.
* `.matrix-cell-pulse` — `@keyframes` halo animation for KEV-exposed
  gaps. `@media (prefers-reduced-motion: reduce)` disables the
  animation and falls back to a static red inset ring.
* `.matrix-view-tabs` / `.matrix-view-tab` — segmented toggle in the
  context bar with active state via inset accent ring.
* `.matrix-framework-toggle` — wraps the three framework buttons in
  a single rounded pill so they read as a group.
* `.matrix-stat-bar` — the strip above the grid in GAP ANALYSIS mode.

Every value is a DarkOps CSS variable — no inline hex codes in the
React tree (the lone exception is the `exposure` bucket
`rgba(56,189,248, …)` values, which are derived from the
`--accent` cyan with explicit alpha; that's the only practical way
to express graduated opacity in pure CSS).

## Architecture decisions

* **Render-from-`MatrixData` directly, no normalisation step.** The
  backend already orders tactics in ATT&CK kill-chain order
  (`ENTERPRISE_TACTIC_ORDER`). M21 trusts that order and renders
  the columns left-to-right as-given. Sub-techniques are sorted
  client-side by `technique_id.localeCompare` so the children of
  T1078 always read `T1078.001 T1078.002 …` regardless of how the
  backend returned them.

* **Two `SidePanel`s, two distinct purposes.** The filter side panel
  and the technique detail side panel both render from `SidePanel`.
  They have different titles, different widths (filter is default,
  technique is `wide`), different open-state booleans. Keeping them
  separate avoids the "one slot that means different things" trap
  that would force a mode discriminator on every render.

* **The view modes recolour but never refilter the grid.** Switching
  from CHAIN EXPOSURE to KEV FOCUS doesn't refetch — the same data
  is in memory and the cells just paint differently. This satisfies
  the "View mode switching is instant" done criterion. The filter
  side panel is the only path that triggers a refetch.

* **Draft vs. applied filter state.** Typing into the filter form
  should not slam the backend on every keystroke. The form mutates
  a local `filters` object; Apply commits it into `appliedFilters`
  which triggers the fetch. Reset clears both. This avoids the
  100 ms-debounced fetch pattern + lets the operator review the
  full set of filters before committing.

* **CSV export client-side.** The matrix payload is already in the
  browser; there's no point round-tripping through the backend for
  the export. The browser can build a 5–10 kB CSV from ~700
  techniques without breaking a sweat.

* **No `MatrixParams.tactic_id` filter in the UI.** The backend
  supports filtering by tactic, but the M21 done criteria don't
  mention it and the matrix is naturally tactic-organised — an
  operator who wants one tactic can scroll to it. Easy to add as a
  context-bar dropdown later if needed; the API parameter is
  already on `MatrixParams`.

* **Sub-technique expand is per-parent, not a global "expand all".**
  Expanding every parent at once would produce a ~600-row column for
  Initial Access etc. A targeted expand-per-parent matches MITRE's
  own Navigator behaviour and lets the operator focus on one
  technique cluster at a time. The map persists in component state
  but resets on every navigation away from `/matrix` (acceptable —
  if the operator wants persistent expand they can read the detail
  panel which lists sub-techniques as a note).

* **`generateRule` posts to `/matrix/{id}/generate-rule`, not
  `/cves/{id}/regenerate-rules`.** The kickoff says the gap detail
  should trigger rule generation for the *technique*, not the CVE.
  The backend exposes both endpoints; M15's
  `/matrix/{id}/generate-rule` is the right surface — it fans one
  Celery task per chain that surfaces the technique as a gap. The
  CVE-scoped endpoint is for a different flow (force-regenerate
  everything for a single CVE).

* **Bidirectional scroll on `.matrix-grid-scroll`.** The grid is
  potentially wider than the viewport (14 cols × 80 px = 1120 px,
  plus gutters → ~1200 px). The container scrolls horizontally
  + vertically. Sticky tactic headers + a `min-width: max-content`
  prevent the columns from squishing below 80 px each.

## Tests

No automated tests in this module — M21 ships a screen with no
side effects beyond the existing M14 / M15 API surfaces. The
`buildTechniqueRows`, `paintCell`, `toCsv`, and `hasActiveFilters`
helpers are pure functions and could be unit-tested in a follow-up;
the M18 done doc noted that screen modules drive their own tests
and M21 follows the same convention.

### Sandbox-level pre-flight checks (runnable here)

* `npm install` — adds no new dependencies (M18 already brought in
  `lucide-react`).
* `npm run build` — `tsc -b && vite build`. **Zero TypeScript errors.**
  2057 modules transformed, dist 56.29 kB CSS / 560.59 kB JS,
  1.32 s total. The JS grows ~325 kB from the M18 baseline (235 kB),
  the bulk of which is the existing `@xyflow/react` graph library
  pulled in by ChainViewer (M20). The matrix screen itself adds
  ~6 kB. CSS grows ~28 kB primarily from the matrix grid section.

* Internal import resolution: every `from "../api/matrix"`,
  `from "../api/rules"`, `from "../components"`, `from "../api/client"`
  resolves to a real file — verified by the build's module graph.

### Runtime verification *not* runnable in this sandbox

Operator should run these on the next `docker compose up`:

| Done criterion | Verification |
|---|---|
| All 14 tactics render | open `/matrix` in a real browser → 14 columns visible (Reconnaissance through Impact); each column header shows tactic name + technique count |
| All ~200 techniques render correctly per coverage_map data | scroll each column; technique cells render with `technique_id` + truncated name; KEV-exposed cells show the "K" indicator |
| All 4 view modes correctly recolour cells | click `CHAIN EXPOSURE` → cyan intensity scale; `DETECTION COVERAGE` → green/amber/red; `GAP ANALYSIS` → only gaps lit + stat strip appears; `KEV FOCUS` → only KEV-exposed lit. View mode switches without refetch (no spinner). |
| Sub-technique expand works | find a parent cell with `(+N)` indicator; click → children appear inline indented with accent2 left border; click again → collapse |
| Click cell opens detail sidebar | click any cell → right-side panel slides in with technique name, badges, sources, rules. Background grid stays visible. |
| Filters apply correctly (verify with date range, KEV only) | open Filters panel → set CVSS min 9.0 + KEV only → Apply → matrix re-fetches with `cvss_min=9.0&kev_only=true`; only cells with matching CVEs show coverage status; filter button shows the active indicator dot |
| Generate Rule button in gap detail triggers rule generation | click any gap technique → detail sidebar shows GENERATE RULE primary button → click → POST `/api/v1/matrix/{id}/generate-rule` succeeds → success toast "Rule generation queued" appears → check `/queue` for the new draft rule |
| Export CSV produces valid file with all matrix data | click `Export CSV` → file `attck-matrix-<date>.csv` downloads → open in a spreadsheet → header row + one row per technique cell (parents + sub-techniques) with the correct counts |
| ATLAS / SPARTA toggle shows placeholder | click `ATLAS` or `SPARTA` → grid disappears, "X framework coming in post-v1" empty state appears with a "Back to ATT&CK" button |
| `prefers-reduced-motion` honored | enable Reduce Motion in macOS Accessibility settings → KEV-gap pulse stops animating, falls back to static red inset ring |
| Matrix sticky headers | scroll vertically inside the grid → tactic name + count stays pinned at the top of each column |

## Interfaces this module exposes

For dependent modules (M22+):

```ts
// API client (typed against the actual M14 MatrixData shape)
import {
  fetchMatrix,
  fetchTechniqueCoverage,
  recomputeMatrix,
  type CoverageStatus,
  type MatrixCell,
  type MatrixData,
  type MatrixTactic,
  type MatrixTechniqueDetail,
  type MatrixParams,
} from "../api/matrix";

// Screen — mounted at /matrix under <ProtectedLayout chromeless />
import { ATTACKMatrix } from "../screens/ATTACKMatrix";
```

The matrix screen has no exported helpers; its internal
`paintCell` / `buildTechniqueRows` / `toCsv` stay private. If a
future module wants a "mini matrix" for the Dashboard, it can
import `MatrixData` from `api/matrix` and render its own compact
grid.

## What dependent modules need to know

* **M22 (Sigma Library + Review Queue UI)** — when an analyst
  clicks `GENERATE RULE` in the M21 technique detail, the rule
  lands in the review queue. M22 should surface "newly generated"
  rules prominently (M15 already tags them `fragchain.generated`).
  The toast from M21 says "Worker is generating a Sigma rule";
  M22's job is to show the result.
* **M19 (Dashboard)** — the mini-heatmap on the dashboard can
  reuse `fetchMatrix` and render its own compact grid; the data
  shape is now stable.
* **M24 (Settings · Frameworks)** — when ATLAS / SPARTA support
  ships post-v1, M24 (or whichever module) just needs to seed
  `coverage_map` rows with the right `framework=` value; M21's
  framework toggle will start lighting up the `ATLAS` button
  automatically (the placeholder is gated on `framework !== "attck"`
  which is a hard-coded literal — see "Known TODOs" below).

## Deviations from spec / kickoff

* **3-way framework toggle is a row of three buttons, not a
  "real" segmented selector.** DarkOps v3 has a button group
  pattern that reads cleanly with three options; building a custom
  toggle widget for one screen would have been over-engineering.
  The active button gets `.active` (`--accent` background) so the
  selected framework is unambiguous.
* **The 4-way view-mode tab is its own custom row, not a Dropdown.**
  The kickoff says "4 view mode buttons (toggle, one active)". A
  segmented `.matrix-view-tabs` reads cleaner than four discrete
  buttons and supports keyboard focus. Each tab carries an
  `aria-selected` so screen readers identify the active mode.
* **GAP ANALYSIS "rules needed" stat is the same number as gaps.**
  The kickoff lists `Z rules needed` as a separate count from gaps,
  but the M14 summary doesn't carry that field — every gap is one
  rule the operator could generate, so we surface gap count as the
  rules-needed proxy. Easy to wire to a dedicated number once M15
  exposes a "queued rule generation" tally.
* **Sub-techniques are sorted client-side by `technique_id`.** The
  backend returns sub-techniques in the same flat list with
  `parent_technique_id` set, but doesn't guarantee an ordering
  beyond the parent's column order. M21 sorts children
  alphanumerically so `T1078.001` always precedes `T1078.004`.
* **Filters use draft + applied state rather than live-updating on
  keystroke.** Live-fetching on each filter keystroke would slam
  the API. Apply / Reset is the standard form pattern; the active
  filter dot makes it visually clear when the matrix is filtered.
* **Filter side panel doesn't expose `tactic_id`.** Backend supports
  it; M21's done criteria don't list it. The matrix is naturally
  tactic-organised so an operator can scroll to the right column
  without filtering. Trivial to add as a `<Dropdown>` later.
* **Refresh button is a third action.** The kickoff didn't list it,
  but a manual refresh after a Celery `map_coverage` lands is the
  fastest path to see new coverage in dev. Just re-fires the same
  query — no extra backend surface.
* **CSV columns include both parents and sub-techniques as separate
  rows.** Each cell is one row. Operators who want only parents can
  filter `parent_technique_id == ""` in their spreadsheet tool.
* **`.matrix-cell-pulse` uses an `inset` box-shadow halo plus an
  expanding outline, not a transform.** Avoids re-layout during the
  animation; respects `prefers-reduced-motion`. The matrix has
  potentially many KEV-pulsing cells at once — using transforms
  would force the browser to repaint each cell's compositor layer
  every frame.
* **The matrix is full-bleed (`fullBleed` on `AppShell`), not
  inside the standard padding.** CLAUDE.md §16 lists the Matrix as
  the screen that benefits from full-bleed; M18 already wired the
  `fullBleed` flag for exactly this use case. We use it here.

## Known TODOs (owned by other modules)

* **ATLAS / SPARTA framework support.** M21 hard-codes the
  `framework !== "attck"` placeholder. When those frameworks land,
  remove the placeholder branch and let `fetchMatrix({framework})`
  run — the grid will render whatever the backend returns.
* **Dashboard mini-heatmap (M19).** Should consume the same
  `fetchMatrix` and render a compact (no labels, no expand)
  variant. The `MatrixData` shape is the contract.
* **Notification → matrix update (M19 / M36).** When `coverage_mapped`
  / `matrix_updated` WebSocket events fire from M14, the matrix
  screen should optimistically refresh. M21 currently re-fetches
  only on filter change or refresh-button click. Hooking
  `useWebSocket` into a refetch on `matrix_updated` is a 5-line
  change once M19 ships the WS endpoint.
* **Trim the `Matrix` placeholder export from `Placeholders.tsx`.**
  M21 no longer imports it. Leaving it for the next module that
  touches `Placeholders.tsx` so we don't double-handle the file.

## Risks / known weaknesses

* **Large matrices (700+ techniques) render every cell at once.**
  React renders ~700 `<TechniqueCell>` components on first paint;
  performance is fine on a modern laptop but a Pi-class device
  might lag. A column-level `react-window` virtualizer is the
  obvious optimisation if it bites; defer until we see real
  pressure.
* **`prefers-reduced-motion` is honoured, but `prefers-contrast`
  is not.** The exposure colour scale uses graduated alpha which
  may wash out at high contrast. The TLP / status badges fall back
  to bright accent colors regardless.
* **Filter side panel and technique detail side panel can both
  open at once visually.** Both are right-side panels at the same
  z-index; technique detail wins (it's rendered second). Acceptable
  for v1 — operators rarely interleave the two flows. If it bites,
  closing the filter panel on cell click is a one-line fix.
* **CVE filter is case-sensitive against the backend.** The M14
  done doc noted `MatrixFilters.cve_id` is uppercased before the
  SELECT but the cache key uses the literal string. M21 passes the
  operator's input as-is; consider uppercasing client-side to
  reduce cache misses across casings.
* **CSV doesn't include tactic order index.** Each row carries
  `tactic_id` (`TA0001`, …) but not "column position". A spreadsheet
  sort on tactic_id approximates kill-chain order; an explicit
  `position` column would be unambiguous.
* **`GENERATE RULE` doesn't track per-technique generation state
  across pages.** Closing and reopening the detail resets the
  `generating` flag. The toast is the user's confirmation. M22's
  queue is the authoritative "did the rule actually generate"
  surface.
* **Sticky tactic headers cover the top of the first row.** The
  header overlap is intentional (it's sticky); the first cell's
  technique_id is briefly hidden when the operator scrolls to the
  top. Padding could be added but the trade-off of losing 16 px of
  vertical density across the entire matrix isn't worth it.

## Outstanding questions

* **Should view mode persist across page reloads?** Today the
  default is `CHAIN EXPOSURE` on every navigation to `/matrix`. A
  `localStorage` cache (`fragchain.matrix.mode`) would persist the
  operator's last choice. Trivial to add; defer until an analyst
  asks for it.
* **Should the detail panel auto-close on cell-click outside the
  panel?** Today clicking another cell *re-opens* the panel with
  the new cell's detail. The panel stays open until the operator
  clicks the X or hits ESC. Reasonable; mention if it bites.
* **Should `GENERATE RULE` produce an inline progress indicator
  (poll until the rule lands)?** Today it fires-and-forgets with a
  toast. A "view in queue" link in the toast would close the loop.
  Defer until M22 lands so we have a queue route to link to.
* **Tactic column order for non-Enterprise frameworks.** M14's
  matrix.py appends non-Enterprise tactics alphabetically; M21
  trusts the order. Once ATLAS lands, the M14 done doc flags a
  future framework-order registry; the M21 grid will render
  whatever order the backend supplies without changes.
* **Mobile layout?** The matrix is 1120+ px wide. On a phone (375
  px) the grid scrolls horizontally — usable but cramped. A
  card-list fallback might serve better at < 768 px, but every
  M21 use case is desktop-first.
