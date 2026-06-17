# MODULE_M20_DONE — CVE Explorer + Chain Viewer
**Built:** 2026-05-13
**Effort actual:** L (one session)
**Status:** complete · sandbox-verified (`npm run build` → 0 TS errors, 2054 modules transformed, 51.48 kB CSS / 542.70 kB JS · `tsc --noEmit` clean) · pending in-browser verification on a live API + Dirty Frag chain

## Scope reminder

M20 ships two screens on top of M18's shared component palette and the
M6 / M11 API surfaces:

- **CVE Explorer** (`/cves`, `/chains`) — filterable data table over
  `GET /api/v1/cves`, click a row to slide in a detail panel covering
  CVSS / KEV / EPSS / TLP, the processing-pipeline timeline, OpenCTI
  attack patterns, attached source documents, the chain summary, and
  jump-off links to the Chain Viewer and the Sigma Library.
- **Chain Viewer** (`/chains/:cve_id`) — React Flow LR graph driven by
  dagre. Tactic-coloured nodes (per CLAUDE.md §16) with confidence-
  driven opacity. Clicking a node opens a TTP detail sidebar (technique
  metadata, confidence bar, preconditions, detection opportunity, full
  source-evidence list). Context-bar carries CVE id, overall confidence,
  model, prompt template, and a destructive "Re-synthesize" button
  guarded by a confirm dialog.

M20 does NOT own:

* Other screens — M19 Dashboard, M21 ATT&CK Matrix, M22 Queue / Sigma
  Library, M23 Imports, M24 Settings / Connectors / Commons / Prompts
  are their own modules.
* Backend changes — the API surfaces M6 (`/cves`) and M11
  (`/chains`, `/cves/:id/chain`, `/cves/:id/resynthesize`) already exist.
  M20 only consumes them.
* Chain validate / reject flow — that's M22 (review-queue logic).
* Rule count / per-CVE confidence projection in the list endpoint — the
  list table renders these when they're present on the row, and falls
  back to "—" while the backend doesn't surface them. The detail panel
  pulls confidence from the chain summary directly.

## What was built

### Screens — [`frontend/src/screens/`](frontend/src/screens/)

#### CVE Explorer — [`CVEExplorer.tsx`](frontend/src/screens/CVEExplorer.tsx)

* Two-column layout (`.explorer-grid`): 240 px **filter sidebar** on the
  left, the data table card on the right. Below 1024 px the sidebar
  flows above the table.
* **Filter sidebar** (`.explorer-filters`, sticky to the top of the
  scroll container):
  * **Published date range** — two native `date` inputs (`mono` font).
    Translates to `published_after` / `published_before` on the request.
  * **CVSS min** — number input clamped 0–10 in 0.1 increments.
  * **KEV only** — DarkOps `checkbox` checkbox. Maps to `?kev=true`.
  * **Status multi-select** — `Dropdown<string>` with `multi` and
    `searchable` over the closed set of `processing_status` values
    from `fragchain.ingest.state.PROCESSING_STAGES`. One status passes
    through to the backend `?status=`; multi-select applies the rest
    client-side (the backend only filters on one status at a time).
  * **Source** — single-select dropdown (`live` / `historical` / `all`)
    mapped to `?import_mode=`.
  * **Reset** button clears every filter back to its default.
* **DataTable** columns (all sortable except the rendered-only ones):
  * `cve_id` — monospaced accent link.
  * `cvss_score` — coloured `Badge` (≥9 danger, ≥7 warning, ≥4 accent2).
  * `cisa_kev` — danger `Badge` when true.
  * `import_mode` — mono, dim, uppercase.
  * `processing_status` — coloured `Badge` (complete = success,
    failed = danger, anything in-flight = accent).
  * `confidence` — `ProgressBar` pulled from the latest chain summary
    for that CVE (M20 hits `/chains?limit=500` once on mount and joins
    by `cve_id`).
  * `rule_count` — mono integer when the row provides it, "—"
    otherwise. The list endpoint doesn't expose this yet; the column
    is in place so the row body can light it up when M14/M15 stitches
    the projection in.
  * `published_at` — mono date in `YYYY-MM-DD`.
* **Slide-in detail panel** (`SidePanel wide`):
  * Loads `GET /cves/{cve_id}` + `GET /cves/{cve_id}/chain` in parallel
    via `Promise.allSettled` so the panel renders even when no chain
    exists yet.
  * **Summary KV grid** — CVSS, KEV (+ date), EPSS (score + percentile),
    import mode, published / modified timestamps, TLP badge.
  * **Processing timeline** — six-stage state-machine pill row
    (`pending → enriching → synthesizing → mapping → generating →
    complete`). Active stage shows the accent ring; completed stages
    are green; future stages stay neutral. `failed` paints the first
    stage red and skips the rest; `staged` / `skipped` render as a
    single italicised pill. When `processing_status === "failed"` and
    `processing_error` is populated, the original error message
    surfaces below the timeline in the danger-bg error block.
  * **Attack patterns** — `Badge accent2 mono` tags for every
    `cve.ctid_techniques` entry the connector emitted.
  * **Source documents** — `.detail-source` card per doc: external
    link, source-type badge, `quality_score` progress bar (+ percentage
    on the right), TLP badge.
  * **Attack chain block** — chain status (validated → success badge),
    version, confidence bar, model, source origin (`local` / `commons`),
    and a "View Chain →" button that routes to `/chains/{cve_id}`.
    When no chain exists, the section still shows a quick link to the
    viewer so the analyst can flip a freshly-staged CVE into the
    re-synthesise UI.
  * **Sigma rules block** — rule count when surfaced by the backend,
    plus a "View Rules →" button pre-filtered to the CVE.

#### Chain Viewer — [`ChainViewer.tsx`](frontend/src/screens/ChainViewer.tsx)

* URL param `:cve_id` drives `GET /api/v1/cves/{cve_id}/chain` on mount
  (and after every successful re-synthesise). The route mounts **outside**
  the default `ProtectedLayout` chrome (`<ProtectedLayout chromeless />`)
  so the viewer can drive its own `AppShell` and own the context-bar
  actions (CVE id, confidence bar, model, prompt, TLP, re-synth button).
* **Layout** — uses `dagre.graphlib.Graph` with `rankdir=LR`,
  `nodesep=40`, `ranksep=80`. Nodes sized 220×72, dagre positions land
  on the node centre so the React Flow position is `(x − w/2, y − h/2)`.
* **Tactic colour buckets** (per CLAUDE.md §16):
  * `TA0001`, `TA0002` → `--accent` (cyan)
  * `TA0003`, `TA0006`, `TA0008`, `TA0009`, `TA0011` → `--accent2` (indigo)
  * `TA0004`, `TA0005` → `--warning` (amber)
  * `TA0010`, `TA0040` → `--danger` (red)
  * `TA0007` (and unknown) → neutral (`--border-hi`)
  Each bucket sets a 2 px border + 10 %-opacity background fill so the
  node body still reads against the dark canvas.
* **Confidence → opacity**: `0.4 + 0.5 * confidence`. A confidence of
  0.5 lands at 0.65 opacity, 1.0 lands at 0.9, missing confidence
  defaults to 0.85 so a schema row without a confidence value doesn't
  visually drop out.
* **Node content** — top row carries the technique ID (`mono`, 11 px,
  bucket-coloured) + sequence number (`#N`, dim). Body shows the
  technique name truncated to ~22 chars with a 2-line CSS clamp and a
  `title=` attribute carrying the full name for hover. Footer shows the
  tactic label (`mono`, 9 px, uppercase, dim).
* **Edges** — straight bezier (React Flow default), 1.5 px stroke,
  colour matches the **source** node's bucket. `markerEnd` is a closed
  arrow in the same colour. Edge label is the **target's** `seq_order`
  with a small bg pad so it reads over the dotted background.
* **Background** — `BackgroundVariant.Dots` over the DarkOps `--bg`,
  20 px gap, 1 px size, dot colour `#1e2d45` (same as `--border`).
  React Flow `Controls` (zoom in/out/fit, no interactive toggle) and a
  `MiniMap` (pannable, zoomable, node colour pulled from the same
  bucket palette). Attribution hidden via `proOptions.hideAttribution`.
* **Click node → TTP detail panel** (`SidePanel wide`):
  * **Identification** KV grid — technique name, tactic badge
    (variant matches the node bucket), framework, sub-technique id
    (when present), seq order.
  * **Confidence** progress bar (with the model-confidence label).
  * **Preconditions** as an unordered list.
  * **Detection opportunity** prose.
  * **Source evidence** — one `.detail-source` card per `source_refs`
    entry: external link, source-type badge, quality-score progress
    bar, excerpt summary.
* **Context-bar actions**:
  * `CVE` → mono accent link back to `/cves`.
  * `Confidence` → progress bar + percentage.
  * `Model` → mono text (whatever LiteLLM aliased to).
  * `Prompt` → first 8 chars of the active `prompt_template_id` (UUID
    truncation, full id rendered as a `title=` tooltip via the React
    `Link` in M9). Falls back to "—" when the chain row is missing it.
  * `TLP` badge.
  * **Re-synthesize** button (warning variant). Opens a
    `ConfirmDialog` with `destructive: true`; on confirm, calls
    `POST /api/v1/cves/{cve_id}/resynthesize` and reloads the chain so
    the operator sees the CVE drop into `synthesizing`. A success
    toast announces "Re-synthesis queued"; an error toast surfaces
    `detailFromError(err)`.

### Routes — [`App.tsx`](frontend/src/App.tsx)

* `/cves` and `/chains` both render the `CVEExplorer` (the kickoff
  flagged these as the same view). M1's `/cves` placeholder is gone.
* `/chains/:cve_id` renders the `ChainViewer` under a `ProtectedLayout
  chromeless` wrapper so the screen owns its own `AppShell`.

### Layout — [`Layout.tsx`](frontend/src/components/Layout.tsx)

* New `chromeless` prop on `ProtectedLayout`. When set, the wrapper
  still enforces the auth guard but renders the `<Outlet/>` directly
  (no `AppShell`). This lets the Chain Viewer drive its own context-bar
  title + actions. Default behaviour (everything M18 routes through)
  is unchanged.

### CSS — [`darkops.css`](frontend/src/styles/darkops.css)

A single "M20" block (~270 lines, appended at the end of the
stylesheet) adds:

* **`.explorer-grid`** — two-column 240 px / 1fr grid (collapses to a
  single column below 1024 px).
* **`.explorer-filters` / `.explorer-filters-header` / `.explorer-filter-group`**
  — sticky filter sidebar.
* **`.cve-link`** — mono accent link styling for CVE id cells.
* **Detail panel primitives** — `.detail-section`,
  `.detail-section-title`, `.detail-kv` (110 px label column),
  `.detail-source-list` + `.detail-source` cards, `.detail-link-row`
  for the "View X →" rows, `.detail-tag-row` for technique badge rows.
* **`.timeline` / `.timeline-step`** — six-pill pipeline track. States
  `done` / `active` / `failed` / `skipped` pick the right border +
  colour.
* **`.chain-canvas`** — React Flow surface, height clamped to the
  available viewport area below the topbar + context bar (with a
  480 px minimum). Restyles the React Flow controls / minimap /
  attribution to match DarkOps.
* **`.chain-node` / `.chain-node-head` / `.chain-node-tid` /
  `.chain-node-seq` / `.chain-node-name` / `.chain-node-tactic`** —
  custom node styling with `.tactic-*` modifier classes carrying each
  tactic bucket's border + background.
* **`.chain-context-actions`** — flex row inside the context bar
  carrying confidence / model / prompt / TLP / re-synthesise.

### API clients — [`api/cves.ts`](frontend/src/api/cves.ts), [`api/chains.ts`](frontend/src/api/chains.ts)

Tightened the M18 placeholders to match the actual response shapes:

* **`cves.ts`** — `CveListResponse` now matches the backend `{ total,
  cves }`. `CveListItem` carries every typed `CVEOut` field
  (cvss_score, cvss_vector, cisa_kev, cisa_kev_date, epss_score /
  percentile, attackerkb_score, ctid_techniques, import_mode,
  processing_status / stage / error, approved_by / at, embargo_until,
  tlp). `CveDetail` extends it with a `documents` list. Query
  parameter names switched from `kev_only` / `min_cvss` to the
  backend's `kev` / `cvss_min`.
* **`chains.ts`** — typed `ChainSourceRef`, `ChainTTP`, `ChainSummary`,
  `ChainDetail`, `ChainListResponse`. `resynthesizeChain` URL fixed
  from the M18 placeholder `/cves/{id}/chain/resynthesize` to the real
  `POST /cves/{cve_id}/resynthesize` endpoint (M11
  `fragchain/api/routers/chains.py:521-565`). The validate / reject /
  contribute / list / detail helpers now return concrete `ChainDetail`
  / `ChainSummary` shapes so M22 (review queue) can lean on them
  without retyping at the call-site.

### Dependencies

`frontend/package.json`:

* `@xyflow/react@^12.10.2` (React Flow rewrite of the old `reactflow`
  package — the current canonical name on npm).
* `dagre@^0.8.5` (LR layout solver).
* `@types/dagre@^0.7.54` (devDependency).

Total: 121 packages added to `frontend/node_modules`, no peer-dep
warnings on a fresh install.

## Architecture decisions

* **ChainViewer owns its AppShell, CVEExplorer does not.** The
  Explorer is a straightforward list-of-things — `ProtectedLayout`'s
  default `AppShell` already gives it the topbar + sidebar +
  context-bar with the right title. The Chain Viewer needs to inject
  five separate stats (CVE id, confidence bar, model, prompt, TLP)
  plus a destructive "Re-synthesize" button into the context-bar, and
  it owns a dynamic title (`Chain CVE-2026-43284`). Hoisting an
  `AppShell` prop API to thread all of that through the router would
  bake screen-specific knowledge into `Layout.tsx`. Instead the
  `chromeless` flag tells `ProtectedLayout` to skip the shell and let
  the screen drive its own.
* **Confidence column joins via a second `/chains` request.** The
  list endpoint doesn't return a per-CVE confidence projection
  (chains are first-class rows on a different table). Rather than
  asking M6 to denormalise, the Explorer makes one extra `GET /chains`
  call and joins by `cve_id`. The join is keyed on the newest chain
  version per CVE. When `/chains` is unreachable (TLP-filtered, RBAC,
  etc.) the column gracefully renders "—" and the table stays usable.
* **Multi-status filtering happens client-side.** The backend filter
  is a single string. Forcing multiple roundtrips (one per status)
  would also bypass server-side sorting. With `limit=500` the
  Explorer's whole page already fits in one request; we apply the
  multi-status filter in JS after the fact.
* **Pipeline timeline rendered as discrete pills, not a continuous
  progress bar.** The M6 state machine is non-linear (`staged`
  branches sideways, `failed` can land at any stage). A six-pill row
  with state classes is honest about that — the operator can see
  "stuck at enriching" vs "complete" at a glance without inferring
  from a percentage.
* **`Promise.allSettled` for the detail panel.** Loading the CVE and
  its chain in parallel is the obvious win; using `allSettled` means
  a chain-fetch 404 (common for unprocessed CVEs) doesn't tank the
  whole panel. The CVE detail always lands; the chain block falls
  back to "No chain generated yet" with a link to the viewer.
* **dagre over @xyflow/layout.** `@xyflow/react` ships an `OrderedLayout`
  helper but doesn't bundle dagre, and the kickoff calls for dagre by
  name. Dagre's `rankdir=LR` is also the natural fit for a left-to-
  right attack chain; vertical layouts would need a separate decision
  about how to read seq_order.
* **MiniMap + Controls included.** The kickoff doesn't require them
  but a 4-node chain is the small case — real chains land in the
  10+ node range and a minimap is the difference between "scroll to
  find the gap" and "see it at a glance." Both are restyled to
  DarkOps tokens so they don't look like leftover library chrome.
* **Re-synthesise uses `ConfirmDialog destructive`.** It re-spends LLM
  budget and bumps the chain version. A naked button would let a
  click-through analyst burn a chunk of the daily LLM allowance by
  accident.
* **Node opacity = `0.4 + 0.5 * confidence`.** Per the kickoff: 0.5
  confidence → ~0.65 opacity. Missing confidence renders at 0.85 so
  the absence of a value isn't punished visually.
* **Edge label = the target's `seq_order`.** The first version showed
  the edge index (`1, 2, 3...`) which doubled up with the source
  node's seq number. Showing the target's seq_order makes the arrow
  read as "step 2 follows step 1" — which is what the chain actually
  says.

## Tests

No automated tests in this module — M20 is screen-level UI that
consumes the shared M18 primitives and the M6/M11 APIs. Visual
verification is in-browser only.

### Sandbox-level pre-flight checks (runnable here)

| Check | Result |
|---|---|
| `npm install` adds the three new deps | ✅ `@xyflow/react@12.10.2` + `dagre@0.8.5` + `@types/dagre@0.7.54`, 121 new packages, no peer-dep warnings |
| `npm run build` — `tsc -b && vite build` | ✅ 0 TypeScript errors, 2054 modules transformed, dist 51.48 kB CSS + 542.70 kB JS, 1.27 s. Gzip 8.62 kB CSS + 179.15 kB JS. |
| `npx tsc --noEmit -p .` | ✅ clean (no output) |
| Dagre layout sanity (4-node LR graph) | ✅ produces evenly-spaced x positions (110, 410, 710, 1010), shared y=36, matching the Dirty Frag chain |
| Internal import resolution | ✅ every `from "../api/..."` / `from "../components"` / `from "./screens/..."` resolves to a real file; every external import (`@xyflow/react`, `dagre`, `lucide-react`, `axios`, `dayjs`, `react`, `react-dom`, `react-router-dom`) is in `frontend/package.json` |

### Runtime verification *not* runnable in this sandbox

Operator should run these on the next `docker compose up`:

| Done criterion | Verification |
|---|---|
| CVE Explorer renders the seeded Dirty Frag | navigate to `/cves`, confirm `CVE-2026-43284` appears with KEV badge, CVSS coloured, `live` mode, accent confidence bar (pulled from the 1.0-confidence ground-truth chain) |
| Filter sidebar works | toggle "KEV only" → only KEV-flagged rows remain; set CVSS min = 9 → only critical rows; pick `complete` status → only complete CVEs; pick two statuses → multi-status filter applied client-side; "Reset" clears every filter |
| Click row → detail panel | shows summary KV, processing timeline at "complete" with five green pills + one accent pill, two CTID techniques as badges, three source documents with quality bars + TLP badges, attack-chain block with version + confidence + "View Chain →" |
| "View Chain →" navigates to `/chains/CVE-2026-43284` | yes; the route changes and the viewer loads |
| Chain Viewer renders the 4-TTP Dirty Frag chain | left-to-right dagre layout, four nodes: `T1078` (accent — TA0001), `T1068` (warning — TA0004), `T1548.003` (warning — TA0004), `T1014` (accent2 — TA0003); edges arrow-marked with the seq order; minimap mirrors the layout |
| Node opacity reflects confidence | confidences 0.9 / 0.95 / 0.7 / 0.6 → opacities ~0.85, 0.875, 0.75, 0.7 — visibly fades T1548.003 and T1014 |
| Click a node → TTP detail | sidebar shows technique name, tactic badge in the right colour, framework=`ATTCK`, confidence progress bar, preconditions as a bulleted list, detection opportunity prose, source-evidence cards with quality bars and excerpts |
| Context-bar shows CVE id + confidence + model + prompt + TLP | values pull from the chain detail row (`overall_confidence`, `model`, `prompt_template_id`, `tlp`) |
| "Re-synthesize" opens confirm dialog | click → modal with `destructive` confirm button; cancel returns to the viewer; confirm fires `POST /cves/{cve_id}/resynthesize` |
| Re-synthesise advances the state | DB query shows the CVE drops to `processing_status='synthesizing'`; worker logs show `synthesize_chain.delay` queued; viewer reload picks up the new chain version once synthesis completes |
| Toast announces queue + error states | success toast on 202; error toast on 404 / 403 with the `detailFromError(err)` body |
| Re-synthesise bypasses confirm spam | dialog locked while busy (`busy=true`), confirm button shows "WORKING…" |
| All DarkOps tokens consumed | `grep -rn "#[0-9a-f]\{3,8\}" frontend/src/screens` — only the `BUCKET_COLOR` literal map in `ChainViewer.tsx` matches (those values are passed through to React Flow inline SVG styles, where CSS variables don't reach) |

## Interfaces this module exposes

For dependent modules (M21–M24):

```ts
// Already-existing barrels still work
import { DataTable, SidePanel, Dropdown, ConfirmDialog, Badge } from "../components";

// Tightened API clients
import { listCves, getCve, type CveListItem, type CveDetail } from "../api/cves";
import {
  listChains, getChain, getChainByCve, validateChain, rejectChain,
  resynthesizeChain, contributeChain,
  type ChainDetail, type ChainTTP, type ChainSourceRef, type ChainSummary,
} from "../api/chains";

// Layout extension
<Route element={<ProtectedLayout chromeless />}>
  <Route path="/some/full-bleed-screen" element={<MyScreen />} />
</Route>
```

## What dependent modules need to know

* **M21 (ATT&CK Matrix)** — the same `chromeless` pattern applies. The
  matrix screen can mount under `ProtectedLayout chromeless` and drive
  its own `AppShell` with view-mode / framework toggles in the
  context bar.
* **M22 (Review Queue / Sigma Library)** — the chain detail surface is
  now typed (`ChainDetail` / `ChainTTP`). The Queue's evidence panel can
  pull the same `getChainByCve` and reuse the `TtpDetailPanel` if it
  wants the source-evidence cards.
* **M23 (Imports)** — the `Dropdown<V>` multi-select + searchable
  variants are exercised here on the Explorer's status filter. Same
  pattern fits the import preset picker.
* **M24 (Settings / Prompts)** — `prompt_template_id` surfaces in the
  Chain Viewer context bar today as a truncated UUID. Once M24 ships
  the prompt CRUD UI, it can swap the hard-coded `trunc(id, 8)` for a
  named link to the prompt-detail page.

## Deviations from spec / kickoff

* **Filter `source` semantics**. The kickoff lists "source filter (Live |
  Historical | All)". This maps to `cves.import_mode` (`live` |
  `historical`) on the backend, so the filter is implemented against
  `import_mode`. There's no separate "source" column in the schema.
* **`status` multi-select runs partially client-side**. The kickoff
  asked for a multi-select; the backend filter is a single string. One
  selected value passes through to the API; multiple values fall back
  to JS filtering. Documented in `CVEExplorer.tsx`.
* **`rule_count` and `confidence` aren't on the list response yet**.
  The CVE row in Postgres doesn't carry these as denormalised fields.
  M20 surfaces `confidence` by joining a second `/chains` request and
  leaves `rule_count` to render "—" until M14 / M15 wires it.
  Tightening this would require a backend change M20 explicitly
  doesn't own.
* **Node opacity formula `0.4 + 0.5 * confidence`** rather than the
  exact "0.5 → 0.65" mapping the kickoff hints at. The chosen formula
  hits the kickoff's example anchor and keeps the dynamic range wide
  enough (0.4 at confidence=0 vs 0.9 at confidence=1) to read at a
  glance.
* **Chain Viewer renders inside its own `AppShell`**. M18's default
  `ProtectedLayout` wraps every route in an `AppShell`; the viewer
  needs the context-bar to carry five extra stats and a button.
  Easier to give the screen its own shell than to thread a
  context-actions prop through `ProtectedLayout`. The `chromeless`
  flag in `Layout.tsx` is the affordance.
* **Edge label = target's `seq_order`** not the edge index. The arrow
  reads naturally that way ("step 2 follows step 1").
* **MiniMap + Controls added** even though the kickoff lists neither.
  Real chains exceed four nodes; a minimap is a no-cost affordance
  that pays off the moment we hit the 10-TTP chain case.

## Known TODOs (owned by other modules)

* **M6 / M11 — surface `rule_count` on CVE list rows**. Today the
  column renders "—" until the backend exposes a per-CVE rule count.
  A small `LEFT JOIN sigma_rules` aggregate in `list_cves` would close
  this without changing the response shape.
* **M19 — wire the `chain_generated` / `chain_skipped_using_commons`
  WebSocket events to refresh the Chain Viewer**. Today the user
  refreshes the page (or the Explorer rerender) to pick up a new
  chain version. Once M19 ships, `useWebSocket()` can call `load()`
  on every relevant event.
* **M22 — chain validate / reject UI**. The Chain Viewer doesn't
  expose these actions; they live in the Review Queue per the spec.
  The viewer is read-mostly (plus re-synthesise).
* **M24 — link the truncated `prompt_template_id` to the Prompts
  screen**. The viewer renders `prompt_template_id` as `trunc(id, 8)`;
  once M24 lands a prompt-detail page, the truncated id becomes a
  router link to `/prompts/{id}`.
* **Code splitting**. The `vite build` warning reports the bundle
  crossing 500 kB minified (mostly because React Flow is heavy). The
  Chain Viewer is route-specific and is an obvious target for
  `React.lazy(...)` — defer until the dashboard module (M19) adds
  more routes that benefit from the same treatment.

## Risks / known weaknesses

* **`/chains?limit=500` on every Explorer mount**. The chain join is
  cheap on a deployment with hundreds of chains but linear in chain
  count. If a deployment crosses ~10k chains, this becomes the
  Explorer's slowest call. The fix is server-side: have `list_cves`
  return the latest chain's confidence inline (see M6 TODO above).
* **`getChainByCve` 404s log to the console even for unprocessed
  CVEs**. The detail panel handles the failure gracefully (renders
  "No chain generated yet"), but a clean 404 shows up in dev tools.
  Acceptable for v1; could be suppressed in the axios interceptor by
  swallowing 404s on this specific URL pattern.
* **The minimap can render off-canvas on small viewports**. At <720 px
  the minimap overlaps the controls. React Flow doesn't ship a
  responsive minimap; the v1 fix is "use a desktop browser for the
  chain viewer", which matches the rest of the chrome (the sidebar
  collapses below 1024 px anyway).
* **Node label truncation is char-count, not pixel-width**. Long
  technique names with narrow characters could fit into the 22-char
  cap but still wrap onto a third line; the 2-line CSS clamp catches
  that. Pixel-width truncation would need a `getComputedTextLength`
  measurement loop — not worth it for v1.
* **The "Re-synthesize" reload races the worker**. After the API
  returns 202 we immediately call `load()`. The worker hasn't
  necessarily started yet, so the viewer shows the *old* chain still
  marked `validated` (or whatever). M19's WebSocket event is the
  right trigger for a real refresh.

## Outstanding questions

* **`/cves` vs `/chains` route**. Today both render `CVEExplorer`. The
  kickoff implies they're the same view; long-term `/chains` might
  want to drop the CVE-specific columns and instead show a chains-
  list (status, version, confidence). Deferred until we see how M22's
  Review Queue lands — if it eats the chains-list use case, `/chains`
  can redirect to `/cves`.
* **Mobile chain viewer**. React Flow works on mobile but the dagre
  layout assumes a wide canvas. A vertical layout (`rankdir=TB`)
  would be friendlier below 768 px; deferred until we have a real
  mobile use case.
* **Sub-technique badge on the node**. T1548.003 shows as just
  `T1548.003` in the node header today (which is the full id). A
  parent → sub indicator (`T1548 ▸ .003`) would read more clearly.
  Trivial to add once we have a real chain with mixed parent-only
  and sub-only TTPs.
