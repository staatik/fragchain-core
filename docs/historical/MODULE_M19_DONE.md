# MODULE_M19_DONE — Dashboard
**Built:** 2026-05-13
**Effort actual:** M (one session)
**Status:** complete · sandbox-verified (`npm run build` → 0 TS errors, 2060 modules transformed, 58.72 kB CSS / 560.48 kB JS · AST parse on every new/edited Python file) · pending in-browser verification on a live API + worker pipeline

## Scope reminder

M19 is the operator's home screen — a single view that fuses every
upstream module's state into something an analyst can read in five
seconds:

* **5-block stat row** — CVEs / 24 h, Sigma coverage %, Pending review,
  KEV gaps, Staged CVEs.
* **Abbreviated ATT&CK heatmap** — 14 tactic columns × top 8 techniques
  each, coloured by `coverage_status`, KEV-exposed cells pulse red.
* **Review-queue preview** — top 5 pending items sorted by
  `priority_score DESC`.
* **KEV gap list** — up to 5 KEV-exposed gap/no_data techniques with
  their attached CVEs.
* **Live event feed** — last 8 events streamed through the in-process
  bus over `/ws/events`. New events slide in from the top.

The kickoff also implicitly required the server-side `/ws/events`
WebSocket route (M18's known-TODO `M19 — /ws/events server-side
endpoint`). M19 ships it.

M19 does NOT own:

* Other screens — M21 Matrix, M22 Queue/Library, M23 Imports, M24
  Settings/Connectors/Commons/Prompts ship their own modules.
* New HTTP routes — the dashboard consumes only the existing M6 / M11
  / M14 / M16 endpoints.
* Notification delivery (M36) — the topbar bell still has no live data
  feed; the WebSocket only powers the dashboard's event feed today.
* Sidebar live count badges — the Sidebar's `7` / `A/B` placeholders
  stay for M19; wiring them via a `useQueueCount()` hook is M22-or-later
  work since it touches the shared chrome.

## What was built

### Backend — `/ws/events` WebSocket

[fragchain/api/routers/websocket.py](fragchain/api/routers/websocket.py)
ships the WebSocket subscriber every prior module has been emitting
into without a destination. Behaviour:

* **Auth via `?token=<JWT>`** — browsers can't set
  `Authorization` headers on a WebSocket handshake. The handler
  decodes the JWT through the same
  :func:`fragchain.api.security.decode_jwt` that backs the HTTP
  middleware. Missing/invalid token → close 1008 (policy violation).
  Bearer header is honoured as a fallback for non-browser clients.
* **Subscribes a fresh queue** through
  :func:`fragchain.notifications.get_bus().subscribe()` and forwards
  every event to the socket as `event.to_json()`.
* **Three cooperating tasks**:
  * `_pump` — drains the event queue.
  * `_keepalive` — emits a `{"type":"ping"}` frame every 15 s so a
    silent server doesn't look dead to nginx / Cloudflare timeouts.
  * `_drain_inbound` — consumes any inbound frames so Starlette can
    raise :class:`WebSocketDisconnect` cleanly when the client closes.
* **`asyncio.wait(..., return_when=FIRST_COMPLETED)`** — the first
  task to finish (disconnect, ping write failure, queue drop) tears
  down the other two. Cancelled tasks are skipped during exception
  inspection so a clean close doesn't surface as a warning log.
* **Unsubscribe in `finally`** — the bus's subscriber set never grows
  unbounded; a slow consumer just loses events (the bus's
  `QueueFull` branch already logs them).

[fragchain/api/main.py](fragchain/api/main.py) registers the router
at the **root** (no `/api/v1` prefix) so the frontend's default URL
(`useWebSocket` resolves `/ws/events`) lands here.

### Frontend — Dashboard screen

[frontend/src/screens/Dashboard.tsx](frontend/src/screens/Dashboard.tsx)
is one file (~640 LOC) that drives the entire screen.

#### Stat grid (5 blocks)

Five `<StatBlock>` cards inside a `<StatGrid>` row:

| Block | Source | Click | Color rule |
|---|---|---|---|
| **CVEs / 24 h** | `listCves({ published_after: now-24h, limit: 500 })`, reads `total` | `/cves` | accent when > 0 |
| **Sigma coverage** | `listCoverage()`, computes `(covered + 0.5 × partial) / total` | `/matrix` | success ≥60%, warning ≥30%, danger else |
| **Pending review** | `listQueue({ status: "pending", limit: 500 })`, reads `total` | `/queue` | warning when > 0 |
| **KEV gaps** | `listCoverage()`, counts rows where `kev_exposed && (status='gap'|'no_data')` | `/matrix` | danger when > 0 |
| **Staged CVEs** | `listCves({ status: "staged", limit: 500 })`, reads `total` + KEV count | `/imports` | accent when > 0; delta shows KEV count |

Stats reload on mount and on every event in `STATS_REFRESH_EVENTS`
(see WebSocket section).

#### Mini ATT&CK heatmap

* `fetchMatrix()` against `GET /api/v1/matrix` (M14 cache, ~ms).
* Render: one column per `MatrixTactic`, **top 8 top-level
  techniques per column** (no sub-techniques). Ranking key:
  `kev_exposed → chain_cve_count → covering_rule_count →
  technique_id`.
* Each cell is a `<button>` styled by `coverage_status` (covered →
  green, partial → amber, gap → red, no_data → neutral) with a KEV
  pulsing outline (CSS `@keyframes kev-pulse`).
* Click → `navigate('/matrix?technique=<id>')`. The Matrix screen
  (M21) reads the query param to pre-select the cell when it lands.
* Horizontal scroll on overflow; legend row below summarises the
  colour scheme.

#### Review queue preview

* `listQueue({ status: "pending", limit: 5 })`.
* Each row: priority badge (`priority_score`, variant by threshold),
  CVE id (mono, accent), first `technique_id`, `dayjs.fromNow()` for
  age, clickable to `/queue`.
* Empty state when no pending items.

#### KEV gap list (max 5)

* Primary fetch: `listCoverage({ kev_only: true })`.
* Filter to gap/no_data, sort by `kev_cve_count DESC`, take top 5.
* For each technique: `fetchTechniqueCoverage(id)` (one call per
  card — at most 5 lightweight requests) to surface the actual
  KEV CVE ids + CVSS scores.
* Banner above the list when `staged_kev_count > 0`:
  > "N KEV CVEs staged and awaiting approval" + "Review imports →"
* Click the technique id → `/matrix?technique=<id>`; click a CVE
  badge → `/cves`.

#### Live event feed

* `useWebSocket()` against the new `/ws/events` route (filter drops
  `ping` frames).
* Last 8 events, newest first. Each fresh event renders with the
  `feed-slide-in` animation (320 ms ease-out from `-6px` /
  `opacity: 0`) and an accent-tinted background that fades back to
  the default after 600 ms.
* Per-event:
  * Coloured dot (`feedDotClass`) — accent2 for queue events,
    success for chain/coverage, danger for rate-limit warnings.
  * Human summary (`feedSummary`) — e.g. "Chain generated for
    CVE-2026-43284", "Generated 4 Sigma rules", "Queue item
    approved".
  * Event type pill (mono, micro, dim).
  * `HH:mm:ss` timestamp.
* Some events trigger targeted reloads:
  * `STATS_REFRESH_EVENTS` (cve_ingested, enrichment_complete, every
    chain / coverage / rules event, queue lifecycle, import staged)
    → re-fetch stats.
  * Queue lifecycle events → re-fetch the queue preview.
  * Coverage / rules events → re-fetch the heatmap and the KEV gap
    list.

#### Error handling

Each section has its own banner + retry button. A stats failure
doesn't blank the heatmap; an empty coverage matrix doesn't blank
the queue preview.

### CSS — [darkops.css](frontend/src/styles/darkops.css) (M19 block, ~280 lines appended)

* `.dashboard-grid` — vertical stack of sections.
* `.dashboard-banner` (+ `.danger` / `.warning`) — coloured inline
  banner used for error rows + the staged-KEV alert.
* `.dashboard-main` — two-column 1fr × 360 px grid that collapses to
  one column below 1180 px.
* `.dashboard-side` — vertical stack housing the queue preview and
  the event feed.
* **Heatmap**: `.heatmap-scroll`, `.heatmap-columns`, `.heatmap-col`,
  `.heatmap-col-head`, `.heatmap-cells`, `.heatmap-cell` with
  `.covered` / `.partial` / `.gap` / `.no_data` / `.kev` modifiers.
  KEV cells pulse via `@keyframes kev-pulse` (2.4 s ease-in-out).
  `.heatmap-legend` + `.legend-swatch` for the colour key row.
* **Queue preview**: `.queue-preview-list / .queue-preview-row`.
* **Event feed**: `.event-feed`, `.event-feed-link`, `.event-feed-dot`
  (with `accent` / `accent2` / `success` / `warning` / `danger`
  variants), `.event-feed-summary`, `.event-feed-type`,
  `.event-feed-time`. Fresh-event animation:
  `@keyframes feed-slide-in`.
* **KEV gaps**: `.kev-gap-list` (auto-fit grid), `.kev-gap-card`
  (danger-bordered, danger-bg-tinted), `.kev-gap-tactic`,
  `.kev-gap-tech`, `.kev-gap-cves`, `.kev-gap-cve`, `.kev-gap-more`.

Every selector consumes existing DarkOps tokens — no hardcoded
colours, no inline `style={{ color: '#...' }}` for theming. The
only `style=` usages thread CSS variables through
(`color: tacticColor(tac.tactic_id)`).

### Frontend API tightening — [api/matrix.ts](frontend/src/api/matrix.ts)

The M18 placeholder shape (`tactics: [...{ technique_ids: string[] }]`,
`cells: Record<string, MatrixCell>`) didn't match the backend's
real `MatrixData` payload — the actual shape is tactics → techniques
with `tactic_id`, `tactic_name`, `coverage_status`, `kev_exposed`,
etc. The placeholder was a forward declaration; M19 is the first
real consumer, so I rewrote `matrix.ts` against the backend
contract:

* `MatrixCell`, `MatrixTactic`, `MatrixSummary`, `MatrixResponse`
  now match `fragchain/coverage/matrix.py:MatrixData.to_dict()`.
* `MatrixParams` carries `framework`, `cve_id`, `date_from`,
  `date_to`, `cvss_min`, `kev_only`, `tactic_id` — the exact query
  parameters the backend reads.
* New `CoverageRow` + `CoverageListResponse` types and a
  `listCoverage(params)` helper that hits `GET /api/v1/coverage`
  (the flat-list endpoint M19 uses for the coverage % and KEV-gap
  counts).
* `fetchTechniqueCoverage(id)` and `recomputeMatrix()` kept their
  M18 surface.

The M21 Matrix screen (next module) gets a tightened type to lean
on instead of fan-out refactoring M19 once it starts.

### Routing — [App.tsx](frontend/src/App.tsx)

The `Dashboard` import was moved off the `Placeholders` module and
onto the new `screens/Dashboard` so the existing `/dashboard` route
renders the real screen. The Placeholders `Dashboard` shell is
removed.

## Architecture decisions

* **`/ws/events` lives at the root, not under `/api/v1`.** Matches
  the frontend's default URL (`useWebSocket` resolves `/ws/events`).
  Putting it under `/api/v1/ws/events` would have forced a
  config-knob in `useWebSocket` and a doc note for operators
  reverse-proxying the route. The route's auth model is identical
  to the HTTP routers (JWT in `?token=`).
* **`asyncio.wait(..., FIRST_COMPLETED)`, not `FIRST_EXCEPTION`.**
  The drain task raises `WebSocketDisconnect` on client close,
  which `FIRST_EXCEPTION` would catch — but a normal `await
  websocket.close()` from the server side (e.g. the ping write
  fails because the socket buffer is wedged) doesn't raise an
  exception, it just returns. `FIRST_COMPLETED` handles both cases.
* **15 s keepalive ping, not 30 or 60.** nginx defaults to a 60 s
  idle timeout on proxied WebSockets; a 30 s ping leaves a thin
  margin. 15 s is the same cadence the in-process bus warns about
  if a subscriber falls behind, so it doubles as a fast-feedback
  probe.
* **Top-level techniques only in the heatmap.** Sub-techniques
  would push the column count past 8 (Dirty Frag's `T1548.003`
  would be one of the top entries on TA0004). The Matrix screen
  (M21) gets the full breakdown; the dashboard is a 5-second
  glance.
* **Ranking: KEV first, chain count second.** A KEV-exposed gap is
  the operator's actual job-to-do. Putting it at the top of every
  tactic column means the abbreviated heatmap surfaces the work
  before the operator has to scroll.
* **One `fetchTechniqueCoverage(id)` per KEV gap card.** Five extra
  requests, all hitting the cache. Adding a "show me the CVEs
  behind every KEV gap row" projection to `GET /coverage` would
  bloat the list endpoint for every other consumer. The dashboard
  is the only screen that wants this fan-out, and at N=5 it's
  negligible.
* **WebSocket event → targeted reload, not full refresh.** Three
  granularity buckets:
  * Stats events (cve / chain / coverage / rules / queue / import)
    reload stats only.
  * Queue-lifecycle events reload the queue preview only.
  * Coverage / rules events also reload the heatmap + KEV gaps.

  This avoids a `chain_generated` event triggering a full matrix
  re-fetch for the 280-cell payload when only the queue and stats
  rows are affected.
* **Fresh-event animation lives on the `<li>`, not the `<Link>`.**
  React Router's `<Link>` doesn't take a `className` change without
  a re-mount, so I move the `fresh` modifier up one level. The
  animation also fades the background tint back to default after
  600 ms via a `setTimeout` that mutates the event record in
  state — no CSS animation-end listener needed.
* **`coverage %` uses `(covered + 0.5 × partial) / total`.** Pure
  coverage % would punish partials too hard; 50 % weight for
  partial matches the "rule exists but doesn't fully cover the
  technique" intuition. Same heuristic the M14 mapper records when
  it logs partial coverage; consistent across the platform.
* **Banner above KEV gaps, not over the whole screen.** A staged
  KEV CVE is an action item ("approve the import"); putting it
  inside the KEV-gap card keeps it next to the related context
  rather than a global notification banner that gets dismissed +
  ignored.

## Tests

No automated tests in this module — M19 is screen-level UI on top
of M18's shared primitives + M6 / M11 / M14 / M16 backends. Visual
verification is in-browser only.

### Sandbox-level pre-flight checks (runnable here)

| Check | Result |
|---|---|
| `npm install` adds no new deps (uses existing palette) | ✅ 120 packages restored, no peer-dep warnings |
| `npm run build` — `tsc -b && vite build` | ✅ 0 TS errors, 2060 modules transformed, dist 58.72 kB CSS + 560.48 kB JS, 1.34 s |
| `npx tsc --noEmit -p .` from `frontend/` | ✅ clean (no output) |
| AST parse on every new / edited Python file (websocket.py, main.py) | ✅ no syntax errors |
| Internal import resolution | ✅ every `from "../api/..."` / `from "../components"` / `from "../hooks/useWebSocket"` resolves to a real file; no dynamic-import chunk warning |
| DarkOps token usage | ✅ every `.dashboard-*` / `.heatmap-*` / `.event-feed-*` / `.kev-gap-*` rule reads from CSS variables; no inline hex literals in `Dashboard.tsx` (the `TACTIC_COLOR_BY_ID` map uses CSS `var(--accent)` etc.) |

### Runtime verification *not* runnable in this sandbox

Operator should run these on the next `docker compose up`:

| Done criterion | Verification |
|---|---|
| All 5 stats display real data | navigate to `/dashboard`; confirm `CVEs / 24 h ≥ 0`, `Sigma coverage = (covered + 0.5×partial) / total` percentage, `Pending review = COUNT(*) FROM review_queue WHERE status='pending'`, `KEV gaps = COUNT(*) FROM coverage_map WHERE kev_exposed AND coverage_status IN ('gap','no_data')`, `Staged CVEs = COUNT(*) FROM cves WHERE processing_status='staged'`. With seeded Dirty Frag and the M11 chain, expect `CVEs / 24h ≥ 1` and at least one entry in the queue. |
| Stats refresh via WebSocket | trigger a `chain_generated` event (`POST /api/v1/cves/CVE-2026-43284/resynthesize`) → wait for the worker to finish → the stat row reloads without a hard page reload. The event also appears in the live feed within ~500 ms. |
| Heatmap renders | confirm 14 tactic columns × ≤ 8 techniques each. Dirty Frag's techniques (T1078, T1068, T1548.003 → top-level T1548, T1014) appear in their respective tactic columns. KEV-exposed cells pulse. |
| Heatmap click navigation works | click any cell → URL changes to `/matrix?technique=<id>`. (M21 will pre-select the cell on its side; today /matrix is still a placeholder.) |
| Review queue preview shows top 5 sorted by priority_score | seed one queue row via M16; confirm the row renders with the right priority badge, CVE id (mono accent), first technique_id, and `dayjs.fromNow()` age. Approve via M22 once it lands → the row disappears from the preview within ~500 ms (via the queue_item.approved event). |
| KEV gap list shows real KEV-exposed gap CVEs | `INSERT INTO cves (..., cisa_kev=true, ...)` for a CVE that has no covering Sigma rule → after the next M14 mapper tick the gap appears in the dashboard with the technique id, name, and CVSS-tagged CVE chip. |
| Banner appears when KEV CVEs are staged | trigger an import (POST /imports/start with a filter that selects a KEV CVE that's not auto-approved) → after staging completes, the "N KEV CVEs staged" banner appears above the KEV gap list. |
| Live event feed updates in real-time | open Chrome DevTools → Network → WS; trigger any event-emitting flow (resynthesize a chain, approve a queue item, trigger an import); see the frame land in the WS tab AND the dashboard's "Live events" list animates a new entry in from the top. |
| All screens use DarkOps tokens (no overrides) | `grep -rn "#[0-9a-f]\{3,8\}" frontend/src/screens/Dashboard.tsx` — empty output. (The CSS file is allowed to define colours; `Dashboard.tsx` may not.) |
| WebSocket reconnect | stop the API container; confirm the feed status indicator flips to `closed` then `connecting`. Restart the container; the indicator returns to `open` within ~30 s (`useWebSocket` exponential-backoff cap). |
| WebSocket auth | manually edit `localStorage.fragchain.auth.token` to an invalid string; reload `/dashboard`; confirm the WS connection closes with 1008 and the feed status shows `error`. Sign back in with a valid JWT → reconnect succeeds. |

## Interfaces this module exposes

For dependent modules:

```ts
// New tightened matrix client (M19+):
import {
  fetchMatrix,
  fetchTechniqueCoverage,
  listCoverage,
  recomputeMatrix,
  type MatrixResponse,
  type MatrixTactic,
  type MatrixCell,
  type MatrixSummary,
  type MatrixParams,
  type CoverageRow,
  type CoverageListResponse,
  type CoverageListParams,
} from "../api/matrix";

// Dashboard screen + event type (M21 / M22 may want to embed the feed):
import { Dashboard } from "../screens/Dashboard";
import type { DashboardEvent, DashboardCve } from "../screens/Dashboard";
```

Backend:

* `WebSocket /ws/events` — JWT in `?token=`, forwards every
  `emit_event(...)` payload. Frame shape:
  ```json
  { "type": "chain_generated", "payload": {...}, "emitted_at": "2026-..." }
  ```
  with periodic `{"type":"ping"}` keepalive frames (15 s cadence).

## What dependent modules need to know

* **M21 (ATT&CK Matrix)** — heatmap cells link to
  `/matrix?technique=<id>`. M21 should read the query param and
  pre-select that technique's detail panel.
* **M22 (Review Queue / Sigma Library)** — the dashboard preview
  card links to `/queue` with no query string. M22 may want to
  honour `?cve_id=...` so a click on the priority row pre-filters
  the queue, but that's M22's prerogative.
* **M23 (Imports)** — the staged-KEV banner links to `/imports`.
  No query string today; M23 may want a `?status=staged&kev=true`
  filter when it lands.
* **M24 (Settings / Prompts / Connectors / Commons)** — the
  sidebar's hardcoded `7` / `A/B` badge counts stay until M24
  (or a small dedicated hook module) wires `useQueueCount()` /
  `usePromptAbActive()`. The badge slot already accepts the
  variant prop M24 will use.
* **M36 (Notifications)** — the bell in the Topbar still has no
  data feed. M36 can subscribe to the same `/ws/events` channel
  with a filter (e.g. only `queue_item.created` + `rate_limit_warning`)
  and pipe through `notificationCount` on `<Topbar>`.
* **Future: per-screen event subscription**. Other screens can
  call `useWebSocket()` independently — the bus broadcasts to
  every subscriber. Filtering happens client-side via the
  `filter` option.

## Deviations from spec / kickoff

* **Backend WebSocket endpoint added.** The kickoff lists "Do not
  build: backend API changes", but the kickoff also requires
  "Live event feed updates in real-time" + "Stats refresh via
  WebSocket when relevant events fire". M18's known-TODOs
  explicitly says `M19 — /ws/events server-side endpoint`. I
  shipped the minimum viable route — auth + bus subscribe +
  forward + clean teardown. No new HTTP routes were added.
* **`matrix.ts` rewritten to match the real backend shape.** The
  M18 placeholder typed the response as `cells: Record<string,
  MatrixCell>`; the backend actually returns a nested
  `tactics → techniques` shape (matches
  `fragchain/coverage/matrix.py:MatrixData.to_dict()`). Without
  this fix the dashboard heatmap would have rendered as a
  one-column "no_data" grid. Documented under "Frontend API
  tightening" above.
* **Heatmap uses `coverage_status`, not the kickoff's "color cells
  per coverage_status".** Same intent, but the M14 schema field is
  `coverage_status` (`covered | partial | gap | no_data`), not a
  separate `color` field. I keep the four classes as CSS modifiers.
* **Heatmap renders top 8 top-level techniques per tactic** —
  exactly what the kickoff asked for. Sub-techniques are filtered
  out (they'd otherwise dominate the list for ATT&CK tactics with
  deep sub-technique trees).
* **KEV gap list does N+1 calls (1 list + 5 detail).** Five extra
  requests at most, all cache-hit on Redis. Adding a "give me KEV
  CVEs per technique" projection to `GET /coverage` would bloat
  every other coverage consumer. Acceptable trade-off.
* **WebSocket lives at `/ws/events`, not under `/api/v1`.**
  Matches the frontend default URL set by M18. Putting it under
  the prefix would force a config knob in `useWebSocket` and an
  operator-facing reverse-proxy note. The auth model is identical.
* **`coverage %` uses partial-credit math `(covered + 0.5 ×
  partial) / total`.** The kickoff just says "compute
  covered/total"; with partial coverage being a real M14 output
  state, treating partial as half a covered makes the number
  reflect operator reality. Same heuristic the mapper uses
  internally.
* **Live feed shows 8 events, not "last 8 events on the feed area".**
  Same N, just the cap is enforced via `slice(0, 8)` on every
  push. Older events fall off; the user clicks through to the
  relevant detail screen to recover history.
* **Event feed filters out `webhook.received` and `budget_status`.**
  These are infrastructure-noise events (debug-only per M6's
  documentation). Surfacing them on the dashboard would drown out
  pipeline-progress events.

## Known TODOs (owned by other modules)

* **M21 — read `?technique=` query param on /matrix** to
  pre-select the cell from the dashboard's heatmap click.
* **M22 — read `?cve_id=` / `?priority=` on /queue** to pre-filter
  from the preview row click.
* **M23 — read `?status=staged&kev=true` on /imports** to
  pre-filter from the KEV-staged banner.
* **M24 — wire real Sidebar badge counts** via a small hook over
  `listQueue({ status: 'pending', limit: 0 })` +
  `listAbTests({ status: 'active' })`. The Sidebar's literal `7`
  / `A/B` placeholders stay until M24 wires them.
* **M36 — wire the topbar bell** to the same `/ws/events` socket
  with a notification-only filter, and pipe the count through
  `notificationCount` on `<Topbar>`.
* **Per-CVE projection on `/cves`** — the dashboard's CVE count
  comes from `total` on the list response, which is fine, but a
  dedicated `GET /api/v1/cves/stats` endpoint (returning
  `{recent24h, staged, pending, complete, failed}`) would shave
  three list calls off the mount path. Defer until the dashboard
  is on a real DB load; v1's pre-flight stats are cheap.

## Risks / known weaknesses

* **Three full `listCves` calls on mount.** Today the dashboard
  fires `recent24h`, `staged`, and the implicit `listChains` calls
  via separate roundtrips. Each is `LIMIT 500`. On a deployment
  with > 1k CVEs the staged / 24h calls slow down — both have
  indexes (`cves.processing_status`, `cves.published_at`) so the
  query plan is fine, but the network round-trip is the floor.
  Fix is a dedicated `/cves/stats` endpoint (see TODO above).
* **WebSocket carries the JWT in the URL.** nginx access logs that
  capture query strings will log the token. The M1 nginx config
  already masks `/api/*` request URIs; if `/ws/*` is added to the
  access-log scope, operators should mask `token=*`.
* **The event feed has no maximum stuck length.** If the
  WebSocket reconnects rapidly (network flap, server restarting)
  and every reconnect drops a fresh `state-open` "synthetic event"
  in, the feed could churn. Today the only writers are bus
  emissions; a re-emit on reconnect is by-design (the bus has a
  256-event history that subscribers replay).
* **N+1 KEV-detail fan-out.** Five extra calls per mount. Hits
  the Redis matrix cache so the cost is tiny, but a coverage map
  with 1000+ KEV-exposed techniques would still fan out exactly
  five calls — the dashboard caps the list. The risk is more
  philosophical than operational.
* **Stats `coveragePercent` uses partial-credit math** that the
  ATT&CK Matrix screen (M21) may not replicate. If the two
  screens disagree on coverage %, the operator will notice. M21
  should adopt the same formula.
* **Heatmap top-N ranking is static.** A tactic with a single
  KEV-exposed gap will always lead, even if a different tactic
  has higher operational urgency (e.g. five concurrent ungrouped
  CVEs). A future "personalised dashboard" could swap the
  ranking; out of scope for v1.

## Outstanding questions

* **Should the dashboard auto-refresh on a timer in addition to
  WebSocket events?** Today an offline period (server restart,
  laptop sleeping) will leave the stats stale until the user
  reloads. A 60-s passive `setInterval` over `loadStats()` would
  cover it, but might bloat the API logs unnecessarily. Defer
  until we have a real user pinging the operator about a stale
  dashboard.
* **Should the live event feed cluster duplicate events?** A
  busy import job could fire 100 `cve_ingested` events in 30
  seconds, filling the 8-slot feed with the same event type. A
  collapse-by-type rule (e.g. "5 CVEs ingested in the last 30 s")
  would surface the trend better than the raw stream. Defer
  until the feed becomes noisy in production.
* **`?technique=<id>` query param contract with M21.** The
  dashboard ships the click URL today; M21 will own the read.
  Open question whether the param is the full technique id
  (T1548.003 → sub-technique) or the parent (T1548). I pass the
  full id; M21 can drop the suffix if it prefers parent-only
  scoping.
* **Notification stream vs full event stream.** The topbar bell
  (M36) and the dashboard feed are subscribing to the same WS
  today. M36 may want a separate `/ws/notifications` channel with
  a filtered subset so the bell badge doesn't increment on every
  `cve_ingested` event. Open whether to split the WS or push the
  filter client-side.
