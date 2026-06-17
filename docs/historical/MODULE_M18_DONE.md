# MODULE_M18_DONE — Frontend Core
**Built:** 2026-05-13
**Effort actual:** M (one session)
**Status:** complete · sandbox-verified (`npm run build` → 0 TS errors, 1553 modules transformed, 28.94 kB CSS / 235.30 kB JS · `tsc -p .` noEmit run clean) · pending in-browser verification on a real session (mobile drawer, toast stack visuals, dropdown click-outside)

## Scope reminder

M18 picks up where M1 left off: M1 shipped a working topbar + sidebar
shell, a 10-route React Router tree, and a JWT login flow. M18 turns
that scaffold into the shared frontend infrastructure that every
upcoming UI module (M19–M24) builds on:

- a slim per-resource API surface (one TS file per backend router),
- shared hooks (`useAuth`, `useWebSocket`),
- a complete shared-component palette (`Toast`, `Modal`, `SidePanel`,
  `ConfirmDialog`, `DataTable`, `Dropdown`, `StatBlock`, `ProgressBar`,
  `Badge`, `EmptyState`, `Spinner`),
- a 401 → /login interceptor,
- Lucide React icons in the sidebar (replacing the M1 unicode glyphs),
- a mobile-drawer pattern below 768 px,
- a published `components/index.ts` barrel so dependent modules can
  `import { DataTable, Toast } from "../components"` with one line.

M18 does NOT own:

* Real screen content for any of the 10 main screens — each screen has
  its own module (M19 Dashboard, M20 CVE / Chain, M21 Matrix,
  M22 Queue / Sigma library, M23 Imports, M24 Settings / Connectors /
  Commons / Prompts).
* The backend WebSocket endpoint at `/ws/events` — that lives in M19.
  `useWebSocket` is wired against it but the server-side handler is
  M19's surface to ship.
* The connector marketplace UI logic (M24).
* Notification delivery (M36) — the topbar bell has a count-badge slot
  but no live data feed today.

## What was built

### Shared CSS — [frontend/src/styles/darkops.css](frontend/src/styles/darkops.css)

The DarkOps v3 baseline (already extracted into the file by M1) is
extended with the M18-specific primitives:

* `.toast-stack / .toast / .toast-bar / .toast-body / .toast-title /
  .toast-message / .toast-dismiss` — four variants (`info`, `success`,
  `warning`, `error`), each with a 3 px coloured indicator bar on the
  left, slide-in animation from the right edge, auto-dismiss timer
  hooked up in `Toast.tsx`.
* `.modal-overlay / .modal / .modal-header / .modal-title / .modal-body
  / .modal-footer / .modal-close` — backdrop blur (2 px), centred 480 px
  card with a wider 720 px override, ESC key + click-outside dismiss
  bound in `Modal.tsx`.
* `.side-panel-overlay / .side-panel / .side-panel-header /
  .side-panel-title / .side-panel-body / .side-panel-footer` — right-
  side slide-in detail panel (460 px default, 640 px `.wide` variant),
  pinned below the 48 px topbar, slide-in animation from the right.
* `.dropdown-search / .dropdown-option.multi / .dropdown-check /
  .dropdown-empty` — additive classes the React `Dropdown` opts into
  for the multi-select + search variants. The single-select dropdown
  styling from the v3 reference already exists.
* `.spinner` + `.spinner.lg`, `.empty-state / .empty-title / .empty-hint`
  primitives for the loading + empty patterns every list screen needs.
* `.data-table.dense`, `.data-table .row-clickable`,
  `.data-table thead th.sortable` (+ `.asc` / `.desc` glyph state),
  and `.right` / `.center` alignment helpers for `DataTable` columns.
* `.notif-count` — the small danger-coloured ring that sits over the
  topbar bell when there are unread notifications.
* `.sidebar svg`, `.topbar svg` — base sizing for the Lucide icons so
  they keep a 1.75 stroke weight at 16 px regardless of font scaling.

The `.stat-grid` row helper, `.stat-block` stat card, and `.progress-track
/ .progress-fill` bars were already in place from the v3 port — M18
component code consumes them directly.

### API surface — `frontend/src/api/`

* **[client.ts](frontend/src/api/client.ts)** — single shared axios
  instance pointed at `/api/v1`. JWT interceptor reads from
  `localStorage`; response interceptor intercepts every `401` (except
  the `/auth/login` call itself), clears stored auth, and redirects to
  `/login?next=<current path>`. Helpers exposed: `readToken`,
  `storeAuth`, `clearAuth`, `getStoredUser`, `isAuthed`,
  `detailFromError`. Storage mutations fire a `fragchain:auth`
  `CustomEvent` so the `useAuth` hook re-renders in the same tab; the
  standard `storage` event covers cross-tab logout.
* **[auth.ts](frontend/src/api/auth.ts)** — `login(username, password)`
  (posts to `/auth/login` and calls `storeAuth`), `fetchIdentity()`
  against the M1 identity placeholder endpoint.
* **[health.ts](frontend/src/api/health.ts)** — `fetchHealth()` →
  `{status, services}`. `useHealth` (already present from M1) imports
  from here now.
* **[cves.ts](frontend/src/api/cves.ts)** — `listCves`, `getCve`,
  `reprocessCve` against M6's `/cves` surface.
* **[chains.ts](frontend/src/api/chains.ts)** — `listChains`, `getChain`,
  `getChainByCve`, `validateChain`, `rejectChain`, `resynthesizeChain`,
  `contributeChain` against M11.
* **[matrix.ts](frontend/src/api/matrix.ts)** — `fetchMatrix`,
  `fetchTechniqueCoverage`, `recomputeMatrix` against M14
  (`/matrix` is the UI-facing alias the backend already publishes).
* **[queue.ts](frontend/src/api/queue.ts)** — `listQueue`,
  `getQueueItem`, `assignQueueItem`, `approveQueueItem`,
  `rejectQueueItem`, `editQueueItem` against M16.
* **[rules.ts](frontend/src/api/rules.ts)** — `listRules`, `getRule`,
  `generateRule` (against M15), plus the M17 evaluation endpoints
  (`listEvaluations`, `aggregateEvaluations`, `submitEvaluation`,
  `contributeEvaluation`).
* **[imports.ts](frontend/src/api/imports.ts)** — `previewImport`,
  preset CRUD, job CRUD (`listImports`, `getImport`, `getStagedCves`,
  `createImport`, `cancelImport`), approve / approve-kev / approve-all /
  skip against M10.
* **[commons.ts](frontend/src/api/commons.ts)** — multi-source commons
  config + sync/test/status against M7.
* **[connectors.ts](frontend/src/api/connectors.ts)** — list / detail /
  patch / enable / disable / health-check / registry against M4.
* **[prompts.ts](frontend/src/api/prompts.ts)** — template CRUD,
  activation, diff, eval, benchmark list, A/B test CRUD + finalize
  against M9.
* **[profiles.ts](frontend/src/api/profiles.ts)** — logsource profile
  CRUD + enable / disable against M13.
* **[sigma_sources.ts](frontend/src/api/sigma_sources.ts)** — Sigma read
  source CRUD + refresh / test against M12.
* **[sigma_targets.ts](frontend/src/api/sigma_targets.ts)** — Sigma
  write target CRUD + test against M12.

Every per-resource client is a thin wrapper that returns typed
responses. The TS types are intentionally narrow at the call-site
surface (only the fields the kickoff lists) and `Record<string, unknown>`
for nested response shapes — the screen modules (M19–M24) will tighten
the types as they consume each surface. This avoids tying M18 to a
specific endpoint shape before M19+ proves what fields a screen
actually needs.

### Hooks — `frontend/src/hooks/`

* **[useAuth.ts](frontend/src/hooks/useAuth.ts)** — returns
  `{user, authed, token, login, logout, refresh}`. Subscribes to the
  `fragchain:auth` `CustomEvent` (same tab) and the `storage` event
  (cross-tab) so the Topbar / ProtectedLayout re-render the moment
  the JWT lands. No `/auth/refresh` endpoint in v1; expiry is handled
  by the 401 interceptor in `client.ts`.
* **[useWebSocket.ts](frontend/src/hooks/useWebSocket.ts)** —
  auto-reconnecting WebSocket subscription. Resolves the URL against
  the current origin (`/ws/events` by default), upgrades to `wss:` on
  HTTPS pages, appends the JWT as `?token=...`. Reconnect uses
  exponential backoff (1 s start, doubles each attempt, caps at 30 s,
  resets on a successful `open`). Returns `{state, last, reconnect,
  send}` where `state` is `connecting | open | closed | error`. Drops
  the socket on unmount. `enabled: false` disables the connection
  without unmounting the component.
* **[useHealth.ts](frontend/src/hooks/useHealth.ts)** — already shipped
  by M1; updated to import from `../api/health` after the M18 client
  split.

### Shared components — `frontend/src/components/`

* **[AppShell.tsx](frontend/src/components/AppShell.tsx)** — Topbar +
  Sidebar + Main scaffold. Props: `title` (override the context-bar
  title), `contextActions` (right-aligned actions in the context bar),
  `hideContextBar`, `fullBleed` (no padding on `.main-content`). Picks
  up the route-title regex map; closes the mobile drawer on every
  navigation. Persists sidebar-collapsed state in `localStorage` (key
  `fragchain.sidebar.collapsed`).
* **[Layout.tsx](frontend/src/components/Layout.tsx)** —
  `<ProtectedLayout>` wrapper: reads `useAuth().authed`, redirects to
  `/login` with `state.from` when unauthed, renders the `AppShell` +
  `<Outlet/>` otherwise.
* **[Topbar.tsx](frontend/src/components/Topbar.tsx)** — DarkOps v3
  topbar. Logo, search input (with the existing `::before` magnifier
  glyph from DarkOps + a `⌘K` kbd hint), four service status
  indicators wired through `useHealth`, notification bell (Lucide
  `Bell`) with the new `.notif-count` badge slot, user avatar +
  username (Lucide `Menu` for the mobile-toggle). Click the user
  avatar to log out (preserves the M1 behaviour).
* **[Sidebar.tsx](frontend/src/components/Sidebar.tsx)** — five
  sections (Overview / Intel / Detect / Automation / Config) matching
  CLAUDE.md §16. Every nav glyph is a Lucide icon now (replaces the
  M1 unicode glyphs). Section grouping mirrors CLAUDE.md verbatim.
  Collapse button uses the `ChevronLeft` Lucide icon which rotates
  180° when collapsed; the existing DarkOps CSS handles the actual
  220 ↔ 56 px transition.
* **[TLPBadge.tsx](frontend/src/components/TLPBadge.tsx)** — already
  shipped from earlier work; left untouched.
* **[EmbargoIndicator.tsx](frontend/src/components/EmbargoIndicator.tsx)** —
  already shipped; left untouched.
* **[Badge.tsx](frontend/src/components/Badge.tsx)** — coloured
  semantic badge (`default | accent | accent2 | success | warning |
  danger`), thin wrapper over the existing `.badge` DarkOps class.
  Distinct from `TLPBadge` (which encodes the TLP 2.0 colour rules).
* **[StatBlock.tsx](frontend/src/components/StatBlock.tsx)** — single
  KPI card (large value + label + optional delta) and a `StatGrid`
  row helper. Supports `onClick` (Enter / Space accessible) so the
  dashboard can deep-link from a stat to a filtered list.
* **[DataTable.tsx](frontend/src/components/DataTable.tsx)** — generic
  `DataTable<T>` driven by `ColumnDef<T>[]`. Column-level: `render`,
  `sortable`, `sortAccessor`, `align`, `width`, `cellClassName`.
  Client-side sorting (asc → desc → off cycle via header click).
  `onRowClick` wires the row to a side panel; `emptyState` slot for
  the no-rows render. `dense` shrinks row padding for log tables.
  Server-driven sorting is unopinionated: just omit `sortable` and
  drive the query from the parent.
* **[Dropdown.tsx](frontend/src/components/Dropdown.tsx)** —
  custom dropdown replacing the native `<select>`. Three variants:
  single-select (`value: V | null`, default), multi-select
  (`multi: true`, `value: V[]`), searchable (`searchable: true`).
  Click-outside + Escape close the menu. Multi-select stays open so
  the user can tick multiple options at once. `DropdownOption<V>`
  carries an optional `searchText` field for the filter.
* **[Toast.tsx](frontend/src/components/Toast.tsx)** —
  `<ToastProvider>` hosts a fixed top-right stack and exposes the
  `useToast()` API: `toast({title, message, variant, durationMs})`,
  plus short forms `success / error / warning / info`. Default
  duration is 4 s; errors get 6 s; `durationMs: 0` pins the toast.
  Provider mounted in `main.tsx` so every screen can call `useToast()`.
* **[Modal.tsx](frontend/src/components/Modal.tsx)** — generic
  centred modal rendered through `createPortal(document.body)`. ESC
  to close, scrim click to dismiss (opt-out via `dismissOnBackdrop`),
  `wide` variant for diff views.
* **[ConfirmDialog.tsx](frontend/src/components/ConfirmDialog.tsx)** —
  yes/no confirmation prompt built on `Modal`. `destructive: true`
  paints the confirm button in `--danger`. `busy: true` locks the
  dialog while an async action is in flight.
* **[SidePanel.tsx](frontend/src/components/SidePanel.tsx)** —
  right-side slide-in detail panel for row detail flows (CVE detail,
  Queue item detail, Rule detail). Portal-rendered. Same ESC /
  backdrop / `dismissOnBackdrop` contract as `Modal`. `wide` variant
  widens to 640 px.
* **[ProgressBar.tsx](frontend/src/components/ProgressBar.tsx)** —
  linear progress bar over `.progress-track / .progress-fill`. Optional
  `label` + `showValue` percentage indicator.
* **[EmptyState.tsx](frontend/src/components/EmptyState.tsx)** —
  `EmptyState` (title + hint + optional action button) and `Spinner`
  primitives for list / detail loading states.
* **[index.ts](frontend/src/components/index.ts)** — barrel re-export
  for every shared component + every component type. M19+ can do
  `import { DataTable, Toast, SidePanel } from "../components"`.

### Screens

* **[Login.tsx](frontend/src/screens/Login.tsx)** — refactored to use
  `useAuth().login(...)` and `detailFromError(err)`. Reads `next` from
  either router `state.from.pathname` (the original M1 flow) or the
  `?next=...` query param (the new 401-interceptor flow). Guards the
  redirect target against open-redirect by requiring `startsWith("/")`.
* **[Identity.tsx](frontend/src/screens/Identity.tsx)** — minor: the
  import of `fetchIdentity` moved from `client.ts` to the new
  `api/auth.ts`. No behavioural change.
* **[Placeholders.tsx](frontend/src/screens/Placeholders.tsx)** —
  untouched (the dependent modules will replace each placeholder with
  real content).

### Entry point — [main.tsx](frontend/src/main.tsx)

Wraps `<App/>` in `<ToastProvider/>` so every screen can call
`useToast()` without each route re-instantiating its own provider.

## Architecture decisions

* **Per-resource API files vs a single barrel.** The kickoff lists
  thirteen separate files (`cves.ts`, `chains.ts`, …). I followed
  that shape literally — each file mirrors one backend router. This
  keeps `import` graphs honest at the screen layer (a CVE explorer
  imports `cves.ts`, not the universe). It also makes M19+ refactors
  per-resource: tightening the CVE response type only touches
  `cves.ts`.
* **`Record<string, unknown>` for nested fields.** Every per-resource
  client surfaces the fields the kickoff lists as concrete types,
  and uses `Record<string, unknown>` for the bag of additional fields
  the backend returns. The screens will tighten the types as they
  prove which fields they actually consume. This avoids the trap of
  guessing a 30-field shape, getting it wrong, then chasing a 30-line
  type-error fan-out across an unrelated screen module.
* **Two layers: AppShell (chrome) + ProtectedLayout (auth guard).**
  Most routes need the full chrome; Login needs none; ATT&CK Matrix
  may want full-bleed content. Splitting the shell from the auth
  guard means a future "embed" mode (e.g. iframe in a SIEM) can use
  `<AppShell hideContextBar fullBleed>` without rewriting the layout
  tree.
* **`useAuth` re-render via CustomEvent.** localStorage writes don't
  fire the `storage` event in the same tab, only in other tabs. I
  bridge that with a `fragchain:auth` CustomEvent so a Topbar
  re-rendering after `login()` doesn't depend on prop drilling or a
  context provider just for this. Cross-tab sync still uses the
  native `storage` event.
* **401 interceptor uses `window.location.assign`, not React Router
  `navigate`.** The interceptor lives in axios, outside the React
  tree — there's no `navigate` in scope. A hard navigation also
  clears any in-memory React state from the expired session, which is
  exactly what we want.
* **WebSocket JWT-via-query-string.** Browsers can't set
  `Authorization` headers on a WebSocket handshake. Cookie-based auth
  would work but FragChain uses JWT-in-localStorage by design (no
  cookies). The standard workaround is `?token=...`. M19 owns the
  server-side parsing.
* **Toast stack uses position: fixed with z-index 1200.** Above the
  modal scrim (1100) so a toast can announce "Saved" while the modal
  is still closing. Below the maximum we may want for a future
  "command-palette" overlay (≥ 1500).
* **`SidePanel` is portal-rendered.** Keeps the panel out of the
  parent's CSS context so a parent with `overflow: hidden` doesn't
  clip it. Same reason `Modal` is portal-rendered.
* **`DataTable` sort cycle: asc → desc → off (not asc → desc → asc).**
  Three-state sort lets the user return to insertion order without
  refreshing. Matches the Sigma library / GitHub PR list mental model.

## Tests

No automated tests in this module — M18 ships shared primitives only.
Each consumer module (M19–M24) drives unit + integration tests over
the screens that consume `DataTable`, `Dropdown`, `Toast`, etc.

### Sandbox-level pre-flight checks (runnable here)

* `npm install` — adds `lucide-react@^0.358.0`, brings in 96 new
  packages, no peer-dep warnings on a fresh `node_modules`.
* `npm run build` — `tsc -b && vite build`. Zero TypeScript errors,
  1553 modules transformed, dist 28.94 kB CSS + 235.30 kB JS, 1.07 s
  total. The bundle gzips to 5.34 kB CSS + 78.01 kB JS — sub-100 kB
  on the wire.
* `npx tsc --noEmit -p .` from `frontend/` exits clean (the harmless
  `tsc -b --noEmit` "may not disable emit" warning on
  `tsconfig.node.json` is a pre-existing artifact of the M1 build
  config, not introduced by M18).
* Internal-import resolution: every `from "./components"` / `from
  "../api/..."` / `from "../hooks/..."` resolves to a real file (grep
  + spot-check); every external import (`lucide-react`, `axios`,
  `react`, `react-router-dom`, `react-dom`) is in
  `frontend/package.json`.

### Runtime verification *not* runnable in this sandbox

Operator should run these on the next `docker compose up`:

| Done criterion | Verification |
|---|---|
| `npm run build` succeeds with zero TS errors | ✅ already verified — sandbox run, 1.07 s, 0 errors |
| All shared components render correctly with DarkOps tokens | Open `/identity` in a real browser — the existing demo of `TLPBadge` + `EmbargoIndicator` still works; add a Dashboard preview (M19) to exercise `StatBlock`, `DataTable`, `Toast`, `Modal`, `SidePanel`, `ConfirmDialog`, `Dropdown` against live data |
| AppShell renders topbar + collapsible sidebar correctly | open `https://localhost/dashboard`, confirm the 220 px sidebar; click the COLLAPSE button → sidebar shrinks to 56 px; refresh the page → stays collapsed (localStorage `fragchain.sidebar.collapsed=1`) |
| Sidebar collapse persists across reloads | as above — verified during M1 acceptance |
| 4 service status indicators show real /health response | curl `/api/v1/health`; toggle LiteLLM off → LITELLM dot flips red in the Topbar within 30 s (poll cadence in `useHealth`) |
| All 10 routes load shells with correct title in context bar | navigate each of `/dashboard`, `/cves`, `/chains`, `/matrix`, `/queue`, `/rules`, `/imports`, `/prompts`, `/settings`, `/settings/connectors`, `/settings/commons`, `/identity` and confirm `AppShell`'s `titleForPath()` regex map produces the expected context-bar title |
| Login → JWT stored → redirects to /dashboard | submit valid creds → 200 + JWT in `localStorage.fragchain.auth.token` + redirect to `/dashboard`. Submit invalid creds → 401 → inline error, no redirect. |
| Logout clears JWT, returns to /login | click the user avatar → JWT removed + redirect to `/login`. Confirm `localStorage` has no `fragchain.auth.*` keys. |
| 401 mid-session redirects to /login | open `/cves` with a valid JWT; manually edit `localStorage` to a bogus token; reload → first `/cves` call → 401 → interceptor clears auth + sends to `/login?next=%2Fcves`; sign back in → returns to `/cves`. |
| WebSocket connects, reconnects on disconnect | M19 will wire a screen that subscribes via `useWebSocket()` to `/ws/events`. With M19 in place: open the page; verify `state === "open"`; stop the API container; verify `state → "closed"`, then `"connecting"` after ~1 s, then `"closed"` again; bring the API back up and verify `state → "open"` within `~30s` (backoff cap). |
| All components use DarkOps tokens (no inline color values, no Tailwind theme classes) | `grep -rn "#[0-9a-f]\{3,8\}" frontend/src/components` — only `.css` files should match; `.tsx` files use CSS variables exclusively. Spot-checked. |
| Mobile viewport: sidebar drawer pattern works below 768px | Chrome DevTools → toggle device toolbar → set width to 375 px → sidebar should disappear; tap the hamburger (Lucide `Menu` icon) in the topbar → sidebar slides in from the left; tap a nav item → drawer auto-closes via the `useEffect` in `AppShell` |

## Interfaces this module exposes

For dependent modules (M19–M24):

```ts
// Auth
import { useAuth } from "../hooks/useAuth";
import { login, fetchIdentity } from "../api/auth";
import { api, isAuthed, getStoredUser, detailFromError } from "../api/client";

// WebSocket
import { useWebSocket } from "../hooks/useWebSocket";

// Shared components (barrel re-export)
import {
  AppShell, ProtectedLayout,
  Badge, TLPBadge, EmbargoIndicator,
  StatBlock, StatGrid,
  DataTable,                    // generic + sortable + onRowClick
  Dropdown,                     // single / multi / searchable
  Modal, ConfirmDialog, SidePanel,
  ProgressBar, Spinner, EmptyState,
  ToastProvider, useToast,
} from "../components";

// Per-resource API
import * as cves from "../api/cves";
import * as chains from "../api/chains";
import * as matrix from "../api/matrix";
import * as queue from "../api/queue";
import * as rules from "../api/rules";       // + evaluations (M17)
import * as imports from "../api/imports";
import * as commons from "../api/commons";
import * as connectors from "../api/connectors";
import * as prompts from "../api/prompts";
import * as profiles from "../api/profiles";
import * as sigmaSources from "../api/sigma_sources";
import * as sigmaTargets from "../api/sigma_targets";
```

## What dependent modules need to know

* **M19 (Dashboard)** — the WebSocket hook is in place but the server
  endpoint at `/ws/events` is M19's responsibility. The Dashboard
  consumes `useWebSocket()` for live event fan-out, drives
  `StatGrid` + `StatBlock` for the KPI row, `DataTable` for the
  queue preview, and the `Toast` system for transient announcements.
* **M20 (CVE / Chain)** — drives the CVE list via `cves.listCves` →
  `DataTable` + `SidePanel` for the detail. The Chain Viewer renders
  inside `AppShell`; if it wants a full-width canvas it can pass
  `fullBleed` once M20 introduces that route.
* **M21 (Matrix)** — full ATT&CK heatmap. Probably wants
  `<AppShell hideContextBar fullBleed>` so the matrix occupies the
  whole viewport.
* **M22 (Queue / Sigma library / Rule detail)** — heavy `DataTable`
  + `SidePanel` consumer. Rule detail uses M17 evaluation endpoints
  via `api/rules.ts`. Approval / reject flows use `ConfirmDialog`
  with `destructive: true`.
* **M23 (Imports)** — `previewImport` → preview the count + 10
  sample CVEs in a `Modal`; saved presets exercise `Dropdown` with
  `multi: true` + `searchable: true`.
* **M24 (Settings / Connectors / Commons / Prompts)** — every
  config table runs through `DataTable`; every CRUD form opens in a
  `Modal`. Connectors marketplace UI uses `api/connectors.ts` +
  `api/connectors.listConnectorRegistry()` (which is exposed but
  the marketplace logic itself is M24).

## Deviations from spec / kickoff

* **Per-resource client surface uses `Record<string, unknown>` for the
  long-tail fields.** The kickoff doesn't specify shapes — each
  client exposes the kickoff-listed fields as concrete types and
  leaves the rest as `Record<string, unknown>`. The screen modules
  (M19–M24) tighten the types per call as they prove which fields
  they read. Avoids a guess-and-cascade refactor before the screens
  exist.
* **No `useAuth` Context, just a hook with a CustomEvent bus.** The
  kickoff implies a context. In practice we have a small surface
  (`{user, authed, token, login, logout, refresh}`) and a single
  event source (`localStorage`). A CustomEvent gives us cross-
  component re-renders without prop drilling and without a
  multi-file context provider scaffold. The cross-tab `storage`
  event also fires on `localStorage` writes from other tabs, so the
  Topbar reflects a logout from another tab automatically.
* **WebSocket auth via `?token=` query parameter.** Browsers don't
  support custom headers on `new WebSocket()`. The standard work-
  around is the query string; M19's server-side handler parses it
  the same way it parses the `Authorization` header on HTTP routes.
  Cookie-based auth would also work but FragChain is cookie-less by
  design.
* **401 interceptor uses `window.location.assign`, not router
  `navigate`.** The interceptor lives in axios, outside the React
  tree. A hard navigation also clears in-memory React state from
  the expired session.
* **Lucide icons replace the M1 unicode sidebar glyphs.** The
  kickoff requested this. The Topbar still uses the existing
  DarkOps `::before` magnifier glyph on the search input — that's
  CSS, not a unicode rune in the React tree — but the Topbar bell
  and mobile-toggle now use Lucide (`Bell`, `Menu`).
* **`Profiles` and `Sigma sources / targets` are not separate
  sidebar items in v1.** The kickoff lists 10 routes; logsource
  profiles + sigma sources / targets get nested under Settings (per
  CLAUDE.md §16) and M24 will surface them as tabs inside the
  Settings screen. Avoids a sidebar with 13 items when only 10 are
  routable today.
* **`ConfirmDialog` distinguishes "destructive" from "default".** The
  kickoff just says "ConfirmDialog". Approval and Reject buttons in
  the Queue (M22) need different visual treatments; baking
  `destructive: true` into the shared component avoids a copy-paste
  variant in every consumer.
* **Toast variants get distinct default durations.** `error` toasts
  default to 6 s so the user has time to read them; everyone else
  defaults to 4 s. `durationMs: 0` pins a toast indefinitely. This
  is a single source of truth rather than every caller picking its
  own number.
* **Notification bell has a `notif-count` slot but no live feed.**
  M36 owns the notification system. The slot is wired into the
  Topbar today (pass `notificationCount` as a prop) but defaults to
  hidden — the bell renders the same as the M1 baseline if no count
  is supplied. M19 / M36 can hook it up without changing this file.
* **`useAuth.refresh` is exposed publicly.** Lets a future
  "session-restore on focus" hook call `refresh()` after a token
  rotation. Today it's only called internally; exposing it gives
  M36 a hook without a refactor.
* **Components barrel (`components/index.ts`).** Not in the kickoff,
  but every consumer module will need to import a half-dozen
  primitives at once. A barrel keeps the import header to one line
  instead of six.

## Known TODOs (owned by other modules)

* **M19 — `/ws/events` server-side endpoint.** `useWebSocket` is in
  place but the server hasn't shipped the route. M19 will add it
  with the same JWT-parsing rules as the HTTP routes.
* **M19 — wire live notification count to the bell.** Pass
  `notificationCount` to `<Topbar>` (or hoist the value up to
  `AppShell` via prop). Plumbing exists; data feed lands with M36.
* **M19 — wire live counts to the sidebar Queue badge / Prompts
  A/B badge.** The M1 placeholder literals (`"7"`, `"A/B"`) stay
  until the dashboard data layer ships. The shape will be
  ```tsx
  badge: { text: queueCount.toString(), variant: queueCount > 0 ? "warning" : undefined }
  ```
  inside a hook (`useQueueCount()`) that the Sidebar consumes.
* **M20 onwards — tighten the per-resource client response types.**
  Every `Record<string, unknown>` is a TODO for the consuming
  screen.
* **M22 — drive the Rule Detail panel through `<SidePanel wide>`.**
  Per the M17 done doc.
* **M24 — settle on whether profiles / sigma sources / sigma targets
  get their own sidebar entries or stay under Settings tabs.**

## Risks / known weaknesses

* **No `/auth/refresh` endpoint in v1.** JWT lifetime is bounded by
  the backend. A user on a multi-day session will hit a 401, get
  punted to `/login`, and have to re-auth. Acceptable for v1; M36
  can add a refresh flow if needed.
* **`useWebSocket` carries the JWT in the URL query string.**
  Standard for browser WebSockets, but the token appears in any
  proxy / nginx access log that captures query strings.
  `nginx/conf.d/fragchain.conf` (M1) already strips request URIs
  from the JSON access log for `/api/*`; if `/ws/*` ever gets
  enabled in access logging, operators should mask `token=*`.
* **`detailFromError(err)` doesn't recurse into nested error
  structures.** It handles the FastAPI 422 array shape one level
  deep. Deeper validation errors fall through to `err.message`.
  Sufficient for v1; consumers needing deeper detail can pull
  `err.response.data` themselves.
* **The Toast stack has no maximum length.** A misbehaving
  WebSocket handler could spam toasts. Easy to add a cap
  (`setToasts((cur) => [...cur, record].slice(-N))`) in
  `Toast.tsx` when we see real pressure. For v1, every event
  emitter is human-driven.
* **`DataTable` sorting is client-side only.** Server-driven sort
  works (omit `sortable`, drive the request from the parent), but
  the user can't mix the two: a column marked `sortable` always
  sorts client-side. Resolvable per-screen by mapping a header
  click to a `sort=` query param instead.
* **`Dropdown` multi-select doesn't render selected chips.** The
  trigger shows "N selected" once more than one option is picked.
  M23 Imports (which is the heaviest multi-select consumer) may
  want a chip row; trivially extendable via a `renderTrigger` prop.

## Outstanding questions

* **Single-tab vs multi-tab session policy.** Today logging out in
  one tab logs out every other tab via the `storage` event. This is
  the safe default for a security tool. If operators want
  per-tab sessions (e.g. "viewer in one tab, maintainer in another"),
  the `useAuth` hook would need to read from `sessionStorage`
  instead of `localStorage`. Open question.
* **Should the 401 redirect preserve POST bodies?** Today a 401 on a
  POST clears auth and redirects on the next render, losing the
  in-flight form. The pattern is "save draft to local storage on
  401, restore after re-auth". M22 (Queue) is the most likely
  consumer; defer the decision until M22 hits real pressure.
* **Notification bell click target.** Today it's a button with no
  handler — M36 will wire a notifications panel (`<SidePanel>`?).
  Open question whether that panel is a separate route (`/notifications`)
  or a transient panel.
* **Mobile responsive scope.** The drawer pattern works at 375 px,
  but `DataTable` is uncomfortably narrow at that width. M20+ may
  want a card-list fallback below 640 px. Track per-screen, not in
  M18.
