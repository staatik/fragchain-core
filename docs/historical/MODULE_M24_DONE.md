# MODULE_M24_DONE — Settings + Marketplace UI
**Built:** 2026-05-13
**Effort actual:** L (one session)
**Status:** complete · sandbox-verified (`tsc -p tsconfig.json --noEmit` 0 errors · `npm run build` → 2109 modules transformed, 83.72 kB CSS / 1.14 MB JS) · pending in-browser verification on a live backend (Modal scroll behaviour with long form, CodeMirror keystroke flow for routing-rules JSON, marketplace install copy flow, A/B traffic-split slider edge cases)

## Scope reminder

M24 turns the prior `/settings` + `/prompts` placeholder screens into the
catch-all configuration screen and the runtime prompt-management screen.
It is the last UI module in Phase 6 and the last screen that needed a
real implementation; everything M24 talks to was already exposed by
earlier modules:

- M4 connectors (orchestrator + registry browse)
- M5 LLM providers (read-only list + health probe)
- M7 commons sources (multi-source CRUD + sync/test)
- M9 prompt templates + evaluations + A/B tests
- M12 Sigma sources + Sigma targets (CRUD + routing-rules validation)
- M13 logsource profiles (built-in + custom CRUD)
- M18 frontend core (Modal, SidePanel, Dropdown, DataTable, toasts)

M24 does NOT own:

* Backend changes. Every endpoint M24 calls lives in an existing
  router; nothing was added or modified on the API side.
* Email notifications (M36) — the Notifications section surfaces it
  as a deferred placeholder.
* A live `/system/config` API. Processing Limits and Notifications
  draft values are stored in `localStorage` for review/copy-out; the
  server still reads these from environment variables in v1.
* A backend pip-install hook for the marketplace. The "Install"
  button surfaces the `pip install <package>` command to run on the
  API container; an installable POST endpoint is post-v1.
* The Identity placeholder screen — already shipped under M1/M18 as
  a 501-aware "not implemented" message.

## What was built

### Settings shell + sub-routes — [Settings.tsx](frontend/src/screens/Settings.tsx)

`/settings/*` mounts a two-pane shell: a sticky left sub-nav and a
right-hand section pane. The shell uses nested `<Routes>` so the section
deep-links correctly (sidebar item "Connectors" goes straight to
`/settings/connectors`; "Commons" to `/settings/commons`). The bare
`/settings` URL redirects to `/settings/connectors`.

Sub-routes:

| Path                          | Section                | Backed by API              |
|-------------------------------|------------------------|----------------------------|
| `/settings/connectors`        | Connectors + Marketplace | M4 `/connectors`, `/connectors/registry` |
| `/settings/commons`           | Commons Sources        | M7 `/commons/sources`      |
| `/settings/sigma-sources`     | Sigma Sources          | M12 `/sigma/sources`       |
| `/settings/sigma-targets`     | Sigma Targets          | M12 `/sigma/targets`       |
| `/settings/profiles`          | Logsource Profiles     | M13 `/profiles`            |
| `/settings/limits`            | Processing Limits      | env-managed, local draft   |
| `/settings/notifications`     | Notifications          | env-managed, local draft   |
| `/settings/providers`         | AI Providers           | M5 `/llm/providers`        |

Each section is its own file under `frontend/src/screens/settings/` so
the screen splits cleanly:

* [SettingsLayout.tsx](frontend/src/screens/settings/SettingsLayout.tsx) — sticky 180px sub-nav with Lucide icons + active highlight.
* [ConnectorsSection.tsx](frontend/src/screens/settings/ConnectorsSection.tsx)
* [CommonsSection.tsx](frontend/src/screens/settings/CommonsSection.tsx)
* [SigmaSourcesSection.tsx](frontend/src/screens/settings/SigmaSourcesSection.tsx)
* [SigmaTargetsSection.tsx](frontend/src/screens/settings/SigmaTargetsSection.tsx)
* [ProfilesSection.tsx](frontend/src/screens/settings/ProfilesSection.tsx)
* [LimitsSection.tsx](frontend/src/screens/settings/LimitsSection.tsx)
* [NotificationsSection.tsx](frontend/src/screens/settings/NotificationsSection.tsx)
* [ProvidersSection.tsx](frontend/src/screens/settings/ProvidersSection.tsx)

#### Connectors + Marketplace

Lists installed connectors with a coloured health pill (green/amber/red
dot using `.health-pill`), a per-connector enable/disable toggle, a
"Health check" button that POSTs `/connectors/{name}/health` and toasts
the result, and a "Configure" button that opens a right-side
`SidePanel` with a JSON editor for the connector's `config` blob.
Inline JSON validation drives an error/ok status line; Save patches
`/connectors/{name}` and refreshes the list.

The Marketplace modal calls `/connectors/registry` and renders
`fragchain-registry` entries as a 260px grid of cards (name, official
badge, version, description, type, maintainer, repo link). Filter chips
narrow by `type` (`source_stream` / `enrichment`) and `official only`.
Already-installed entries show a green `installed` badge; un-installed
entries show an "Install" button that opens a `ConfirmDialog` and
surfaces the `pip install <package>` command via toast (no backend
install endpoint exists in v1; the wire-up is forward-compatible).

#### Commons Sources, Sigma Sources, Sigma Targets

All three follow the same row layout (settings-row with name, mono
metadata line, action cluster) and the same modal-driven CRUD flow:
"Add …" opens a wide Modal in create mode; clicking a row opens the
same Modal in edit mode. Each modal validates required fields and
serialises Updates so that `auth_credentials_ref` is only sent when
the operator changed it (the existing value is masked as
`(unchanged)`).

- **Commons:** add/edit form for url + auth type + trust level
  (community/partner/internal) + priority + sync/contribute toggles.
  Per-row "Test" calls `/commons/sources/{id}/test`; "Sync now" calls
  `/sync` and reports `chains_imported / chains_skipped`.
- **Sigma Sources:** url + branch + auth type + optional path filter +
  enabled toggle. "Test" probes the repo; "Refresh" runs
  `/sigma/sources/{id}/refresh` and toasts `inserted/updated/unchanged`
  rule counts.
- **Sigma Targets:** the heavier section because routing rules are
  a JSON blob. The modal embeds a CodeMirror editor (oneDark theme,
  line wrapping; the `lang-json` extension was not installed so we
  rely on JSON.parse + structural validation locally, then send to the
  server which re-validates each clause's `if` expression against the
  M12 condition compiler). Inline status line flips red on invalid
  JSON or missing `if`/`target_name` fields; Save is disabled until
  it goes green. Auth fields, `is_default`, `auto_pr`, and `enabled`
  use the DarkOps `.toggle` slider.

#### Logsource Profiles

Two sub-lists: built-in (read-only edit, can still be enabled/disabled
via toggle) and custom (full edit + delete). The custom-profile modal
collects `name` (slug), `display_name`, `platform` (dropdown of
linux/windows/network/cloud — matches `VALID_PLATFORMS`),
`sigma_product`, `sigma_service`, description, `field_conventions`
(JSON object), and `example_rules` (JSON array — few-shot fixtures for
the LLM prompt). Both JSON inputs are textareas with inline
parse-on-keystroke validation and a status line.

#### Processing Limits + Notifications

Both sections are env-managed in v1. They render full forms (number
inputs for `MAX_LIVE_CVE_PER_HOUR`, `MAX_HISTORICAL_CVE_PER_DAY`,
`OPENCTI_POLL_MAX_PER_RUN`; toggle for `AUTO_PROCESS_KEV`; masked
inputs for Slack + generic webhook URLs) and save a draft to
`localStorage` so the operator can review their planned env changes.
The Limits section also has a collapsible `<details>` block that
renders the corresponding `.env` snippet, copy-ready.

The Notifications section has a `Test` button per webhook that does
not POST anywhere (the notifications subsystem fans out from the
backend worker, not the API request path); instead it surfaces the
`curl` command the operator can run to exercise the webhook. When M36
ships a real `/notifications/test` route, this swaps over.

#### AI Providers

Read-only list backed by `/llm/providers`. Each provider shows its
version, capability flags (chat / embeddings / streaming), and
`default chat` / `default embed` accent badges if it matches the
registry's chosen default. The "Test connection" button calls
`/llm/providers/{name}/health` and renders a live health pill plus
toast with `latency_ms` and `models_available.length`. A small grey
panel at the bottom lists the env vars the operator needs to set
(`LITELLM_BASE_URL`, `LITELLM_API_KEY`, `LITELLM_CHAT_MODEL`,
`LITELLM_EMBEDDING_MODEL`).

### Prompts screen — [Prompts.tsx](frontend/src/screens/Prompts.tsx)

`/prompts` mounts the runtime prompt-management screen. Layout: a
sticky 320px left list grouped by `(task_type × target_model ×
target_provider)` with all versions stacked under the same group
(descending by version, active version flagged with a green `active`
badge); a right pane that shows the selected template detail plus an
A/B-tests card below.

Detail features:

* Two CodeMirror editors (oneDark, line wrapping) for the system
  prompt and user template, plus a small textarea for notes. Edits
  flip the form dirty; "Save as new version" PATCHes the template and
  the server clones a new version (bump-on-PATCH semantics from M9).
  "Activate" POSTs `/activate`, demoting whichever sibling version
  used to be active.
* "Run eval" opens a Modal listing benchmark sets from
  `/prompts/benchmarks`; selecting one and confirming POSTs
  `/{id}/evaluate` and surfaces the result via toast and updates the
  detail's evaluations table (technique overlap, ordering, halluc,
  cost/run, avg latency).
* "Compare with another version" dropdown lists sibling versions in
  the same group. Selecting one and hitting "Open diff" opens a wide
  Modal rendering server-side unified diffs (`system_prompt_diff`,
  `user_template_diff`) with line classes (`add` green / `remove` red
  / `hunk` dim).
* "New template" opens a wide Modal that collects name, task_type,
  target_model, target_provider, full system + user prompts, notes,
  and an "Activate immediately" toggle.

A/B tests card lists active and concluded tests with their split,
their A/B template labels (resolved against the loaded templates), the
current winner badge if any, and per-row controls to pick A / pick B /
end as a tie. "New A/B test" opens a Modal that filters the variant
dropdowns to templates matching the selected task type so the operator
can't pair mismatched prompts.

### Per-resource API clients — `frontend/src/api/`

The M18 scaffolding had stub clients for connectors / commons /
sigma_sources / sigma_targets / profiles / prompts that returned
`{ items: [...] }` (the placeholder shape). The actual backends return
`{ connectors: ... }`, `{ sources: ... }`, `{ targets: ... }`,
`{ profiles: ... }`, `{ templates: ..., total: ... }`. M24 rewrites
every one of those clients to match the real backend response (and the
full response models — `health_status`, `rate_limit`, `routing_rules`,
`evaluations`, etc. — so the new screens can render every field). A
new [llm.ts](frontend/src/api/llm.ts) client wraps `/llm/providers`
and `/llm/providers/{name}/health`.

These edits are surgical to align type definitions with backend
contracts; no behaviour of the API changed.

### CSS — appended block in [darkops.css](frontend/src/styles/darkops.css)

New primitives (~280 lines, appended after the existing M22 block, no
existing class redefined):

* `.settings-shell / .settings-nav / .settings-nav-item` — two-column
  settings shell + sticky sub-nav.
* `.settings-pane / .settings-row / .settings-row-main /
  .settings-row-name / .settings-row-meta / .settings-row-actions` —
  list-row layout shared by all CRUD sections.
* `.health-pill (.ok / .degraded / .unhealthy / .unknown)` — coloured
  dot + status label for connectors and providers.
* `.settings-form-grid / .span-2` — two-column form grid for modals.
* `.marketplace-grid / .marketplace-entry / .marketplace-entry-header
  / .marketplace-entry-name / .marketplace-entry-version /
  .marketplace-entry-desc / .marketplace-entry-footer` — connector
  marketplace card grid.
* `.json-editor / .json-editor.invalid / .json-editor-status (.ok /
  .error)` — inline JSON-editor framing + status line, used by Sigma
  Targets routing rules.
* `.prompts-shell / .prompts-list-card / .prompts-group-header /
  .prompt-list-item (.active) / .prompt-list-item-name /
  .prompt-list-item-meta / .prompts-detail-shell` — Prompts screen
  layout.
* `.prompt-editor / .prompt-editor.short` — CodeMirror wrapper that
  matches DarkOps theming (oneDark + monospace + 1px border + border
  radius).
* `.prompt-diff-card / .diff-line (.add / .remove / .hunk)` — diff
  view styling.
* `.eval-table` — dense evaluation results table.
* `.ab-row` — A/B test list row.
* Responsive break at 900px collapses the sub-nav and prompt-list to
  full width.

### Routes + sidebar

* [App.tsx](frontend/src/App.tsx) — `/settings/*` now routes through
  the new `Settings` screen with nested sub-routes; `/prompts` now
  routes to the new `Prompts` screen. The old `Placeholders.tsx`
  shells are deleted.
* [Sidebar.tsx](frontend/src/components/Sidebar.tsx) — unchanged. The
  existing "Connectors" / "Commons" / "Settings" links continue to
  resolve correctly (the new `Settings` screen redirects `/settings`
  → `/settings/connectors` so the catch-all "Settings" link lands on
  a real section).

## How this maps to the M24 done criteria

| Done criterion | How M24 delivers it |
|---|---|
| All settings sections render and save changes correctly | All 8 sub-sections render against live API shapes; CRUD persists for the 5 DB-backed sections. The 2 env-managed sections persist drafts to localStorage and surface the env snippet because v1 has no live config API. |
| Connectors marketplace browses registry, install triggers pip install | Marketplace renders the registry response with type + official filters. Install surfaces the exact `pip install <package>` command (no backend install hook exists in v1 — UI is forward-compatible). |
| Test Connection buttons work for each external service | Per-row Test wired for commons sources, sigma sources, sigma targets, and AI providers. Connectors have a Health check button. |
| Routing rules editor validates JSON, saves correctly | CodeMirror editor with on-keystroke JSON parse + structural validation; Save disabled while invalid. Server re-validates each `if` expression. |
| Custom logsource profile creation works | Custom profiles via dedicated modal. Built-ins enable/disable but reject Edit/Delete per backend. |
| Prompts screen lists all prompts with version history | List grouped by `(task × model × provider)` with versions stacked desc inside each group, active version flagged. |
| Prompt diff view shows correctly | Server-side unified diff rendered with `add/remove/hunk` line classes. |
| Evaluation run displays results | Run eval modal → POST `/evaluate` → results land in toast + persisted evaluation row in the detail table. |
| A/B test creation and conclusion works | Create modal filters variants by task type; concluded tests show winner; per-row pick-A / pick-B / end-tie buttons. |

## What still needs in-browser verification

* CodeMirror editors for Sigma Targets routing rules and the Prompts
  system/user templates — keystroke flow, undo/redo, copy/paste from
  the `dist/` build (sandbox `tsc + vite build` is clean).
* Marketplace install confirm modal copy + toast.
* Modal scroll behaviour with very long forms (Profile modal in
  particular — two JSON textareas can grow).
* A/B traffic-split numeric input clamping (0.0 — 1.0).
* Health pill colour transitions when a connector flips
  ok → degraded → unhealthy.
* Sticky settings-nav behaviour with a scrolled main pane.
* Mobile breakpoint at < 900px collapsing the two-column layouts.

## Hand-off

M24 closes Phase 6 (Frontend). All 10 main screens + Login + Identity
placeholder now have real implementations and route entries; the
sidebar nav has live deep-link targets to every meaningful path.
Future iteration ideas (not in M24's scope):

* A backend `POST /connectors/install` route that runs `pip install`
  in a sandboxed subprocess so the marketplace can do real
  one-click installs. Today the UI surfaces the command.
* A backend `/system/config` CRUD that mirrors the `system_config`
  table for live Processing Limits + Notifications config so those
  sections can persist server-side and audit-log changes.
* M36 will land email notification channels + the real
  `/notifications/test` route.

---

## Phase 6 scope catch-up applied (2026-05-13)

Closes one silent gap from `SCOPE_REVIEW_M22_M24.md`. See
`SCOPE_CATCHUP_M22_M24_DONE.md` for the full record.

* **Routing-rules template pre-fill.** The original build shipped the
  Sigma Targets create modal with the routing-rules CodeMirror
  opening to `[]` — no starter examples. Added an "Insert template"
  dropdown above the editor with four starter clauses:
  KEV Critical → Production, Experimental → Staging,
  Windows Only → Win Repo, FragChain Generated → Review.
  If the editor has unsaved content, selecting a template opens a
  ConfirmDialog before replacing. Templates use the quoted-tag
  form that the routing parser accepts directly; bareword form is
  also fine via the post-Phase-5 L4 pre-normalization fix.

## v1.x backlog (carried forward from this catch-up)

The catch-up explicitly deferred the items below to v1.x rather than
bundling them with the four silent-gap fixes. Each one is real and
acknowledged; none block Phase 6 audit or M25–M37.

* **`/system/config` CRUD endpoint.** Single backend ticket that
  unblocks five Settings sections at once: AI Providers editable
  config (URL / API key / chat + embedding models), Processing
  Limits save (`MAX_LIVE_CVE_PER_HOUR`, `MAX_HISTORICAL_CVE_PER_DAY`,
  `OPENCTI_POLL_MAX_PER_RUN`, `AUTO_PROCESS_KEV`), Notifications
  save (Slack + generic webhook URLs). Today all three sections
  write to `localStorage` only with an env-snippet display + a
  "restart the API container" message. Add a `system_config` table
  + hot-reload hook (or restart-aware reload) so live changes
  persist server-side and audit-log.
* **Marketplace `POST /connectors/install` hook + restart.** Today
  the Install button on a fragchain-registry entry opens a
  ConfirmDialog whose action surfaces a `pip install <package>`
  command via toast. Real one-click install is a v1.x QoL feature:
  a sandboxed subprocess `pip install` + a graceful container
  restart hook + a re-discovery pass through the entry-point
  registry.
* **Real `/notifications/test` endpoint.** Today the Slack + generic
  webhook Test buttons render `curl` commands via toast because no
  backend route exists in v1. Lands with M36 (notifications module).
* **`POST /sigma/validate-yaml` server-side draft validation.**
  Today the Review Queue runs client-side structural validation
  (`validateDraft()` helper); M15's `/rules/{id}/validate`
  validates the persisted row, not a draft body. A
  `POST /sigma/validate-yaml` endpoint that accepts a candidate
  Sigma body and returns the pySigma error list would replace the
  client-side check with an authoritative one — every other piece
  of plumbing (debounce, render, error list) stays.

These four v1.x items track the "Worth deferring" section of the
Scope Review verbatim. Reopen this list when prioritising the v1.x
release.
