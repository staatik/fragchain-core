# MODULE_M22_DONE — Sigma Library + Review Queue UI
**Built:** 2026-05-13
**Effort actual:** L (one session)
**Status:** complete · sandbox-verified (`npm run build` → 0 TS errors, 2091 modules transformed, 71.62 kB CSS / 1.04 MB JS · `tsc -p . --noEmit` clean) · pending in-browser verification on a real session against a live backend (CodeMirror keystroke flow, Approve→PR toast, dropdown close-outside on the new target picker)

## Scope reminder

M22 ships two analyst screens against the backend surfaces M15 (rule
generator), M16 (review queue lifecycle), M17 (rule evaluations), M18
(frontend core) and M12 (sigma targets) already exposed:

```
/rules    → Sigma Library  (browse + filter + detail sidebar + evaluations)
/queue    → Review Queue   (split-pane CodeMirror + evidence + actions)
```

M22 does NOT own:
* Backend changes — every API call lands on a router that already exists
  (M15 `GET /rules`, `GET /rules/{id}`, `POST /rules/{id}/validate`;
  M16 `GET /queue`, `GET /queue/{id}`, `POST /queue/{id}/approve|reject|edit`;
  M17 `POST /rules/{id}/evaluate`, `GET /rules/{id}/evaluations`,
  `GET /rules/{id}/evaluations/aggregate`, `POST /evaluations/{id}/contribute`;
  M12 `GET /sigma/targets`).
* WebSocket fan-out for queue events (M19 already emits `rule_approved`,
  `git_pr_created`, `rule_rejected` onto the bus — wiring the badge count
  to live data lands when a separate `useQueueCount` hook ships).
* The Sidebar nav entries — M18 already wired `/queue` and `/rules`.

## What was built

### Dependencies — [frontend/package.json](frontend/package.json)

Two new runtime deps for the YAML editor:

* `@uiw/react-codemirror@^4.25.9` — React wrapper.
* `@codemirror/lang-yaml@^6.1.3` — YAML grammar.

`@codemirror/{state,view,language,theme-one-dark,commands,...}` come
in as transitive deps, so the read-only viewer (Library) and the
edit-as-you-type pane (Review Queue) both get the full one-dark theme +
syntax highlighting + line numbers + fold gutters with one install.

### API surface — narrowed to match the real backend shapes

* **[frontend/src/api/queue.ts](frontend/src/api/queue.ts)** rewritten
  against the backend's actual response shape (M16
  `QueueItemOut` / `QueueDetailOut` / `ApproveResponse` / `RejectResponse` /
  `EditResponse`). The list response is `{total, items}`, not the
  generic `{items, total, limit, offset}` the M18 stub used. The
  request body for assign is `{assigned_to: string|null}`, for approve
  is `{target_id?: string|null}`, for reject is `{reason: string}`,
  for edit is `{sigma_yaml: string, target_id?: string|null}`. Each
  function now returns a properly typed dataclass mirror so the screens
  read `detail.item.cve_textual_id` instead of stringly-typed
  `Record<string, unknown>` accesses.
* **[frontend/src/api/rules.ts](frontend/src/api/rules.ts)** rewritten
  to mirror M15's `RuleSummaryOut` / `RuleDetailOut` (the response key
  is `rules`, not `items`, and a `RuleDetailOut` extends summary with
  `sigma_yaml`, `content_hash`, `queue_status`, `priority`,
  `priority_score`). `validateRule(rule_id)` now exists for the
  Library "Validate" button. Evaluation surface (M17) types tightened
  to match `EvaluationOut` / `AggregateOut` / `ContributeResponse`
  exactly — `evaluator_username` field name, `sigma_rule_id` on the
  list / aggregate envelopes, `per_source[]` on contribute.
* **[frontend/src/api/sigma_targets.ts](frontend/src/api/sigma_targets.ts)** —
  list-response key corrected from `items` to `targets` (M12's
  `SigmaTargetListResponse`), `enabled` and `last_pr_at` fields added.

### CSS — appended to [frontend/src/styles/darkops.css](frontend/src/styles/darkops.css)

One new section "M22 — SIGMA LIBRARY + REVIEW QUEUE" with the
screen-specific primitives. No existing rule was modified — every new
class is namespaced (`.library-*`, `.review-*`, `.evidence-*`,
`.eval-*`, `.cm-readonly`, `.validation-*`, `.reject-input-row`).
Highlights:

* `.library-grid` — 240px filter rail + flexible table area, collapses
  to single-column below 1024 px.
* `.rule-tech-tags` — flex row of `.badge.accent2` chips with
  `.rule-tech-overflow` for the "+N" indicator when ≥4 techniques.
* `.eval-aggregate` — 2×N grid of label/value pairs that lives at the
  top of the Sigma Library detail panel's Evaluations section.
* `.eval-list` / `.eval-row` — per-evaluation card styling.
* `.review-shell` / `.review-context-bar` / `.review-split` — full-bleed
  review screen scaffold (60/40 split-pane → single column under
  1100 px), pinned context bar with CVE id + technique + priority badge
  + TLP + queue navigation.
* `.review-editor-host` — flex-1 container that hosts CodeMirror at
  100 % height; `.cm-editor { font-family: var(--font-display); ... }`
  forces JetBrains Mono on the YAML pane.
* `.validation-bar.ok` / `.validation-bar.fail` — bottom strip under the
  editor with green / red status. `.validation-errors` lists individual
  pySigma errors with a max-height scroll so a 30-error response
  doesn't push the action buttons off the screen.
* `.review-actions` — bottom toolbar with target selector (220 px
  Dropdown) + Reject + Edit+Approve + Approve buttons, all wired into
  DarkOps `.btn` variants (`success.active`, `active`, `danger`).
* `.reject-input-row` — slide-down inline reason input that appears
  above the action bar when "Reject" is clicked, with cancel + confirm.
* `.evidence-card` / `.evidence-grid-2` / `.evidence-ttp[.focus]` /
  `.evidence-source` / `.evidence-similar-row` /
  `.evidence-priority-list` — the right-pane card stack (CVE, chain,
  source, similar rules, priority).

### Screen — [frontend/src/screens/SigmaLibrary.tsx](frontend/src/screens/SigmaLibrary.tsx)

`<SigmaLibrary>` (mounted at `/rules`).

**Layout**

* Toolbar row with row count + "Refresh" pill.
* Left filter rail (`.explorer-filters`) with multi-select status,
  technique-id text input, logsource profile, origin, level, and
  created-from / created-to date pickers. "Reset" clears all filters.
* Main table card uses the shared `<DataTable>` from M18, sortable on
  every column where it makes sense (title, status, origin, level,
  created).

**Columns**

* Title — truncated to 40 chars with hover tooltip.
* Techniques — first 3 `.badge.accent2`; `+N` overflow with full list
  in `title=`.
* Logsource — mono `product / service`.
* Status / Origin / Level — `<Badge>` with semantic variants
  (`approved`/`merged`→success, `rejected`→danger, `submitted`→accent,
  `experimental`/`generated`→accent2, `critical`→danger,
  `high`→warning, etc.).
* CVE — link to `/chains/<cve>` when present (mono).
* TLP — `<TLPBadge>` with full prefix (`TLP:GREEN`, etc.).
* Created — `YYYY-MM-DD` mono.

**Detail sidebar (wide `<SidePanel>`)**

Sections:

* **Metadata** — sigma_uuid, status (with optional queue badge),
  origin, level, TLP, profile, logsource (product/service), CVE
  (linked), author, created, content hash (truncated).
* **Tags** — every tag from `sigma_rules.tags` rendered as a default
  `<Badge>` so analysts can scan for `attack.t1078`, `cve.cve-2026-…`,
  `fragchain.generated`, `tlp.amber`, `logsource.profile.…` etc.
* **Sigma YAML** — read-only `<CodeMirror>` with the one-dark theme,
  YAML grammar, JetBrains Mono, line numbers + fold gutter. Wrapped in
  `.cm-readonly` so the host gets a fixed 360 px frame with overflow
  scroll instead of pushing the rest of the panel down.
* **Validation** — only renders after the analyst hits "Validate".
  Shows the 200 / 400 boundary (`validation-bar.ok` vs `.fail`) plus a
  scrollable list of errors / warnings.
* **Evaluations** — header carries the recommendation badge
  (`production_ready` → success, `needs_tuning` → warning,
  `problematic` → danger, `insufficient_data` → default). When
  `count > 0`, the 4-cell `.eval-aggregate` block surfaces avg FP/day,
  total TPs, platforms tested, contributed count. Below it: per-row
  `.eval-row` cards with evaluator + timestamp, platform/scale/TP/FP
  summary, optional `contributed` badge, and notes.

**Footer actions** — Validate (POST `/rules/{id}/validate`, toasts
result), Copy YAML (clipboard write with toast), Add evaluation (opens
the `<EvaluationModal>`).

**`<EvaluationModal>`**

* Form fields: TPs, FP/day (numeric), platform (free text), scale
  (Dropdown small / medium / enterprise), notes (textarea, 4 rows).
* Client-side guard: refuses to submit if all of TPs / FP / notes are
  blank (matches the M17 store's "must include at least one of TP /
  FP / notes" rule, gives the analyst a clean toast instead of a 400).
* On success — pushes the new record onto `evaluations`, refreshes
  `aggregate`, surfaces a `success` toast, and opens the
  "Contribute to commons?" follow-up modal.
* Contribute prompt — POSTs `/evaluations/{id}/contribute`. Success
  shows "Contributed to N commons source(s)". A `submitted=0` response
  surfaces as a `warning` so the analyst knows nothing actually shipped.

### Screen — [frontend/src/screens/ReviewQueue.tsx](frontend/src/screens/ReviewQueue.tsx)

`<ReviewQueue>` (mounted at `/queue`). Renders its own `<AppShell>`
with `hideContextBar` + `fullBleed` so the screen owns its 44 px
context bar and the split-pane fills the rest of the viewport.

**Custom context bar (`.review-context-bar`)**

CVE id (mono), focus technique (`<Badge variant="accent2">`), priority
badge, TLP badge, age (`5m`, `2h`, `3d`). On the right: queue
navigation pills `← N-1 | N+1 →` showing the neighbouring queue items'
CVE ids; disabled at the ends of the list.

**Split pane (`.review-split`, 60 / 40)**

LEFT — editor pane:

* `<CodeMirror>` filling the available height with YAML grammar,
  one-dark theme, JetBrains Mono, line numbers, active-line highlight,
  fold gutter, `lineWrapping`. `value` bound to `editorYaml` state,
  `onChange` updates the local draft.
* Live validation: `editorYaml` change → 600 ms debounced
  `validateDraft(editorYaml)` → `setValidation(...)`. Bar at the bottom
  of the editor renders ✓ Valid / ✗ N error(s); errors + warnings
  expand into scrollable lists below.
* Inline reject: clicking "Reject" reveals a `.reject-input-row` with
  a required reason input + Cancel + Confirm. Confirm-disabled until
  the reason is non-blank.
* Action bar: Target dropdown (220 px, defaults to "Auto (routing
  engine)"; populated from `GET /sigma/targets`), Reject (danger),
  Edit + Approve (`active`, disabled when `editorYaml === originalYaml`),
  Approve (`success.active`, disabled when there are unsaved edits or
  validation is failing).

RIGHT — evidence pane (scrollable column of cards):

* **CVE Context** — `evidence-grid-2` of CVE ID / CVSS / KEV / Published /
  TLP, optional CVE description below. "Open chain →" link to the
  chain viewer when a CVE textual id is available.
* **Chain Context** — focus TTP card with technique id (bright),
  technique name, confidence badge, detection opportunity. Below:
  `← Previous TTP | N / total | Next TTP →` navigation through the
  chain context array (defaults to the focus TTP M16 picked, then
  walks ±N from there).
* **Source Evidence** — per-doc card with URL link, source-type badge,
  TLP badge, quality progress bar, and excerpt (M16's
  `source_documents[]` shape).
* **Similar Existing Rules** — top-N from M16's Qdrant search, each
  row showing the title (truncated, mono) and the cosine score as a
  percentage.
* **Priority Breakdown** — large priority score (28 px JetBrains Mono),
  priority badge in the card header, parsed reason list (splits the
  M14 reason string on `; , \n`, prefixes each clause with `+`).

**Action handlers**

* `onApprove` — POST `/queue/{id}/approve` with optional `target_id`
  override → toast announces PR URL on success → auto-advance to the
  next pending item (via `advanceAfterAction()` which drops the just-
  actioned row from the local list and selects the next one).
* `onEditAndApprove` — POST `/queue/{id}/edit` with `sigma_yaml` +
  optional `target_id`. The backend re-validates with pySigma and
  rolls into the approve flow on success. Failure toast surfaces the
  M16 error body (carries `errors[]` / `warnings[]` for the analyst
  to fix and retry).
* `onReject` — POST `/queue/{id}/reject` with reason → info toast →
  auto-advance.
* `advanceAfterAction()` — when there's no next item, refreshes the
  queue and clears selection. Otherwise drops the current row from
  the local cache and selects the next pending item.

**URL persistence**

The selected queue item's id is mirrored in the URL via
`?id=<uuid>` (using `useSearchParams`) so the queue is link-shareable
and a refresh keeps the current item in focus.

### Routes — [frontend/src/App.tsx](frontend/src/App.tsx)

* `/queue` joins the existing chromeless route group (with the
  ChainViewer + ATTACKMatrix) so the Review Queue can render its own
  `AppShell` with a custom context bar.
* `/rules` swaps the M1 placeholder for the new `<SigmaLibrary>`
  inside the standard `<ProtectedLayout>` (default chrome).
* The placeholder `Queue` and `Rules` exports are removed from
  [frontend/src/screens/Placeholders.tsx](frontend/src/screens/Placeholders.tsx).

## Tests / verification

### Sandbox-level pre-flight checks (runnable here)

* `npm install --no-audit --no-fund` — succeeded; lockfile updated.
* `npm install --save @uiw/react-codemirror @codemirror/lang-yaml` —
  21 packages added including `@codemirror/{state,view,language,
  theme-one-dark,commands,autocomplete,lint,search}`.
* `npx tsc -p . --noEmit` — 0 errors.
* `npm run build` — 0 errors, 2091 modules transformed,
  `dist/assets/index-*.css = 71.62 kB`,
  `dist/assets/index-*.js = 1.04 MB` (gzip 338.86 kB). The chunk-size
  warning is informational only — same warning the matrix screen
  already triggers; deferred to a future code-splitting pass.

### Runtime verification *not* runnable in this sandbox

| Done criterion | Verification |
|---|---|
| Library lists all rules with filtering | `npm run dev` then `/rules` — table populates from `GET /api/v1/rules`; status / technique / profile / origin / level / date filters narrow the result correctly |
| Detail sidebar shows full YAML + metadata + evaluations | click any row — sidebar opens with metadata KV grid, all sigma tags as badges, CodeMirror YAML viewer (line numbers, fold gutter, one-dark), then validation result (after Validate), then evaluations aggregate + per-row list |
| Validate button | click "Validate" in the detail footer — toast shows pass/fail; on fail the validation block lists every pySigma error |
| Copy YAML | click "Copy YAML" — clipboard receives the full body, success toast |
| Add evaluation | click "Add evaluation" — modal opens; submit with TP=12, FP/day=0.5, platform="windows", scale="enterprise", notes="false-positive-free in sample" — record lands in `rule_evaluations`; aggregate row recomputes in-place |
| Contribute prompt | after submit, the "Contribute to commons?" modal opens — "Contribute" POSTs `/evaluations/{id}/contribute`; toast shows submitted source count |
| Review Queue split pane functional | navigate to `/queue` — split-pane renders 60/40; CodeMirror loads the rule's YAML at JetBrains Mono; right pane lists CVE / chain / sources / similar / priority |
| Live YAML validation shows errors as you type | edit the YAML — after a 600ms quiet period the validation bar updates: missing `title:` → ✗ 1 error(s); adding `title: foo` → flips to ✓ Valid |
| Approve creates Git PR, returns URL in success toast | with a configured target — click "Approve" → toast shows "PR opened — https://github.com/owner/repo/pull/123"; row drops from the list; next pending item is selected |
| Auto-advance after action | every approve/edit/reject calls `advanceAfterAction()` which removes the actioned row from local state and selects the next id; URL updates to `?id=<next>` |
| Target selector defaults to routing engine pick but allows override | dropdown placeholder reads "Auto (routing engine)" until the analyst picks a target; pick "staging" → POST body carries `{target_id: "<staging-uuid>"}`; toast confirms `Approved → staging` |
| Evaluation form submits and toast confirms | (covered above) — empty body refused with a warning toast; valid body → success toast; contribute follow-up modal opens |

## Interfaces this module exposes

For dependent / future modules:

```typescript
// New screen exports.
import { SigmaLibrary } from "./screens/SigmaLibrary";
import { ReviewQueue } from "./screens/ReviewQueue";

// API client mirror types — typed against the real backend response shapes.
import {
  QueueItem, QueueDetail, QueueListResponse,
  ApproveResponse, RejectResponse, EditResponse,
  TTPContextOut, SourceDocSnippetOut, SimilarRuleHitOut,
  listQueue, getQueueItem, assignQueueItem,
  approveQueueItem, rejectQueueItem, editQueueItem,
} from "./api/queue";

import {
  RuleSummary, RuleDetail, ValidateResponse,
  EvaluationRecord, EvaluationAggregate, ContributeResponse,
  listRules, getRule, validateRule,
  listEvaluations, aggregateEvaluations, submitEvaluation, contributeEvaluation,
} from "./api/rules";

import { SigmaTarget, SigmaTargetListResponse, listSigmaTargets } from "./api/sigma_targets";
```

## What dependent modules need to know

* **M19 (WebSocket fan-out)** — when you wire the live counter on the
  sidebar's `Review Queue` item, replace the literal `7` in
  [frontend/src/components/Sidebar.tsx](frontend/src/components/Sidebar.tsx)
  with a hook read; the queue list shape is now stable
  (`QueueListResponse.total`).
* **M23 (Import Manager UI)** — the toast pattern in M22 is the
  template: announce success with a clickable link, demote
  partial-success outcomes to `warning`, surface backend `errors[]`
  inline in modals not toasts.
* **M24 (Settings)** — when surfacing the Sigma targets list, the
  shape is now `{targets: SigmaTarget[]}` (corrected from M18's
  `{items: ...}` stub) and includes `enabled` + `last_pr_at` for the
  health badge + freshness indicator.
* **Future "live pySigma validation" backend endpoint** — the
  `validateDraft()` helper in `ReviewQueue.tsx` is intentionally
  client-side today (M15's `/rules/{id}/validate` only checks the
  *persisted* row, not draft YAML). When a `POST /sigma/validate-yaml`
  endpoint that accepts a candidate body lands, swap the helper
  body — every other piece of plumbing (debounce, render, error list)
  stays.
* **`/queue?id=<uuid>` deep-linking** — the Review Queue persists the
  selected item in the URL via `useSearchParams`. The backend's
  M16 `GET /queue/{id}` works with any UUID; new entry points (e.g.
  the dashboard's "review queue" KPI card) can deep-link to a specific
  item.

## Deviations from spec / kickoff

* **Live YAML validation is client-side, not a `POST /api/v1/rules/{id}/validate`
  call as the kickoff said.** That backend endpoint validates the
  *persisted* YAML, not what the analyst is typing — sending the draft
  in the request body would be ignored. The client-side
  `validateDraft()` helper enforces the structural / required-field
  layer (title, id, logsource, detection.condition, status, level)
  on every keystroke; authoritative pySigma validation runs server-
  side at "Edit + Approve" time, where M16's edit endpoint returns
  the full pySigma error body on a 400. Swap-in path for a real
  `POST /sigma/validate-yaml` endpoint is documented above. Trade-off
  documented; behaviour matches the spec's user-visible promise
  (validation feedback as you type, errors block approve).
* **The Approve button is disabled when there are unsaved edits.** The
  kickoff lists Approve / Edit+Approve / Reject as siblings — but if
  the analyst has typed in the editor and clicks Approve (which posts
  the unmodified persisted YAML), they'd silently lose their edits.
  We disable Approve in that state and surface "Use Edit + Approve to
  send your changes." in the button's `title=`. Avoids a mistake an
  analyst would only catch after the PR is open.
* **The Approve button is also disabled when the live validator is
  red.** Same rationale — sending a draft we know won't pass pySigma
  to the backend produces a guaranteed 400. The Edit + Approve button
  is *not* gated on validation since the backend is the authority and
  may accept what our client-side check rejected; the analyst can
  still force-submit and let M16 surface the real diagnostics.
* **Inline reject UI instead of a modal.** The kickoff says "REJECT
  → inline reason input → confirm". We render the reason field as a
  slide-down strip above the action bar (`.reject-input-row`); the
  surrounding action bar greys out the other buttons until the
  analyst confirms or cancels. Avoids stacking another modal on top
  of CodeMirror.
* **`Queue navigation: ← N-1 | N+1 →`** uses CVE textual ids on the
  pills (so the analyst sees what's next), not just chevrons. Disabled
  at the ends of the queue.
* **`?id=<uuid>` URL persistence.** Not in the kickoff — but a deep-
  linked queue item is a common workflow (dashboard "X rules pending"
  card → specific item). The selection is mirrored to the URL on
  every change; navigation between items updates the URL too.
* **Dropdown placeholder reads "Auto (routing engine)"** instead of
  hard-coding the routing-engine pick. The dropdown is `null`-valued
  until the analyst overrides; a `null` `target_id` lets M16's routing
  engine pick the right repo per the rule's tags. The kickoff says
  "default = routing-engine pick"; surfacing the engine's pick would
  require an extra `POST /queue/{id}/preview-target` endpoint that
  doesn't exist in v1.
* **Sigma Library: status filter is multi-select** (matches CLAUDE.md
  §16 wireframe + the kickoff's "status multi-select"). The backend
  `GET /rules?status=` only takes one value, so when the analyst
  picks ≥2 statuses we send the first to the server and filter the
  rest client-side over the response. Acceptable today (the rule
  table is bounded by `limit=500` per the request); a future
  enhancement would have the backend accept a comma-separated list.
* **Date range, level filters: client-side.** Same reason —
  `GET /rules` doesn't expose these knobs. We filter the server
  response in-memory. The 500-row bound keeps this honest for v1.
* **Detail sidebar's CodeMirror is read-only.** The kickoff ambiguously
  says "Full Sigma YAML in CodeMirror (read-only, JetBrains Mono,
  dark theme)". The same library powers the editable editor on the
  Review Queue; here we set `EditorView.editable.of(false)` so an
  analyst can browse the YAML safely without pressing the wrong key.
* **Evaluation modal — "scale" is a Dropdown, "platform" is text.**
  M17's enum allowlist constrains scale to `{small, medium, enterprise}`
  but platform is free-text (some operators use `windows-2022`,
  others `EC2-amazonlinux`). We expose Dropdown for the enum and
  free-text for the open field.
* **`Add evaluation` lives on the Sigma Library detail panel, not the
  Review Queue.** The kickoff lists it under Sigma Library
  ("Evaluations section: list + aggregate stats + 'Add Evaluation'
  button"). Moving it to the queue would tie evaluation submission
  to a still-pending item; the workflow is "approve → deploy →
  observe → record evaluation" and the queue item is gone by step 2.
* **Unused M18 placeholder exports removed.** `Queue` and `Rules`
  shells from
  [frontend/src/screens/Placeholders.tsx](frontend/src/screens/Placeholders.tsx)
  are deleted now that real screens replaced them. The `Imports`,
  `Prompts`, `Settings` placeholders stay until M23 / M24 land.
* **Sidebar review-queue badge stays at the literal `7` from M18.**
  Wiring it to a live count is a separate concern (would need a
  shared `useQueueCount` hook + a poll / WebSocket subscription). The
  M18 stub already documents that the literal will be swapped when a
  hook lands; M22 doesn't take that on.
* **Bundle size: ~1.04 MB (gzip 338 KB).** Adding CodeMirror +
  one-dark theme + YAML grammar grew the bundle from M18's
  ~235 KB to 1.04 MB. The chunk-size-limit warning fires; deferred to
  a future code-splitting pass (`React.lazy` around the Review Queue
  + Sigma Library would bring the initial bundle back under the
  500 KB recommendation). Acceptable today — the screens are the
  primary analyst workflow and lazy-loading them adds a click-time
  delay.

## Known TODOs (owned by other modules)

* **M19 (WebSocket fan-out)** — wire `rule_approved` / `rule_rejected`
  events into the queue list so the analyst sees the row disappear
  the moment another reviewer actions it. Today the local cache only
  updates on the local action; another reviewer's approve appears
  after a manual refresh.
* **M19 (queue badge)** — replace the literal `7` on the Review Queue
  sidebar item with a count from `GET /queue?status=pending&limit=1`
  (or a dedicated `/queue/count` endpoint). Subscribe to
  `rule_approved` + `rule_rejected` to bump the count down.
* **M23 / M24** — keep the toast-with-link pattern (`announceApprove`
  in `ReviewQueue.tsx`) for "background action completed, here's the
  artifact" interactions: imports, PR re-submissions, prompt
  promotions.
* **Sigma library: dedup column.** M15 surfaces `content_hash`; M22
  could surface a "duplicate of <existing>" badge when a new row
  matches an existing one (M15's "no content-hash dedup on regenerate"
  risk). Deferred — needs a backend `GET /rules?content_hash=` knob.
* **Backend `POST /sigma/validate-yaml`** — accepting a draft body
  would let the Review Queue's live validator reflect actual pySigma
  errors instead of the structural-only client-side check.
* **Edit history.** M16's edit overwrites the YAML in place; the
  audit row records `content_hash` before/after but not the body.
  When that ships, the Review Queue editor could surface a "diff vs.
  original" button.

## Risks / known weaknesses

* **CodeMirror's `lineWrapping` + 200-char Sigma rules.** Long YAML
  values (regex patterns in detection blocks) wrap awkwardly inside
  the 60% editor pane on smaller laptops. The fix is to add a
  horizontal scroll override on `.cm-scroller` for narrow viewports;
  deferred until an analyst complains.
* **Approve button gating on client-side validation.** A pathological
  YAML that passes our structural check but fails pySigma server-side
  would still hit the backend and produce a 400. The toast surfaces
  the message; the analyst rolls into Edit + Approve to retry. Worst
  case is one wasted POST.
* **Auto-advance dropping the just-actioned row from local state**
  works because we know a successful approve / reject moves the
  underlying queue row to a terminal status. If a future "soft reject"
  lands (queue stays open), this assumption breaks; we'd need to
  refresh the list rather than splice locally.
* **Sigma target list is fetched once on mount.** A target added in
  Settings while the Review Queue is open won't appear in the
  dropdown until the screen reloads. Acceptable — targets change
  rarely; users typically refresh after a config change.
* **`useSearchParams` URL update fires on every selection change.**
  Browser history accumulates entries (forward/back through the
  queue). For a typical 5-rule review session that's fine; for a
  100-rule batch the history bloats. A future enhancement: use
  `setSearchParams(..., { replace: true })`.
* **Evaluation modal numeric coercion is permissive.** `Number("")` →
  `NaN`, then we drop it. `Number("1.5")` for TPs would be floored
  to 1 (consistent with M17's int validator). A garbage input like
  "abc" silently drops the field; M17's backend will accept the
  remaining fields and the modal toasts success. A future tightening:
  show field-level validation under each input.
* **Read-only CodeMirror in the Library uses the same theme as the
  editor.** A future enhancement: a softer, less-syntax-coloured
  theme for the library's "view-only" pane to visually distinguish it
  from the queue's "edit-this-now" pane.

## Outstanding questions

* **Should the Review Queue editor lock when another reviewer
  approves the same item?** Today two reviewers can both edit + click
  Approve; the second hits a 409 from M16's `_guard_action` check.
  Would a soft-lock via WebSocket-broadcast `queue.assigned` prevent
  the duplicate work?
* **Should the Sigma Library's filter set persist in the URL?** Today
  filters reset on navigation away. Persisting them via
  `useSearchParams` would let analysts share "the Sigma Library
  filtered to KEV-only critical rules" via a URL.
* **Should the evaluation modal pre-populate fields from the rule's
  context?** A rule with `logsource.product=windows` could pre-fill
  the platform field. Marginal value; defer until analysts ask.
* **Should the queue badge differentiate KEV-bearing items?** Today
  the literal `7` is undifferentiated. A future enhancement: a small
  red dot on the badge when any pending item is for a KEV CVE.
* **Should the Approve toast include a "Copy PR URL" affordance?**
  Today the toast renders the URL as a clickable link. A copy button
  would simplify "paste into Slack" workflows.

---

## Phase 6 scope catch-up applied (2026-05-13)

Closes the two silent partials surfaced by `SCOPE_REVIEW_M22_M24.md`.
See `SCOPE_CATCHUP_M22_M24_DONE.md` for the full record.

* **Products row in Review Queue CVE context card.** The kickoff
  listed `products` as the fifth field on the card; the original
  build shipped CVE / CVSS / KEV / Published / TLP. Backend
  `_cve_summary` now includes `affected_products`; the card renders a
  comma-separated mono row truncated at 60 chars with a tooltip
  showing the full list. Empty/missing → em dash.
* **References row in Sigma Library detail sidebar.** The kickoff
  listed `references` as a metadata item; the original build only
  exposed them inside the YAML body. The detail sidebar now parses
  the block-form `references:` list from the rule's YAML and renders
  each entry as a clickable link (target="_blank", rel="noopener
  noreferrer"). Section omitted entirely when the key is absent —
  no "References: —" placeholder.

The Author metadata row remains the literal `"FragChain"` per the
original deviation note; M15 doesn't emit an author field today.
That row will read from payload once M15 adds it (v1.x backlog).
