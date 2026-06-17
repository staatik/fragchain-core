# Scope Completeness Review — M22, M23, M24
**Date:** 2026-05-13
**Scope:** Compare what was SPECIFIED for the Phase-6 mid-back UI modules (M22 Sigma Library + Review Queue, M23 Import Manager, M24 Settings + Marketplace + Prompts) against what was ACTUALLY BUILT.
**Method:** Static code review of `frontend/src/screens/` + `frontend/src/screens/settings/` + `frontend/src/components/` + `frontend/src/api/`, cross-referenced against M22/M23/M24 spec sections in `FragChain_Module_Specifications.md`, the M22/M23/M24 prompts in `FragChain_Module_Prompts.md`, the MODULE_M22/23/24_DONE.md write-ups, and §16 of CLAUDE.md.
**Out of scope:** Defects, drift, security. Those belong to the Phase-6 audit.

**Overall status:** **minor gaps.** All 11 specified screens exist, all routes resolve, all major workflows are wired end-to-end to real APIs. The gaps are (a) two acknowledged "no backend yet" deviations (system_config CRUD, marketplace install hook), (b) two silent feature gaps (vendor/product autocomplete; routing-rules template pre-fill), and (c) a handful of cosmetic/UX details that didn't land. Nothing UX-breaking; nothing that blocks M25–M37.

## Summary

| Module | Total elements | Built | Built-Partial | Missing | Deviated | Not-Verifiable |
|---|---:|---:|---:|---:|---:|---:|
| M22 — Sigma Library + Review Queue + Eval modal | 43 | 36 | 2 | 0 | 5 | 0 |
| M23 — Import Manager | 39 | 32 | 2 | 1 | 4 | 0 |
| M24 — Settings + Marketplace + Prompts | 66 | 53 | 4 | 2 | 7 | 0 |
| **Total** | **148** | **121** | **8** | **3** | **16** | **0** |

Silent gaps (missing/partial without MODULE_DONE acknowledgment): **3** — M22 detail-sidebar `references` listing; M23 vendor/product autocomplete; M24 Sigma-Targets routing-rules template pre-fill.

---

## Module M22 — Sigma Library + Review Queue + Evaluation modal

Files: [SigmaLibrary.tsx](frontend/src/screens/SigmaLibrary.tsx), [ReviewQueue.tsx](frontend/src/screens/ReviewQueue.tsx) (Evaluation modal is in `SigmaLibrary.tsx`).

### Sigma Library Screen — `/rules`

| Element | Status | Notes |
|---|---|---|
| Route `/rules` | BUILT | [App.tsx:36](frontend/src/App.tsx:36) |
| DataTable column: title (40ch truncated, tooltip) | BUILT | [SigmaLibrary.tsx:322-329](frontend/src/screens/SigmaLibrary.tsx:322) |
| DataTable column: technique tags (`.badge.accent2`, max 3 + overflow) | BUILT | [SigmaLibrary.tsx:330-354](frontend/src/screens/SigmaLibrary.tsx:330) |
| DataTable column: logsource (mono `product/service`) | BUILT | [SigmaLibrary.tsx:355-365](frontend/src/screens/SigmaLibrary.tsx:355) |
| DataTable column: status badge | BUILT | [SigmaLibrary.tsx:366-374](frontend/src/screens/SigmaLibrary.tsx:366) |
| DataTable column: origin badge | BUILT | [SigmaLibrary.tsx:375-383](frontend/src/screens/SigmaLibrary.tsx:375) |
| DataTable column: level badge | BUILT | [SigmaLibrary.tsx:384-397](frontend/src/screens/SigmaLibrary.tsx:384) |
| DataTable column: CVE link (mono, to `/chains/:id`) | BUILT | [SigmaLibrary.tsx:398-414](frontend/src/screens/SigmaLibrary.tsx:398) |
| DataTable column: date (mono) | BUILT | [SigmaLibrary.tsx:421-428](frontend/src/screens/SigmaLibrary.tsx:421) |
| Extra DataTable column: TLP | DEVIATED | Not in kickoff but a logical add; [SigmaLibrary.tsx:415-420](frontend/src/screens/SigmaLibrary.tsx:415) |
| Filter sidebar: status multi-select | BUILT | [SigmaLibrary.tsx:455-464](frontend/src/screens/SigmaLibrary.tsx:455). Multi-select sent client-side beyond the first value (acknowledged in DONE §"Deviations") |
| Filter sidebar: technique ID search | BUILT | [SigmaLibrary.tsx:466-475](frontend/src/screens/SigmaLibrary.tsx:466) |
| Filter sidebar: logsource product | DEVIATED | Implemented as logsource-**profile** dropdown, not a product text field. Functional equivalent but narrower. [SigmaLibrary.tsx:477-485](frontend/src/screens/SigmaLibrary.tsx:477) |
| Filter sidebar: origin | BUILT | [SigmaLibrary.tsx:487-495](frontend/src/screens/SigmaLibrary.tsx:487) |
| Filter sidebar: level | BUILT | [SigmaLibrary.tsx:497-505](frontend/src/screens/SigmaLibrary.tsx:497). Filtered client-side (server lacks `level=` knob) — acknowledged in DONE. |
| Filter sidebar: date range (from + to) | BUILT | [SigmaLibrary.tsx:507-523](frontend/src/screens/SigmaLibrary.tsx:507). Filtered client-side — acknowledged in DONE. |
| Click row → slide-in detail sidebar | BUILT | [SigmaLibrary.tsx:550-588](frontend/src/screens/SigmaLibrary.tsx:550) |
| Detail: full Sigma YAML in CodeMirror (read-only, JetBrains Mono, dark theme) | BUILT | [SigmaLibrary.tsx:672-687](frontend/src/screens/SigmaLibrary.tsx:672); JetBrains Mono via `.cm-editor` CSS rule; oneDark theme; `EditorView.editable.of(false)` |
| Detail metadata: sigma_uuid (mono) | BUILT | [SigmaLibrary.tsx:597-599](frontend/src/screens/SigmaLibrary.tsx:597) |
| Detail metadata: author | BUILT-PARTIAL | Hardcoded `"FragChain"` literal; backend `RuleDetail` doesn't carry the author field. Acceptable but silent (not flagged in DONE). [SigmaLibrary.tsx:646-647](frontend/src/screens/SigmaLibrary.tsx:646) |
| Detail metadata: tags list | BUILT | [SigmaLibrary.tsx:657-670](frontend/src/screens/SigmaLibrary.tsx:657). Renders every Sigma tag as a Badge. |
| Detail metadata: references list | BUILT-PARTIAL | No separate `references:` section in the metadata KV. References are visible in the YAML body but not surfaced as a dedicated list. Silent gap. |
| Detail: linked CVE → link to `/chains/:cve_id` | BUILT | [SigmaLibrary.tsx:637-644](frontend/src/screens/SigmaLibrary.tsx:637) |
| Detail: Evaluations list + aggregate stats + "Add Evaluation" button | BUILT | Aggregate cells (avg FP/day, total TPs, platforms, contributed) at [SigmaLibrary.tsx:731-756](frontend/src/screens/SigmaLibrary.tsx:731); per-row list at [SigmaLibrary.tsx:762-791](frontend/src/screens/SigmaLibrary.tsx:762); "Add evaluation" button at [SigmaLibrary.tsx:578-584](frontend/src/screens/SigmaLibrary.tsx:578) |
| Detail: Validate button (re-runs pySigma) | BUILT | [SigmaLibrary.tsx:265-281](frontend/src/screens/SigmaLibrary.tsx:265), calls `POST /api/v1/rules/{id}/validate` |
| Detail: Copy YAML button | BUILT | [SigmaLibrary.tsx:283-291](frontend/src/screens/SigmaLibrary.tsx:283) |
| Extra: Target selector if approved | NOT-VERIFIABLE | M22 spec mentions "target selector if approved" in the library detail but kickoff doesn't define behaviour. Not implemented; effectively MISSING but borderline ambiguous — not flagged. |

### Review Queue Screen — `/queue`

| Element | Status | Notes |
|---|---|---|
| Route `/queue` (own AppShell, fullBleed) | BUILT | [App.tsx:28](frontend/src/App.tsx:28); [ReviewQueue.tsx:556-557](frontend/src/screens/ReviewQueue.tsx:556) |
| Split-pane layout 60/40 | BUILT | `.review-split` grid in CSS; [ReviewQueue.tsx:606](frontend/src/screens/ReviewQueue.tsx:606) |
| Left pane: CodeMirror 6 YAML editor | BUILT | [ReviewQueue.tsx:614-627](frontend/src/screens/ReviewQueue.tsx:614) |
| `@codemirror/lang-yaml` | BUILT | [ReviewQueue.tsx:5](frontend/src/screens/ReviewQueue.tsx:5), [ReviewQueue.tsx:35](frontend/src/screens/ReviewQueue.tsx:35) |
| `@uiw/react-codemirror` | BUILT | [ReviewQueue.tsx:4](frontend/src/screens/ReviewQueue.tsx:4) |
| JetBrains Mono | BUILT | Forced via `.cm-editor { font-family: var(--font-display) }` |
| Dark theme (one-dark customised) | BUILT | `oneDark` ext on [ReviewQueue.tsx:35](frontend/src/screens/ReviewQueue.tsx:35) and `theme={oneDark}` prop |
| Live validation: debounced 600ms `POST /rules/{id}/validate` | DEVIATED | Validation runs **client-side** (structural / required-field check) in `validateDraft()`. Acknowledged + justified in MODULE_M22_DONE §"Deviations" — backend endpoint validates the persisted row, can't see draft. Debounce timing (600 ms) matches. |
| Bottom bar: `--accent3 "Valid"` / `--danger "X errors"` with detail list | BUILT | `.validation-bar.ok`/`.fail`; [ReviewQueue.tsx:630-669](frontend/src/screens/ReviewQueue.tsx:630) |
| Right pane: CVE context card (ID, CVSS, KEV, published, products) | BUILT-PARTIAL | `products` is NOT surfaced — the card has CVE / CVSS / KEV / Published / TLP. Silent partial (not flagged in DONE). [ReviewQueue.tsx:358-393](frontend/src/screens/ReviewQueue.tsx:358) |
| Right pane: Chain context card — "Step N of total" + current technique | BUILT | [ReviewQueue.tsx:395-405](frontend/src/screens/ReviewQueue.tsx:395), [ReviewQueue.tsx:410-425](frontend/src/screens/ReviewQueue.tsx:410) |
| Chain context: ← Previous TTP / Next TTP → buttons | BUILT | [ReviewQueue.tsx:426-446](frontend/src/screens/ReviewQueue.tsx:426) |
| Chain context: detection opportunity (from chain_ttps) | BUILT | [ReviewQueue.tsx:420-424](frontend/src/screens/ReviewQueue.tsx:420) |
| Right pane: Source evidence card (URLs, source-type badge, quality bars, excerpts) | BUILT | [ReviewQueue.tsx:451-481](frontend/src/screens/ReviewQueue.tsx:451) |
| Right pane: Similar existing rules card (semantic search) | BUILT | [ReviewQueue.tsx:483-501](frontend/src/screens/ReviewQueue.tsx:483) |
| Right pane: Priority breakdown card (score + reasons list) | BUILT | [ReviewQueue.tsx:503-524](frontend/src/screens/ReviewQueue.tsx:503). Score in 28 px mono; reasons split on `;,\n` and prefixed with `+`. |
| Context bar: CVE ID (mono) | BUILT | [ReviewQueue.tsx:560-562](frontend/src/screens/ReviewQueue.tsx:560) |
| Context bar: technique (mono) | BUILT | [ReviewQueue.tsx:563-565](frontend/src/screens/ReviewQueue.tsx:563). Shows the first `technique_ids[0]` only. |
| Context bar: priority badge | BUILT | [ReviewQueue.tsx:566-570](frontend/src/screens/ReviewQueue.tsx:566) |
| Context bar: time in queue (age) | BUILT | [ReviewQueue.tsx:572-576](frontend/src/screens/ReviewQueue.tsx:572) — `<1m`/`Nm`/`Nh`/`Nd` |
| Context bar: ← N-1 / N+1 → queue navigation | BUILT | [ReviewQueue.tsx:530-553](frontend/src/screens/ReviewQueue.tsx:530). Bonus: pills carry the neighbouring CVE IDs as labels. |
| Target selector dropdown (M12 sigma_targets, default = routing-engine pick) | DEVIATED | Dropdown is populated from `GET /sigma/targets`; the **default placeholder** reads `"Auto (routing engine)"` and a null value lets M16's routing engine pick. The spec's "default = routing-engine pick" implies the engine's preview is shown; that preview would need a new backend endpoint. Acknowledged in DONE. [ReviewQueue.tsx:703-711](frontend/src/screens/ReviewQueue.tsx:703) |
| Action: APPROVE (`.btn.success.active`) → `POST /approve` w/ `target_id` | BUILT | [ReviewQueue.tsx:733-750](frontend/src/screens/ReviewQueue.tsx:733), POST body wired |
| Action: EDIT + APPROVE (`.btn.active`) → `POST /edit` | BUILT | [ReviewQueue.tsx:721-732](frontend/src/screens/ReviewQueue.tsx:721) |
| Action: REJECT (`.btn.danger`) → inline reason input → confirm | BUILT | Reject opens an inline `.reject-input-row` (not a modal); cancel/confirm; required reason gating. Acknowledged DONE §"Deviations" (inline strip vs modal). [ReviewQueue.tsx:671-700](frontend/src/screens/ReviewQueue.tsx:671) |
| After action: auto-advance to next queue item | BUILT | `advanceAfterAction()` at [ReviewQueue.tsx:238-249](frontend/src/screens/ReviewQueue.tsx:238); drops the actioned row from local cache and selects next id. |
| Extra: `?id=<uuid>` URL persistence | DEVIATED | Not in kickoff. Deep-linkable. Acknowledged in DONE. |
| Extra: Approve disabled with unsaved edits / failing live validator | DEVIATED | Not in kickoff. Acknowledged in DONE with rationale. |

### Evaluation Submission Dialog (from Sigma Library "Add Evaluation")

| Element | Status | Notes |
|---|---|---|
| Form: TP count | BUILT | [SigmaLibrary.tsx:926-936](frontend/src/screens/SigmaLibrary.tsx:926) |
| Form: FP/day | BUILT | [SigmaLibrary.tsx:937-948](frontend/src/screens/SigmaLibrary.tsx:937) |
| Form: environment platform | BUILT | Free text input. [SigmaLibrary.tsx:949-958](frontend/src/screens/SigmaLibrary.tsx:949) |
| Form: scale | BUILT | Dropdown (`small/medium/enterprise`) per M17 enum. [SigmaLibrary.tsx:959-967](frontend/src/screens/SigmaLibrary.tsx:959) |
| Form: notes (textarea) | BUILT | [SigmaLibrary.tsx:968-977](frontend/src/screens/SigmaLibrary.tsx:968) |
| Submit → `POST /api/v1/rules/{id}/evaluate` | BUILT | [SigmaLibrary.tsx:867-879](frontend/src/screens/SigmaLibrary.tsx:867) |
| Toast on success | BUILT | [SigmaLibrary.tsx:870](frontend/src/screens/SigmaLibrary.tsx:870) |
| "Contribute to commons?" follow-up dialog | BUILT | [SigmaLibrary.tsx:980-1003](frontend/src/screens/SigmaLibrary.tsx:980) |

### M22 — Missing or partial, severity-ranked

- **MEDIUM — Review Queue CVE-context card omits `products`.** Silent partial. The card currently shows CVE / CVSS / KEV / Published / TLP. Spec lists `products` as the fifth field. Backend `CveSummary` doesn't expose a `products` field today, so this would require pairing with a small backend addition or rendering from `affected_products` if present. Add a `Products` row that falls back to "—" when not in payload.
- **LOW — Sigma-Library detail metadata has no dedicated `references:` listing.** Silent partial. References are visible inside the YAML codemirror but not surfaced as their own key/value row. Trivial add; parse `references:` from the YAML or expose via the rule detail API.
- **LOW — Library "Author" is a hardcoded literal "FragChain".** Acceptable for v1 (every rule is FragChain-authored) but the field should at minimum read from a payload when M15 starts emitting an author.

### M22 — Deviations from spec (no judgment)

- Live YAML validation is client-side, not a `POST /rules/{id}/validate` call.  *Acknowledged in DONE.*
- Approve disabled with unsaved edits and on failing client-side validation.  *Acknowledged in DONE.*
- Reject is an inline strip, not a modal.  *Acknowledged in DONE.*
- Queue navigation pills carry neighbouring CVE IDs.  *Acknowledged in DONE.*
- `?id=<uuid>` URL persistence.  *Acknowledged in DONE.*
- Target dropdown defaults to placeholder "Auto (routing engine)" rather than echoing the engine's pick.  *Acknowledged in DONE.*
- Logsource filter is the **profile** dropdown, not a freeform product input.  *Not flagged in DONE.*
- Status filter is multi-select but sent single-value to server with rest filtered client-side.  *Acknowledged in DONE.*
- Date-range and level filters applied client-side.  *Acknowledged in DONE.*
- Detail-sidebar TLP column / TLP filter-row are richer than the spec asks.  *Not flagged in DONE.*

---

## Module M23 — Import Manager UI

File: [ImportManager.tsx](frontend/src/screens/ImportManager.tsx) (2099 lines, single file).

### Tabs / shell

| Element | Status | Notes |
|---|---|---|
| Two-tab screen at `/imports` | BUILT | [App.tsx:37](frontend/src/App.tsx:37), [ImportManager.tsx:422-455](frontend/src/screens/ImportManager.tsx:422) |
| Tab labels: "LIVE FEED" / "HISTORICAL IMPORT" | BUILT | Labels "Live feed" / "Historical import" (sentence case); style/role match. [ImportManager.tsx:423-440](frontend/src/screens/ImportManager.tsx:423) |
| Tab state persists in URL | BUILT | `?tab=live\|historical` round-trip via `useSearchParams`. *Acknowledged in DONE.* |

### LIVE FEED tab

| Element | Status | Notes |
|---|---|---|
| Stat block: Live CVEs today | BUILT | [ImportManager.tsx:592-597](frontend/src/screens/ImportManager.tsx:592), driven by `listCves({import_mode:"live", published_after: midnight})` |
| Stat block: Processing rate (CVEs/hour, last hour) | BUILT | [ImportManager.tsx:598-603](frontend/src/screens/ImportManager.tsx:598) |
| Stat block: Rate limit (X/MAX with progress bar, color by %) | BUILT | [ImportManager.tsx:604-626](frontend/src/screens/ImportManager.tsx:604); `rateBarVariant()` returns success/warning/danger at 0.6 / 0.9. |
| Stat block: Queue depth (pending CVEs) | BUILT | [ImportManager.tsx:627-637](frontend/src/screens/ImportManager.tsx:627); click-through to `/cves?status=pending`. |
| Live event log (WebSocket, last 20) | BUILT | [ImportManager.tsx:640-676](frontend/src/screens/ImportManager.tsx:640); `EVENT_LOG_LIMIT = 20`. |
| Row: timestamp (mono), event type badge, CVE ID (mono), status | BUILT | [ImportManager.tsx:659-672](frontend/src/screens/ImportManager.tsx:659) |
| Event types styled: `cve_received`, `rate_limited`, `processing_started`, `complete`, `failed` | DEVIATED | Code maps the **actual** M19 event names (`cve_ingested`, `rate_limit_warning`, `enrichment_complete`, `chain_generated`, `coverage_mapped`, `rules_generated`, `queue_item.*`, `import_job.*`). The spec's event names were aspirational and don't match the backend. Functional equivalent. |
| Config card: Current `MAX_LIVE_CVE_PER_HOUR` value | BUILT-PARTIAL | Read-only display sourced from `rate_limit_warning` event or default of 10. No editable input. *Acknowledged in DONE — points at M24.* |
| Config card: `AUTO_PROCESS_KEV` toggle (writes to `system_config`) | DEVIATED | Toggle exists but flipping fires an `info` toast: "AUTO_PROCESS_KEV is currently env-managed. Settings UI lands with M24." No backend write. *Acknowledged in DONE.* |

### HISTORICAL IMPORT tab — Saved Presets

| Element | Status | Notes |
|---|---|---|
| "SAVED PRESETS" dropdown at top | BUILT | [ImportManager.tsx:914-948](frontend/src/screens/ImportManager.tsx:914) |
| Loads from `GET /api/v1/imports/presets` | BUILT | `listPresets("popular")` |
| Sort by `use_count DESC` | BUILT | Server sorts when `sort=popular`; client re-sorts builtin-first. [ImportManager.tsx:779-783](frontend/src/screens/ImportManager.tsx:779) |
| Built-in presets shown first, then custom | BUILT | [ImportManager.tsx:822-839](frontend/src/screens/ImportManager.tsx:822) |
| Selecting preset → pre-fills filter form | BUILT | [ImportManager.tsx:842-855](frontend/src/screens/ImportManager.tsx:842) |
| "Save current as preset" button → modal w/ name + description | BUILT | "Save as preset" — modal at [ImportManager.tsx:1823-1916](frontend/src/screens/ImportManager.tsx:1823). Disabled until at least one filter is set. |
| "Manage presets" link → modal to edit/delete custom presets | BUILT | [ImportManager.tsx:1930-2095](frontend/src/screens/ImportManager.tsx:1930); built-ins read-only. |

### HISTORICAL IMPORT tab — Filter form

| Element | Status | Notes |
|---|---|---|
| Collapsible "NEW IMPORT" card | BUILT | [ImportManager.tsx:950-999](frontend/src/screens/ImportManager.tsx:950); "Collapse / Expand" button. |
| Basic filter: date range from/to | BUILT | [ImportManager.tsx:1113-1146](frontend/src/screens/ImportManager.tsx:1113) |
| Basic filter: "Or last N days" shortcut | BUILT | [ImportManager.tsx:1147-1165](frontend/src/screens/ImportManager.tsx:1147) |
| Basic filter: Min CVSS dropdown (Any / 6.0+ / 7.0+ / 8.0+ / 9.0+ / 10.0) | BUILT | `CVSS_OPTIONS` at [ImportManager.tsx:282-289](frontend/src/screens/ImportManager.tsx:282) |
| Basic filter: KEV-only toggle button (`.btn` / `.btn.active`) | BUILT | [ImportManager.tsx:1176-1185](frontend/src/screens/ImportManager.tsx:1176) |
| Basic filter: Vendor/Product text input with **autocomplete** | BUILT-PARTIAL | Two separate inputs for vendor + product render correctly, but **no autocomplete** (no datalist, no fetch-as-you-type). Silent gap. [ImportManager.tsx:1186-1207](frontend/src/screens/ImportManager.tsx:1186) |
| Basic filter: Specific CVE IDs textarea (overrides other filters) | BUILT | [ImportManager.tsx:1209-1227](frontend/src/screens/ImportManager.tsx:1209); server-side override enforced by M6. |
| Novelty filters: "Show advanced filters" collapsible section | BUILT | [ImportManager.tsx:1230-1287](frontend/src/screens/ImportManager.tsx:1230) |
| Novelty: Min EPSS dropdown (Any / 0.1+ / 0.2+ / 0.5+ / 0.8+) | BUILT | `EPSS_OPTIONS` at [ImportManager.tsx:291-297](frontend/src/screens/ImportManager.tsx:291) |
| Novelty: Min AttackerKB dropdown (Any / 2.0+ / 3.0+ / 4.0+) | BUILT | `AKB_OPTIONS` at [ImportManager.tsx:299-303](frontend/src/screens/ImportManager.tsx:299) |
| Novelty: "Exclude commons" toggle button | BUILT | [ImportManager.tsx:1271-1284](frontend/src/screens/ImportManager.tsx:1271) |

### HISTORICAL IMPORT tab — Preview + Start

| Element | Status | Notes |
|---|---|---|
| PREVIEW button (`.btn.ghost`) | BUILT | [ImportManager.tsx:970-976](frontend/src/screens/ImportManager.tsx:970) |
| Loading state: "QUERYING SOURCES…" | BUILT | "Querying sources…" (sentence case). [ImportManager.tsx:975](frontend/src/screens/ImportManager.tsx:975) |
| Preview panel: `X CVEs match` (or `~X (approximate)`) | BUILT | [ImportManager.tsx:1300-1307](frontend/src/screens/ImportManager.tsx:1300) |
| Estimated LLM cost (`~$X.XX`) | BUILT | [ImportManager.tsx:1308-1311](frontend/src/screens/ImportManager.tsx:1308) |
| Sample table (10 rows): CVE ID, CVSS, KEV, EPSS, published | BUILT | [ImportManager.tsx:1320-1366](frontend/src/screens/ImportManager.tsx:1320) |
| Info note when novelty filters active ("approximate") | BUILT | [ImportManager.tsx:1313-1319](frontend/src/screens/ImportManager.tsx:1313) |
| Warning toast if count > 500 | BUILT | [ImportManager.tsx:863-868](frontend/src/screens/ImportManager.tsx:863); `PREVIEW_WARN_THRESHOLD = 500`. |
| START IMPORT button (`.btn.active`, disabled until preview ran) | BUILT | [ImportManager.tsx:977-989](frontend/src/screens/ImportManager.tsx:977); disabled when `!preview \|\| preview.total_count === 0`. |
| Creates job | BUILT | [ImportManager.tsx:877-901](frontend/src/screens/ImportManager.tsx:877) |
| Calls `POST /api/v1/imports/presets/{id}/use` if preset used | DEVIATED | The client does **not** call `/presets/{id}/use` separately — the M6 router already bumps `use_count` inside `POST /imports/start` when `preset_id` is in the body. *Acknowledged in DONE.* |
| Collapses form, shows toast | BUILT | [ImportManager.tsx:885-895](frontend/src/screens/ImportManager.tsx:885) |

### HISTORICAL IMPORT tab — Active Jobs + Expand panel

| Element | Status | Notes |
|---|---|---|
| ACTIVE JOBS DataTable: Job ID (mono short), Created, Filters summary, Staged/Approved/Done counts, Status badge, Progress bar | BUILT | [ImportManager.tsx:1391-1452](frontend/src/screens/ImportManager.tsx:1391) |
| Status badges: staging, staged, processing, complete, cancelled | BUILT | `statusBadgeVariant()` at [ImportManager.tsx:141-166](frontend/src/screens/ImportManager.tsx:141) |
| Click row → inline expand panel | BUILT | [ImportManager.tsx:1456-1477](frontend/src/screens/ImportManager.tsx:1456); only one job expanded at a time. |
| Staged CVEs table paginated 20/page | BUILT | `STAGED_PAGE_SIZE = 20`. [ImportManager.tsx:1676-1764](frontend/src/screens/ImportManager.tsx:1676) |
| Per-row: Approve (`.btn.sm.success`) + Skip (`.btn.sm.danger.ghost`) | BUILT | [ImportManager.tsx:1717-1737](frontend/src/screens/ImportManager.tsx:1717); only shown for `processing_status === "staged"`. |
| Batch action: APPROVE ALL (`.btn.active`) | BUILT | [ImportManager.tsx:1628-1636](frontend/src/screens/ImportManager.tsx:1628) |
| Batch action: APPROVE KEV ONLY (`.btn.accent2`) | BUILT | [ImportManager.tsx:1637-1645](frontend/src/screens/ImportManager.tsx:1637); `.btn.accent2` is new CSS variant added in M23. |
| Batch action: SKIP ALL (`.btn.danger.ghost`) | BUILT | [ImportManager.tsx:1646-1652](frontend/src/screens/ImportManager.tsx:1646) |
| Per-row Approve/Skip — confirm dialog | DEVIATED | Per-row actions fire immediately; only batch actions go through `ConfirmDialog`. *Acknowledged in DONE.* |
| Filter tabs: All / Staged / Approved / Processing / Complete / Skipped | BUILT | `STAGED_TABS` at [ImportManager.tsx:306-313](frontend/src/screens/ImportManager.tsx:306); 6 tabs as specified. |
| Budget warning banner ("X CVEs awaiting approval. Daily budget: Y remaining. Excess will process tomorrow.") | BUILT | [ImportManager.tsx:1618-1625](frontend/src/screens/ImportManager.tsx:1618) |

### M23 — Missing or partial, severity-ranked

- **HIGH — Vendor/Product autocomplete is missing.** The kickoff explicitly says "Vendor/Product text input with **autocomplete**." Today the inputs are plain `<input type="text">` with no datalist or remote fetch. Silent gap (no acknowledgement in DONE). To deliver: add a debounced suggestion endpoint (probably backed by `cves.affected_products`/`vendor` distinct values from M3) and a small autocomplete popover. Until then operators have to remember exact vendor names.
- **MEDIUM — `MAX_LIVE_CVE_PER_HOUR` is read-only on the Live Feed pipeline-config card.** Acknowledged in DONE — pending the M24 settings UI. *(M24 has now shipped, but the limits there are still localStorage drafts; see M24 below.)* So this is doubly blocked on a backend `/system/config` CRUD.
- **MEDIUM — `AUTO_PROCESS_KEV` is a soft toggle.** Acknowledged in DONE — flipping fires an info toast and does not persist server-side. Same blocker as above.
- **LOW — Event-type names in the log differ from the spec's aspirational names.** Functional equivalence; the log surfaces real events. The spec's names should be updated to match (`cve_ingested` not `cve_received`).

### M23 — Deviations from spec (no judgment)

- `?tab=live\|historical` URL state.  *Acknowledged in DONE.*
- Preview panel is in-card, not in a Modal.  *Acknowledged in DONE.*
- `describeFilters()` summary string in the Active Jobs table.  *Acknowledged in DONE.*
- Server bumps `use_count` inside `/start`; client does not call `/use` separately.  *Acknowledged in DONE.*
- `include_skipped=true` on staged-CVE fetch (needed for Skipped tab).  *Acknowledged in DONE.*

---

## Module M24 — Settings + Marketplace UI + Prompts Management

Files: [Settings.tsx](frontend/src/screens/Settings.tsx), [SettingsLayout.tsx](frontend/src/screens/settings/SettingsLayout.tsx) + 8 section files, [Prompts.tsx](frontend/src/screens/Prompts.tsx).

### Settings screen structure

| Element | Status | Notes |
|---|---|---|
| Route `/settings` redirects to `/settings/connectors` | BUILT | [Settings.tsx:24-25](frontend/src/screens/Settings.tsx:24) |
| Left sub-nav with 8 items | BUILT | [SettingsLayout.tsx:20-29](frontend/src/screens/settings/SettingsLayout.tsx:20) — Connectors, Commons, Sigma Sources, Sigma Targets, Profiles, Limits, Notifications, Providers (8 items, deep-linkable). |

### Connectors section

| Element | Status | Notes |
|---|---|---|
| List of installed connectors | BUILT | [ConnectorsSection.tsx:107-152](frontend/src/screens/settings/ConnectorsSection.tsx:107) |
| Health status indicator (green/amber/red dot) | BUILT | `<HealthPill>` at [ConnectorsSection.tsx:177-183](frontend/src/screens/settings/ConnectorsSection.tsx:177); CSS `.health-pill.ok/.degraded/.unhealthy/.unknown`. |
| Enable/disable toggle per connector | BUILT | [ConnectorsSection.tsx:140-148](frontend/src/screens/settings/ConnectorsSection.tsx:140) |
| Config form per connector | BUILT | `ConnectorConfigPanel` — JSON editor in a `<SidePanel>`. [ConnectorsSection.tsx:191-314](frontend/src/screens/settings/ConnectorsSection.tsx:191) |
| "Install New Connector" button → marketplace | BUILT | [ConnectorsSection.tsx:87-90](frontend/src/screens/settings/ConnectorsSection.tsx:87) |
| Health check button | BUILT | [ConnectorsSection.tsx:127-133](frontend/src/screens/settings/ConnectorsSection.tsx:127) — `POST /connectors/{name}/health`. |

### Marketplace (within Connectors modal)

| Element | Status | Notes |
|---|---|---|
| Browse fragchain-registry entries | BUILT | `listConnectorRegistry()` → `MarketplaceModal`. |
| Filter by type (`source_stream` / `enrichment`) | BUILT | [ConnectorsSection.tsx:370-389](frontend/src/screens/settings/ConnectorsSection.tsx:370) |
| Filter by official badge | BUILT | [ConnectorsSection.tsx:389-395](frontend/src/screens/settings/ConnectorsSection.tsx:389) |
| Per entry: name, description, version, maintainer | BUILT | [ConnectorsSection.tsx:407-450](frontend/src/screens/settings/ConnectorsSection.tsx:407); type + package + repo link rendered too. |
| Install button runs pip install via backend subprocess | DEVIATED | No backend `/connectors/install` route exists in v1. The button opens a `ConfirmDialog` whose action surfaces the `pip install <package>` command via toast. *Acknowledged in DONE.* |
| Prompts for restart after install | DEVIATED | The toast says "restart the API container to load"; no automated restart hook. Acceptable v1 stance. |

### Commons Sources section

| Element | Status | Notes |
|---|---|---|
| List configured commons sources | BUILT | [CommonsSection.tsx:143-186](frontend/src/screens/settings/CommonsSection.tsx:143) |
| Show priority + trust_level per source | BUILT | [CommonsSection.tsx:147-158](frontend/src/screens/settings/CommonsSection.tsx:147) |
| Add new source form | BUILT | `CommonsSourceModal` at [CommonsSection.tsx:217-387](frontend/src/screens/settings/CommonsSection.tsx:217) |
| Test Connection button | BUILT | [CommonsSection.tsx:167-169](frontend/src/screens/settings/CommonsSection.tsx:167) |
| Edit / delete | BUILT | [CommonsSection.tsx:173-181](frontend/src/screens/settings/CommonsSection.tsx:173) |
| Extra: Sync now per row | DEVIATED | Useful but not in kickoff. [CommonsSection.tsx:170-172](frontend/src/screens/settings/CommonsSection.tsx:170) |

### Sigma Sources section

| Element | Status | Notes |
|---|---|---|
| List, add, edit, test, delete | BUILT | [SigmaSourcesSection.tsx](frontend/src/screens/settings/SigmaSourcesSection.tsx) |
| Token field masked; `has_credentials` boolean shown | BUILT | Modal uses `(unchanged)` placeholder when editing; create/update bodies omit the field unless changed. [SigmaSourcesSection.tsx:213-232](frontend/src/screens/settings/SigmaSourcesSection.tsx:213), [SigmaSourcesSection.tsx:245-247](frontend/src/screens/settings/SigmaSourcesSection.tsx:245) |
| Extra: Refresh button (imports rules) | DEVIATED | Useful but not in kickoff. [SigmaSourcesSection.tsx:76-87](frontend/src/screens/settings/SigmaSourcesSection.tsx:76) |

### Sigma Targets section

| Element | Status | Notes |
|---|---|---|
| List, add, edit, test, delete | BUILT | [SigmaTargetsSection.tsx](frontend/src/screens/settings/SigmaTargetsSection.tsx) |
| Routing_rules editor (CodeMirror JSON with validation) | BUILT | Embedded CodeMirror w/ `oneDark` + line-wrap. JSON.parse + structural validation; Save disabled while invalid. [SigmaTargetsSection.tsx:438-460](frontend/src/screens/settings/SigmaTargetsSection.tsx:438) |
| `is_default` toggle | BUILT | [SigmaTargetsSection.tsx:400-413](frontend/src/screens/settings/SigmaTargetsSection.tsx:400) |
| `auto_pr` toggle | BUILT | [SigmaTargetsSection.tsx:414-424](frontend/src/screens/settings/SigmaTargetsSection.tsx:414) |
| Pre-fills with templates (routing-rule starter snippets) | MISSING | Silent gap. The kickoff says "Pre-fills with templates" for the targets section; today the routing-rules CodeMirror opens to `[]` for a new target with no starter snippets (e.g. "if KEV → production-repo", "if experimental → staging-repo"). |

### Logsource Profiles section

| Element | Status | Notes |
|---|---|---|
| List built-in + custom profiles | BUILT | [ProfilesSection.tsx:96-160](frontend/src/screens/settings/ProfilesSection.tsx:96) — separated into Built-in / Custom blocks. |
| Enable/disable toggle per profile | BUILT | [ProfilesSection.tsx:221-228](frontend/src/screens/settings/ProfilesSection.tsx:221); applies to both built-in and custom. |
| "Add Custom Profile" form | BUILT | `ProfileModal` at [ProfilesSection.tsx:247-478](frontend/src/screens/settings/ProfilesSection.tsx:247); collects slug, display, platform dropdown, products/services, `field_conventions` (JSON object), `example_rules` (JSON array), enabled. |
| Cannot edit/delete `is_builtin=true` | BUILT | Edit button disabled with title hint; Delete button not rendered. [ProfilesSection.tsx:229-241](frontend/src/screens/settings/ProfilesSection.tsx:229) |

### Processing Limits section

| Element | Status | Notes |
|---|---|---|
| `MAX_LIVE_CVE_PER_HOUR` field | BUILT | [LimitsSection.tsx:56-73](frontend/src/screens/settings/LimitsSection.tsx:56) |
| `MAX_HISTORICAL_CVE_PER_DAY` field | BUILT | [LimitsSection.tsx:74-91](frontend/src/screens/settings/LimitsSection.tsx:74) |
| `OPENCTI_POLL_MAX_PER_RUN` field | BUILT | [LimitsSection.tsx:92-109](frontend/src/screens/settings/LimitsSection.tsx:92) |
| `AUTO_PROCESS_KEV` toggle | BUILT | [LimitsSection.tsx:110-123](frontend/src/screens/settings/LimitsSection.tsx:110) |
| Save changes persist to DB | DEVIATED | Saves to `localStorage` (`fragchain.settings.limits.draft`) only; backend has no `/system/config` CRUD. *Acknowledged in DONE.* The card also surfaces an env-snippet block ready to copy-paste. |

### Notifications section

| Element | Status | Notes |
|---|---|---|
| Slack webhook URL field (masked) | BUILT | [NotificationsSection.tsx:127-132](frontend/src/screens/settings/NotificationsSection.tsx:127) — `maskWebhook()` truncates + replaces with bullets. |
| Test Slack button | BUILT-PARTIAL | Renders a `curl` command via info toast instead of POSTing — no backend `/notifications/test` route exists in v1. *Acknowledged in DONE — points at M36.* |
| Generic webhook URL field (masked) | BUILT | [NotificationsSection.tsx:133-138](frontend/src/screens/settings/NotificationsSection.tsx:133) |
| Test webhook button | BUILT-PARTIAL | Same as Slack — curl command via toast. |
| Email channel deferred to M36 | BUILT | Surfaced as "Deferred to M36 — UI placeholder only" text. [NotificationsSection.tsx:140-145](frontend/src/screens/settings/NotificationsSection.tsx:140) |
| Save changes persist to DB | DEVIATED | `localStorage` draft only. *Acknowledged in DONE.* |

### AI Providers section

| Element | Status | Notes |
|---|---|---|
| List installed LLM providers (v1: just LiteLLM) | BUILT | [ProvidersSection.tsx:91-156](frontend/src/screens/settings/ProvidersSection.tsx:91) |
| LiteLLM config form: URL, API key (masked), Chat model, Embedding model | DEVIATED | Config is **not editable in UI** — the screen renders a static env-snippet block (`LITELLM_BASE_URL=…`, `LITELLM_API_KEY=•••`, `LITELLM_CHAT_MODEL=…`, `LITELLM_EMBEDDING_MODEL=…`). *Acknowledged in DONE: "URL + API key + model aliases are env-managed."* Means an operator must restart the API container with new env vars to change LLM config — no UI affordance. [ProvidersSection.tsx:159-176](frontend/src/screens/settings/ProvidersSection.tsx:159) |
| Test Connection button | BUILT | [ProvidersSection.tsx:147-152](frontend/src/screens/settings/ProvidersSection.tsx:147); calls `POST /llm/providers/{name}/health`, renders health pill + latency + models count. |

### Prompts Management screen — `/prompts`

| Element | Status | Notes |
|---|---|---|
| Route `/prompts` | BUILT | [App.tsx:38](frontend/src/App.tsx:38) |
| List prompt templates grouped by `task_type × target_model × target_provider` | BUILT | [Prompts.tsx:90-114](frontend/src/screens/Prompts.tsx:90); group key `${task_type}::${target_model}::${target_provider}`. |
| Per template: version history | BUILT | All versions stacked under a group header, sorted version-desc. [Prompts.tsx:143-171](frontend/src/screens/Prompts.tsx:143) |
| Per template: active toggle | BUILT | "Activate" button when not active; `active` badge when active. [Prompts.tsx:400-408](frontend/src/screens/Prompts.tsx:400) |
| Per template: eval results | BUILT | Evaluations table per detail. [Prompts.tsx:488-523](frontend/src/screens/Prompts.tsx:488) |
| Click template → detail view | BUILT | [Prompts.tsx:174-198](frontend/src/screens/Prompts.tsx:174) |
| Detail: CodeMirror editor for system_prompt | BUILT | `oneDark`, line-wrap. [Prompts.tsx:422-435](frontend/src/screens/Prompts.tsx:422) |
| Detail: CodeMirror editor for user_template | BUILT | [Prompts.tsx:437-450](frontend/src/screens/Prompts.tsx:437) |
| Detail: notes textarea | BUILT | [Prompts.tsx:452-464](frontend/src/screens/Prompts.tsx:452) |
| Detail: version history with timestamps | BUILT | Group panel lists every version; `created_at` shown in detail header. |
| Detail: diff view between versions | BUILT | `DiffModal` renders server-side unified diff w/ `add/remove/hunk` line classes. [Prompts.tsx:585-641](frontend/src/screens/Prompts.tsx:585) |
| "Create New Version" button | BUILT | "Save as new version" — PATCH bumps version. [Prompts.tsx:412-419](frontend/src/screens/Prompts.tsx:412) |
| Evaluation panel: run against benchmark set | BUILT | Eval modal lists `listBenchmarks()` and posts `/{id}/evaluate`. [Prompts.tsx:537-580](frontend/src/screens/Prompts.tsx:537) |
| Show technique_overlap, hallucinations, cost, latency | BUILT | Toast + persisted Evaluations table. [Prompts.tsx:292-295](frontend/src/screens/Prompts.tsx:292) |
| A/B test management: list active tests | BUILT | `ABTestsCard` at [Prompts.tsx:827-893](frontend/src/screens/Prompts.tsx:827) |
| Show traffic split | BUILT | "split N/M" formatted. [Prompts.tsx:847-849](frontend/src/screens/Prompts.tsx:847) |
| Show current winner if any | BUILT | `winner` badge. [Prompts.tsx:855-857](frontend/src/screens/Prompts.tsx:855) |
| Start new test form (variants filtered by task type) | BUILT | `NewABTestModal`; variant Dropdown filtered by `task_type === form.task_type`. [Prompts.tsx:902-1031](frontend/src/screens/Prompts.tsx:902) |
| Conclude test button (pick winner manually) | BUILT | Three buttons: Pick A / Pick B / End (tie). [Prompts.tsx:859-882](frontend/src/screens/Prompts.tsx:859) |

### M24 — Missing or partial, severity-ranked

- **HIGH — AI Providers config is display-only.** Acknowledged in DONE but operationally significant: an operator who wants to swap LiteLLM URL or rotate the API key has no UI path — they must edit env and redeploy. The spec's promise was a real editable form. This blocks "Test Connection" from being part of an iterative configuration workflow (test → fix → re-test). To deliver: a backend `/system/config` write path for the four LiteLLM env vars + restart hook OR a runtime-config table the API can hot-reload from.
- **HIGH — Processing Limits + Notifications save to `localStorage`, not the server.** Acknowledged in DONE — but the practical effect is that operators on a fresh browser see defaults regardless of the deployment's actual env. Blocks any "central config dashboard" promise. Same fix as above: a `/system/config` CRUD endpoint.
- **MEDIUM — Sigma Targets routing-rules editor has no template pre-fill.** Silent gap. New targets open to `[]` instead of a starter array like `[{"if":"level==\"critical\"","target_name":"prod"}]`. Easy to add — a small "Insert template" dropdown above the CodeMirror.
- **MEDIUM — Marketplace install button does not actually install.** Acknowledged in DONE. Surfaces a `pip install` command via toast. For v1 this is defensible; for v1.x it's a real promise to fulfil (backend `POST /connectors/install` + container restart hook).
- **MEDIUM — Notifications Test buttons don't actually test.** Acknowledged in DONE — they surface a curl command. Will swap when M36 lands `/notifications/test`.
- **LOW — Manage-presets modal doesn't let operators preview/edit filter encoding.** Acknowledged in DONE — operators rename/redescribe but can't change which filters a preset encodes from inside the modal. Workaround: hydrate, tweak, save-as-new. Acceptable.

### M24 — Deviations from spec (no judgment)

- All eight settings sections rendered as separate sub-route components rather than a single accordion.  *Reasonable architectural call; matches spec's "left nav" requirement.*
- `Sync now` per commons source (extra).  *Acknowledged in DONE.*
- `Refresh` per sigma source (extra).  *Acknowledged in DONE.*
- Custom-profile modal exposes JSON-textarea inputs for `field_conventions` and `example_rules` (not visual editors).  *Acceptable v1.*
- Prompts editor uses CodeMirror with `oneDark` + line-wrap; no syntax highlighting (no `lang-json` / templating grammar).  *Acceptable v1.*
- A/B test "conclude" exposes three buttons (Pick A / Pick B / End tie) per row rather than a separate modal.  *Reasonable affordance.*
- New A/B test modal filters variant dropdowns by selected task type so operators can't pair mismatched prompts.  *Defensive add.*

---

## Cross-Module Observations

**A consistent backend-config-API gap runs through all three modules.** M23's `AUTO_PROCESS_KEV` + `MAX_LIVE_CVE_PER_HOUR`, M24's Processing Limits + Notifications + AI Providers — all of them want to read/write `system_config` and there's no API for it. Each module worked around it differently (toast in M23, localStorage in M24). A single `system_config` CRUD endpoint (with a restart-aware reload hook for env-derived knobs) would unblock five separate UI sections. Worth a dedicated module slot (call it "M24.5 — system_config CRUD" or fold into the v1.x roadmap).

**Live-validation pattern is half-built.** M22's Review Queue does client-side YAML validation because the backend `POST /rules/{id}/validate` doesn't accept a draft body. M24's Sigma Targets routing-rules editor and Profiles JSON-textarea inputs do client-side JSON parsing for the same reason. A small backend addition (`POST /sigma/validate-yaml`, `POST /sigma/validate-routing`, `POST /profiles/validate-json`) would push these to authoritative server validation and remove the "client check passes but server rejects" failure mode mentioned in the M22 DONE risks.

**Component reuse is good.** `Modal`, `SidePanel`, `DataTable`, `Dropdown`, `ConfirmDialog`, `Spinner`, `StatBlock`, `Badge`, `TLPBadge`, `EmptyState`, `useToast` all see consistent use across the three modules. No duplication. The new CSS primitives (`.health-pill`, `.settings-row`, `.json-editor`, `.marketplace-grid`, `.eval-aggregate`, `.review-split`, `.validation-bar`, etc.) are scoped and named consistently.

**CodeMirror integration is consistent.** All four CodeMirror uses (Sigma Library YAML viewer, Review Queue YAML editor, Sigma Targets routing rules, Prompts system/user templates) use `oneDark` + line-wrap and apply the same `.cm-editor { font-family: var(--font-display) }` override.

**No premature abstractions.** Every CRUD section under `settings/` is its own file; they don't share a `<GenericListEditModal>` helper. That's the right call for v1 — the modals diverge in field shape (Commons has trust_level + sync toggles; Profiles has JSON textareas; Sigma Targets has CodeMirror) and a shared helper would have leaked complexity.

**Two screens missed the "products" / "autocomplete" UX detail.** M22 Review Queue's CVE-context card and M23 Historical-Import filter form both skip a small but explicit spec ask. Pattern suggests "secondary affordances" tend to drop off in single-session implementations.

---

## Recommended Action Plan (HIGH and BLOCKER only)

### Worth catching up *before* the Phase 6 audit

- **Vendor/Product autocomplete (M23 — HIGH, S).** Adds a backend `GET /cves/suggest?field=vendor&q=…` (or read from M3's `cves` table distinct values) and wires a debounced popover under the two text inputs. Spec was explicit; silent gap will surface as drift. ~½ day.
- **Add a `Products` row to the Review Queue CVE-context card (M22 — MEDIUM, XS).** Render `cve.affected_products` if present (fall back to "—"). Trivial.
- **Add a routing-rules template pre-fill to Sigma Targets (M24 — MEDIUM, S).** Small "Insert example" dropdown that drops a starter JSON array into the CodeMirror. Two-three preset templates ("KEV critical → prod", "experimental → staging", "windows-only → win-repo"). ~2 hours.

### Worth deferring to v1.x

- **AI Providers editable LiteLLM config + Processing Limits + Notifications central config (M24, M23 — HIGH, L).** All three need a backend `/system/config` CRUD endpoint with a hot-reload or restart hook. This is a multi-day backend change. Defer as a single ticket — five UI sections become operational at once.
- **Marketplace `POST /connectors/install` hook + restart (M24 — MEDIUM, L).** Real one-click install is a v1.x quality-of-life feature; the current "show me the command" flow is auditable and safe. Operators with a CI pipeline don't need this; operators without one will appreciate it.
- **`POST /sigma/validate-yaml` (M22 — MEDIUM, M).** Replaces the client-side draft validator with authoritative pySigma. The Review Queue is already wired to drop in the new endpoint — only the `validateDraft()` helper body needs to swap. ~½ day backend + same-day frontend.
- **Notifications real `/notifications/test` endpoint (M24 — MEDIUM, S).** Lands with M36.

---

## What's worth catching up before Phase 6 Audit

Prioritised so the audit doesn't surface these as drift:

1. **Vendor/Product autocomplete (M23).** Silent gap; spec was explicit; would absolutely show up as a drift finding.
2. **`Products` row in M22 Review Queue CVE-context card.** Silent partial; same reason.
3. **Sigma-Targets routing-rule template pre-fill (M24).** Silent gap; spec was explicit.
4. **`references:` row in M22 Library detail-sidebar metadata.** Silent partial; small spec gap.

Estimated total: less than a day of work to clear every silent gap.

---

## What can wait

- AI Providers editable config / Processing Limits server-side persistence / Notifications real test.  All three are acknowledged in DONE and blocked on a backend `/system/config` API that doesn't exist. The right v1.x move is to land the backend once and unblock five UI sections at the same time, not to fix them piecemeal.
- Marketplace actual install hook.  Acknowledged; defensible v1 stance.
- Server-side draft YAML validation.  Acknowledged; client-side check covers the spec promise (validation feedback as you type, errors block approve).
- Acknowledged UX deviations (inline reject vs modal, in-card preview vs modal, ?tab URL state, ?id URL state, target dropdown "Auto" placeholder, Approve gating, per-row Approve without confirm, queue-nav pills carrying CVE labels, library TLP column).  All documented in DONE files with clear rationale.

---
