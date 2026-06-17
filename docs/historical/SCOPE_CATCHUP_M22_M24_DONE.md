# Scope Catch-Up M22 / M23 / M24 — Done

**Date completed:** 2026-05-13
**Scope:** four silent gaps closed from `SCOPE_REVIEW_M22_M24.md` + one minor spec sync. All five items were specified in the original M22 / M23 / M24 kickoffs but did not land in the original build sessions.
**Status:** complete · 5 per-fix commits on `claude/charming-lamport-a9972a` · full `pytest` (476/476) + `tsc --noEmit` + `npm run build` clean · live-stack curl + UI bundle deployed and verified.

This document is the authoritative record of what changed, how each change was verified, and what was explicitly deferred. `PHASE5_CLEANUP_DONE.md` is the format model.

---

## Operating note

All code changes were applied in the git worktree at
[.claude/worktrees/charming-lamport-a9972a/](. ). Because the worktree's
`frontend/` is checked out without `node_modules` and the running stack
mounts the previously built `dist/` into the UI container, the steps to
exercise the changes against the live stack were:

1. Build the frontend locally (`npm install && npm run build`).
2. `docker cp frontend/dist/. fragchain-fragchain-ui-1:/app/dist/` so
   nginx serves the new bundle.
3. `docker cp` the modified backend files into
   `fragchain-fragchain-api-1:/app/` and `docker compose restart
   fragchain-api` to load them.
4. Hit the API directly with `curl -ks` for the autocomplete + 422
   probes; eyeball the UI through the Chrome connection.

Commit splitting is one commit per fix (5 total), per the catch-up
prompt's deliverable shape.

---

## Fix 1 — M23 vendor/product autocomplete (HIGH, ~½ day)

**Why:** The M23 kickoff explicitly says "Vendor/Product text input with
**autocomplete**." Today the inputs are plain `<input type="text">` with
no datalist or remote fetch. Silent gap (no acknowledgement in
`MODULE_M23_DONE.md`). Operators had to remember exact vendor names.

**Files changed:**

- `fragchain/api/routers/cves.py` — new `GET /api/v1/cves/suggest`
  endpoint. Accepts `field` (must be `vendor` or `product` — anything
  else returns 422), `q` (1..100 chars, prefix), `limit` (1..50,
  default 10). Runs a JSONB scan over `cves.affected_products`,
  groups by extracted value, orders by count DESC then value ASC.
  Response shape: `{"suggestions": [...]}`. Cached in Redis for
  5 minutes (key `suggest:{field}:{q.lower()}:{limit}`); cache
  failure degrades to direct DB hit. DB failure degrades to empty
  suggestions list with a logged warning. Auth: any authenticated
  user (`require_authenticated`); the data is non-sensitive
  vendor / product names.
- `frontend/src/api/cves.ts` — `suggestCves(field, q, limit)` client.
- `frontend/src/screens/ImportManager.tsx` — replaces the two plain
  text inputs with a new inline `SuggestInput` component:
  - debounces 300 ms before firing `suggestCves`,
  - requires `value.trim().length >= 2` before fetching,
  - tracks the latest in-flight request id so rapid typing doesn't
    stomp the popover with stale results,
  - keyboard support: `ArrowUp` / `ArrowDown` move the highlight,
    `Enter` picks, `Esc` and `Tab` close the popover,
  - click-outside (document `mousedown`) closes the popover,
  - "No matches" rendered when the result is empty,
  - small `<Spinner>` while loading.
- `frontend/src/styles/darkops.css` — `.suggest-input` /
  `.suggest-popover` / `.suggest-list` / `.suggest-option` /
  `.suggest-status` rules, scoped under the existing DarkOps tokens.
- `tests/test_cves_suggest.py` — five new tests:
  - happy path returns `[microsoft, micro_focus]` for `q=mic`,
  - invalid field returns 422 with a helpful detail string,
  - empty result returns `[]`,
  - DB failure returns `[]` (graceful degradation),
  - rows with `None` values are filtered out of the response.

**Evidence of fix:**

Backend e2e — see "Verification command outputs" §A–D. Highlights:

```
$ curl -ks -H "Authorization: Bearer $JWT" "https://localhost/api/v1/cves/suggest?field=vendor&q=mic&limit=5"
{"suggestions":["microsoft","micro_focus"]}

$ curl -ks -o /tmp/b.json -w "HTTP %{http_code}\n" -H "Authorization: Bearer $JWT" "https://localhost/api/v1/cves/suggest?field=invalid&q=x"
HTTP 422
{"detail":"field must be 'vendor' or 'product'"}
```

Frontend test (manual against the live stack): in the Import Manager →
Historical Import → Vendor input, type "mic"; popover renders 300 ms
later with the two seeded vendor names; type "m" alone (below min
chars) and no request fires; click "microsoft" → input populates and
popover closes.

Pytest:

```
$ docker exec fragchain-fragchain-api-1 sh -lc 'cd /app && python -m pytest tests/test_cves_suggest.py -q'
.....                                                                    [100%]
5 passed in 0.56s
```

---

## Fix 2 — M22 Products row in Review Queue CVE context card (MEDIUM, XS)

**Why:** The M22 kickoff lists "CVE context card (ID, CVSS, KEV,
published, **products**)" — today the card shows CVE / CVSS / KEV /
Published / TLP. Silent partial (not flagged in `MODULE_M22_DONE.md`).

**Files changed:**

- `fragchain/queue/manager.py` — `_cve_summary()` now includes
  `affected_products` in the dict the queue surfaces as
  `QueueDetailOut.cve`. The Pydantic envelope (`QueueDetailOut.cve:
  dict[str, Any] | None`) already permits arbitrary keys, so no
  router-level schema change is required.
- `frontend/src/screens/ReviewQueue.tsx` — extended the local
  `CveSummary` type with `affected_products?: unknown`; added a
  `formatProducts(value)` helper that normalizes both list-of-string
  (`["linux:kernel"]`) and list-of-object (`[{vendor, product}]`)
  shapes; rendered a new "Products" row after Published in the CVE
  Context card. Truncates at 60 characters with the full list in a
  `title=` tooltip; renders an em dash in `--text-muted` when no
  data is present.
- `tests/test_queue.py` — `_FakeCVE` dataclass gained an
  `affected_products: Any = None` default so the existing
  `test_get_item_with_evidence_bundles_chain_and_cve_context` test
  still passes after the backend change.

**Evidence of fix:**

Pytest:

```
$ docker exec fragchain-fragchain-api-1 sh -lc 'cd /app && python -m pytest tests/test_queue.py -q'
36 passed in 0.42s
```

UI: open `/queue?id=<any pending uuid>` and observe the CVE Context
card — Products row appears between Published and TLP. For a CVE with
no `affected_products`, the row renders "—" in muted colour.

---

## Fix 3 — M24 Sigma Targets routing-rules template pre-fill (MEDIUM, ~2 hours)

**Why:** A new operator creating a Sigma Target has no hint about what
`routing_rules` JSON looks like; today the CodeMirror opens to `[]`.
Implied in M24 but silent gap.

**Files changed:**

- `frontend/src/screens/settings/SigmaTargetsSection.tsx` — added a
  `RoutingTemplate[]` constant with four starter clauses, an
  "Insert template" `<Dropdown>` placed above the routing-rules
  `<CodeMirror>` editor, a `hasContent(text)` predicate, an
  `applyTemplate(tpl)` helper, and a `ConfirmDialog` that fires
  when the editor has unsaved content. Templates:

  | Key | Label | Clause |
  |---|---|---|
  | `kev-critical` | KEV Critical → Production | `kev_only AND level=="critical"` |
  | `experimental-staging` | Experimental → Staging | `status=="experimental"` |
  | `windows-only` | Windows Only → Win Repo | `'logsource.profile.windows-security' in tags OR 'logsource.profile.windows-sysmon' in tags` |
  | `fragchain-review` | FragChain Generated → Review | `'fragchain.generated' in tags` |

  Templates use the quoted-tag form (`'fragchain.generated' in tags`)
  that the M16 routing parser accepts directly; the bareword form
  is also accepted because of the post-Phase-5 L4 pre-normalization
  fix, so either path round-trips.
- `frontend/src/styles/darkops.css` — `.routing-templates` /
  `.routing-templates-label` / `.routing-templates .dropdown` rules
  so the dropdown sits flush above the CodeMirror and visually
  reads as part of the editor toolbar.

**Evidence of fix:**

Click "Add Sigma target" → modal opens; "Insert template" dropdown is
visible above the routing-rules CodeMirror. Selecting "KEV Critical →
Production" populates the editor with:

```json
[
  {
    "if": "kev_only AND level==\"critical\"",
    "target_name": "production"
  }
]
```

The editor remains live-editable after insert; submitting produces a
target the M16 routing parser accepts. Selecting a second template
when the editor has content opens the confirm dialog
"Replace current routing rules with template ..."; clicking Cancel
preserves the previous content.

---

## Fix 4 — M22 References row in Sigma Library detail (LOW, XS)

**Why:** The M22 kickoff lists "Metadata: sigma_uuid, author, tags
list, references" — today the references are visible inside the YAML
body but not surfaced as a metadata row. Silent partial.

**Files changed:**

- `frontend/src/screens/SigmaLibrary.tsx` — added a
  `parseSigmaReferences(yaml)` helper that scans the YAML body for
  the `references:` key and reads its block-form items. Returns an
  empty list when the key is absent; the caller omits the row
  entirely in that case (no "References: —" placeholder). Each
  reference renders as `<a href={url} target="_blank"
  rel="noopener noreferrer">`.
- `frontend/src/styles/darkops.css` — `.detail-refs` rules: vertical
  flex layout with 4 px gap, `--accent` link colour, `word-break:
  break-all` so long URLs don't overflow the side panel.

Parsing is a focused regex over the YAML block rather than a full
js-yaml load to avoid adding a new runtime dependency for a single
read-only call site. The FragChain rule generator always emits the
block form, so the parser covers every rule produced by the platform.

**Evidence of fix:**

UI: open `/rules`, click a rule with a `references:` list in its YAML
(e.g. any rule with attribution to NVD or vendor advisories). The
detail sidebar now shows a "References" section between Tags and
Sigma YAML, with each URL rendered as a clickable accent-coloured
link that opens in a new tab. Open a rule without `references:` →
the section is omitted entirely.

`npm run build`:

```
✓ 2109 modules transformed.
dist/assets/index-BUd_WA3K.css     84.89 kB │ gzip:  12.90 kB
dist/assets/index-DggRm3oI.js   1,152.27 kB │ gzip: 363.21 kB
```

---

## Fix 5 — Spec sync M23 event names

**Why:** The Scope Review noted that the M23 kickoff in
`FragChain_Module_Prompts.md` used aspirational event names
(`cve_received`, `rate_limited`, `processing_started`, `complete`,
`failed`) that don't match what `fragchain/api/routers/websocket.py`
actually emits. The Live Feed log surfaces the real events and the
backend's docstring lists them; the spec drifted.

**Files changed:**

- `FragChain_Module_Prompts.md` — M23 "Live event log" block updated to
  enumerate the actual emitter names: `cve_ingested`,
  `enrichment_complete`, `rate_limit_warning`, `budget_status`,
  `chain_generated`, `chain_skipped_using_commons`, `coverage_mapped`,
  `rules_generated`, `queue_item.*` (assign/approve/reject/submit),
  `import_job.created`, `import_job.staged`, `webhook.received`.
- `FragChain_Module_Specifications.md` — M23 "Live Feed Tab" line
  expanded with the same list to keep the spec aligned with the
  websocket router's docstring.

The actual frontend logic in `ImportManager.tsx` already maps the real
event names — only the docs were stale.

---

## Spec updates applied (this catch-up only)

| File | Section | Update |
|---|---|---|
| `FragChain_Module_Prompts.md` | M23 — Live event log | replaced aspirational event types with the real `cve_ingested` / `enrichment_complete` / etc. list (Fix 5) |
| `FragChain_Module_Specifications.md` | M23 — Live Feed Tab | added the canonical event-type list to the "Live event log" bullet (Fix 5) |

No CLAUDE.md edits were required for this catch-up; every fix lands
inside the M22 / M23 / M24 surface area that's already documented in
§16 and §13.

---

## Verification command outputs

### A. Backend autocomplete happy path

```
$ JWT=$(curl -ks -X POST -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"change-me-on-first-login"}' \
    https://localhost/api/v1/auth/login | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')

$ curl -ks -H "Authorization: Bearer $JWT" \
    "https://localhost/api/v1/cves/suggest?field=vendor&q=mic&limit=5"
{"suggestions":["microsoft","micro_focus"]}
```

Seeded against three test rows so the order proves the count-DESC
sort: `microsoft` appears in 2 CVEs, `micro_focus` in 1.

### B. Backend validation rejects bad field

```
$ curl -ks -o /tmp/b.json -w "HTTP %{http_code}\n" -H "Authorization: Bearer $JWT" \
    "https://localhost/api/v1/cves/suggest?field=invalid&q=x"
HTTP 422
{"detail":"field must be 'vendor' or 'product'"}
```

### C. Backend validation rejects empty q

```
$ curl -ks -o /tmp/c.json -w "HTTP %{http_code}\n" -H "Authorization: Bearer $JWT" \
    "https://localhost/api/v1/cves/suggest?field=vendor&q="
HTTP 422
{"detail":[{"type":"string_too_short","loc":["query","q"],"msg":"String should have at least 1 character","input":"","ctx":{"min_length":1}}]}
```

Documented behavior: empty `q` returns 422 (Pydantic `min_length=1`).

### D. Backend requires auth

```
$ curl -ks -o /tmp/d.json -w "HTTP %{http_code}\n" \
    "https://localhost/api/v1/cves/suggest?field=vendor&q=mic"
HTTP 401
{"detail":"Authentication required"}
```

### E. Full pytest suite

```
$ docker exec fragchain-fragchain-api-1 sh -lc 'cd /app && python -m pytest tests/ -q'
476 passed, 21 warnings in 2.30s
```

The new `tests/test_cves_suggest.py` contributes 5 of the 476 passes;
the existing 471 are unchanged. The four pre-existing transient
failures (chains fixture + benchmarks fixture not mounted in the
container by default) are environmental and unrelated; copying
`chains/` and `benchmarks/` into the container makes the full suite
green, which is what's reported above.

### F. Frontend build

```
$ npm run build
> fragchain-ui@0.1.0 build
> tsc -b && vite build
vite v5.4.21 building for production...
✓ 2109 modules transformed.
dist/assets/index-BUd_WA3K.css     84.89 kB │ gzip:  12.90 kB
dist/assets/index-DggRm3oI.js   1,152.27 kB │ gzip: 363.21 kB
✓ built in 1.96s
```

### G. TypeScript

```
$ npx tsc -p . --noEmit
(no output)
```

### H. Live-stack UI

```
$ curl -ks https://localhost/ | grep -oE 'index-[A-Za-z0-9_-]+\.(js|css)' | sort -u
index-BUd_WA3K.css
index-DggRm3oI.js
```

The new bundle is the one nginx serves; the new screens are reachable
at `/imports`, `/queue?id=<uuid>`, `/rules`, `/settings/sigma-targets`.

---

## Discovered but not fixed (out of scope — v1.x backlog)

These items are real gaps from the same Scope Review but were explicitly
deferred by the catch-up prompt. They are tracked here so the Phase 6
audit doesn't re-surface them as drift:

- **`system_config` CRUD endpoint.** Blocks AI Providers persist,
  Processing Limits persist, and Notifications persist all together —
  one backend ticket. Today three Settings sections write to
  `localStorage` only; the env-snippet display + restart-the-container
  workaround stays.
- **Marketplace `POST /connectors/install` hook + container restart.**
  Today the Install button surfaces a `pip install` command via toast.
  Real one-click install is a v1.x quality-of-life feature.
- **`POST /sigma/validate-yaml` server-side draft validation.** Today
  the Review Queue runs client-side structural validation only;
  `M16`'s persisted-row validator can't see draft YAML. The drop-in
  point for an authoritative endpoint is `validateDraft()` in
  `ReviewQueue.tsx` — swap the body, keep the debounce / render /
  error-list plumbing.
- **Notifications real `/notifications/test` endpoint.** Today the
  Test buttons render `curl` commands via toast. Lands with M36
  (notifications module).
- **Library "Author" field reading from payload.** Today the metadata
  row is the literal `"FragChain"`. Defer until M15 emits an
  author field on generated rules.

No new findings were introduced in this catch-up beyond the four the
prompt explicitly enumerated.

---

## Commit list

```
$ git log --oneline main..HEAD
99129ac docs: sync M23 spec event names with implementation
01e67f1 feat(M22): references row in Sigma Library detail sidebar
dfe0898 feat(M24): routing-rules template pre-fill on Sigma Targets create
84d543c feat(M22): products row in Review Queue CVE context card
cda939f feat(M23): vendor/product autocomplete on import filter
```

One commit per fix. Each commit is self-contained (frontend + backend
+ tests + CSS for that fix). Reverting any single commit removes only
that fix without affecting the other four.

---

## Updated MODULE_DONE files

- `MODULE_M22_DONE.md` — appended "Phase 6 scope catch-up applied"
  section noting the Products row + References row additions and
  the spec-sync of event names that touches M22 indirectly.
- `MODULE_M23_DONE.md` — same shape; vendor/product autocomplete +
  event-name spec sync.
- `MODULE_M24_DONE.md` — same shape; routing-rules templates added;
  also adds an explicit "v1.x backlog" section listing the four
  deferred items (`system_config` CRUD, marketplace install hook,
  real notifications test, `/sigma/validate-yaml`).

---

## Ready for Phase 6 audit?

Yes. The four silent gaps the audit would otherwise have surfaced as
drift findings are closed; the spec is now aligned with the actual
event names emitted by the websocket router; the explicitly deferred
items are documented as v1.x backlog rather than left silent.
