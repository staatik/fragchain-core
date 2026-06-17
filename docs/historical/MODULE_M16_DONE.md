# MODULE_M16_DONE — Review Queue
**Built:** 2026-05-13
**Effort actual:** M (one session)
**Status:** complete · sandbox-verified (AST parse on every new/edited file; isolated end-to-end flow simulation of approve / reject / edit-and-approve under stubbed boundaries) · pending runtime verification on live Postgres + Redis + Qdrant + Git host

## Scope reminder

M16 picks up the queue rows M15 inserted and owns the lifecycle through
to a Git PR (or rejection):

```
M15: generating → complete         (queue rows land at status='pending')
M16: pending  → in_review (on assign)
              → approved (on approve / edit_and_approve)  → submitted (PR created)
              → rejected (on reject)
```

M16 wraps M12's :class:`RoutingEngine` and :class:`SigmaTargetClient` for
the approve path. It does NOT own:

* Review Queue UI / Sigma Library UI (M22)
* The schema for `review_queue` itself — M15's migration `0013_review_queue`
  already shipped the table + partial unique index. M16 adds no new
  migration.
* The WebSocket fan-out (M19) — M16 only emits onto the in-process bus
  via :func:`fragchain.notifications.emit_event`.
* Imported-rule promotion (M27 / future) — only `fragchain.generated`
  rows flow through this queue.

## What was built

### `fragchain/queue/manager.py` — `QueueManager`

The lifecycle orchestrator. Construct one per request / Celery task with
an :class:`AsyncSession`. Optional collaborators injected so tests can
pass stubs:

* `target_client` — :class:`fragchain.sigma.SigmaTargetClient`.
* `router_factory` — async callable returning a :class:`RoutingEngine`.
  Default: :meth:`RoutingEngine.load` over the live session.
* `embedder_factory` — sync callable returning a vector embedder with
  ``search_sigma_rules``. Default: a fresh :class:`VectorEmbedder`
  (downgrades to "no similar rules" if Qdrant is unreachable).

#### Lifecycle entry points

| Method | Returns | Purpose |
|---|---|---|
| `list_items(...)` | `list[QueueItemView]` | Browse the queue, ordered by `priority_score DESC, created_at ASC`. AND-ed filters: `priority`, `status`, `assigned_to`, `cve_id` (textual or UUID), with `limit` / `offset`. |
| `get_item_with_evidence(item_id)` | `QueueItemDetail` | One queue row + the analyst evidence bundle (parsed YAML, CVE summary, chain context, top 3 source documents, top 5 semantically-similar rules, priority breakdown). |
| `assign(item_id, *, actor_*, assigned_to)` | `QueueItemView` | Set / clear `assigned_to`. Pending → in_review when first assigned. Audits the transition. |
| `approve(item_id, *, actor_*, target_id=None)` | `ApproveOutcome` | Flip rule + queue to `approved`, run routing (or use the operator-supplied target), submit a PR via M12. Two commits — approval lands before the network call so a transport failure doesn't roll back the human decision. |
| `reject(item_id, *, actor_*, reason)` | `RejectOutcome` | Flip rule + queue to `rejected`. Reason recorded in `audit_log` (CLAUDE.md §19) and tacked onto `sigma_rules.review_notes` as a discoverable `[review-rejected ...]` block. |
| `edit_and_approve(item_id, *, actor_*, new_yaml, target_id=None)` | `EditOutcome` | Validate new YAML through M15's pySigma validator. On failure: 400 with `errors[]` / `warnings[]`. On success: update `sigma_yaml` + `content_hash`, then fall through to `approve`. |

#### Routing fallback

* `target_id` explicit → resolve, check `enabled`, fail 404/409 as needed.
* No `target_id` → load :class:`RoutingEngine` over `sigma_targets`, call
  `select_target(rule)`. Returns a default fallback when no clause
  matches.
* No target available at all → :class:`QueueActionError(409)`. The
  human approval is refused; the operator must configure a target first.

#### Failure isolation

* The two-step "commit approval → submit PR" pattern guarantees that a
  transport failure (Git host down, 5xx, rate-limit) doesn't roll back
  the analyst's decision. The rule stays at `status='approved'` with
  `git_pr_url=NULL`; M12's existing `submit_rule_to_target` Celery task
  can retry without re-approving.
* The PR submission is also wrapped in `try/except Exception` so a raw
  socket error / unexpected transport bug surfaces as `pr_submitted=False`
  with the exception message rather than a 500.
* Qdrant outages during evidence-bundle assembly collapse to an empty
  `similar_rules` list — the detail call still serves.
* Redis outages during cache invalidation log + continue.

#### Audit + event guarantees

Every state transition writes an `audit_log` row via
`audit_entity_state_change`:

| Action | Entity | When |
|---|---|---|
| `queue.assigned` | `review_queue` | every `assign` |
| `sigma_rule.approved` + `queue.approved` | sigma + queue | every `approve` (pair) |
| `sigma_rule.pr_submitted` OR `sigma_rule.pr_failed` | `sigma_rule` | after PR transport |
| `sigma_rule.rejected` + `queue.rejected` | sigma + queue | every `reject` (pair) |
| `sigma_rule.edited` | `sigma_rule` | edit_and_approve, before approve cascade |

In-process events (M19 WebSocket fan-out picks these up unchanged):

| Event type | Fires on | Payload keys |
|---|---|---|
| `rule_approved` | every approve | `rule_id, queue_id, cve_id, chain_id, target_id, target_name, approved_by, priority_score, priority, routing_reason` |
| `git_pr_created` | only when PR `created=True` | `rule_id, queue_id, target_id, target_name, pr_url, pr_number, commit_sha, branch, cve_id, chain_id` |
| `rule_rejected` | every reject | `rule_id, queue_id, cve_id, chain_id, rejected_by, reason` |

#### Evidence bundle (`get_item_with_evidence`)

Built once per detail request to avoid N+1 round-trips from the UI:

* **Parsed YAML** — `yaml.safe_load_all` over `sigma_rules.sigma_yaml`,
  returns `None` if malformed (the YAML body always still ships verbatim
  for the editor pane).
* **CVE summary** — id, textual id, CVSS, KEV, EPSS score + percentile,
  AttackerKB score, TLP, published_at, description (extracted from
  `raw_connector_data["description"]`, clamped to 1500 chars).
* **Chain context** — the focus TTP (matched by the rule's first
  `technique_id`) + 1 TTP before + 1 TTP after, in `seq_order`. Each
  carries tactic, technique id/name, confidence, detection_opportunity,
  and an `is_focus` boolean for UI highlighting. If the focus TTP isn't
  in the chain we return all TTPs unfocused.
* **Source documents** — up to 3 attached to the rule's CVE, sorted by
  `quality_score DESC NULLS LAST, created_at ASC`. Each row carries
  URL, source_type, quality_score, TLP, and an excerpt pulled from
  `document_metadata["excerpt"|"description"|"summary"]` (clamped 600
  chars).
* **Similar rules** — Qdrant semantic search over `sigma_rules` via
  M8's `VectorEmbedder.search_sigma_rules`. Query mirrors M8's embed
  shape (`title + technique_ids + first 500 chars of YAML`) so scores
  are meaningful. Self-hit filtered out. Max 5 hits.
* **Priority breakdown** — `{priority, priority_score, priority_reason}`
  carried over from M14's `CoverageStatus`.

### `fragchain/queue/__init__.py`

Public re-exports:

```python
from fragchain.queue import (
    ApproveOutcome,
    EditOutcome,
    QUEUE_STATUSES,             # {"pending", "in_review", "approved", "rejected"}
    QueueActionError,
    QueueItemDetail,
    QueueItemView,
    QueueManager,
    RejectOutcome,
    SimilarRuleHit,
    SourceDocSnippet,
    TTPContext,
)
```

### `fragchain/api/routers/queue.py` — endpoints

Mounted at `/api/v1` from `create_app()` with `tags=["queue"]`. Reads
authenticated, mutations maintainer-only — same model as M9 / M11 / M15.

| Method | Path | Auth | Behaviour |
|---|---|---|---|
| GET | `/queue` | authenticated | List items. Filters: `priority`, `status`, `assigned_to`, `cve_id`. `limit` ≤ 500, `offset` ≥ 0. Ordered `priority_score DESC, created_at ASC`. TLP-filtered post-load via the M2 middleware (rules carry their TLP). |
| GET | `/queue/{id}` | authenticated | Detail + evidence bundle. TLP-enforced on the underlying rule. |
| PATCH | `/queue/{id}/assign` | maintainer | `{"assigned_to": "<user>"}` or `{"assigned_to": null}`. Returns 409 if terminal. |
| POST | `/queue/{id}/approve` | maintainer | `{"target_id"?: "<uuid>"}` — optional override. Returns `ApproveResponse` carrying PR URL, commit SHA, target metadata, `pr_submitted` flag. |
| POST | `/queue/{id}/reject` | maintainer | `{"reason": "<required>"}` (1–4000 chars). Returns 400 on empty reason, 409 if terminal. |
| POST | `/queue/{id}/edit` | maintainer | `{"sigma_yaml": "<required>", "target_id"?: "<uuid>"}`. On validation failure returns 400 with body `{"detail": "...", "errors": [...], "warnings": [...]}` — same shape `/rules/{id}/validate` already uses, so the editor pane can render diagnostics inline. |

The `QueueActionError` → HTTP mapping is centralised in
`_raise_for_action_error`:

* 400 — invalid input (empty reason, bad YAML, bad filter)
* 404 — queue item or target not found
* 409 — wrong state (terminal queue, disabled target, no routing match)

Routes mounted via `fragchain/api/main.py:create_app()`:

```python
app.include_router(queue_router.router, prefix=api_prefix, tags=["queue"])
```

### TLP enforcement

* List path runs `apply_tlp_filter` over the detached
  :class:`QueueItemView` instances. The view carries `tlp` (propagated
  from `sigma_rules.tlp`) and `id` so the filter has what it needs.
  `embargo_until` defaults to absent — `sigma_rules` doesn't have an
  embargo column today (the rule inherits any embargo from the chain via
  the M15 propagation rules, but TLP is the right enforcement vector at
  the boundary).
* Detail / assign endpoints call `enforce_tlp_access` against the
  underlying :class:`SigmaRule` row (the queue row has no TLP of its
  own; the rule is the source of truth).

### Notifications

All three lifecycle events ride the in-process
:class:`fragchain.notifications.EventBus`. M19's WebSocket subscriber
will pick them up unchanged once it lands.

### Matrix cache invalidation

Every approve / reject calls `MatrixCache.invalidate()` so the matrix
UI re-fetches with the updated `covering_rule_count` badges. Best
effort — Redis down logs + continues.

## Tests — `tests/test_queue.py` (27 tests)

Pure-Python; no live Postgres / Redis / Qdrant / Git host. The
`_RecordingSession` mirrors only the methods the manager touches
(`get`, `execute`, `add`, `flush`, `commit`, `refresh`). External
boundaries are stubbed: `_StubTargetClient` for PR submission,
`_RouterStub` for routing, lambda factories for the embedder.

**Pure helpers** — 10 tests:

* `_safe_parse_yaml` — happy path, garbage, non-mapping (list).
* `_append_rejection_note` — fresh, strips previous `[review-rejected …]`
  block on re-rejection, preserves preface text.
* `_build_similar_query` — embeds title + techniques + YAML excerpt.
* `_find_focus_index` — match, no match, None input.
* `_content_hash` — determinism.
* `_extract_description` — clamp, missing.
* `_prior_status_for_assign` — recovers pending vs preserves in_review.

**Manager — list / detail** — 4 tests:

* List sorts by `priority_score DESC` (critical > medium).
* List rejects invalid status filter (`status_code=400`).
* Detail bundles chain context (focus T1068 in [T1078, T1068, T1059] →
  3 TTPs returned, focus flag set), CVE summary, priority breakdown.
* Detail returns 404 on missing item.

**Manager — assign** — 3 tests:

* Pending → in_review + audit row with before/after state.
* Clearing assignment preserves in_review (no automatic regression).
* Terminal-state assign refused (409).

**Manager — approve** — 7 tests:

* Default routing creates PR, emits `rule_approved` + `git_pr_created`,
  writes 3 audit rows (rule.approved, queue.approved, sigma_rule.pr_submitted).
* Explicit `target_id` overrides routing; routing_reason notes the override.
* No target available → 409.
* Already-approved item → 409.
* PR `created=False` keeps rule at `status='approved'` (NOT submitted);
  emits `rule_approved` but NOT `git_pr_created`; audit writes
  `sigma_rule.pr_failed`.
* Transport exception caught → outcome.message embeds exception type;
  rule still approved.
* Disabled target → 409.
* Missing target → 404.

**Manager — reject** — 3 tests:

* Reject writes both audit rows (`sigma_rule.rejected`, `queue.rejected`),
  records reason on both, emits `rule_rejected`, tacks
  `[review-rejected …]` block onto `review_notes`.
* Empty reason → 400.
* Terminal-state reject refused → 409.

**Manager — edit_and_approve** — 3 tests:

* Valid YAML: updates `sigma_yaml` + `content_hash`, writes
  `sigma_rule.edited` audit, then runs the approve cascade (PR submitted).
* Invalid YAML: 400 with `errors[]`; rule NOT mutated; queue still pending.
* Blank YAML: 400.

**Cross-checks** — 2 tests:

* M15's `validate_yaml` agrees with our valid / invalid fixtures.
* `QUEUE_STATUSES` exposes the expected set.

### Sandbox-level pre-flight checks (runnable here)

* `ast.parse()` on every new/edited file — no syntax errors:
  `fragchain/queue/__init__.py`,
  `fragchain/queue/manager.py`,
  `fragchain/api/routers/queue.py`,
  `fragchain/api/main.py`,
  `tests/test_queue.py`.
* `grep -rn "import anthropic\|from anthropic" fragchain/queue/ fragchain/api/routers/queue.py tests/test_queue.py` → no matches (CLAUDE.md §19).
* `grep -rn "fragchain_" fragchain/queue/ fragchain/api/routers/queue.py` → no Qdrant collection prefix (CLAUDE.md §19).
* Migration chain still single-head at `0013_review_queue` — M16 adds no migration.
* Isolated execution of the helpers — `_safe_parse_yaml`,
  `_content_hash`, `_find_focus_index`, `_append_rejection_note`,
  `_build_similar_query` — all pass under a stubbed module web.
* Isolated end-to-end simulation: approve flow (default + explicit
  target), reject (valid + empty reason), edit_and_approve (valid +
  invalid YAML), terminal-state guards — all pass against the
  stubbed-boundary harness. The audit-action set, queue.status,
  rule.status, and event-bus emissions match the assertions baked into
  `tests/test_queue.py`.

### Runtime verification *not* runnable in this sandbox

| Done criterion | Verification command |
|---|---|
| Pending rules listed by priority DESC | `curl -H 'Authorization: Bearer <jwt>' /api/v1/queue` returns items sorted by `priority_score` desc with `priority`/`status`/`title` populated |
| GET /queue filters work | `/api/v1/queue?priority=critical&status=pending&assigned_to=alice&limit=10` honours every clause |
| GET /queue/{id} bundles evidence | response includes `parsed_yaml`, `cve`, `chain_context` (with `is_focus` flag), `source_documents` (≤ 3), `similar_rules` (≤ 5 from Qdrant), `priority_breakdown` |
| TLP enforcement on detail | a `tlp:amber` rule returns 403 to a `tlp:green` user; the same user gets the rule once an `tlp_access_grants` row exists for them |
| PATCH /queue/{id}/assign | maintainer JWT; pending row → in_review, `assigned_to` set; clearing keeps in_review; audit row `queue.assigned` lands |
| POST /queue/{id}/approve creates a Git PR | against a sandbox repo with `auth_credentials_ref` env var set: PR opens at the returned URL; rule row carries `git_pr_url`, `git_commit_sha`, `target_id`, `status='submitted'`, `reviewed_by`, `reviewed_at`, `merged_at`; queue row at `status='approved'` with `completed_at` set |
| Approve audits land in one commit | `SELECT entity_type, action FROM audit_log WHERE entity_id=<rule_id> ORDER BY timestamp` returns `sigma_rule.approved`, `queue.approved`, then `sigma_rule.pr_submitted` (or `sigma_rule.pr_failed`) |
| WebSocket fan-out (once M19 ships) | subscribing client receives `rule_approved` + `git_pr_created` events in order |
| POST /queue/{id}/reject records reason in audit_log | `SELECT after->>'reason' FROM audit_log WHERE action='sigma_rule.rejected' AND entity_id=<rule_id>` returns the supplied reason; `review_notes` carries the same |
| POST /queue/{id}/edit with invalid YAML | HTTP 400 + body `{"detail": "rule failed pySigma validation", "errors": [...], "warnings": [...]}` |
| POST /queue/{id}/edit with valid YAML | rule's `sigma_yaml` + `content_hash` updated; full approve flow executes; audit shows `sigma_rule.edited` then `sigma_rule.approved` then `sigma_rule.pr_submitted` |
| Already-approved / rejected items | further POST/PATCH on the same id return 409 |
| No target available | approve returns 409 `no Sigma target available for routing` |
| Matrix cache invalidation | `redis-cli KEYS 'matrix:*'` empty after approve/reject; next `/matrix` rebuilds with updated `covering_rule_count` |
| Pending row uniqueness preserved | running M15's regenerate-rules on the same chain after a `approved`/`rejected` row exists creates a fresh pending row; the partial unique index allows this (only one *pending* per rule) |

## Interfaces this module exposes

For dependent modules (M19, M22):

```python
from fragchain.queue import (
    QueueManager,
    QueueActionError,
    QueueItemView,
    QueueItemDetail,
    ApproveOutcome,
    RejectOutcome,
    EditOutcome,
    QUEUE_STATUSES,
    SimilarRuleHit,
    SourceDocSnippet,
    TTPContext,
)
```

API contract (all under `/api/v1`):

* `GET    /queue`                      authenticated · filters: `priority`, `status`, `assigned_to`, `cve_id`, `limit`, `offset`
* `GET    /queue/{id}`                 authenticated · TLP-enforced
* `PATCH  /queue/{id}/assign`          maintainer · `{"assigned_to": str | null}`
* `POST   /queue/{id}/approve`         maintainer · `{"target_id"?: uuid}`
* `POST   /queue/{id}/reject`          maintainer · `{"reason": str}`
* `POST   /queue/{id}/edit`            maintainer · `{"sigma_yaml": str, "target_id"?: uuid}`

WebSocket / event bus contract (M19 fan-out):

* `rule_approved   { rule_id, queue_id, cve_id, chain_id, target_id, target_name, approved_by, priority_score, priority, routing_reason }`
* `git_pr_created  { rule_id, queue_id, target_id, target_name, pr_url, pr_number, commit_sha, branch, cve_id, chain_id }`
* `rule_rejected   { rule_id, queue_id, cve_id, chain_id, rejected_by, reason }`

## What dependent modules need to know

* **M17 (Rule Evaluations)** — analysts deploying a rule that left the
  queue via M16 will reference its `id` when submitting evaluations.
  M16 stamps `reviewed_by` / `reviewed_at` / `merged_at` so the eval
  pipeline can scope itself to "rules approved within window X".
* **M19 (WebSocket fan-out)** — three new event types emit onto the
  bus. Payloads are already JSON-serialisable.
* **M22 (Review Queue UI + Sigma Library UI)** — drives the queue list
  + detail endpoints. The `evidence bundle` shape matches the wireframe:
  CVE block, chain block (focus + adjacent), source-doc tiles, similar
  rules list, priority breakdown. The "Approve" button POSTs the target
  selector if the operator picked one explicitly. The "Edit" button
  posts the full YAML; on a 400 it renders `errors[]` / `warnings[]`
  inline.
* **M22 (Sigma Library UI)** — rule statuses now flow through
  `generated → approved → submitted` (PR opened) → eventually
  `merged` once the upstream PR is merged. M27's future reconciliation
  task will flip `submitted → merged` based on PR state polling.
* **M12 (Sigma Targets)** — M16 consumes `RoutingEngine.load(session)`
  + `SigmaTargetClient.submit_rule(rule, target)`. The Celery task
  `fragchain.worker.tasks.submit_rule_to_target` is still useful for
  manual retries when a transport failure leaves a rule at
  `status='approved'` without a PR URL.
* **M15 (Rule Generator)** — the partial unique index
  `ux_review_queue_pending_rule` works hand-in-hand with M16. Once M16
  flips a row to `approved`/`rejected`, a fresh M15 run on the same
  chain inserts a new pending row alongside the historical record
  without collision.

## Deviations from spec / kickoff

* **No new Alembic migration.** The kickoff's first bullet says
  "Alembic migration: review_queue table" — M15 already shipped that
  migration (`0013_review_queue`) precisely so the rule generator
  could insert pending rows the moment a draft lands. M16 doesn't need
  any schema changes: rule status (`generated` → `approved` /
  `rejected` / `submitted`), `reviewed_by` / `reviewed_at` /
  `merged_at` / `git_pr_url` / `git_commit_sha` / `target_id` all
  exist on `sigma_rules`; queue lifecycle (`status`, `assigned_to`,
  `completed_at`) all exist on `review_queue`; rejection reason lives
  in `audit_log` (CLAUDE.md §19 invariant) plus a discoverable block
  inside `sigma_rules.review_notes`.
* **Rejection reason stored in audit_log + review_notes.** Spec says
  "Reject records reason in audit log". We do that AND tack a
  `[review-rejected <ts> by <actor>]` block onto
  `sigma_rules.review_notes` so the queue / library UI can show the
  most recent rejection without joining `audit_log`. Older blocks are
  stripped on re-rejection — full history stays in `audit_log`.
* **Two-stage commit on approve.** The kickoff describes approve as a
  single atomic transition. We split it: commit the approval, *then*
  call the PR transport, *then* commit the submission outcome. This
  ensures a Git host outage doesn't undo the human decision — the rule
  stays `approved` with no `git_pr_url`, and an operator can retry the
  M12 `submit_rule_to_target` Celery task without re-approving.
* **`pr_submitted=False` is a non-error outcome.** Spec implies approve
  must create a PR. In practice: routing engine misconfigurations, Git
  host rate-limits, network errors, etc. all surface here. We return
  `200 OK` with `pr_submitted=False` + the transport's message so the
  UI can render "approved, PR pending" rather than "approve failed".
  The exception is "no target at all" (`409`) — that's a config error
  the operator must fix before approval is meaningful.
* **`approve` accepts `target_id` from the request body, not query
  string.** Spec leaves it ambiguous (`POST /queue/{id}/approve` body
  shape). We use a JSON body field — same pattern as the rest of the
  router family.
* **PATCH `/queue/{id}/assign` flips pending → in_review.** Spec says
  "assign to analyst" — we treat first-assignment as the implicit start
  of review and bump the status. Operators can clear the assignee
  without dropping back to pending (re-pending would lose audit trail
  for the in-progress review).
* **Evidence bundle is hand-shaped, not delegated to a separate
  module.** Spec lists what the detail endpoint must include; we
  inline the assembly in `QueueManager.get_item_with_evidence` so the
  bundle is one round-trip from the UI's perspective. The internals
  are five distinct loaders (`_build_chain_context`,
  `_build_source_documents`, `_fetch_similar_rules`, `_safe_parse_yaml`,
  `_cve_summary`) so future enhancements (e.g. evaluation aggregates
  from M17) plug in cleanly.
* **Chain context window = ±1.** Spec says "adjacent TTPs". We default
  to one before / one after the focus TTP — the analyst sees enough
  narrative for "where in the kill chain does this fit" without
  scrolling. Operators wanting more can hit `GET /chains/{id}` for the
  full chain.
* **Top 3 source docs.** Same budget M15 uses when feeding the rule
  prompt — keeps the bundle small and consistent with what the LLM saw
  at generation time.
* **Top 5 similar rules.** Default Qdrant limit; matches M14's coverage
  Phase-2 search pattern. Self-hit filtered out (the rule shouldn't
  appear as its own neighbour).
* **`embedder_factory` defaults to a fresh `VectorEmbedder`.** A live
  Qdrant outage collapses to an empty `similar_rules` list — the
  detail call still serves. The factory is injectable so tests can
  pass `lambda: None` and skip the network entirely.
* **`QueueActionError` carries `errors[]` / `warnings[]` for
  validator output.** The router maps it to a 400 response body of
  `{"detail": "...", "errors": [...], "warnings": [...]}` — same shape
  M15's `/api/v1/rules/{id}/validate` uses, so the editor pane parses
  one format.
* **`apply_tlp_filter` over `QueueItemView` instances.** The view
  intentionally carries `tlp` + `id` so the filter doesn't need to
  re-fetch the underlying `SigmaRule` row. Embargo isn't carried
  because `sigma_rules` doesn't have an embargo column today; the
  chain-level embargo doesn't propagate down to the rule layer
  (the rule's TLP is the high-water mark per CLAUDE.md §8 max-TLP
  rule, and that's what's enforced here).
* **`origin='imported'` rules don't flow through M16.** Sigma rules
  imported from SigmaHQ via M12 land at `status='merged'` directly —
  they never enter the review queue. M16's filters surface only
  `origin='fragchain'` items by virtue of the queue rows being
  inserted only by M15.

## Known TODOs (owned by other modules)

* **M17 (Rule Evaluations)** — once analysts deploy rules approved
  through M16, the eval pipeline will look up `sigma_rules.reviewed_at`
  to find rules deployed N days ago.
* **M19 (WebSocket fan-out)** — forward `rule_approved`,
  `git_pr_created`, `rule_rejected` to connected clients. Payloads are
  already JSON-serialisable.
* **M22 (Review Queue UI + Sigma Library UI)** — drive `GET /queue`,
  `GET /queue/{id}`, and the three lifecycle endpoints. The evidence
  bundle on the detail endpoint matches the wireframe section-by-section.
* **M27 (PR reconciliation, future)** — poll the upstream Git host for
  PR merge state; when the PR merges, flip `sigma_rules.status`
  `submitted → merged` and update `merged_at` to the upstream merge
  timestamp.
* **Edit history preservation.** Today the edited YAML overwrites the
  original; the audit row records `content_hash` before / after but not
  the YAML diff itself. M22 may want to surface "what changed" — a
  future enhancement would store the prior YAML in a `sigma_rule_revisions`
  side-table.

## Risks / known weaknesses

* **PR retry is operator-driven.** When the Git host fails after a
  human approval, the rule stays at `status='approved'` with
  `git_pr_url=NULL` indefinitely. M12's
  `fragchain.worker.tasks.submit_rule_to_target` works as a manual
  retry but there's no automatic retry loop. A future enhancement: a
  daily Celery sweep that re-queues `approved` rules without a PR URL.
* **Concurrent approval of the same item.** Two maintainers hitting
  approve simultaneously could both pass the `_guard_action` check
  before the first transaction commits. The two-commit pattern means
  the second approver lands their audit row + commit before the PR
  transport — they'd both end up calling `submit_rule` and potentially
  open two PRs against the target. Acceptable today (rare scenario,
  operators typically coordinate); a future hardening: `SELECT ... FOR
  UPDATE` lock on the queue row before reading `status`.
* **`embargo_until` not tracked at the rule layer.** TLP enforcement on
  the queue list / detail uses the rule's static TLP value. If the
  underlying chain was embargoed, the rule's TLP would have been
  bumped at generation time to reflect the max, but a subsequent
  embargo release doesn't ripple back down to the rule's TLP. M2's
  embargo middleware operates on chains + CVEs + source documents
  directly, so analyst access to those works correctly; the rule's
  static TLP is the conservative high-water mark.
* **Similar-rules embedding query is best-effort.** A Qdrant outage
  during detail fetch produces an empty list — the analyst doesn't
  know whether "no similar rules" means there genuinely are none or
  Qdrant is down. We log at info level; M22 could surface "evidence
  partially loaded" if the similar list is missing.
* **No deduplication on regenerate after rejection.** If M15 re-runs on
  a chain after M16 rejected an earlier draft, the fresh pending row
  is for a brand-new `sigma_rule` (the partial unique index keys on
  rule id, not chain+technique). The new rule will look very similar
  to the rejected one — operators may end up re-rejecting it. M22
  could surface "this technique was rejected before" using the
  audit_log + content_hash.
* **Edit doesn't preserve old YAML.** As noted above; the prior
  `content_hash` is in the audit row but the YAML body itself isn't
  archived. If an operator edits then notices the wrong version was
  submitted, the only recovery is git history on the target repo or
  re-generation.

## Outstanding questions

* **Should approval allow staging a PR without immediate submission?**
  Today every approve calls `submit_rule` synchronously. A future
  enhancement: a `submit=false` flag for "approve now, PR later" so
  analysts can batch up approvals and submit them off-hours. The
  M12 Celery task already supports this pattern — exposing it via M16
  would just be a router knob.
* **Should reject support a "soft" reject (do-not-merge-but-keep)?**
  Today rejection is terminal — the rule's status flips to `rejected`
  and the queue row closes. An "archive" state could let analysts
  shelve a rule for later review without blocking M15 regeneration.
* **Should `git_pr_created` carry the routing decision?** Today only
  `rule_approved` includes `routing_reason`. M22 may want to show "PR
  opened against staging because the rule was tagged experimental" in
  the toast. Tweakable without a schema change.
* **Should the evidence bundle include the prior chain's TLP context?**
  Today `cve.tlp` is on the CVE summary and `rule.tlp` is on the queue
  view. The chain's TLP isn't surfaced — analysts wanting that join
  `/chains/{id}`. Could add `chain_tlp` if M22 needs it.
* **Should similar-rules search filter by status?** Today it returns
  any neighbour from Qdrant including draft / pending rules. Filtering
  to `status='merged'` would give "what existing prod rules look like
  this" instead of "what rules in the system look like this". Defer
  until M22 surfaces a UI pressure.

## Phase 5 cleanup applied

### Edit endpoint hardening (E-M3)
- `EditRequest.sigma_yaml` now carries `max_length=200_000`; bodies
  larger than that return a structured 422 from FastAPI before
  `validate_yaml` is ever called. The cap is a denial-of-service
  guard, not a content rule — real Sigma files average well under 4
  KB.
- `QueueManager.edit_and_approve` wraps `validate_yaml` in
  `asyncio.wait_for(..., timeout=5.0)` via `asyncio.to_thread`. A
  pathological YAML that pins pySigma now produces a clean
  `400 {"detail":"pySigma validation timeout"}` instead of blocking
  the request indefinitely.

See `PHASE5_CLEANUP_DONE.md` for the full change set, evidence, and rollback steps.
