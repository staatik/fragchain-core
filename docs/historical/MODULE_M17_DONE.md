# MODULE_M17_DONE — Rule Evaluations
**Built:** 2026-05-13
**Effort actual:** M (one session)
**Status:** complete · sandbox-verified (AST parse on every new/edited file; internal import resolution; SQLAlchemy clause-introspection harness exercised end-to-end against an in-memory shim) · pending runtime verification on live Postgres + Redis + a configured commons source

## Scope reminder

M17 picks up where M16 leaves off: once an analyst approves a rule and
it lands in a target environment, M17 captures field efficacy data
(true positives, false positives per day, query cost, deployment
complexity, environment shape). Aggregated stats expose which rules
actually work — the dashboard reads
``aggregate.recommendation`` directly. Optional contribution back to a
configured commons source (M7) lets the community benefit from the
evaluator's read.

M17 does NOT own:

* Evaluation UI (M22 — Rule Detail panel).
* Notification delivery for "X rules ready for evaluation" (M36).
* The commons-side schema for evaluation contributions — M7's existing
  ``contribute_chain`` transport is re-used in v1, with a
  ``type=rule_evaluation`` discriminator in the payload. M35 (commons
  repo schema) can split this into a dedicated path without changing
  the engine-side contract.

## What was built

### Schema

* **Alembic migration**
  [fragchain/db/migrations/versions/0014_rule_evaluations.py](fragchain/db/migrations/versions/0014_rule_evaluations.py)
  creates ``rule_evaluations`` exactly per FragChain_Module_Specifications.md
  M17 plus three index helpers operations needs:
  * ``ix_rule_evaluations_sigma_rule_id`` — hot path for every list /
    aggregate call.
  * ``ix_rule_evaluations_evaluated_at`` — covering index for the daily
    pending-eval sweep.
  * ``ix_rule_evaluations_contributed`` — partial index on
    ``contributed_to_commons=true`` so the dashboard can count
    contributions without a full scan.
  Downgrade drops indexes then table. Revises ``0013_review_queue``.

* **ORM model** [fragchain/db/models.py:1163](fragchain/db/models.py:1163)
  ``RuleEvaluation``. Foreign key to ``sigma_rules.id`` with
  ``ondelete=CASCADE`` — if an analyst hard-deletes a rule (rare; we
  don't expose that today), the historical evaluations go with it.
  Schema fields match the spec verbatim.

### Backend — `fragchain/evaluations/`

* **[store.py](fragchain/evaluations/store.py)** —
  * ``EvaluationStore`` async wrapper:
    * ``record(rule_id, evaluator, results, actor_id=...)`` — validates
      the body, appends a row, writes an ``audit_log`` row
      (``rule_evaluation.recorded``) via
      :func:`fragchain.audit.audit_entity_state_change` per CLAUDE.md §19,
      returns a detached :class:`EvaluationRecord`. Rejects empty bodies
      (``EvaluationError`` HTTP 400): an evaluation must include at least
      one of ``true_positives`` / ``false_positives_per_day`` / ``notes``.
      Validates enums (``environment_scale`` ∈ {small, medium,
      enterprise}, ``query_cost`` ∈ {low, medium, high},
      ``deployment_complexity`` ∈ {trivial, moderate, complex}).
      Numeric coercion rejects negative FP rates, non-numeric strings,
      and the ``bool`` sub-type-of-``int`` footgun.
    * ``list_for_rule(rule_id, limit, offset)`` — newest-first list
      bounded to 500 rows per page.
    * ``aggregate(rule_id)`` — delegates to the pure
      :func:`aggregate_stats` helper after fetching every row for the
      rule.
    * ``mark_contributed(evaluation_id, actor_*)`` — flips the
      ``contributed_to_commons`` flag and writes an audit row
      (``rule_evaluation.contributed``). Idempotent — re-marking is a
      no-op for the flag but still writes the audit row so the
      contribution attempt is recorded.
    * ``get(evaluation_id)`` — single-row read with TLP enforcement at
      the router boundary.
  * Pure helpers (extracted so tests drive them without a DB):
    * :func:`aggregate_stats(rule_id, rows)` — averages FP/day,
      deduplicates platforms/scales, counts contributions, computes the
      recommendation bucket. Rows without a non-NULL FP/day value are
      excluded from the average but still count toward platform /
      scale coverage.
    * :func:`compute_recommendation(avg_fp, sample_size)`:
      * ``production_ready`` — avg FP/day < 1 AND ≥ 3 FP-bearing samples.
      * ``needs_tuning``    — 1 ≤ avg FP/day < 5.
      * ``problematic``     — avg FP/day ≥ 5.
      * ``insufficient_data`` — fewer than 3 FP-bearing samples (or none).
    * Numeric coercion helpers (``_coerce_fp_per_day``,
      ``_coerce_true_positives``) and the enum validator
      (``_validate_enum``).
  * Detached read-side dataclasses: :class:`EvaluationRecord`,
    :class:`AggregateStats`, :class:`PendingEvaluation`.
  * :func:`identify_rules_pending_evaluation(session, window_days=7,
    now=None, limit=200)` — the daily Celery sweep walks rules with
    ``status ∈ {submitted, merged}`` AND ``origin='fragchain'`` AND
    ``reviewed_at <= now - window_days`` AND zero rows in
    ``rule_evaluations``. Result capped at 200 rows so a large backlog
    surfaces incrementally; M36 (when it ships) will deliver these in
    a daily digest.

* **[__init__.py](fragchain/evaluations/__init__.py)** —
  Public re-exports for downstream consumers (M22):
  ```python
  from fragchain.evaluations import (
      AggregateStats, EvaluationError, EvaluationRecord, EvaluationStore,
      PendingEvaluation, RECOMMENDATION_LEVELS,
      aggregate_stats, compute_recommendation,
      identify_rules_pending_evaluation,
  )
  ```

### Backend — Celery

* **[fragchain/worker/tasks/__init__.py](fragchain/worker/tasks/__init__.py)** —
  New task ``prompt_evaluations(window_days=7)``. Runs the pending-eval
  sweep, emits one ``evaluation.prompt`` structlog event per pending
  rule (M36 will replace this with a structured notification once
  delivery lands). Wraps in ``try/except`` so a session / DB outage
  surfaces as ``status="error"`` rather than crashing the beat worker.
* **[fragchain/worker/celery.py](fragchain/worker/celery.py)** — Beat
  schedule entry ``prompt_evaluations`` fires daily at ``13:00 UTC``
  (off-peak relative to the hourly commons sync at ``:00`` and the
  6-hourly sigma source refresh).

### Backend — API

* **[fragchain/api/routers/evaluations.py](fragchain/api/routers/evaluations.py)** —
  Four endpoints under ``/api/v1``:
  * ``POST /rules/{id}/evaluate`` (maintainer) — submit one evaluation.
    Body: every field optional; store enforces "TP / FP / notes"
    minimum. TLP-gated on the underlying rule. Returns 201 with the
    detached :class:`EvaluationRecord` shape.
  * ``GET /rules/{id}/evaluations`` (auth) — every evaluation for a
    rule, newest first. ``limit`` ≤ 500, ``offset`` ≥ 0. TLP-gated.
  * ``GET /rules/{id}/evaluations/aggregate`` (auth) — :class:`AggregateStats`
    plus the four-bucket recommendation. TLP-gated.
  * ``POST /evaluations/{id}/contribute`` (maintainer) — push to every
    eligible commons source (via :meth:`CommonsClient.contribute_chain`).
    Body is the rule reference (sigma_uuid, title, technique_ids, TLP)
    + the evaluation payload. ``contributed_to_commons`` flips to
    ``true`` once at least one PR opens; per-source PR URLs are in the
    response. TLP-gated on the underlying rule.
  Errors raised by :class:`EvaluationError` map to their HTTP status
  via ``_raise_for_eval_error``:
  * 400 — invalid input (empty body, bad enum, negative numeric).
  * 404 — rule or evaluation not found.

* **[fragchain/api/main.py](fragchain/api/main.py)** —
  Registers ``evaluations_router`` at ``/api/v1`` with tag
  ``evaluations``.

### Audit + invariants

Every state transition writes one ``audit_log`` row via
``audit_entity_state_change`` (CLAUDE.md §19):

| Action | Entity | When |
|---|---|---|
| ``rule_evaluation.recorded``    | ``rule_evaluation`` | on every ``record`` |
| ``rule_evaluation.contributed`` | ``rule_evaluation`` | on every ``mark_contributed`` |

CLAUDE.md §19 audit invariant satisfied: every status transition lands
in ``audit_log``.

### TLP enforcement

Every router endpoint runs ``enforce_tlp_access`` against the
underlying ``sigma_rules`` row before touching evaluations. Analysts
without access to a ``tlp:amber`` rule cannot peek at its field
outcomes either.

## Tests — `tests/test_evaluations.py` (21 tests)

Pure-Python; no live Postgres / Redis. The ``_FakeSession`` mirrors
only the operations the store touches (``get``, ``execute``, ``add``,
``flush``, ``commit``, ``refresh``); SELECT statements are walked
via SQLAlchemy's clause tree to extract BindParameter values for
filtering. External boundaries: no commons client / no transport
needed (the contribute path is exercised through router-level
integration tests in M22, not unit tests of the store).

**Pure helpers — 6 tests:**

* ``_coerce_fp_per_day`` — accepts numeric (int/float/str/Decimal),
  rejects negatives, rejects bool sub-type-of-int, rejects garbage.
* ``_coerce_true_positives`` — accepts int / "7" / 3.0, rejects -1,
  rejects 1.5, rejects "abc".

**Recommendation logic — 2 tests:**

* Every bucket boundary (0.0 / 0.99 → production_ready, 1.0 / 4.99 →
  needs_tuning, 5.0 / 50.0 → problematic, None / size < 3 →
  insufficient_data).
* ``RECOMMENDATION_LEVELS`` constant contains every literal returned.

**``aggregate_stats`` — 4 tests:**

* Empty input → zero-stats with ``recommendation='insufficient_data'``.
* Mixed FP values: average computed correctly, platforms / scales
  deduplicated, contributed_count tallied.
* NULL FP rows excluded from the average but still in ``count`` —
  collapses to ``insufficient_data`` when the FP-bearing sample size
  drops below 3.
* High-FP averages → ``problematic``; mid-band → ``needs_tuning``.

**``EvaluationStore.record`` — 6 tests:**

* Happy path: row + audit land; one commit; record returned.
* Unknown rule → ``EvaluationError`` status 404; no rows written.
* Empty body → 400; no rows written.
* Negative FP → ``EvaluationError`` 400.
* Unknown ``environment_scale`` → 400 with field name in message.
* Unknown ``query_cost`` → 400.

**``EvaluationStore.list_for_rule`` / ``aggregate`` — 2 tests:**

* List returns rows newest first.
* ``aggregate`` round-trips through the store → DB-side query → pure
  ``aggregate_stats`` and yields ``production_ready`` when 3 low-FP
  rows are present.

**``EvaluationStore.mark_contributed`` — 3 tests:**

* Flips the flag, writes ``rule_evaluation.contributed`` audit row.
* Idempotent on a row already at ``contributed_to_commons=True`` —
  one audit row still lands with ``before={"contributed_to_commons":
  True}`` for the attempt-trace.
* Missing evaluation id → 404.

**``identify_rules_pending_evaluation`` — 3 tests:**

* Excludes: rules reviewed < window_days ago; rules with at least one
  evaluation already; rules at ``status='approved'`` (no PR yet);
  rules with ``origin='imported'`` (no review loop).
* Empty session → empty list.
* Negative ``window_days`` → ``ValueError``.

**Constants surface — 1 test:**

* ``VALID_ENVIRONMENT_SCALES`` / ``VALID_QUERY_COSTS`` /
  ``VALID_DEPLOYMENT_COMPLEXITY`` match the spec language verbatim.

### Sandbox-level pre-flight checks (runnable here)

* ``ast.parse()`` on every new / edited file — no syntax errors:
  ``fragchain/evaluations/__init__.py``,
  ``fragchain/evaluations/store.py``,
  ``fragchain/api/routers/evaluations.py``,
  ``fragchain/api/main.py``,
  ``fragchain/worker/tasks/__init__.py``,
  ``fragchain/worker/celery.py``,
  ``fragchain/db/models.py``,
  ``fragchain/db/migrations/versions/0014_rule_evaluations.py``,
  ``tests/test_evaluations.py``.
* ``grep -rn "import anthropic\|from anthropic" fragchain/evaluations/`` →
  no matches (CLAUDE.md §19).
* ``grep -rn "fragchain_" fragchain/evaluations/`` → no Qdrant
  collection prefix (CLAUDE.md §19).
* Migration chain still single-head at ``0014_rule_evaluations``;
  ``down_revision`` points at ``0013_review_queue``.
* Internal-import resolution: every ``from fragchain.evaluations …``
  and every ``from fragchain.commons … import CommonsClient`` resolves
  to a real top-level name in the target module.
* SQLAlchemy clause-walking harness exercised against
  ``select(...).where(Column == uuid_value)`` /
  ``select(...).where(Column <= datetime_value)`` /
  ``select(...).where(Column.in_(...))`` — BindParameter.value is
  readable at every shape the store / sweep generates.

### Runtime verification *not* runnable in this sandbox

Operator should run these on the next ``docker compose up``:

| Done criterion | Verification command |
|---|---|
| ``alembic upgrade head`` reaches ``0014_rule_evaluations`` | ``docker compose exec fragchain-api alembic current`` → ``0014_rule_evaluations (head)``; ``\d rule_evaluations`` shows the spec columns plus three indexes |
| ``POST /rules/{id}/evaluate`` records a row | ``curl -X POST -H "Authorization: Bearer $JWT_MAINTAINER" -d '{"environment_platform":"linux","environment_scale":"small","true_positives":5,"false_positives_per_day":0.2,"query_cost":"low","deployment_complexity":"trivial","notes":"works"}' .../api/v1/rules/<rule>/evaluate`` → 201 + body; ``SELECT * FROM rule_evaluations`` returns one row |
| Audit row lands | ``SELECT entity_type, action, after FROM audit_log WHERE entity_id=<evaluation_id>`` returns ``rule_evaluation`` / ``rule_evaluation.recorded`` |
| Empty body rejected | ``-d '{}'`` → 400 ``evaluation must include at least one of …`` |
| Bad enum rejected | ``-d '{"environment_scale":"galactic","notes":"x"}'`` → 400 |
| TLP enforcement | Submitting against a ``tlp:amber`` rule with a ``tlp:green`` user → 403 |
| ``GET /rules/{id}/evaluations`` lists rows | newest-first by ``evaluated_at`` |
| ``GET /rules/{id}/evaluations/aggregate`` returns stats | ``recommendation`` reflects the FP average + sample size; with 3+ rows at FP < 1 → ``production_ready`` |
| ``POST /evaluations/{id}/contribute`` opens commons PR | against a contribute-enabled commons source: ``submitted >= 1``, ``contributed_to_commons=true`` flag flips on the row, ``per_source[*].pr_url`` populated |
| Daily Celery prompt task runs | ``celery -A fragchain.worker.celery inspect scheduled`` shows ``prompt_evaluations`` firing at 13:00 UTC; running it manually (``celery call fragchain.worker.tasks.prompt_evaluations``) returns ``status=ok`` with ``pending_count`` ≥ 0 and one ``evaluation.prompt`` structlog event per pending rule |
| Pending sweep filter correctness | seed two rules: one approved-only (no PR), one submitted+reviewed 10 days ago. Pending list contains only the second. |
| Evaluated rule excluded from sweep | recording an evaluation on the submitted rule then re-running the task → ``pending_count`` decrements by one |

## Interfaces this module exposes

For dependent modules (M19 WebSocket, M22 UI):

```python
from fragchain.evaluations import (
    EvaluationStore,
    EvaluationError,
    EvaluationRecord,
    AggregateStats,
    PendingEvaluation,
    RECOMMENDATION_LEVELS,
    aggregate_stats,
    compute_recommendation,
    identify_rules_pending_evaluation,
)
```

API contract (all under ``/api/v1``):

* ``POST   /rules/{id}/evaluate``                  maintainer · ``{environment_platform?, environment_logsource?, environment_scale?, true_positives?, false_positives_per_day?, query_cost?, deployment_complexity?, notes?}`` — at least one of TP/FP/notes
* ``GET    /rules/{id}/evaluations``               authenticated · ``?limit, ?offset`` · TLP-enforced
* ``GET    /rules/{id}/evaluations/aggregate``     authenticated · TLP-enforced · returns ``{count, avg_false_positives_per_day, total_true_positives, platforms_tested, scales_tested, contributed_count, recommendation}``
* ``POST   /evaluations/{id}/contribute``          maintainer · pushes via M7 ``CommonsClient.contribute_chain``

## What dependent modules need to know

* **M19 (WebSocket fan-out)** — M17 does not emit events onto the
  in-process bus today. If M22 wants real-time "new evaluation"
  banners on a rule detail page, M19 can fan out ``evaluation_recorded``
  / ``evaluation_contributed`` — add the ``emit_event`` calls
  alongside the existing ``audit_entity_state_change`` writes.
* **M22 (Rule Detail UI)** — drives the four endpoints. The Rule Detail
  panel surfaces the aggregate stats first (the ``recommendation``
  badge is the headline) with the evaluation list as a collapsible
  table beneath. The Dashboard reads ``identify_rules_pending_evaluation``
  output (via M36 when it lands, or directly via a future
  ``GET /evaluations/pending`` endpoint) to render the "X rules ready
  for evaluation" prompt.
* **M36 (Notifications)** — once channel delivery lands, replace the
  ``logger.info("evaluation.prompt", ...)`` block in
  ``prompt_evaluations`` with a call into the notifications dispatcher.
  The payload is already a structured dict per pending rule
  (``sigma_rule_id``, ``title``, ``reviewed_at``, ``days_since_review``).
* **M7 (Commons)** — M17 contributes via the existing
  ``CommonsClient.contribute_chain(cve_id=..., chain_payload=...,
  actor_username=...)`` API. The ``cve_id`` argument is overloaded
  here to carry an evaluation-specific branch key
  (``eval-<sigma_uuid[:8]>``); M35 (commons repo schema) may want to
  split evaluations into a dedicated path / branch family. The current
  pattern keeps the engine-side code small without prejudicing the
  commons-side schema.

## Deviations from spec / kickoff

* **Empty-body guard.** The spec doesn't say the body needs a minimum
  payload. I added ``at least one of true_positives / FP / notes`` so
  a row carries something useful — otherwise the aggregate FP/day
  collapses to NaN and the recommendation badge becomes meaningless.
  Operators wanting to file an "environment shape only" row can supply
  a one-character note.
* **``insufficient_data`` is a fourth recommendation bucket.** The
  kickoff lists three: production_ready, needs_tuning, problematic.
  In practice a rule with one evaluation at FP=0.1 doesn't mean
  "production ready" — it means "we don't know yet". Added
  ``insufficient_data`` for sample sizes < 3 so the Dashboard renders
  a neutral colour rather than a green-light badge prematurely.
  The kickoff's three remaining buckets behave exactly as specified
  for sample_size >= 3.
* **NULL FP rows excluded from the average.** Evaluators can submit
  "environment platform + notes" rows without a FP rate (e.g. for a
  rule that is still in shakedown). Those rows count toward
  ``count`` and platform / scale coverage but drop out of the average
  so a half-baked early read doesn't poison the recommendation.
* **Contribute path piggybacks on M7's ``contribute_chain`` API.** The
  spec says "Contribution to commons creates PR (via M7)". M7's
  current contribute API is shaped around chain payloads; I pass the
  evaluation as the ``chain_payload`` with a ``type=rule_evaluation``
  discriminator. This works because the M7 transport doesn't inspect
  the payload shape — it just opens a PR with the JSON. M35 can
  introduce a dedicated commons evaluations directory + path without
  changing M17.
* **Daily Celery cadence at 13:00 UTC, not midnight.** The spec just
  says "daily". 13:00 UTC is mid-business-day in the Americas + late
  afternoon in EMEA — analysts notice the digest while their target
  consoles are still open. Easily tunable via the beat schedule.
* **``window_days`` is a task parameter, not a hardcoded constant.**
  The spec calls out "7+ days". I made it a kwarg with default 7 so
  operators in fast-iteration environments can drop it to ~3 without
  rebuilding the image. The Celery task forwards the value.
* **``identify_rules_pending_evaluation`` filters on
  ``status ∈ {submitted, merged}``, not just ``approved``.** A rule
  at ``status='approved'`` without a PR URL hasn't actually been
  deployed anywhere — nagging the analyst to file a field evaluation
  is premature. The sweep waits until the rule landed via M12's PR
  flow (``submitted``) or got merged upstream (``merged``).
* **Filter also excludes ``origin='imported'``.** Imported rules don't
  go through the M16 review loop, so M17 doesn't track field efficacy
  for them — that data already lives in the upstream Sigma repo's
  rule comments. Easy to relax if a future deployment wants to
  re-evaluate imported rules locally.
* **Result list capped at 200 rows per task run.** A large backlog
  surfaces incrementally — 200 rules of context is more than M36 can
  reasonably batch deliver in one digest anyway, and operators
  clearing them out shrinks the list naturally. Easy to raise via the
  ``limit`` kwarg.
* **Audit row writes a single transition per call, not before+after on
  the same row.** ``rule_evaluation.recorded`` has ``before=None``
  because the row didn't exist before the call. This matches the M11
  / M16 audit pattern.
* **Idempotent ``mark_contributed`` still writes an audit row.** If
  an operator re-runs the contribute path (e.g. for a different
  commons source after the first round), the flag stays ``true`` but
  the contribution attempt is still recorded in ``audit_log`` so the
  history is reconstructable.

## Known TODOs (owned by other modules)

* **M22 (Rule Detail UI)** — drive the four endpoints. The aggregate
  ``recommendation`` field is the headline; the list is the supporting
  detail.
* **M36 (Notifications)** — replace the ``logger.info`` block in
  ``prompt_evaluations`` with a call into the notifications
  dispatcher once it lands. Pending list shape is already structured.
* **M35 (commons repo schema)** — define a dedicated
  ``evaluations/`` directory in ``fragchain-intelligence`` so M17
  contributions land in their own namespace rather than overloading
  the chain contribution path.
* **Pending evaluation API endpoint** — operators / UI may want a
  ``GET /evaluations/pending`` directly (today the data is only
  observable via the Celery task's logs). Defer until M22 shows
  pressure.
* **Evaluation-bearing event emissions** — M19 may want to fan out
  ``evaluation_recorded`` / ``evaluation_contributed`` over the
  WebSocket bus. Hook points are already in the store's audit calls.

## Risks / known weaknesses

* **No per-evaluator dedup.** An evaluator can file multiple rows
  against the same rule + environment. By design — corrections /
  re-evaluations should produce a fresh row rather than overwriting
  history. M22 should surface "evaluator X filed 3 rows" cleanly.
* **Aggregate ignores evaluator quality.** Every evaluator is treated
  equally. Once M3 lands identity tiers (M38 placeholder), a future
  enhancement could weight evaluators by trust level — but that's a
  post-v1 concern.
* **Contribute uses sigma_uuid (or rule id) as the commons branch
  key.** Two evaluations for the same rule generate two PRs against
  branches with different UUID suffixes (uuid4 inside the
  ``contribute_chain`` branch generator). This is fine for the public
  commons today — the M35 schema may want to normalise to one PR per
  rule with appended evaluations.
* **TLP gating on contribute is binary.** A ``tlp:amber`` rule with an
  evaluator on ``tlp:green`` access cannot contribute its evaluation
  to the commons, even though the evaluation itself might be
  ``tlp:clear``. By design (CLAUDE.md §8 max-TLP rule) — the
  evaluation inherits the rule's classification. Operators wanting to
  contribute "the rule works in our shop" without disclosing the
  rule's classification can rephrase the evaluation as a generic
  comment outside the commons system.
* **``window_days`` math uses ``timedelta(days=N)``, not calendar
  days.** A rule reviewed at 23:00 UTC won't show up in a 6-day-old
  sweep run at 22:00 the next week. Off-by-an-hour at worst; fine
  given the daily cadence.

## Outstanding questions

* **Should "evaluator" be a separate role?** Today the API requires
  maintainer tier. Once M3 hardens role assignment, M17 could expose
  an ``evaluator`` role that can submit / list / aggregate but not
  approve. Easy refactor (one ``Depends(...)`` switch per endpoint)
  when the upstream identity tier work lands.
* **Should ``mark_contributed`` track per-source contributions
  separately?** Today it's a single boolean. Operators with multiple
  commons sources (e.g. public + internal partner) might want to know
  "contributed to public yes, partner no". A future schema split
  (``rule_evaluation_contributions(source_id, evaluation_id, pr_url)``)
  would resolve this; for v1 the per-source PR URLs in the response
  body are enough.
* **Should the recommendation bucket factor in ``contributed_count``?**
  A rule with 3 evaluations and 3 contributions is more battle-tested
  than 3 evaluations with no contributions. Today the buckets are
  purely FP-driven. Worth revisiting once M22 surfaces real usage.
* **Should the daily sweep batch rules by chain / by CVE?** Today the
  output is a flat list. M36 may want to group "5 evaluations missing
  for the Dirty Frag attack chain" into one digest entry. Easy to add
  at the M36 layer without changing M17.
