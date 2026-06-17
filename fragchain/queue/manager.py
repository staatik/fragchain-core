"""Review-queue lifecycle manager (M16).

Picks up where M15 stopped: a generated rule + pending review queue row
sit in the DB. M16 owns every transition from that point on:

  * **List / Get** — paginated browsing + a detail view that hydrates the
    evidence the analyst needs in one round-trip (CVE summary, chain
    context, top 3 source docs, similar rules from Qdrant, priority
    breakdown).
  * **Assign** — set ``assigned_to`` on the queue row.
  * **Approve** — flip the rule ``status`` to ``approved``, run M12's
    :class:`RoutingEngine` (or use an operator-supplied ``target_id``),
    and call :class:`SigmaTargetClient.submit_rule` so a PR opens against
    the target repo. On success the rule lands at ``status='submitted'``
    with ``git_pr_url`` / ``git_commit_sha`` / ``target_id`` populated and
    ``reviewed_by`` / ``reviewed_at`` / ``merged_at`` (best label for
    "left the queue") stamped.
  * **Reject** — flip the rule to ``status='rejected'`` and the queue row
    to ``status='rejected'``. The reason is recorded in ``audit_log``.
  * **Edit + approve** — re-validate the supplied YAML through M15's
    validator. On success: update ``sigma_yaml`` + ``content_hash`` then
    fall through to the approve flow. On failure: surface validator
    errors (HTTP 400 at the router boundary).

Every transition writes an :class:`AuditLog` row via
:func:`fragchain.audit.audit_entity_state_change` (CLAUDE.md §19) and
emits an event onto the in-process bus (M19 will fan these out over a
WebSocket). The three lifecycle events are:

  * ``rule_approved``  — on every approve / edit_and_approve regardless
    of PR submission outcome.
  * ``rule_rejected``  — on every reject.
  * ``git_pr_created`` — on a successful PR submission. Carries the PR
    URL + commit SHA + target_name so the UI can deep-link.

Failure modes are bounded — the approve flow flips ``rule.status`` and
``queue.status`` *before* the PR transport call. If the transport fails,
the row stays at ``approved`` (no PR URL); the UI surfaces this as
"approved, PR pending" and a Celery retry / manual operator action can
re-submit later via :func:`fragchain.worker.tasks.submit_rule_to_target`.
This preserves the human-review invariant ("approved means a human
signed off") even when the upstream Git host is down.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog
import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.audit import audit_entity_state_change
from fragchain.db.models import (
    CVE,
    AttackChainRow,
    ChainTTPRow,
    ReviewQueueItem,
    SigmaRule,
    SigmaTarget,
    SourceDocument,
)
from fragchain.notifications import emit_event
from fragchain.rules.validator import ValidationResult, validate_yaml
from fragchain.sigma import (
    RoutingEngine,
    SigmaTargetClient,
    SubmitOutcome,
)

logger = structlog.get_logger(__name__)


QUEUE_STATUSES: frozenset[str] = frozenset(
    {"pending", "in_review", "approved", "rejected"}
)
"""Allowed queue ``status`` values. Validated on PATCH filters."""

_TERMINAL_QUEUE_STATUSES: frozenset[str] = frozenset({"approved", "rejected"})
"""Statuses that block further lifecycle actions — once a row is
approved/rejected it stays that way; re-running M15 creates a fresh
pending row alongside the historical record."""

_EDIT_VALIDATION_TIMEOUT_S: float = 5.0
"""Wall-clock cap on ``validate_yaml`` during the edit flow. pySigma
runs in-process and a pathological YAML can pin the event loop for a
long time; surface a clean 400 instead (E-M3 in the Phase 5 security
review)."""

_ADJACENT_TTP_WINDOW: int = 1
"""How many TTPs before/after the focus technique to bundle with the
detail response. ±1 gives the analyst narrative context without
over-fetching."""

_TOP_SOURCE_DOCS: int = 3
"""How many source documents to surface on the detail response — same
budget M15 uses when feeding the rule prompt."""

_SIMILAR_RULES_LIMIT: int = 5
"""Number of semantic neighbours pulled from Qdrant ``sigma_rules``."""


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class QueueActionError(Exception):
    """Raised when a queue transition is refused.

    ``status_code`` is the HTTP code the router should surface (404 for
    "not found", 400 for invalid input, 409 for "wrong state",
    422 for validator failures). ``errors`` / ``warnings`` carry the
    structured validator output on edit failures so the UI can render
    field-level diagnostics.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 400,
        errors: list[str] | None = None,
        warnings: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.errors = list(errors or [])
        self.warnings = list(warnings or [])


# ---------------------------------------------------------------------------
# Read-side dataclasses (detached from ORM)
# ---------------------------------------------------------------------------


@dataclass
class QueueItemView:
    """Summary row for ``GET /api/v1/queue`` list responses.

    Detached from the ORM so callers don't have to keep a live
    :class:`AsyncSession`. ``tlp`` mirrors :class:`SigmaRule.tlp` so the
    TLP middleware can filter the list without an extra join.
    """

    id: uuid.UUID
    sigma_rule_id: uuid.UUID
    priority: str
    priority_score: int
    priority_reason: str | None
    assigned_to: str | None
    status: str
    created_at: datetime
    completed_at: datetime | None
    title: str
    rule_status: str
    origin: str
    technique_ids: list[str]
    logsource_profile: str | None
    detection_level: str | None
    tlp: str
    cve_id: uuid.UUID | None
    cve_textual_id: str | None
    chain_id: uuid.UUID | None
    review_notes: str | None
    git_pr_url: str | None
    # Plan C Phase 6: assessment-link projection. Defaults keep older
    # callers (and internal constructions that don't yet pass these)
    # working without modification.
    assessment_id: uuid.UUID | None = None
    low_detectability_override: bool = False
    superseded_by_assessment_id: uuid.UUID | None = None


@dataclass
class TTPContext:
    """One TTP row included in the chain-context block."""

    id: uuid.UUID
    seq_order: int
    tactic: str | None
    tactic_id: str | None
    technique_id: str | None
    technique_name: str | None
    confidence: float | None
    detection_opportunity: str | None
    is_focus: bool = False


@dataclass
class SourceDocSnippet:
    """One source-doc reference attached to the detail response."""

    id: uuid.UUID
    url: str
    source_type: str | None
    quality_score: float | None
    tlp: str
    excerpt: str | None


@dataclass
class SimilarRuleHit:
    """One Qdrant semantic neighbour."""

    rule_id: str | None
    sigma_uuid: str | None
    title: str | None
    technique_ids: list[str]
    score: float
    logsource_product: str | None
    logsource_service: str | None
    origin: str | None


@dataclass
class QueueItemDetail:
    """Detail payload for ``GET /api/v1/queue/{id}``.

    Embeds enough context for an analyst to make an approve/reject call
    without further round-trips: parsed YAML, CVE context, chain context
    (the focus TTP + 1 before / 1 after), top 3 source documents, top 5
    semantically-similar existing rules, and the priority breakdown
    carried over from M14.
    """

    item: QueueItemView
    sigma_yaml: str
    parsed_yaml: dict[str, Any] | None
    cve: dict[str, Any] | None
    chain_context: list[TTPContext] = field(default_factory=list)
    source_documents: list[SourceDocSnippet] = field(default_factory=list)
    similar_rules: list[SimilarRuleHit] = field(default_factory=list)
    priority_breakdown: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Outcome dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ApproveOutcome:
    """Result of a successful approve / edit_and_approve."""

    rule_id: uuid.UUID
    queue_id: uuid.UUID
    rule_status: str
    queue_status: str
    target_id: uuid.UUID | None
    target_name: str | None
    pr_submitted: bool
    pr_url: str | None
    pr_number: int | None
    commit_sha: str | None
    branch: str | None
    routing_reason: str
    message: str


@dataclass
class RejectOutcome:
    rule_id: uuid.UUID
    queue_id: uuid.UUID
    rule_status: str
    queue_status: str
    reason: str


@dataclass
class EditOutcome:
    """Result of a successful edit-then-approve."""

    rule_id: uuid.UUID
    queue_id: uuid.UUID
    approve: ApproveOutcome
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class QueueManager:
    """Lifecycle orchestrator for review queue items.

    Construct one per request / Celery task with an :class:`AsyncSession`.
    Optional collaborators are injected so tests can pass stubs:

      * ``target_client`` — :class:`SigmaTargetClient` (defaults to a fresh one).
      * ``router_factory`` — async callable returning a :class:`RoutingEngine`
        (defaults to :meth:`RoutingEngine.load`).
      * ``embedder_factory`` — sync callable returning a vector embedder
        with a ``search_sigma_rules`` coroutine. Defaults to a fresh
        :class:`fragchain.vector.VectorEmbedder` instance — a Qdrant
        outage downgrades to "no similar rules" rather than failing the
        detail call.

    The manager performs every state transition inside the supplied
    session and commits at the end of each action. Callers that share a
    session across multiple actions should still get coherent behaviour
    because each transition is committed before the next is attempted.
    """

    def __init__(
        self,
        session: AsyncSession,
        *,
        target_client: SigmaTargetClient | None = None,
        router_factory=None,
        embedder_factory=None,
    ) -> None:
        self._session = session
        self._target_client = target_client
        self._router_factory = router_factory
        self._embedder_factory = embedder_factory

    # ------------------------------------------------------------------
    # Read paths
    # ------------------------------------------------------------------

    async def list_items(
        self,
        *,
        priority: str | None = None,
        status_filter: str | None = None,
        assigned_to: str | None = None,
        cve_id: str | None = None,
        assessment_id: uuid.UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[QueueItemView]:
        """Browse the queue, ordered by priority_score DESC then created_at ASC.

        Filters are AND-ed. The list is *not* TLP-filtered here — the
        router is responsible for invoking
        :func:`fragchain.api.middleware.tlp_filter.apply_tlp_filter` on
        the returned views (which carry ``tlp`` + ``id`` so the helper
        can run).
        """
        if priority is not None and not priority.strip():
            raise QueueActionError("priority cannot be empty", status_code=400)
        if status_filter is not None:
            if status_filter not in QUEUE_STATUSES:
                raise QueueActionError(
                    f"status must be one of {sorted(QUEUE_STATUSES)}",
                    status_code=400,
                )

        stmt = (
            select(ReviewQueueItem, SigmaRule)
            .join(SigmaRule, SigmaRule.id == ReviewQueueItem.sigma_rule_id)
            .order_by(
                ReviewQueueItem.priority_score.desc(),
                ReviewQueueItem.created_at.asc(),
            )
        )
        if priority:
            stmt = stmt.where(ReviewQueueItem.priority == priority)
        if status_filter:
            stmt = stmt.where(ReviewQueueItem.status == status_filter)
        if assigned_to:
            stmt = stmt.where(ReviewQueueItem.assigned_to == assigned_to)
        if cve_id:
            cve_row = await self._resolve_cve(cve_id)
            if cve_row is None:
                return []
            stmt = stmt.where(SigmaRule.cve_id == cve_row.id)
        if assessment_id is not None:
            stmt = stmt.where(ReviewQueueItem.assessment_id == assessment_id)

        stmt = stmt.limit(limit).offset(offset)
        rows = list((await self._session.execute(stmt)).all())
        if not rows:
            return []

        cve_ids = sorted({r[1].cve_id for r in rows if r[1].cve_id is not None})
        textual_map = await self._resolve_cve_textual_ids(cve_ids)

        return [
            _build_view(item, rule, textual_map.get(rule.cve_id) if rule.cve_id else None)
            for item, rule in rows
        ]

    async def get_item_with_evidence(
        self, item_id: uuid.UUID
    ) -> QueueItemDetail:
        """Return one queue row plus the evidence bundle for review.

        Raises :class:`QueueActionError` (404) if the row doesn't exist.
        Qdrant failures collapse to an empty ``similar_rules`` list.
        """
        item = await self._session.get(ReviewQueueItem, item_id)
        if item is None:
            raise QueueActionError("queue item not found", status_code=404)
        rule = await self._session.get(SigmaRule, item.sigma_rule_id)
        if rule is None:
            raise QueueActionError(
                "queue item references missing sigma rule",
                status_code=409,
            )

        cve_textual_id: str | None = None
        cve_summary: dict[str, Any] | None = None
        if rule.cve_id:
            cve = await self._session.get(CVE, rule.cve_id)
            if cve is not None:
                cve_textual_id = cve.cve_id
                cve_summary = _cve_summary(cve)

        chain_context = await self._build_chain_context(rule)
        source_docs = await self._build_source_documents(rule)
        parsed_yaml = _safe_parse_yaml(rule.sigma_yaml or "")
        similar = await self._fetch_similar_rules(rule, parsed_yaml)

        priority_breakdown = {
            "priority": item.priority,
            "priority_score": int(item.priority_score or 0),
            "priority_reason": item.priority_reason,
        }

        view = _build_view(item, rule, cve_textual_id)
        return QueueItemDetail(
            item=view,
            sigma_yaml=rule.sigma_yaml or "",
            parsed_yaml=parsed_yaml,
            cve=cve_summary,
            chain_context=chain_context,
            source_documents=source_docs,
            similar_rules=similar,
            priority_breakdown=priority_breakdown,
        )

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    async def assign(
        self,
        item_id: uuid.UUID,
        *,
        actor_username: str | None,
        actor_id: uuid.UUID | None,
        assigned_to: str | None,
    ) -> QueueItemView:
        """Set / clear the queue row's ``assigned_to``.

        Passing ``None`` (or empty) clears the assignment. The PATCH
        endpoint accepts a JSON body of ``{"assigned_to": "<user>"}`` or
        ``{"assigned_to": null}``.
        """
        item, rule = await self._load_pair(item_id)
        if item.status in _TERMINAL_QUEUE_STATUSES:
            raise QueueActionError(
                f"queue item already {item.status} — assignment is read-only",
                status_code=409,
            )
        previous = item.assigned_to
        new_value = assigned_to.strip() if isinstance(assigned_to, str) and assigned_to.strip() else None
        item.assigned_to = new_value
        # An assignment moves the row to ``in_review`` only if it was pending —
        # explicit re-assignment of an already-in-review row stays in_review.
        if new_value and item.status == "pending":
            item.status = "in_review"

        await audit_entity_state_change(
            self._session,
            entity_type="review_queue",
            entity_id=item.id,
            action="queue.assigned",
            before={"assigned_to": previous, "status": _prior_status_for_assign(item, previous)},
            after={"assigned_to": new_value, "status": item.status},
            actor=actor_id,
        )
        await self._session.commit()
        logger.info(
            "queue.assigned",
            queue_id=str(item.id),
            sigma_rule_id=str(rule.id),
            assigned_to=new_value,
            actor=actor_username,
        )
        cve_textual_id = await self._cve_textual_id(rule.cve_id)
        return _build_view(item, rule, cve_textual_id)

    async def approve(
        self,
        item_id: uuid.UUID,
        *,
        actor_username: str | None,
        actor_id: uuid.UUID | None,
        target_id: uuid.UUID | None = None,
        skip_pr: bool = False,
    ) -> ApproveOutcome:
        """Approve a pending rule and submit a PR via M12.

        ``target_id`` is optional — when omitted, M12's
        :class:`RoutingEngine` picks the right target based on the
        rule's tags / fields / level. Returns an :class:`ApproveOutcome`
        carrying the PR metadata if submission succeeded; ``pr_submitted=False``
        means the rule is approved but no PR landed (e.g. no enabled
        targets, target down, transport error). Operators can resubmit
        via the M12 Celery task without re-approving.

        When ``skip_pr=True``, the approval persists locally without
        attempting Git PR submission. The rule lands at
        ``status='approved'``; ``target_id`` / ``git_pr_url`` stay null
        and routing is bypassed entirely. Useful for evaluation
        deployments that haven't configured a Sigma target yet.
        """
        item, rule = await self._load_pair(item_id)
        self._guard_action(item, "approve")

        if skip_pr:
            return await self._approve_local_only(
                item=item,
                rule=rule,
                actor_username=actor_username,
                actor_id=actor_id,
            )

        target, routing_reason = await self._select_target(rule, target_id)
        if target is None:
            raise QueueActionError(
                "no Sigma target available for routing — configure a "
                "target or pass an explicit target_id, or set "
                "skip_pr=true to approve without a PR.",
                status_code=409,
            )

        previous_rule_status = rule.status
        previous_queue_status = item.status

        rule.status = "approved"
        rule.reviewed_by = actor_username
        rule.reviewed_at = datetime.now(tz=timezone.utc)
        item.status = "approved"
        item.completed_at = datetime.now(tz=timezone.utc)

        await audit_entity_state_change(
            self._session,
            entity_type="sigma_rule",
            entity_id=rule.id,
            action="sigma_rule.approved",
            before={"status": previous_rule_status},
            after={
                "status": "approved",
                "reviewed_by": actor_username,
                "queue_id": str(item.id),
                "target_id": str(target.id),
                "target_name": target.name,
            },
            actor=actor_id,
        )
        await audit_entity_state_change(
            self._session,
            entity_type="review_queue",
            entity_id=item.id,
            action="queue.approved",
            before={"status": previous_queue_status},
            after={
                "status": "approved",
                "sigma_rule_id": str(rule.id),
                "target_id": str(target.id),
                "target_name": target.name,
                "actor": actor_username,
            },
            actor=actor_id,
        )

        # Commit the approval before the network call so a transport
        # failure doesn't roll back the human decision. The PR retry path
        # picks up the row at status='approved'.
        await self._session.commit()
        # Re-load so subsequent submit_rule call sees the committed state.
        await self._session.refresh(rule)
        await self._session.refresh(item)
        emit_event(
            "rule_approved",
            {
                "rule_id": str(rule.id),
                "queue_id": str(item.id),
                "cve_id": str(rule.cve_id) if rule.cve_id else None,
                "chain_id": str(rule.chain_id) if rule.chain_id else None,
                "target_id": str(target.id),
                "target_name": target.name,
                "approved_by": actor_username,
                "priority_score": int(item.priority_score or 0),
                "priority": item.priority,
                "routing_reason": routing_reason,
            },
        )

        outcome = await self._submit_pr(rule, target)

        # The submission may flip status='approved' → 'submitted', set
        # git_pr_url/commit/target_id, and stamp last_pr_at on the target.
        # If created=True we also mark merged_at (best-effort timestamp
        # for "left the queue" — the actual upstream merge happens later
        # and gets reconciled when M27 lands).
        if outcome.created:
            rule.merged_at = rule.merged_at or datetime.now(tz=timezone.utc)
            emit_event(
                "git_pr_created",
                {
                    "rule_id": str(rule.id),
                    "queue_id": str(item.id),
                    "target_id": str(target.id),
                    "target_name": target.name,
                    "pr_url": outcome.url,
                    "pr_number": outcome.number,
                    "commit_sha": outcome.commit_sha,
                    "branch": outcome.branch,
                    "cve_id": str(rule.cve_id) if rule.cve_id else None,
                    "chain_id": str(rule.chain_id) if rule.chain_id else None,
                },
            )

        await audit_entity_state_change(
            self._session,
            entity_type="sigma_rule",
            entity_id=rule.id,
            action="sigma_rule.pr_submitted" if outcome.created else "sigma_rule.pr_failed",
            before={"git_pr_url": None, "status": "approved"},
            after={
                "git_pr_url": outcome.url,
                "git_commit_sha": outcome.commit_sha,
                "status": rule.status,
                "target_id": str(target.id),
                "target_name": target.name,
                "submitted": bool(outcome.created),
                "message": outcome.message,
            },
            actor=actor_id,
        )
        await self._session.commit()

        await self._invalidate_matrix_cache()

        logger.info(
            "queue.approved",
            queue_id=str(item.id),
            sigma_rule_id=str(rule.id),
            target_id=str(target.id),
            target_name=target.name,
            pr_submitted=bool(outcome.created),
            pr_url=outcome.url,
            actor=actor_username,
        )

        return ApproveOutcome(
            rule_id=rule.id,
            queue_id=item.id,
            rule_status=rule.status,
            queue_status=item.status,
            target_id=target.id,
            target_name=target.name,
            pr_submitted=bool(outcome.created),
            pr_url=outcome.url,
            pr_number=outcome.number,
            commit_sha=outcome.commit_sha,
            branch=outcome.branch,
            routing_reason=routing_reason,
            message=outcome.message,
        )

    async def reject(
        self,
        item_id: uuid.UUID,
        *,
        actor_username: str | None,
        actor_id: uuid.UUID | None,
        reason: str,
    ) -> RejectOutcome:
        """Reject a pending rule.

        Updates rule + queue status. Reason lives in ``audit_log``
        (CLAUDE.md §19) and is appended to ``sigma_rules.review_notes``
        for at-a-glance UI visibility (we don't add a dedicated column —
        the audit log is the source of truth).
        """
        if not isinstance(reason, str) or not reason.strip():
            raise QueueActionError("reason is required", status_code=400)
        reason = reason.strip()

        item, rule = await self._load_pair(item_id)
        self._guard_action(item, "reject")

        previous_rule_status = rule.status
        previous_queue_status = item.status

        rule.status = "rejected"
        rule.reviewed_by = actor_username
        rule.reviewed_at = datetime.now(tz=timezone.utc)
        rule.review_notes = _append_rejection_note(rule.review_notes, reason, actor_username)
        item.status = "rejected"
        item.completed_at = datetime.now(tz=timezone.utc)

        await audit_entity_state_change(
            self._session,
            entity_type="sigma_rule",
            entity_id=rule.id,
            action="sigma_rule.rejected",
            before={"status": previous_rule_status},
            after={
                "status": "rejected",
                "reviewed_by": actor_username,
                "queue_id": str(item.id),
            },
            actor=actor_id,
            reason=reason,
        )
        await audit_entity_state_change(
            self._session,
            entity_type="review_queue",
            entity_id=item.id,
            action="queue.rejected",
            before={"status": previous_queue_status},
            after={
                "status": "rejected",
                "sigma_rule_id": str(rule.id),
                "actor": actor_username,
            },
            actor=actor_id,
            reason=reason,
        )

        await self._session.commit()
        emit_event(
            "rule_rejected",
            {
                "rule_id": str(rule.id),
                "queue_id": str(item.id),
                "cve_id": str(rule.cve_id) if rule.cve_id else None,
                "chain_id": str(rule.chain_id) if rule.chain_id else None,
                "rejected_by": actor_username,
                "reason": reason,
            },
        )

        await self._invalidate_matrix_cache()

        logger.info(
            "queue.rejected",
            queue_id=str(item.id),
            sigma_rule_id=str(rule.id),
            reason=reason,
            actor=actor_username,
        )

        return RejectOutcome(
            rule_id=rule.id,
            queue_id=item.id,
            rule_status=rule.status,
            queue_status=item.status,
            reason=reason,
        )

    async def edit_and_approve(
        self,
        item_id: uuid.UUID,
        *,
        actor_username: str | None,
        actor_id: uuid.UUID | None,
        new_yaml: str,
        target_id: uuid.UUID | None = None,
    ) -> EditOutcome:
        """Validate ``new_yaml`` via M15's pySigma validator, then approve.

        On validation failure the queue row is *not* mutated — the caller
        sees the structured errors and can resubmit. On success the rule
        is updated with the new YAML + recomputed ``content_hash`` and
        falls through to the approve flow (which writes the audit row,
        flips status, and opens the PR).
        """
        if not isinstance(new_yaml, str) or not new_yaml.strip():
            raise QueueActionError("sigma_yaml is required", status_code=400)

        item, rule = await self._load_pair(item_id)
        self._guard_action(item, "edit_and_approve")

        try:
            validation: ValidationResult = await asyncio.wait_for(
                asyncio.to_thread(validate_yaml, new_yaml),
                timeout=_EDIT_VALIDATION_TIMEOUT_S,
            )
        except asyncio.TimeoutError as exc:
            raise QueueActionError(
                "pySigma validation timeout",
                status_code=400,
            ) from exc
        if not validation.valid:
            raise QueueActionError(
                "rule failed pySigma validation",
                status_code=400,
                errors=list(validation.errors),
                warnings=list(validation.warnings),
            )

        previous_yaml = rule.sigma_yaml
        previous_hash = rule.content_hash
        rule.sigma_yaml = new_yaml
        rule.content_hash = _content_hash(new_yaml)

        await audit_entity_state_change(
            self._session,
            entity_type="sigma_rule",
            entity_id=rule.id,
            action="sigma_rule.edited",
            before={
                "content_hash": previous_hash,
                "yaml_length": len(previous_yaml or ""),
            },
            after={
                "content_hash": rule.content_hash,
                "yaml_length": len(new_yaml),
                "editor": actor_username,
                "queue_id": str(item.id),
            },
            actor=actor_id,
        )
        # Flush the edits so the approve flow's subsequent commit sees
        # the updated row.
        await self._session.flush()

        approve_outcome = await self.approve(
            item.id,
            actor_username=actor_username,
            actor_id=actor_id,
            target_id=target_id,
        )

        return EditOutcome(
            rule_id=rule.id,
            queue_id=item.id,
            approve=approve_outcome,
            warnings=list(validation.warnings),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _load_pair(
        self, item_id: uuid.UUID
    ) -> tuple[ReviewQueueItem, SigmaRule]:
        item = await self._session.get(ReviewQueueItem, item_id)
        if item is None:
            raise QueueActionError("queue item not found", status_code=404)
        rule = await self._session.get(SigmaRule, item.sigma_rule_id)
        if rule is None:
            raise QueueActionError(
                "queue item references missing sigma rule",
                status_code=409,
            )
        return item, rule

    def _guard_action(self, item: ReviewQueueItem, action: str) -> None:
        if item.status in _TERMINAL_QUEUE_STATUSES:
            raise QueueActionError(
                f"queue item already {item.status} — {action} refused",
                status_code=409,
            )

    async def _approve_local_only(
        self,
        *,
        item: ReviewQueueItem,
        rule: SigmaRule,
        actor_username: str | None,
        actor_id: uuid.UUID | None,
    ) -> ApproveOutcome:
        """Approve a rule without dispatching a Git PR.

        Persists ``rule.status='approved'`` + ``item.status='approved'``,
        writes parallel audit_log rows, invalidates the matrix cache, and
        emits the ``rule_approved`` event so dashboards update. Routing
        / submit_pr are skipped entirely — target stays None.

        Operators using this path should plan to ship rules out of band
        (export the YAML, drop into a SIEM, etc.) or configure a Sigma
        target later and re-submit via the M12 resubmit task.
        """
        previous_rule_status = rule.status
        previous_queue_status = item.status

        rule.status = "approved"
        rule.reviewed_by = actor_username
        rule.reviewed_at = datetime.now(tz=timezone.utc)
        item.status = "approved"
        item.completed_at = datetime.now(tz=timezone.utc)

        await audit_entity_state_change(
            self._session,
            entity_type="sigma_rule",
            entity_id=rule.id,
            action="sigma_rule.approved",
            before={"status": previous_rule_status},
            after={
                "status": "approved",
                "reviewed_by": actor_username,
                "queue_id": str(item.id),
                "target_id": None,
                "target_name": None,
                "pr_submitted": False,
                "skip_pr": True,
            },
            actor=actor_id,
        )
        await audit_entity_state_change(
            self._session,
            entity_type="review_queue",
            entity_id=item.id,
            action="queue.approved",
            before={"status": previous_queue_status},
            after={
                "status": "approved",
                "sigma_rule_id": str(rule.id),
                "target_id": None,
                "actor": actor_username,
                "skip_pr": True,
            },
            actor=actor_id,
        )

        await self._session.commit()
        await self._session.refresh(rule)
        await self._session.refresh(item)

        emit_event(
            "rule_approved",
            {
                "rule_id": str(rule.id),
                "queue_id": str(item.id),
                "cve_id": str(rule.cve_id) if rule.cve_id else None,
                "chain_id": str(rule.chain_id) if rule.chain_id else None,
                "target_id": None,
                "target_name": None,
                "approved_by": actor_username,
                "priority_score": int(item.priority_score or 0),
                "priority": item.priority,
                "routing_reason": "skipped (local approval, no PR)",
            },
        )

        await self._invalidate_matrix_cache()

        logger.info(
            "queue.approved.local_only",
            queue_id=str(item.id),
            sigma_rule_id=str(rule.id),
            actor=actor_username,
        )

        return ApproveOutcome(
            rule_id=rule.id,
            queue_id=item.id,
            rule_status=rule.status,
            queue_status=item.status,
            target_id=None,
            target_name=None,
            pr_submitted=False,
            pr_url=None,
            pr_number=None,
            commit_sha=None,
            branch=None,
            routing_reason="skipped (local approval, no PR)",
            message="Rule approved locally; no Git PR submitted (skip_pr=true).",
        )

    async def _select_target(
        self,
        rule: SigmaRule,
        explicit_target_id: uuid.UUID | None,
    ) -> tuple[SigmaTarget | None, str]:
        if explicit_target_id is not None:
            target = await self._session.get(SigmaTarget, explicit_target_id)
            if target is None:
                raise QueueActionError(
                    f"target {explicit_target_id} not found",
                    status_code=404,
                )
            if not target.enabled:
                raise QueueActionError(
                    f"target {target.name!r} is disabled",
                    status_code=409,
                )
            return target, f"operator-supplied target_id={target.id}"

        if self._router_factory is not None:
            router = await self._router_factory(self._session)
        else:
            router = await RoutingEngine.load(self._session)
        decision = router.select_target(rule)
        if decision.target_id is None:
            return None, decision.reason
        target = await self._session.get(SigmaTarget, decision.target_id)
        return target, decision.reason

    async def _submit_pr(
        self, rule: SigmaRule, target: SigmaTarget
    ) -> SubmitOutcome:
        client = self._target_client or SigmaTargetClient(self._session)
        try:
            return await client.submit_rule(rule, target)
        except Exception as exc:  # noqa: BLE001
            # The transport itself shouldn't raise (it returns
            # PullRequestResult with created=False) but we guard the
            # whole call anyway — a connection error mid-stream would
            # otherwise blow up the request and leave the approve
            # transaction half-committed. The PR remains "not submitted";
            # the operator can retry via the Celery task.
            logger.warning(
                "queue.pr_submit_failed",
                rule_id=str(rule.id),
                target_id=str(target.id),
                error=str(exc),
            )
            return SubmitOutcome(
                rule_id=str(rule.id),
                target_id=str(target.id),
                target_name=target.name,
                created=False,
                url=None,
                number=None,
                branch=None,
                commit_sha=None,
                message=f"transport raised {type(exc).__name__}: {exc}",
            )

    async def _resolve_cve(self, ident: str) -> CVE | None:
        ident = ident.strip()
        if not ident:
            return None
        try:
            cve_uuid = uuid.UUID(ident)
            result = await self._session.execute(
                select(CVE).where(CVE.id == cve_uuid)
            )
        except (ValueError, TypeError):
            result = await self._session.execute(
                select(CVE).where(CVE.cve_id == ident.upper())
            )
        return result.scalar_one_or_none()

    async def _resolve_cve_textual_ids(
        self, cve_uuids: list[uuid.UUID]
    ) -> dict[uuid.UUID, str]:
        if not cve_uuids:
            return {}
        rows = (
            await self._session.execute(select(CVE).where(CVE.id.in_(cve_uuids)))
        ).scalars().all()
        return {r.id: r.cve_id for r in rows}

    async def _cve_textual_id(
        self, cve_pk: uuid.UUID | None
    ) -> str | None:
        if cve_pk is None:
            return None
        cve = await self._session.get(CVE, cve_pk)
        return cve.cve_id if cve is not None else None

    async def _build_chain_context(
        self, rule: SigmaRule
    ) -> list[TTPContext]:
        if rule.chain_id is None:
            return []
        chain = await self._session.get(AttackChainRow, rule.chain_id)
        if chain is None:
            return []
        ttps = (
            await self._session.execute(
                select(ChainTTPRow)
                .where(ChainTTPRow.chain_id == chain.id)
                .order_by(ChainTTPRow.seq_order.asc())
            )
        ).scalars().all()
        if not ttps:
            return []
        focus_technique = (rule.technique_ids or [None])[0]
        focus_index = _find_focus_index(list(ttps), focus_technique)
        if focus_index is None:
            return [_ttp_to_context(t, is_focus=False) for t in ttps]
        lo = max(0, focus_index - _ADJACENT_TTP_WINDOW)
        hi = min(len(ttps), focus_index + _ADJACENT_TTP_WINDOW + 1)
        return [
            _ttp_to_context(ttps[i], is_focus=i == focus_index)
            for i in range(lo, hi)
        ]

    async def _build_source_documents(
        self, rule: SigmaRule
    ) -> list[SourceDocSnippet]:
        if rule.cve_id is None:
            return []
        rows = (
            await self._session.execute(
                select(SourceDocument)
                .where(SourceDocument.cve_id == rule.cve_id)
                .order_by(
                    SourceDocument.quality_score.desc().nullslast(),
                    SourceDocument.created_at.asc(),
                )
                .limit(_TOP_SOURCE_DOCS)
            )
        ).scalars().all()
        return [_doc_to_snippet(d) for d in rows]

    async def _fetch_similar_rules(
        self,
        rule: SigmaRule,
        parsed: dict[str, Any] | None,
    ) -> list[SimilarRuleHit]:
        query = _build_similar_query(rule, parsed)
        if not query.strip():
            return []
        embedder = self._make_embedder()
        if embedder is None:
            return []
        try:
            hits = await embedder.search_sigma_rules(
                query, limit=_SIMILAR_RULES_LIMIT
            )
        except Exception as exc:  # noqa: BLE001
            logger.info(
                "queue.similar_rules.search_failed",
                rule_id=str(rule.id),
                error=str(exc),
            )
            return []
        finally:
            close = getattr(embedder, "close", None)
            if callable(close):
                try:
                    await close()
                except Exception:  # noqa: BLE001
                    pass
        return [
            SimilarRuleHit(
                rule_id=h.rule_id,
                sigma_uuid=h.sigma_uuid,
                title=h.title,
                technique_ids=list(h.technique_ids or []),
                score=float(h.score),
                logsource_product=h.logsource_product,
                logsource_service=h.logsource_service,
                origin=h.origin,
            )
            for h in hits
            if str(h.rule_id) != str(rule.id)  # skip self
        ]

    def _make_embedder(self):
        if self._embedder_factory is not None:
            try:
                return self._embedder_factory()
            except Exception as exc:  # noqa: BLE001
                logger.info("queue.embedder.unavailable", error=str(exc))
                return None
        try:
            from fragchain.vector import VectorEmbedder

            return VectorEmbedder()
        except Exception as exc:  # noqa: BLE001
            logger.info("queue.embedder.unavailable", error=str(exc))
            return None

    async def _invalidate_matrix_cache(self) -> None:
        try:
            from fragchain.coverage.matrix import MatrixCache

            cache = MatrixCache()
            try:
                await cache.invalidate()
            finally:
                await cache.close()
        except Exception as exc:  # noqa: BLE001
            logger.info("queue.matrix_cache.invalidate_failed", error=str(exc))


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _prior_status_for_assign(
    item: ReviewQueueItem, previous_assigned_to: str | None
) -> str:
    """Reconstruct the queue.status the row had before assign() ran.

    The assign flow may flip pending → in_review when an assignee is
    set. The audit row's ``before`` block should reflect the original
    status, not the post-flip value.
    """
    if item.status == "in_review" and not previous_assigned_to:
        return "pending"
    return item.status


def _build_view(
    item: ReviewQueueItem,
    rule: SigmaRule,
    cve_textual_id: str | None,
) -> QueueItemView:
    return QueueItemView(
        id=item.id,
        sigma_rule_id=rule.id,
        priority=item.priority,
        priority_score=int(item.priority_score or 0),
        priority_reason=item.priority_reason,
        assigned_to=item.assigned_to,
        status=item.status,
        created_at=item.created_at,
        completed_at=item.completed_at,
        title=rule.title,
        rule_status=rule.status,
        origin=rule.origin,
        technique_ids=list(rule.technique_ids or []),
        logsource_profile=rule.logsource_profile,
        detection_level=rule.detection_level,
        tlp=rule.tlp,
        cve_id=rule.cve_id,
        cve_textual_id=cve_textual_id,
        chain_id=rule.chain_id,
        review_notes=rule.review_notes,
        git_pr_url=rule.git_pr_url,
        assessment_id=item.assessment_id,
        low_detectability_override=bool(item.low_detectability_override),
        superseded_by_assessment_id=item.superseded_by_assessment_id,
    )


def _cve_summary(cve: CVE) -> dict[str, Any]:
    return {
        "id": str(cve.id),
        "cve_id": cve.cve_id,
        "cvss_score": float(cve.cvss_score) if cve.cvss_score is not None else None,
        "cisa_kev": bool(cve.cisa_kev),
        "epss_score": float(cve.epss_score) if cve.epss_score is not None else None,
        "epss_percentile": (
            float(cve.epss_percentile) if cve.epss_percentile is not None else None
        ),
        "attackerkb_score": (
            float(cve.attackerkb_score) if cve.attackerkb_score is not None else None
        ),
        "tlp": cve.tlp,
        "published_at": cve.published_at.isoformat() if cve.published_at else None,
        "description": _extract_description(cve),
        "affected_products": cve.affected_products,
    }


def _extract_description(cve: CVE) -> str | None:
    raw = cve.raw_connector_data or {}
    if isinstance(raw, dict):
        desc = raw.get("description")
        if isinstance(desc, str) and desc.strip():
            return desc.strip()[:1500]
    return None


def _ttp_to_context(ttp: ChainTTPRow, *, is_focus: bool) -> TTPContext:
    return TTPContext(
        id=ttp.id,
        seq_order=int(ttp.seq_order),
        tactic=ttp.tactic,
        tactic_id=ttp.tactic_id,
        technique_id=ttp.technique_id,
        technique_name=ttp.technique_name,
        confidence=float(ttp.confidence) if ttp.confidence is not None else None,
        detection_opportunity=ttp.detection_opportunity,
        is_focus=is_focus,
    )


def _doc_to_snippet(doc: SourceDocument) -> SourceDocSnippet:
    excerpt: str | None = None
    meta = doc.document_metadata or {}
    if isinstance(meta, dict):
        for key in ("excerpt", "description", "summary"):
            value = meta.get(key)
            if isinstance(value, str) and value.strip():
                excerpt = value.strip()[:600]
                break
    return SourceDocSnippet(
        id=doc.id,
        url=doc.url,
        source_type=doc.source_type,
        quality_score=(
            float(doc.quality_score) if doc.quality_score is not None else None
        ),
        tlp=doc.tlp,
        excerpt=excerpt,
    )


def _find_focus_index(
    ttps: list[ChainTTPRow], focus_technique: str | None
) -> int | None:
    if not focus_technique:
        return None
    needle = focus_technique.upper()
    for i, ttp in enumerate(ttps):
        if (ttp.technique_id or "").upper() == needle:
            return i
    return None


def _build_similar_query(
    rule: SigmaRule, parsed: dict[str, Any] | None
) -> str:
    """Build the prompt that drives Qdrant semantic search.

    The query mirrors the embedding shape M8 uses so neighbour scores
    are meaningful: ``title + technique_ids + first 500 chars of YAML``.
    """
    title = (parsed or {}).get("title") if parsed else None
    title = title or rule.title or ""
    techniques = ", ".join(rule.technique_ids or [])
    yaml_excerpt = (rule.sigma_yaml or "")[:500]
    return "\n".join(
        line for line in [
            f"title: {title}",
            f"techniques: {techniques}" if techniques else "",
            yaml_excerpt,
        ] if line.strip()
    )


def _safe_parse_yaml(text: str) -> dict[str, Any] | None:
    if not text or not text.strip():
        return None
    # F-012 (SAST S-012, defense-in-depth): queue YAML is LLM-bounded
    # but the cap makes that assumption explicit at the parser boundary.
    from fragchain.security.yaml_safe import (
        YamlTooLargeError,
        safe_load_all_capped,
    )

    try:
        loaded = safe_load_all_capped(text, source_label="queue-yaml")
    except (YamlTooLargeError, yaml.YAMLError):
        return None
    if not loaded:
        return None
    doc = loaded[0]
    return doc if isinstance(doc, dict) else None


def _content_hash(yaml_text: str) -> str:
    return hashlib.sha256(yaml_text.encode("utf-8")).hexdigest()


_NOTE_BLOCK_RE = re.compile(
    r"\n?\s*\[review-(?:rejected|edited|approved)\b.*?(?:\n\n|\Z)",
    re.DOTALL,
)


def _append_rejection_note(
    existing: str | None,
    reason: str,
    actor: str | None,
) -> str:
    """Append a one-paragraph rejection note to review_notes.

    The block is fenced with a discoverable marker so the UI can render
    it inline without parsing the whole text. We don't try to keep more
    than the latest rejection — older blocks are stripped (history lives
    in ``audit_log``).
    """
    cleaned = _NOTE_BLOCK_RE.sub("", existing or "").rstrip()
    actor_str = actor or "anonymous"
    now = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
    block = (
        f"[review-rejected {now} by {actor_str}]\n"
        f"{reason.strip()}"
    )
    return f"{cleaned}\n\n{block}".strip() if cleaned else block


__all__ = [
    "ApproveOutcome",
    "EditOutcome",
    "QUEUE_STATUSES",
    "QueueActionError",
    "QueueItemDetail",
    "QueueItemView",
    "QueueManager",
    "RejectOutcome",
    "SimilarRuleHit",
    "SourceDocSnippet",
    "TTPContext",
]
