"""Manual Supersede analyst action (Phase A §3.6).

When an analyst clicks "Supersede with existing rule" on a pending
review-queue item, this service:

1. Closes the queue item — ``status='superseded'``, records the chosen
   existing rule and the rationale.
2. Writes one ``CoverageBenchmark`` row per technique on the queued rule
   with ``source='supersede'`` + ``expected_verdict='covered'``. These
   rows feed ``scripts/run_coverage_benchmark.py`` and the
   ``/api/v1/coverage/benchmarks/runs`` endpoint directly — analyst
   decisions become ground truth.
3. Adds the existing rule to ``coverage_map.covering_rule_ids`` for each
   relevant technique so the matrix reflects the analyst's call.

The persisted state is the ``CoverageBenchmark`` rows + the queue-item
update. ``coverage_map`` mutation is best-effort: a missing
``coverage_map`` row is a no-op (the next ``map_coverage`` run will
pick the rule up via the new Phase 1.5 path).

Note on ``partial_rule_ids``: that field exists only on the
``CoverageStatus`` runtime dataclass, not on the persisted
``coverage_map`` table. The supersede service therefore only needs to
ensure the chosen rule is in ``covering_rule_ids``; there is nothing to
"move" from a partial column.

No ``session.commit()`` here — the caller (router) commits after the
service returns. (``QueueManager.approve`` commits internally; this
service deliberately leaves transaction control to the caller so audit
log + benchmark labeling + coverage_map updates land in one transaction.)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.audit import audit_entity_state_change
from fragchain.db.models import (
    CoverageBenchmark,
    CoverageMap,
    ReviewQueueItem,
    SigmaRule,
)

logger = structlog.get_logger(__name__)

_MAX_RATIONALE_LEN = 200
_DEFAULT_FRAMEWORK = "attck"


class SupersedeError(Exception):
    """Raised when a supersede request cannot be honoured.

    ``status_code`` is the HTTP status code the endpoint should surface.
    Mirrors the ``QueueActionError`` pattern so routers can handle both
    with the same ``except`` clause.
    """

    def __init__(self, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


class SupersedeService:
    """Encapsulates the three-step supersede write path."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def supersede(
        self,
        *,
        review_id: uuid.UUID,
        supersede_rule_id: uuid.UUID,
        rationale: str,
        actor_username: str | None,
        actor_id: uuid.UUID | None,
    ) -> dict:
        """Execute the supersede action and return a summary dict.

        Raises :class:`SupersedeError` on validation failures, unknown
        entities, or illegal state transitions. Does **not** commit the
        session — the caller is responsible.

        Args:
            review_id: PK of the ``review_queue`` row to close.
            supersede_rule_id: PK of the existing ``sigma_rules`` row
                that already covers the CVE/technique.
            rationale: One-line explanation (1–200 chars).
            actor_username: Username of the analyst performing the action
                (stored in ``CoverageBenchmark.labeled_by``).
            actor_id: UUID of the actor (reserved for future audit log;
                not persisted in this version).

        Returns:
            ``{"review_id": ..., "status": "superseded", "supersede_rule_id": ...}``
        """
        # ------------------------------------------------------------------
        # 0. Input validation (fail fast before any DB round-trip).
        # ------------------------------------------------------------------
        rationale = (rationale or "").strip()
        if not rationale:
            raise SupersedeError("rationale must be non-empty", status_code=400)
        if len(rationale) > _MAX_RATIONALE_LEN:
            raise SupersedeError(
                f"rationale exceeds {_MAX_RATIONALE_LEN} char cap",
                status_code=400,
            )

        # ------------------------------------------------------------------
        # 1. Load the review-queue item.
        # ------------------------------------------------------------------
        item: ReviewQueueItem | None = await self._session.get(
            ReviewQueueItem, review_id
        )
        if item is None:
            raise SupersedeError(
                f"review item {review_id} not found", status_code=404
            )
        if item.status not in ("pending", "in_review"):
            raise SupersedeError(
                f"review item {review_id} cannot be superseded from "
                f"status='{item.status}' (must be pending or in_review)",
                status_code=409,
            )

        # ------------------------------------------------------------------
        # 2. Load the queued rule (source of technique/CVE context).
        # ------------------------------------------------------------------
        queued_rule: SigmaRule | None = await self._session.get(
            SigmaRule, item.sigma_rule_id
        )
        if queued_rule is None:
            raise SupersedeError(
                f"queued rule {item.sigma_rule_id} not found", status_code=404
            )

        # ------------------------------------------------------------------
        # 3. Load the existing rule the analyst chose as the replacement.
        # ------------------------------------------------------------------
        existing_rule: SigmaRule | None = await self._session.get(
            SigmaRule, supersede_rule_id
        )
        if existing_rule is None:
            raise SupersedeError(
                f"supersede target rule {supersede_rule_id} not found",
                status_code=404,
            )

        technique_ids: list[str] = list(queued_rule.technique_ids or [])
        cve_uuid: uuid.UUID | None = queued_rule.cve_id

        # ------------------------------------------------------------------
        # 4. Close the queue item.
        # ------------------------------------------------------------------
        previous_status = item.status  # capture before flip for audit log
        item.status = "superseded"
        item.supersede_rule_id = supersede_rule_id
        item.supersede_rationale = rationale
        item.completed_at = datetime.now(tz=timezone.utc)

        await audit_entity_state_change(
            self._session,
            entity_type="review_queue",
            entity_id=item.id,
            action="queue.superseded",
            before={"status": previous_status},
            after={
                "status": "superseded",
                "supersede_rule_id": str(supersede_rule_id),
                "rationale": rationale,
            },
            actor=actor_id,
            reason=rationale,
        )

        # ------------------------------------------------------------------
        # 5. Write one CoverageBenchmark labeling row per technique.
        #    Skip if queued rule has no CVE context — the benchmark table
        #    requires cve_id (FK to cves.id NOT NULL).
        # ------------------------------------------------------------------
        if cve_uuid is not None:
            for tid in technique_ids:
                self._session.add(
                    CoverageBenchmark(
                        cve_id=cve_uuid,
                        technique_id=tid,
                        rule_id=supersede_rule_id,
                        expected_verdict="covered",
                        rationale=rationale,
                        labeled_by=actor_username or "unknown",
                        source="supersede",
                    )
                )

        # ------------------------------------------------------------------
        # 6. Update coverage_map.covering_rule_ids per technique.
        #    Best-effort: a missing coverage_map row is a no-op.
        #    Note: partial_rule_ids is a runtime-dataclass-only field;
        #    it does NOT exist on the persisted table so we only touch
        #    covering_rule_ids.
        # ------------------------------------------------------------------
        for tid in technique_ids:
            coverage: CoverageMap | None = (
                await self._session.execute(
                    select(CoverageMap)
                    .where(CoverageMap.technique_id == tid)
                    .where(CoverageMap.framework == _DEFAULT_FRAMEWORK)  # no chain TTP in scope to read .framework; default to "attck"
                )
            ).scalar_one_or_none()
            if coverage is None:
                continue
            covering: list[uuid.UUID] = list(coverage.covering_rule_ids or [])
            if supersede_rule_id not in covering:
                covering.append(supersede_rule_id)
            coverage.covering_rule_ids = covering

        logger.info(
            "queue.supersede.applied",
            review_id=str(review_id),
            supersede_rule_id=str(supersede_rule_id),
            actor=actor_username,
            technique_count=len(technique_ids),
            benchmarks_written=len(technique_ids) if cve_uuid is not None else 0,
        )

        return {
            "review_id": item.id,
            "status": "superseded",
            "supersede_rule_id": supersede_rule_id,
        }
