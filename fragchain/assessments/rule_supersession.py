"""Rule-level supersession (spec §4.5).

When Loop 3 produces a rule for ``(cve_id, technique_id, profile_name)`` and a
prior rule for the same triple exists, the prior rule is superseded
(pending) or deprecated (approved). This is per spec: analyst work supersedes
live-feed work for the same CVE.

Schema note: ``ReviewQueueItem`` has no triple columns of its own — it joins
through ``sigma_rule_id`` to :class:`SigmaRule` which carries ``cve_id``,
``technique_ids: list[str]``, and ``logsource_profile`` (the profile name).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.db.models import ReviewQueueItem, SigmaRule

logger = structlog.get_logger(__name__)


class RuleSuperseder:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def supersede_prior_for_triple(
        self,
        *,
        cve_id: uuid.UUID,
        technique_id: str,
        profile_name: str,
        new_rule_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> dict[str, int]:
        summary = {"pending_superseded": 0, "approved_deprecated": 0}

        # Match the technique EXACTLY (technique_ids == [technique_id]), not
        # array-containment. FragChain generates one rule per technique per
        # profile, so a prior rule for this triple has technique_ids ==
        # [technique_id]. Containment would also clobber a broader, still-valid
        # multi-technique rule (e.g. ['T1190','T1059']) that merely *includes*
        # this technique — that rule covers more and must not be superseded by
        # a narrower one.

        # 1. Pending queue rows for the same triple, excluding the new rule.
        pending_q = await self._session.execute(
            select(ReviewQueueItem)
            .join(SigmaRule, ReviewQueueItem.sigma_rule_id == SigmaRule.id)
            .where(SigmaRule.cve_id == cve_id)
            .where(SigmaRule.technique_ids == [technique_id])
            .where(SigmaRule.logsource_profile == profile_name)
            .where(ReviewQueueItem.status == "pending")
            .where(ReviewQueueItem.sigma_rule_id != new_rule_id)
            .where(ReviewQueueItem.superseded_by_assessment_id.is_(None))
        )
        for row in pending_q.scalars().all():
            row.status = "superseded"
            row.superseded_by_assessment_id = assessment_id
            summary["pending_superseded"] += 1

        # 2. Approved sigma rules for the same triple, excluding the new rule.
        approved_q = await self._session.execute(
            select(SigmaRule)
            .where(SigmaRule.cve_id == cve_id)
            .where(SigmaRule.technique_ids == [technique_id])
            .where(SigmaRule.logsource_profile == profile_name)
            .where(SigmaRule.status == "approved")
            .where(SigmaRule.deprecated_at.is_(None))
            .where(SigmaRule.id != new_rule_id)
        )
        for sr in approved_q.scalars().all():
            sr.deprecated_at = datetime.now(tz=timezone.utc)
            sr.deprecated_by_rule_id = new_rule_id
            sr.deprecated_by_assessment_id = assessment_id
            summary["approved_deprecated"] += 1

        if summary["pending_superseded"] or summary["approved_deprecated"]:
            logger.info(
                "assessment.rule_supersession.applied",
                cve_id=str(cve_id),
                technique_id=technique_id,
                profile_name=profile_name,
                new_rule_id=str(new_rule_id),
                **summary,
            )
        return summary
