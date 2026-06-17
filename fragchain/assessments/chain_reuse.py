"""Existing-chain reuse service (spec §4.4).

Resolves an active chain for a CVE, and on "use as start" writes a
synthetic Loop 1 row pointing at the existing chain, jumps the
assessment state to ``loop1_done``, and back-fills ``assessment_id``
on the chain row.
"""
from __future__ import annotations

import uuid

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.schemas import AssessmentState
from fragchain.assessments.service import AssessmentNotFoundError
from fragchain.audit import audit_entity_state_change
from fragchain.db.models import (
    AssessmentLoopRun,
    AttackChainRow,
    CoverageAssessment,
)

logger = structlog.get_logger(__name__)


class ChainNotFoundError(LookupError):
    """Raised when the referenced chain doesn't exist for the CVE."""


class ChainReuseService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def find_existing_chain(
        self, cve_id: uuid.UUID
    ) -> AttackChainRow | None:
        """Return the active chain for ``cve_id`` (superseded_at IS NULL)."""
        result = await self._session.execute(
            select(AttackChainRow)
            .where(AttackChainRow.cve_id == cve_id)
            .where(AttackChainRow.superseded_at.is_(None))
            .order_by(AttackChainRow.version.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def use_as_start(
        self, assessment_id: uuid.UUID, chain_id: uuid.UUID
    ) -> AssessmentLoopRun:
        asmt_result = await self._session.execute(
            select(CoverageAssessment).where(
                CoverageAssessment.id == assessment_id
            )
        )
        asmt = asmt_result.scalar_one_or_none()
        if asmt is None:
            raise AssessmentNotFoundError(str(assessment_id))
        prior_state = asmt.state

        chain_result = await self._session.execute(
            select(AttackChainRow)
            .where(AttackChainRow.id == chain_id)
            .where(AttackChainRow.cve_id == asmt.cve_id)
            .where(AttackChainRow.superseded_at.is_(None))
        )
        chain = chain_result.scalar_one_or_none()
        if chain is None:
            raise ChainNotFoundError(
                f"no active chain id={chain_id} for cve_id={asmt.cve_id}"
            )

        # Demote any existing active Loop 1 row (a prior synthetic row from
        # a double-click, or a real Loop 1 run) BEFORE inserting the new
        # active one, and flush the demotion first — the partial unique
        # index uq_assessment_loop_run_active allows only one active row
        # per (assessment, loop), so insert-then-demote raises
        # IntegrityError. Mirrors the orchestrator's demote-flush-activate
        # ordering (and its status='superseded' marking).
        prior_active_result = await self._session.execute(
            select(AssessmentLoopRun).where(
                AssessmentLoopRun.assessment_id == assessment_id,
                AssessmentLoopRun.loop_number == 1,
                AssessmentLoopRun.is_active.is_(True),
            )
        )
        for prior in prior_active_result.scalars().all():
            prior.is_active = False
            prior.status = "superseded"
        await self._session.flush()

        max_version_result = await self._session.execute(
            select(func.coalesce(func.max(AssessmentLoopRun.version), 0)).where(
                AssessmentLoopRun.assessment_id == assessment_id,
                AssessmentLoopRun.loop_number == 1,
            )
        )
        next_version = int(max_version_result.scalar_one()) + 1

        run = AssessmentLoopRun(
            assessment_id=assessment_id,
            loop_number=1,
            version=next_version,
            status="succeeded",
            is_active=True,
            output={
                "kind": "imported_from_chain",
                "chain_id": str(chain.id),
                "origin": chain.source_origin,
            },
            cost_usd=0,
        )
        self._session.add(run)

        chain.assessment_id = assessment_id
        asmt.state = AssessmentState.LOOP1_DONE.value

        await audit_entity_state_change(
            self._session,
            entity_type="coverage_assessment",
            entity_id=assessment_id,
            action="use_as_start",
            before={"state": prior_state},
            after={"state": AssessmentState.LOOP1_DONE.value, "chain_id": str(chain.id)},
            actor=asmt.creator_id,
        )

        await self._session.commit()
        logger.info(
            "assessment.use_as_start",
            assessment_id=str(assessment_id),
            chain_id=str(chain.id),
        )
        return run
