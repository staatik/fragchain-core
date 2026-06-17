"""AssessmentService — CRUD + lifecycle for ``coverage_assessment`` rows.

Stateless aside from the session it's constructed with. Service methods
take typed inputs and persist via the session; the FastAPI router is the
HTTP boundary.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.schemas import (
    AssessmentCreateRequest,
    AssessmentState,
)
from fragchain.assessments.state_machine import (
    StateTransitionError,
    can_close,
)
from fragchain.assessments.trigger_resolver import validate_trigger
from fragchain.db.models import CoverageAssessment

logger = structlog.get_logger(__name__)


class AssessmentNotFoundError(LookupError):
    """Raised when the requested assessment doesn't exist."""


class DuplicateAssessmentError(ValueError):
    """Raised when an assessment for the given CVE already exists."""


class AssessmentService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        req: AssessmentCreateRequest,
        *,
        creator_id: uuid.UUID,
    ) -> CoverageAssessment:
        validate_trigger(req.trigger)
        existing = await self._session.execute(
            select(CoverageAssessment).where(
                CoverageAssessment.cve_id == req.cve_id
            )
        )
        if existing.scalar_one_or_none() is not None:
            raise DuplicateAssessmentError(
                f"assessment for cve_id={req.cve_id} already exists"
            )

        row = CoverageAssessment(
            cve_id=req.cve_id,
            creator_id=creator_id,
            initial_trigger=req.trigger.model_dump(mode="json"),
            context_note=req.context_note,
            state=AssessmentState.CREATED.value,
        )
        self._session.add(row)
        await self._session.commit()
        await self._session.refresh(row)
        logger.info(
            "assessment.created",
            assessment_id=str(row.id),
            cve_id=str(req.cve_id),
            creator_id=str(creator_id),
        )
        return row

    async def get(self, assessment_id: uuid.UUID) -> CoverageAssessment:
        result = await self._session.execute(
            select(CoverageAssessment).where(
                CoverageAssessment.id == assessment_id
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            raise AssessmentNotFoundError(str(assessment_id))
        return row

    async def list(
        self,
        *,
        state: AssessmentState | None = None,
        creator_id: uuid.UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[CoverageAssessment]:
        stmt = select(CoverageAssessment).order_by(
            CoverageAssessment.created_at.desc()
        ).limit(limit).offset(offset)
        if state is not None:
            stmt = stmt.where(CoverageAssessment.state == state.value)
        if creator_id is not None:
            stmt = stmt.where(CoverageAssessment.creator_id == creator_id)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def close(
        self,
        assessment_id: uuid.UUID,
        *,
        closed_by: uuid.UUID,
    ) -> CoverageAssessment:
        row = await self.get(assessment_id)
        current = AssessmentState(row.state)
        if not can_close(current):
            raise StateTransitionError(
                f"cannot close assessment in state={current.value}"
            )
        row.state = AssessmentState.COMPLETED.value
        row.closed_by = closed_by
        row.completed_at = datetime.now(tz=timezone.utc)
        await self._session.commit()
        logger.info(
            "assessment.closed",
            assessment_id=str(row.id),
            closed_by=str(closed_by),
        )
        return row

    async def set_auto_advance(
        self, assessment_id: uuid.UUID, value: bool
    ) -> None:
        """Set the auto-advance flag for headless chaining (W3a-1)."""
        row = await self._session.get(CoverageAssessment, assessment_id)
        if row is None:
            raise AssessmentNotFoundError(str(assessment_id))
        row.auto_advance = value
        await self._session.commit()
