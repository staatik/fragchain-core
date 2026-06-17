"""SourceService — paste + soft-delete of analyst-pasted sources."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.content import (
    normalize_content,
    sha256_hex,
    validate_paste,
)
from fragchain.assessments.schemas import SourceCreateRequest
from fragchain.assessments.service import AssessmentNotFoundError
from fragchain.db.models import AssessmentSource, CoverageAssessment

logger = structlog.get_logger(__name__)


class SourceNotFoundError(LookupError):
    """Raised when the source id doesn't exist or is already deleted."""


class SourceService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        assessment_id: uuid.UUID,
        req: SourceCreateRequest,
        *,
        actor_id: uuid.UUID,
    ) -> AssessmentSource:
        asmt_result = await self._session.execute(
            select(CoverageAssessment).where(
                CoverageAssessment.id == assessment_id
            )
        )
        asmt = asmt_result.scalar_one_or_none()
        if asmt is None:
            raise AssessmentNotFoundError(str(assessment_id))

        # Sum of existing (non-deleted) source sizes for cumulative cap.
        total_result = await self._session.execute(
            select(func.coalesce(func.sum(AssessmentSource.size_bytes), 0)).where(
                AssessmentSource.assessment_id == assessment_id,
                AssessmentSource.deleted_at.is_(None),
            )
        )
        current_total = int(total_result.scalar_one())

        normalized = normalize_content(req.content)
        validate_paste(normalized, current_total=current_total)

        row = AssessmentSource(
            assessment_id=assessment_id,
            kind=req.kind,
            title=req.title,
            content=normalized,
            content_hash=sha256_hex(normalized),
            size_bytes=len(normalized.encode("utf-8")),
            tlp=req.tlp or asmt.tlp,
            pasted_by=actor_id,
        )
        self._session.add(row)
        await self._session.commit()
        await self._session.refresh(row)

        # Dispatch async embedding.
        from fragchain.worker.tasks.embed_assessment_source import (
            embed_assessment_source,
        )

        embed_assessment_source.delay(str(row.id))

        logger.info(
            "assessment.source.pasted",
            assessment_id=str(assessment_id),
            source_id=str(row.id),
            size_bytes=row.size_bytes,
            actor_id=str(actor_id),
        )
        return row

    async def list(
        self, assessment_id: uuid.UUID, *, include_deleted: bool = False
    ) -> list[AssessmentSource]:
        stmt = select(AssessmentSource).where(
            AssessmentSource.assessment_id == assessment_id
        )
        if not include_deleted:
            stmt = stmt.where(AssessmentSource.deleted_at.is_(None))
        stmt = stmt.order_by(AssessmentSource.pasted_at.asc())
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def delete(
        self,
        source_id: uuid.UUID,
        *,
        actor_id: uuid.UUID,
        rationale: str,
    ) -> None:
        result = await self._session.execute(
            select(AssessmentSource).where(AssessmentSource.id == source_id)
        )
        row = result.scalar_one_or_none()
        if row is None or row.deleted_at is not None:
            raise SourceNotFoundError(str(source_id))
        row.deleted_at = datetime.now(tz=timezone.utc)
        row.deleted_by = actor_id
        row.delete_rationale = rationale
        await self._session.commit()
        logger.info(
            "assessment.source.deleted",
            source_id=str(source_id),
            actor_id=str(actor_id),
        )
