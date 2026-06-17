"""Per-CVE assessment summary for the CVE Explorer (read-only, advisory).

Assembles the compact badge data ``GET /cves`` embeds per row: assessment
state, the active Loop-2 detectability classification, active generated-
artifact counts by status, and per-CVE sigma-rule counts. A constant
number of batched queries for the returned page, plus the per-row access
checks inside :func:`filter_assessments_for_user` (creator/elevated short-
circuit; non-owned rows may each cost one grant lookup).

Access (F-002): summaries are computed only for assessments the requester
passes :func:`filter_assessments_for_user` for; an inaccessible assessment
renders exactly like an unassessed CVE. Failures degrade to empty maps so
badge assembly can never break the CVE list.

Spec: docs/superpowers/specs/2026-06-10-cve-explorer-assessment-badging-design.md
"""
from __future__ import annotations

import uuid
from typing import Any, Iterable

import structlog
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.access import filter_assessments_for_user
from fragchain.db.models import (
    AssessmentLoopRun,
    CoverageAssessment,
    DetectabilityAssessmentRow,
    GeneratedArtifactRow,
    SigmaRule,
)

logger = structlog.get_logger(__name__)


class CveAssessmentSummary(BaseModel):
    """Compact read projection embedded per CVE row (spec §Backend)."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: uuid.UUID
    state: str
    detectability_class: str | None = None
    detectability_confidence: float | None = None
    artifact_counts: dict[str, int]


async def summarize_assessments_for_cves(
    session: AsyncSession,
    cve_ids: Iterable[uuid.UUID],
    *,
    user: Any,
) -> dict[uuid.UUID, CveAssessmentSummary]:
    """Map ``cve_id -> summary`` for the page's CVEs. Advisory: never raises."""
    ids = list(cve_ids)
    if not ids:
        return {}
    try:
        return await _summarize(session, ids, user=user)
    except Exception as exc:  # noqa: BLE001 — advisory, never breaks the list
        logger.warning("cves.assessment_summary.failed", error=repr(exc))
        return {}


async def _summarize(
    session: AsyncSession,
    cve_ids: list[uuid.UUID],
    *,
    user: Any,
) -> dict[uuid.UUID, CveAssessmentSummary]:
    rows = (
        (
            await session.execute(
                select(CoverageAssessment).where(
                    CoverageAssessment.cve_id.in_(cve_ids)
                )
            )
        )
        .scalars()
        .all()
    )
    readable = await filter_assessments_for_user(session, list(rows), user=user)
    if not readable:
        return {}
    assessment_ids = [a.id for a in readable]

    det_rows = (
        (
            await session.execute(
                select(DetectabilityAssessmentRow)
                .join(
                    AssessmentLoopRun,
                    DetectabilityAssessmentRow.loop_run_id == AssessmentLoopRun.id,
                )
                .where(
                    DetectabilityAssessmentRow.assessment_id.in_(assessment_ids),
                    AssessmentLoopRun.is_active.is_(True),
                    AssessmentLoopRun.loop_number == 2,
                )
            )
        )
        .scalars()
        .all()
    )
    det_by_assessment = {d.assessment_id: d for d in det_rows}

    count_rows = (
        await session.execute(
            select(
                GeneratedArtifactRow.assessment_id,
                GeneratedArtifactRow.status,
                func.count(),
            )
            .where(
                GeneratedArtifactRow.assessment_id.in_(assessment_ids),
                GeneratedArtifactRow.is_active.is_(True),
            )
            .group_by(
                GeneratedArtifactRow.assessment_id, GeneratedArtifactRow.status
            )
        )
    ).all()
    counts: dict[uuid.UUID, dict[str, int]] = {}
    for assessment_id, status_value, n in count_rows:
        counts.setdefault(assessment_id, {})[str(status_value)] = int(n)

    out: dict[uuid.UUID, CveAssessmentSummary] = {}
    for asmt in readable:
        det = det_by_assessment.get(asmt.id)
        out[asmt.cve_id] = CveAssessmentSummary(
            assessment_id=asmt.id,
            state=asmt.state,
            detectability_class=det.detectability_class if det else None,
            detectability_confidence=(
                float(det.confidence) if det is not None else None
            ),
            artifact_counts=counts.get(asmt.id, {}),
        )
    return out


async def rule_counts_for_cves(
    session: AsyncSession,
    cve_ids: Iterable[uuid.UUID],
) -> dict[uuid.UUID, int]:
    """Map ``cve_id -> non-deprecated sigma-rule count``. Advisory: never raises.

    Keyed by ``sigma_rules.cve_id`` (the table has no ``assessment_id``), so
    dormant-path rules count too — matching the Rules column's "rules for
    this CVE" semantics.
    """
    ids = list(cve_ids)
    if not ids:
        return {}
    try:
        rows = (
            await session.execute(
                select(SigmaRule.cve_id, func.count())
                .where(
                    SigmaRule.cve_id.in_(ids),
                    SigmaRule.deprecated_at.is_(None),
                )
                .group_by(SigmaRule.cve_id)
            )
        ).all()
        return {cve_id: int(n) for cve_id, n in rows if cve_id is not None}
    except Exception as exc:  # noqa: BLE001 — advisory, never breaks the list
        logger.warning("cves.rule_count.failed", error=repr(exc))
        return {}
