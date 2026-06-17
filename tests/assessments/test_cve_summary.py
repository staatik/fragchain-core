"""Per-CVE assessment summary assembly for the CVE Explorer badges."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments import cve_summary as mod
from fragchain.assessments.cve_summary import (
    CveAssessmentSummary,
    rule_counts_for_cves,
    summarize_assessments_for_cves,
)


def _asmt(cve_id: uuid.UUID, state: str = "loop2_done") -> MagicMock:
    row = MagicMock()
    row.id = uuid.uuid4()
    row.cve_id = cve_id
    row.state = state
    return row


def _result_scalars(rows: list) -> MagicMock:
    result = MagicMock()
    result.scalars.return_value.all.return_value = rows
    return result


def _result_tuples(rows: list[tuple]) -> MagicMock:
    result = MagicMock()
    result.all.return_value = rows
    return result


@pytest.mark.asyncio
async def test_empty_cve_ids_returns_empty() -> None:
    session = MagicMock()
    out = await summarize_assessments_for_cves(session, [], user=MagicMock())
    assert out == {}
    session.execute.assert_not_called()


@pytest.mark.asyncio
async def test_unassessed_cves_return_empty(monkeypatch) -> None:
    session = MagicMock()
    session.execute = AsyncMock(return_value=_result_scalars([]))
    out = await summarize_assessments_for_cves(
        session, [uuid.uuid4()], user=MagicMock()
    )
    assert out == {}


@pytest.mark.asyncio
async def test_state_only_before_loop2(monkeypatch) -> None:
    cve_id = uuid.uuid4()
    asmt = _asmt(cve_id, state="loop1_done")
    session = MagicMock()
    session.execute = AsyncMock(
        side_effect=[
            _result_scalars([asmt]),   # coverage_assessment page query
            _result_scalars([]),       # detectability join → none yet
            _result_tuples([]),        # artifact counts → none
        ]
    )
    monkeypatch.setattr(
        mod, "filter_assessments_for_user", AsyncMock(return_value=[asmt])
    )

    out = await summarize_assessments_for_cves(session, [cve_id], user=MagicMock())

    summary = out[cve_id]
    assert isinstance(summary, CveAssessmentSummary)
    assert summary.assessment_id == asmt.id
    assert summary.state == "loop1_done"
    assert summary.detectability_class is None
    assert summary.detectability_confidence is None
    assert summary.artifact_counts == {}


@pytest.mark.asyncio
async def test_full_pipeline_summary(monkeypatch) -> None:
    cve_id = uuid.uuid4()
    asmt = _asmt(cve_id, state="loop3_done")
    det = MagicMock()
    det.assessment_id = asmt.id
    det.detectability_class = "directly_detectable"
    det.confidence = 0.875
    session = MagicMock()
    session.execute = AsyncMock(
        side_effect=[
            _result_scalars([asmt]),
            _result_scalars([det]),
            _result_tuples(
                [(asmt.id, "generated", 2), (asmt.id, "failed", 1)]
            ),
        ]
    )
    monkeypatch.setattr(
        mod, "filter_assessments_for_user", AsyncMock(return_value=[asmt])
    )

    out = await summarize_assessments_for_cves(session, [cve_id], user=MagicMock())

    summary = out[cve_id]
    assert summary.detectability_class == "directly_detectable"
    assert summary.detectability_confidence == pytest.approx(0.875)
    assert summary.artifact_counts == {"generated": 2, "failed": 1}


@pytest.mark.asyncio
async def test_access_filtered_assessment_is_omitted(monkeypatch) -> None:
    cve_id = uuid.uuid4()
    asmt = _asmt(cve_id)
    session = MagicMock()
    session.execute = AsyncMock(return_value=_result_scalars([asmt]))
    # F-002: the requester can't read it → behaves exactly like unassessed.
    monkeypatch.setattr(
        mod, "filter_assessments_for_user", AsyncMock(return_value=[])
    )

    out = await summarize_assessments_for_cves(session, [cve_id], user=MagicMock())
    assert out == {}


@pytest.mark.asyncio
async def test_summary_failure_is_advisory(monkeypatch) -> None:
    session = MagicMock()
    session.execute = AsyncMock(side_effect=RuntimeError("db boom"))
    out = await summarize_assessments_for_cves(
        session, [uuid.uuid4()], user=MagicMock()
    )
    assert out == {}  # never raises into the CVE list


@pytest.mark.asyncio
async def test_rule_counts_grouped_by_cve() -> None:
    a, b = uuid.uuid4(), uuid.uuid4()
    session = MagicMock()
    session.execute = AsyncMock(return_value=_result_tuples([(a, 3), (b, 1)]))
    out = await rule_counts_for_cves(session, [a, b, uuid.uuid4()])
    assert out == {a: 3, b: 1}


@pytest.mark.asyncio
async def test_rule_counts_failure_is_advisory() -> None:
    session = MagicMock()
    session.execute = AsyncMock(side_effect=RuntimeError("db boom"))
    out = await rule_counts_for_cves(session, [uuid.uuid4()])
    assert out == {}
