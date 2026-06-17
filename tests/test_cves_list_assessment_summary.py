"""GET /cves embeds the per-row assessment summary + rule_count (badging spec)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.api.routers import cves as cves_router
from fragchain.api.routers.cves import list_cves
from fragchain.assessments.cve_summary import CveAssessmentSummary


def _cve_row(cve_uuid: uuid.UUID) -> SimpleNamespace:
    now = datetime.now(tz=timezone.utc)
    return SimpleNamespace(
        id=cve_uuid, cve_id="CVE-2026-1234", title=None, description=None,
        published_at=now, modified_at=None, cvss_score=None, cvss_vector=None,
        cisa_kev=False, cisa_kev_date=None, epss_score=None,
        epss_percentile=None, attackerkb_score=None, ctid_techniques=[],
        affected_products=None, import_mode="live", processing_status="complete",
        processing_stage=None, processing_error=None, approved_by=None,
        approved_at=None, import_job_id=None, enrichment_sources={},
        tlp="tlp:clear", embargo_until=None, created_at=now, updated_at=now,
    )


class _FakeResult:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def scalars(self):  # noqa: ANN201
        outer = self

        class _S:
            def all(self) -> list:
                return list(outer._rows)

        return _S()


class _FakeSession:
    def __init__(self, rows: list) -> None:
        self.rows = rows

    async def execute(self, _stmt):  # noqa: ANN001
        return _FakeResult(self.rows)


@pytest.fixture(autouse=True)
def _passthrough_tlp(monkeypatch):
    async def _allow_all(_db, rows, _user):  # noqa: ANN001
        return list(rows)

    monkeypatch.setattr(cves_router, "apply_tlp_filter", _allow_all)
    monkeypatch.setattr(
        cves_router, "get_request_user", lambda _request: MagicMock()
    )


@pytest.mark.asyncio
async def test_list_embeds_summary_and_rule_count(monkeypatch) -> None:
    cve_uuid = uuid.uuid4()
    row = _cve_row(cve_uuid)
    summary = CveAssessmentSummary(
        assessment_id=uuid.uuid4(),
        state="loop2_done",
        detectability_class="environment_dependent",
        detectability_confidence=0.6,
        artifact_counts={"generated": 1},
    )
    monkeypatch.setattr(
        cves_router,
        "summarize_assessments_for_cves",
        AsyncMock(return_value={cve_uuid: summary}),
    )
    monkeypatch.setattr(
        cves_router,
        "rule_counts_for_cves",
        AsyncMock(return_value={cve_uuid: 3}),
    )

    resp = await list_cves(
        request=MagicMock(), kev=None, status_filter=None, import_mode=None,
        cvss_min=None, published_after=None, published_before=None,
        limit=50, offset=0, db=_FakeSession([row]), _user=MagicMock(),
    )

    out = resp.cves[0]
    assert out.rule_count == 3
    assert out.assessment is not None
    assert out.assessment.state == "loop2_done"
    assert out.assessment.detectability_class == "environment_dependent"
    assert out.assessment.artifact_counts == {"generated": 1}


@pytest.mark.asyncio
async def test_list_without_assessment_is_null_and_zero(monkeypatch) -> None:
    cve_uuid = uuid.uuid4()
    row = _cve_row(cve_uuid)
    monkeypatch.setattr(
        cves_router,
        "summarize_assessments_for_cves",
        AsyncMock(return_value={}),
    )
    monkeypatch.setattr(
        cves_router, "rule_counts_for_cves", AsyncMock(return_value={})
    )

    resp = await list_cves(
        request=MagicMock(), kev=None, status_filter=None, import_mode=None,
        cvss_min=None, published_after=None, published_before=None,
        limit=50, offset=0, db=_FakeSession([row]), _user=MagicMock(),
    )

    out = resp.cves[0]
    assert out.assessment is None
    assert out.rule_count == 0


@pytest.mark.asyncio
async def test_summary_computed_for_returned_page_only(monkeypatch) -> None:
    rows = [_cve_row(uuid.uuid4()) for _ in range(3)]
    seen: dict[str, list] = {}

    async def _summary(_db, cve_ids, *, user):  # noqa: ANN001
        seen["summary_ids"] = list(cve_ids)
        return {}

    async def _counts(_db, cve_ids):  # noqa: ANN001
        seen["count_ids"] = list(cve_ids)
        return {}

    monkeypatch.setattr(cves_router, "summarize_assessments_for_cves", _summary)
    monkeypatch.setattr(cves_router, "rule_counts_for_cves", _counts)

    await list_cves(
        request=MagicMock(), kev=None, status_filter=None, import_mode=None,
        cvss_min=None, published_after=None, published_before=None,
        limit=2, offset=0, db=_FakeSession(rows), _user=MagicMock(),
    )

    # Only the sliced page (limit=2 of 3 visible) feeds the batched queries.
    assert len(seen["summary_ids"]) == 2
    assert len(seen["count_ids"]) == 2
