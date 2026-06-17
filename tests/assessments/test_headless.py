"""Tests for the headless auto-assessment trigger (W3a-1)."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fragchain.assessments.headless import (
    HeadlessSource,
    auto_assess,
)
from fragchain.assessments.service import DuplicateAssessmentError


def _src(content="x" * 1000, title="t"):
    return HeadlessSource(title=title, content=content)


def _patches(*, create_side=None, begin_run_id=None):
    """Patch the collaborators auto_assess orchestrates."""
    asmt = MagicMock()
    asmt.id = uuid.uuid4()
    svc = MagicMock()
    svc.create = AsyncMock(return_value=asmt) if create_side is None else AsyncMock(side_effect=create_side)
    svc.set_auto_advance = AsyncMock()
    src_svc = MagicMock()
    src_svc.create = AsyncMock()
    run = MagicMock()
    run.id = begin_run_id or uuid.uuid4()
    orch = MagicMock()
    orch.begin_run = AsyncMock(return_value=run)
    return asmt, svc, src_svc, orch, run


@pytest.mark.asyncio
async def test_auto_assess_happy_path_dispatches_loop1():
    asmt, svc, src_svc, orch, run = _patches()
    dispatched = {}
    session = MagicMock()
    session.commit = AsyncMock()
    with patch("fragchain.assessments.headless._creator_exists", AsyncMock(return_value=True)), \
         patch("fragchain.assessments.headless.AssessmentService", return_value=svc), \
         patch("fragchain.assessments.headless.SourceService", return_value=src_svc), \
         patch("fragchain.assessments.headless.build_orchestrator", return_value=orch):
        result = await auto_assess(
            session,
            cve_id=uuid.uuid4(),
            cve_textual_id="CVE-2024-0001",
            sources=[_src()],
            creator_id=uuid.uuid4(),
            dispatch=lambda rid: dispatched.setdefault("rid", rid),
        )
    assert result.status == "started"
    assert result.assessment_id == asmt.id
    assert result.loop1_run_id == run.id
    svc.set_auto_advance.assert_awaited_once_with(asmt.id, True)
    src_svc.create.assert_awaited()                     # source attached
    assert dispatched["rid"] == str(run.id)             # Loop 1 dispatched
    # never auto-overrides:
    _, kwargs = orch.begin_run.await_args
    assert kwargs.get("override_rationale") is None


@pytest.mark.asyncio
async def test_auto_assess_rejects_thin_sources():
    asmt, svc, src_svc, orch, run = _patches()
    session = MagicMock()
    with patch("fragchain.assessments.headless._creator_exists", AsyncMock(return_value=True)), \
         patch("fragchain.assessments.headless.AssessmentService", return_value=svc), \
         patch("fragchain.assessments.headless.SourceService", return_value=src_svc), \
         patch("fragchain.assessments.headless.build_orchestrator", return_value=orch):
        result = await auto_assess(
            session, cve_id=uuid.uuid4(), cve_textual_id="CVE-2024-0001",
            sources=[_src(content="tiny")],  # 4 bytes < 500 floor
            creator_id=uuid.uuid4(), dispatch=lambda rid: None,
        )
    assert result.status == "rejected_thin_sources"
    assert result.assessment_id is None
    svc.create.assert_not_awaited()       # no assessment created
    orch.begin_run.assert_not_awaited()   # no loop run


@pytest.mark.asyncio
async def test_auto_assess_rejects_zero_sources():
    _, svc, src_svc, orch, _ = _patches()
    session = MagicMock()
    with patch("fragchain.assessments.headless._creator_exists", AsyncMock(return_value=True)), \
         patch("fragchain.assessments.headless.AssessmentService", return_value=svc), \
         patch("fragchain.assessments.headless.SourceService", return_value=src_svc), \
         patch("fragchain.assessments.headless.build_orchestrator", return_value=orch):
        result = await auto_assess(
            session, cve_id=uuid.uuid4(), cve_textual_id="CVE-2024-0001",
            sources=[], creator_id=uuid.uuid4(), dispatch=lambda rid: None,
        )
    assert result.status == "rejected_thin_sources"
    svc.create.assert_not_awaited()


@pytest.mark.asyncio
async def test_auto_assess_duplicate_returns_duplicate():
    asmt, svc, src_svc, orch, run = _patches(create_side=DuplicateAssessmentError("dup"))
    session = MagicMock()
    with patch("fragchain.assessments.headless._creator_exists", AsyncMock(return_value=True)), \
         patch("fragchain.assessments.headless.AssessmentService", return_value=svc), \
         patch("fragchain.assessments.headless.SourceService", return_value=src_svc), \
         patch("fragchain.assessments.headless.build_orchestrator", return_value=orch):
        result = await auto_assess(
            session, cve_id=uuid.uuid4(), cve_textual_id="CVE-2024-0001",
            sources=[_src()], creator_id=uuid.uuid4(), dispatch=lambda rid: None,
        )
    assert result.status == "duplicate"
    orch.begin_run.assert_not_awaited()
