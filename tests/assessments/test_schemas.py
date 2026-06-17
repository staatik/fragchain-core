"""Pydantic schema validation tests."""
from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from fragchain.assessments.schemas import (
    AssessmentCreateRequest,
    AssessmentState,
    LoopNumber,
    SourceCreateRequest,
    TriggerKind,
)


def test_assessment_create_request_accepts_cve_id_trigger() -> None:
    req = AssessmentCreateRequest(
        trigger={"kind": "cve_id", "value": "CVE-2026-1234"},
        cve_id=uuid.uuid4(),
        context_note="testing",
    )
    assert req.trigger.kind == TriggerKind.CVE_ID


def test_assessment_create_request_rejects_unknown_trigger_kind() -> None:
    with pytest.raises(ValidationError):
        AssessmentCreateRequest(
            trigger={"kind": "telepathy", "value": "x"},
            cve_id=uuid.uuid4(),
        )


def test_source_create_request_requires_free_text_kind_in_v1() -> None:
    SourceCreateRequest(kind="free_text", content="hello world")

    with pytest.raises(ValidationError):
        SourceCreateRequest(kind="url", content="https://example.com")


def test_source_create_request_strips_empty_title() -> None:
    req = SourceCreateRequest(kind="free_text", title="   ", content="x")
    assert req.title is None


def test_loop_number_enum() -> None:
    assert LoopNumber.ONE == 1
    with pytest.raises(ValueError):
        LoopNumber(4)


def test_assessment_state_enum_contains_all_expected_states() -> None:
    expected = {
        "created", "loop1_done", "loop2_done", "loop3_done", "completed"
    }
    assert {s.value for s in AssessmentState} == expected


def test_assessment_response_carries_auto_advance() -> None:
    import datetime as dt

    from fragchain.assessments.schemas import AssessmentResponse

    r = AssessmentResponse(
        id=uuid.uuid4(),
        cve_id=uuid.uuid4(),
        creator_id=uuid.uuid4(),
        initial_trigger={"kind": "cve_id", "value": "CVE-2024-1"},
        context_note=None,
        state=AssessmentState.CREATED,
        completed_at=None,
        tlp="tlp:clear",
        auto_advance=True,
        created_at=dt.datetime.now(dt.timezone.utc),
        updated_at=dt.datetime.now(dt.timezone.utc),
    )
    assert r.auto_advance is True
