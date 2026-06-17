"""Deterministic per-type artifact validators (ADR-0004 Phase 3 / W3b).

Honest by design: the three non-Sigma artifact types cannot be auto-validated
for correctness — these lints are shallow advisory checks (reference format +
telemetry-contract catalog cross-check). Human sign-off is the real validation.
"""
from __future__ import annotations

from fragchain.assessments.artifact_validation import (
    ValidationOutcome,
    validate_artifact_content,
)

_GOOD = {
    "title": "Mitigation plan",
    "summary": "s",
    "sections": [{"heading": "h", "items": ["b"]}],
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-0001", "CVE-2024-0001"],
}


def test_clean_mitigation_plan_passes_with_no_warnings():
    out = validate_artifact_content("mitigation_plan", _GOOD, catalog_tokens=set())
    assert isinstance(out, ValidationOutcome)
    assert out.passed is True
    assert out.errors == []
    assert out.warnings == []


def test_malformed_reference_is_a_warning_not_a_failure():
    content = {**_GOOD, "references": ["not a url or cve", "https://ok.example"]}
    out = validate_artifact_content("analyst_research_task", content, catalog_tokens=set())
    assert out.passed is True  # advisory — references never hard-fail
    assert any("reference" in w for w in out.warnings)


def test_missing_content_hard_fails():
    out = validate_artifact_content("mitigation_plan", None, catalog_tokens=set())
    assert out.passed is False
    assert out.errors


def test_telemetry_contract_warns_when_no_catalog_match():
    content = {
        "title": "Telemetry contract",
        "summary": "s",
        "sections": [{"heading": "Required telemetry", "items": ["collect zeek conn logs"]}],
        "references": [],
    }
    out = validate_artifact_content(
        "telemetry_contract", content, catalog_tokens={"windows", "security", "auditd"}
    )
    assert out.passed is True
    assert any("catalog" in w.lower() for w in out.warnings)


def test_telemetry_contract_clean_when_catalog_matches():
    content = {
        "title": "Telemetry contract",
        "summary": "s",
        "sections": [{"heading": "Required telemetry", "items": ["windows security event log"]}],
        "references": [],
    }
    out = validate_artifact_content(
        "telemetry_contract", content, catalog_tokens={"windows", "security"}
    )
    assert out.passed is True
    assert out.warnings == []


def test_catalog_lint_only_applies_to_telemetry_contract():
    # a mitigation_plan that never mentions the catalog is fine — no telemetry lint.
    content = {**_GOOD, "sections": [{"heading": "h", "items": ["patch it"]}]}
    out = validate_artifact_content("mitigation_plan", content, catalog_tokens={"windows"})
    assert out.warnings == []


def test_telemetry_contract_matches_a_field_convention_token():
    content = {
        "title": "t", "summary": "s",
        "sections": [{"heading": "Required telemetry", "items": ["capture the CommandLine field"]}],
        "references": [],
    }
    out = validate_artifact_content(
        "telemetry_contract", content, catalog_tokens={"sysmon", "CommandLine"}
    )
    assert out.warnings == []  # matches the field-name token, not just product/service


def test_telemetry_catalog_match_is_word_boundary_not_substring():
    # "securely" must NOT satisfy the catalog token "security" (substring would).
    content = {
        "title": "t", "summary": "s",
        "sections": [{"heading": "h", "items": ["log things securely"]}],
        "references": [],
    }
    out = validate_artifact_content(
        "telemetry_contract", content, catalog_tokens={"security"}
    )
    assert any("catalog" in w.lower() for w in out.warnings)


# --- service (state machine) ------------------------------------------------

import uuid  # noqa: E402
from unittest.mock import AsyncMock, MagicMock  # noqa: E402

import pytest  # noqa: E402

from fragchain.assessments.artifact_validation import (  # noqa: E402
    ArtifactNotFoundError,
    ArtifactValidator,
    InvalidValidationTransitionError,
)
from fragchain.db.models import GeneratedArtifactRow  # noqa: E402


def _row(validation_status="not_validated", status="generated", content=None):
    return GeneratedArtifactRow(
        id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        artifact_type="mitigation_plan",
        version=1,
        is_active=True,
        status=status,
        validation_status=validation_status,
        content=content if content is not None else dict(_GOOD),
    )


def _svc(row):
    session = MagicMock()
    session.get = AsyncMock(return_value=row)
    session.commit = AsyncMock()
    session.add = MagicMock()
    profile_store = MagicMock()
    profile_store.get_enabled = AsyncMock(return_value=[])
    return ArtifactValidator(session, profile_store=profile_store), session


@pytest.mark.asyncio
async def test_validate_moves_not_validated_to_needs_review():
    row = _row("not_validated")
    svc, session = _svc(row)
    await svc.validate(row.id)
    assert row.validation_status == "needs_review"
    session.add.assert_called()  # audit row written


@pytest.mark.asyncio
async def test_validate_is_idempotent_on_terminal_no_demote():
    row = _row("analyst_approved")
    svc, _ = _svc(row)
    await svc.validate(row.id)
    assert row.validation_status == "analyst_approved"  # not demoted


@pytest.mark.asyncio
async def test_approve_then_reject_is_blocked():
    row = _row("needs_review")
    svc, _ = _svc(row)
    await svc.approve(row.id, reviewer=uuid.uuid4())
    assert row.validation_status == "analyst_approved"
    with pytest.raises(InvalidValidationTransitionError):
        await svc.reject(row.id, reason="too late")


@pytest.mark.asyncio
async def test_reject_records_reason():
    row = _row("needs_review")
    svc, session = _svc(row)
    await svc.reject(row.id, reason="off base")
    assert row.validation_status == "rejected"
    session.add.assert_called()


@pytest.mark.asyncio
async def test_approve_is_idempotent():
    row = _row("analyst_approved")
    svc, _ = _svc(row)
    await svc.approve(row.id)
    assert row.validation_status == "analyst_approved"


@pytest.mark.asyncio
async def test_validate_requires_generated_status():
    row = _row("not_validated", status="generating")
    svc, _ = _svc(row)
    with pytest.raises(InvalidValidationTransitionError):
        await svc.validate(row.id)


@pytest.mark.asyncio
async def test_missing_artifact_raises():
    svc, session = _svc(None)
    session.get = AsyncMock(return_value=None)
    with pytest.raises(ArtifactNotFoundError):
        await svc.validate(uuid.uuid4())


@pytest.mark.asyncio
async def test_catalog_tokens_includes_field_conventions():
    svc, _ = _svc(_row())
    profile = MagicMock(
        sigma_product="windows", sigma_service="sysmon",
        field_conventions={"CommandLine": {}, "ParentImage": {}},
    )
    svc._profile_store.get_enabled = AsyncMock(return_value=[profile])
    tokens = await svc._catalog_tokens()
    assert {"windows", "sysmon", "CommandLine", "ParentImage"} <= tokens
