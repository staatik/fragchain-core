"""Trigger normalization tests.

In v1 the resolver only validates shape; ticket / PSIRT URL kinds are
stored as audit metadata. The caller is required to provide a
``cve_id`` separately because connectors / URL fetchers aren't built.
"""
from __future__ import annotations

import pytest

from fragchain.assessments.schemas import Trigger, TriggerKind
from fragchain.assessments.trigger_resolver import (
    InvalidTriggerError,
    validate_trigger,
)


def test_cve_id_trigger_must_match_pattern() -> None:
    validate_trigger(Trigger(kind=TriggerKind.CVE_ID, value="CVE-2026-1234"))
    with pytest.raises(InvalidTriggerError, match="CVE format"):
        validate_trigger(Trigger(kind=TriggerKind.CVE_ID, value="not-a-cve"))


def test_ticket_trigger_accepted_as_freeform() -> None:
    validate_trigger(Trigger(kind=TriggerKind.TICKET, value="JIRA-12345"))
    validate_trigger(Trigger(kind=TriggerKind.TICKET, value="SN-INC0011223"))


def test_psirt_url_trigger_must_be_https() -> None:
    validate_trigger(
        Trigger(kind=TriggerKind.PSIRT_URL, value="https://msrc.microsoft.com/x")
    )
    with pytest.raises(InvalidTriggerError, match="https"):
        validate_trigger(
            Trigger(kind=TriggerKind.PSIRT_URL, value="ftp://example.com")
        )
    with pytest.raises(InvalidTriggerError, match="https"):
        validate_trigger(
            Trigger(kind=TriggerKind.PSIRT_URL, value="http://example.com")
        )
