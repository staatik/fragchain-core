"""Trigger normalization for the multi-input create flow.

v1 scope: validate shape only. CVE-ID format check (regex), ticket as
free-form string, PSIRT URL must be ``https://``. Resolving a ticket to
a CVE-ID or fetching a PSIRT URL to extract CVE references requires
connector + URL-fetch infrastructure that isn't built yet (spec §4.4
notes connectors as a future track). Until then the caller must supply
``cve_id`` separately on the create request.
"""
from __future__ import annotations

import re

from fragchain.assessments.schemas import Trigger, TriggerKind

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


class InvalidTriggerError(ValueError):
    """Raised when the trigger payload fails v1 shape checks."""


def validate_trigger(trigger: Trigger) -> None:
    """Raise ``InvalidTriggerError`` if ``trigger`` violates shape rules."""
    if trigger.kind == TriggerKind.CVE_ID:
        if not _CVE_PATTERN.match(trigger.value):
            raise InvalidTriggerError(
                f"trigger value {trigger.value!r} does not match CVE format "
                "(expected CVE-YYYY-NNNN)"
            )
    elif trigger.kind == TriggerKind.PSIRT_URL:
        if not trigger.value.startswith("https://"):
            raise InvalidTriggerError(
                "PSIRT URL must use https:// (v1 does not fetch but enforces "
                "the protocol for forward compatibility)"
            )
    # TICKET kind: any non-empty string passes (Pydantic min_length=1 already
    # enforced).
