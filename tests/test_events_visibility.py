"""F-010 / SAST S-002 — per-event visibility predicate on the event bus.

The bus previously broadcast every event to every WebSocket subscriber.
This file tests the new ``Event.visible_to(session, user)`` predicate
that gates per-event delivery against the same ``can_user_access``
check the REST middleware uses, plus a maintainer/admin bypass that
matches the F-002 assessment-access semantics.

The unit tests run against the predicate directly with mocked TLP
helpers; an integration test for the WebSocket ``_pump`` lives in
``tests/api/test_ws_tickets.py`` so the WS-handler regression suite
sees it.
"""
from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.notifications.events import Event


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _user(
    *,
    tier: str = "authenticated",
    clearance: str = "tlp:clear",
    user_id: uuid.UUID | None = None,
) -> Any:
    u = MagicMock()
    u.id = user_id or uuid.uuid4()
    u.tier = tier
    u.clearance_level = clearance
    return u


def _patch_can_user_access(monkeypatch: pytest.MonkeyPatch, allowed: bool):
    """Replace ``can_user_access`` at the events-module import site so the
    predicate uses our stub.
    """
    calls: list[dict[str, Any]] = []

    async def _stub(
        session: Any,
        user: Any,
        entity_tlp: Any,
        entity_id: Any = None,
        *,
        embargoed: bool = False,
    ) -> bool:
        calls.append(
            {
                "tlp": str(entity_tlp),
                "entity_id": entity_id,
                "embargoed": embargoed,
                "user_tier": getattr(user, "tier", None),
            }
        )
        return allowed

    monkeypatch.setattr(
        "fragchain.notifications.events.can_user_access",
        _stub,
    )
    return calls


# ---------------------------------------------------------------------------
# Unit tests — Event.visible_to()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_untyped_event_visible_to_anyone() -> None:
    """Events without TLP classification stay broadcast — backwards compat."""
    event = Event(type="cve.ingested", payload={"cve_id": "CVE-2026-0001"})
    session = AsyncMock()
    user = _user()

    assert await event.visible_to(session, user) is True


@pytest.mark.asyncio
async def test_tlp_clear_event_visible_to_anyone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_can_user_access(monkeypatch, allowed=True)
    event = Event(
        type="chain.generated",
        payload={"cve_id": "CVE-2026-0001"},
        tlp="tlp:clear",
        entity_id=uuid.uuid4(),
    )
    session = AsyncMock()
    user = _user(clearance="tlp:clear")

    assert await event.visible_to(session, user) is True


@pytest.mark.asyncio
async def test_tlp_amber_event_denied_without_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SAST S-002 attack scenario: amber event to a clear-clearance user
    without an explicit grant is silently dropped (predicate returns False).
    """
    calls = _patch_can_user_access(monkeypatch, allowed=False)
    chain_id = uuid.uuid4()
    event = Event(
        type="chain.generated",
        payload={"cve_id": "CVE-2026-0001", "chain_id": str(chain_id)},
        tlp="tlp:amber",
        entity_id=chain_id,
    )
    session = AsyncMock()
    user = _user(clearance="tlp:clear")  # cannot read amber

    assert await event.visible_to(session, user) is False
    assert len(calls) == 1
    assert calls[0]["tlp"] == "tlp:amber"
    assert calls[0]["entity_id"] == chain_id
    assert calls[0]["embargoed"] is False


@pytest.mark.asyncio
async def test_tlp_amber_event_visible_with_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_can_user_access(monkeypatch, allowed=True)
    event = Event(
        type="chain.generated",
        payload={},
        tlp="tlp:amber",
        entity_id=uuid.uuid4(),
    )
    session = AsyncMock()
    user = _user(clearance="tlp:amber")

    assert await event.visible_to(session, user) is True


@pytest.mark.asyncio
async def test_tlp_amber_strict_event_denied_without_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_can_user_access(monkeypatch, allowed=False)
    event = Event(
        type="chain.generated",
        payload={},
        tlp="tlp:amber+strict",
        entity_id=uuid.uuid4(),
    )
    session = AsyncMock()
    user = _user(clearance="tlp:green")

    assert await event.visible_to(session, user) is False


@pytest.mark.asyncio
async def test_embargoed_event_propagates_embargoed_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``embargoed=True`` must reach ``can_user_access`` so the participant
    check kicks in rather than the standard TLP comparison.
    """
    calls = _patch_can_user_access(monkeypatch, allowed=False)
    event = Event(
        type="assessment.chain.synthesized",
        payload={},
        tlp="tlp:clear",  # would normally be visible
        entity_id=uuid.uuid4(),
        embargoed=True,
    )
    session = AsyncMock()
    user = _user()

    assert await event.visible_to(session, user) is False
    assert calls[0]["embargoed"] is True


@pytest.mark.asyncio
async def test_maintainer_bypasses_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Operational visibility: maintainers see every event regardless of
    TLP. Matches the F-002 elevated-tier semantics.
    """
    calls = _patch_can_user_access(monkeypatch, allowed=False)  # would deny
    event = Event(
        type="chain.generated",
        payload={},
        tlp="tlp:amber+strict",
        entity_id=uuid.uuid4(),
    )
    session = AsyncMock()
    user = _user(tier="maintainer", clearance="tlp:clear")

    assert await event.visible_to(session, user) is True
    # The bypass short-circuits BEFORE can_user_access is consulted.
    assert calls == []


@pytest.mark.asyncio
async def test_admin_bypasses_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_can_user_access(monkeypatch, allowed=False)
    event = Event(
        type="chain.generated",
        payload={},
        tlp="tlp:red",
        entity_id=uuid.uuid4(),
    )
    session = AsyncMock()
    user = _user(tier="admin", clearance="tlp:clear")

    assert await event.visible_to(session, user) is True


@pytest.mark.asyncio
async def test_unknown_tier_does_not_bypass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``analyst`` / unknown tiers go through the normal predicate."""
    _patch_can_user_access(monkeypatch, allowed=False)
    event = Event(
        type="chain.generated",
        payload={},
        tlp="tlp:amber",
        entity_id=uuid.uuid4(),
    )
    session = AsyncMock()
    user = _user(tier="analyst", clearance="tlp:clear")

    assert await event.visible_to(session, user) is False


@pytest.mark.asyncio
async def test_predicate_safe_against_None_user() -> None:
    """No claims → deny everything except untyped events."""
    typed = Event(
        type="chain.generated",
        payload={},
        tlp="tlp:clear",
        entity_id=uuid.uuid4(),
    )
    untyped = Event(type="ping", payload={})
    session = AsyncMock()

    # Untyped events still pass (the predicate's contract is "is this
    # event for this caller"; None means anonymous and untyped events
    # carry no per-tenant data).
    assert await untyped.visible_to(session, None) is True
    # Typed events always require an authenticated subject.
    assert await typed.visible_to(session, None) is False


@pytest.mark.asyncio
async def test_emit_event_accepts_tlp_kwargs() -> None:
    """``emit_event`` should plumb ``tlp`` / ``entity_id`` / ``embargoed``
    into the resulting Event so existing emit sites can opt in without a
    schema change.
    """
    from fragchain.notifications.events import emit_event, reset_bus

    reset_bus()
    chain_id = uuid.uuid4()
    event = emit_event(
        "chain.generated",
        {"cve_id": "CVE-2026-0001"},
        tlp="tlp:amber",
        entity_id=chain_id,
        embargoed=False,
    )
    assert event.tlp == "tlp:amber"
    assert event.entity_id == chain_id
    assert event.embargoed is False
    reset_bus()
