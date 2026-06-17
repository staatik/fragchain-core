"""Unit tests for M2 — TLP enum, propagation, access predicate, embargo overrides.

These tests are pure-Python: they use an in-memory fake session for grants and
participants. The real SQLAlchemy-backed code path is exercised in integration
tests once the schema is available in CI.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import pytest

from fragchain.security.embargo import effective_tlp, is_embargoed
from fragchain.security.tlp import (
    TLP,
    filter_tlp_visible,
    max_tlp,
)
from fragchain.security import tlp as tlp_mod


# ---------------------------------------------------------------------------
# In-memory fake session — substitutes for the AsyncSession passed into
# `has_explicit_grant` and `is_embargo_participant`. The real implementations
# are tested via integration tests once the DB is up.
# ---------------------------------------------------------------------------


@dataclass
class FakeUser:
    id: uuid.UUID
    tier: str = "authenticated"
    clearance_level: str = "tlp:green"


@dataclass
class FakeSession:
    grants: set[tuple[uuid.UUID, uuid.UUID]] = field(default_factory=set)
    embargo_participants: set[tuple[uuid.UUID, uuid.UUID]] = field(default_factory=set)


async def _fake_has_grant(session, user_id, entity_id):
    return (user_id, entity_id) in session.grants


async def _fake_is_participant(session, user_id, entity_id):
    return (user_id, entity_id) in session.embargo_participants


@pytest.fixture(autouse=True)
def patch_db_lookups(monkeypatch):
    """Bypass the DB in unit tests by monkeypatching the lookup helpers."""
    monkeypatch.setattr(tlp_mod, "has_explicit_grant", _fake_has_grant)
    monkeypatch.setattr(tlp_mod, "is_embargo_participant", _fake_is_participant)


# ---------------------------------------------------------------------------
# Enum + ordering
# ---------------------------------------------------------------------------


def test_tlp_has_all_five_levels():
    assert {t.value for t in TLP} == {
        "tlp:clear",
        "tlp:green",
        "tlp:amber",
        "tlp:amber+strict",
        "tlp:red",
    }


def test_restriction_level_ordering():
    levels = [TLP.CLEAR, TLP.GREEN, TLP.AMBER, TLP.AMBER_STRICT, TLP.RED]
    for a, b in zip(levels, levels[1:]):
        assert a.restriction_level < b.restriction_level


def test_parse_accepts_strings_and_enums():
    assert TLP.parse("tlp:clear") == TLP.CLEAR
    assert TLP.parse("TLP:Red") == TLP.RED  # case-insensitive
    assert TLP.parse(TLP.AMBER) == TLP.AMBER
    assert TLP.parse(None) == TLP.CLEAR
    assert TLP.parse("") == TLP.CLEAR


def test_parse_rejects_unknown():
    with pytest.raises(ValueError):
        TLP.parse("tlp:purple")


# ---------------------------------------------------------------------------
# max_tlp
# ---------------------------------------------------------------------------


def test_max_tlp_returns_most_restrictive():
    assert max_tlp(TLP.CLEAR, TLP.GREEN, TLP.AMBER) == TLP.AMBER
    assert max_tlp(TLP.RED, TLP.CLEAR) == TLP.RED
    assert max_tlp(TLP.GREEN) == TLP.GREEN


def test_max_tlp_handles_mixed_input():
    assert max_tlp("tlp:green", TLP.AMBER, "tlp:clear") == TLP.AMBER


def test_max_tlp_empty_input_is_clear():
    assert max_tlp() == TLP.CLEAR


# ---------------------------------------------------------------------------
# can_user_access — the contract every endpoint enforces
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_clear_content_visible_to_anonymous():
    assert await tlp_mod.can_user_access(FakeSession(), None, TLP.CLEAR) is True


@pytest.mark.asyncio
async def test_green_content_not_visible_to_anonymous():
    assert await tlp_mod.can_user_access(FakeSession(), None, TLP.GREEN) is False


@pytest.mark.asyncio
async def test_green_content_visible_to_authenticated_with_green_clearance():
    user = FakeUser(id=uuid.uuid4(), clearance_level="tlp:green")
    assert await tlp_mod.can_user_access(FakeSession(), user, TLP.GREEN) is True


@pytest.mark.asyncio
async def test_green_content_visible_to_anyone_with_higher_clearance():
    user = FakeUser(id=uuid.uuid4(), clearance_level="tlp:amber")
    assert await tlp_mod.can_user_access(FakeSession(), user, TLP.GREEN) is True


@pytest.mark.asyncio
async def test_green_content_blocked_for_clear_only_clearance():
    user = FakeUser(id=uuid.uuid4(), clearance_level="tlp:clear")
    assert await tlp_mod.can_user_access(FakeSession(), user, TLP.GREEN) is False


@pytest.mark.asyncio
async def test_amber_requires_explicit_grant():
    user = FakeUser(id=uuid.uuid4(), clearance_level="tlp:amber")
    entity_id = uuid.uuid4()
    session = FakeSession()
    # No grant on record — must be denied.
    assert (
        await tlp_mod.can_user_access(session, user, TLP.AMBER, entity_id) is False
    )
    # Add a grant — must be allowed.
    session.grants.add((user.id, entity_id))
    assert (
        await tlp_mod.can_user_access(session, user, TLP.AMBER, entity_id) is True
    )


@pytest.mark.asyncio
async def test_red_requires_explicit_grant_even_for_red_clearance():
    user = FakeUser(id=uuid.uuid4(), clearance_level="tlp:red")
    entity_id = uuid.uuid4()
    session = FakeSession()
    assert await tlp_mod.can_user_access(session, user, TLP.RED, entity_id) is False
    session.grants.add((user.id, entity_id))
    assert await tlp_mod.can_user_access(session, user, TLP.RED, entity_id) is True


@pytest.mark.asyncio
async def test_amber_strict_requires_explicit_grant():
    user = FakeUser(id=uuid.uuid4(), clearance_level="tlp:red")
    entity_id = uuid.uuid4()
    session = FakeSession()
    assert (
        await tlp_mod.can_user_access(session, user, TLP.AMBER_STRICT, entity_id)
        is False
    )
    session.grants.add((user.id, entity_id))
    assert (
        await tlp_mod.can_user_access(session, user, TLP.AMBER_STRICT, entity_id)
        is True
    )


# ---------------------------------------------------------------------------
# Embargo overrides
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_embargo_overrides_clear_classification():
    """A CLEAR entity under active embargo is still effectively RED."""
    user = FakeUser(id=uuid.uuid4(), clearance_level="tlp:green")
    entity_id = uuid.uuid4()
    session = FakeSession()
    # CLEAR but under embargo: should require participant membership.
    assert (
        await tlp_mod.can_user_access(
            session, user, TLP.RED, entity_id, embargoed=True
        )
        is False
    )
    session.embargo_participants.add((user.id, entity_id))
    assert (
        await tlp_mod.can_user_access(
            session, user, TLP.RED, entity_id, embargoed=True
        )
        is True
    )


def test_effective_tlp_during_embargo_is_red():
    declared = TLP.CLEAR
    embargo_until = datetime.now(timezone.utc) + timedelta(hours=1)
    assert effective_tlp(declared, embargo_until) == TLP.RED


def test_effective_tlp_after_embargo_is_declared_value():
    declared = TLP.AMBER
    embargo_until = datetime.now(timezone.utc) - timedelta(hours=1)
    assert effective_tlp(declared, embargo_until) == TLP.AMBER


def test_is_embargoed_returns_true_only_for_active():
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    assert is_embargoed(future) is True
    assert is_embargoed(past) is False
    assert is_embargoed(None) is False


# ---------------------------------------------------------------------------
# filter_tlp_visible — synchronous fast-path
# ---------------------------------------------------------------------------


def test_filter_tlp_visible_anonymous_only_sees_clear():
    user = None
    items = [
        (uuid.uuid4(), TLP.CLEAR),
        (uuid.uuid4(), TLP.GREEN),
        (uuid.uuid4(), TLP.AMBER),
    ]
    visible = filter_tlp_visible(items, user)
    assert len(visible) == 1


def test_filter_tlp_visible_authenticated_sees_clear_and_green():
    user = FakeUser(id=uuid.uuid4(), clearance_level="tlp:green")
    items = [
        (uuid.uuid4(), TLP.CLEAR),
        (uuid.uuid4(), TLP.GREEN),
        (uuid.uuid4(), TLP.AMBER),  # excluded — needs DB-backed grant check
    ]
    visible = filter_tlp_visible(items, user)
    assert len(visible) == 2
