"""TLP filter middleware tests.

`apply_tlp_filter` (list filtering) and `enforce_tlp_access` (single-entity gate)
are the only things every TLP-aware endpoint needs to call. These tests verify
both paths reject over-classified content and respect embargo overrides.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from fragchain.api.middleware.tlp_filter import (
    RequestUser,
    apply_tlp_filter,
    enforce_tlp_access,
    visible_to_user_sync,
)
from fragchain.security import tlp as tlp_mod


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
    monkeypatch.setattr(tlp_mod, "has_explicit_grant", _fake_has_grant)
    monkeypatch.setattr(tlp_mod, "is_embargo_participant", _fake_is_participant)


def _make_user(clearance="tlp:green", tier="authenticated") -> RequestUser:
    return RequestUser(
        id=uuid.uuid4(),
        username="tester",
        tier=tier,
        clearance_level=clearance,
    )


@pytest.mark.asyncio
async def test_apply_tlp_filter_strips_over_classified_content_for_anonymous():
    items = [
        {"id": str(uuid.uuid4()), "tlp": "tlp:clear", "title": "public"},
        {"id": str(uuid.uuid4()), "tlp": "tlp:green", "title": "internal"},
        {"id": str(uuid.uuid4()), "tlp": "tlp:amber", "title": "restricted"},
    ]
    visible = await apply_tlp_filter(FakeSession(), items, user=None)
    assert [i["title"] for i in visible] == ["public"]


@pytest.mark.asyncio
async def test_apply_tlp_filter_returns_green_to_authenticated():
    user = _make_user(clearance="tlp:green")
    items = [
        {"id": str(uuid.uuid4()), "tlp": "tlp:clear"},
        {"id": str(uuid.uuid4()), "tlp": "tlp:green"},
        {"id": str(uuid.uuid4()), "tlp": "tlp:amber"},  # blocked — no grant
    ]
    visible = await apply_tlp_filter(FakeSession(), items, user=user)
    tlps = sorted({i["tlp"] for i in visible})
    assert tlps == ["tlp:clear", "tlp:green"]


@pytest.mark.asyncio
async def test_apply_tlp_filter_includes_amber_when_grant_exists():
    user = _make_user(clearance="tlp:amber")
    entity_id = uuid.uuid4()
    items = [{"id": str(entity_id), "tlp": "tlp:amber"}]
    session = FakeSession(grants={(user.id, entity_id)})
    visible = await apply_tlp_filter(session, items, user=user)
    assert len(visible) == 1


@pytest.mark.asyncio
async def test_enforce_tlp_access_rejects_with_403():
    user = _make_user(clearance="tlp:green")
    item = {"id": str(uuid.uuid4()), "tlp": "tlp:amber"}
    with pytest.raises(HTTPException) as exc:
        await enforce_tlp_access(FakeSession(), item, user)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_enforce_tlp_access_allows_when_clear():
    item = {"id": str(uuid.uuid4()), "tlp": "tlp:clear"}
    # Should not raise.
    await enforce_tlp_access(FakeSession(), item, user=None)


@pytest.mark.asyncio
async def test_embargoed_entity_treated_as_red():
    """An entity declared CLEAR but under embargo is invisible to non-participants."""
    user = _make_user(clearance="tlp:red")
    entity_id = uuid.uuid4()
    item = {
        "id": str(entity_id),
        "tlp": "tlp:clear",
        "embargo_until": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    }
    visible = await apply_tlp_filter(FakeSession(), [item], user=user)
    assert visible == []


@pytest.mark.asyncio
async def test_embargoed_entity_visible_to_participant():
    user = _make_user(clearance="tlp:green")
    entity_id = uuid.uuid4()
    item = {
        "id": str(entity_id),
        "tlp": "tlp:clear",
        "embargo_until": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    }
    # No participant membership -> hidden.
    assert await apply_tlp_filter(FakeSession(), [item], user=user) == []
    # Add participant -> visible.
    session = FakeSession(embargo_participants={(user.id, entity_id)})
    visible = await apply_tlp_filter(session, [item], user=user)
    assert len(visible) == 1


@pytest.mark.asyncio
async def test_apply_tlp_filter_accepts_pydantic_models():
    from pydantic import BaseModel

    class Entry(BaseModel):
        id: uuid.UUID
        tlp: str

    entries = [
        Entry(id=uuid.uuid4(), tlp="tlp:clear"),
        Entry(id=uuid.uuid4(), tlp="tlp:green"),
        Entry(id=uuid.uuid4(), tlp="tlp:red"),
    ]
    visible = await apply_tlp_filter(FakeSession(), entries, user=None)
    assert [e.tlp for e in visible] == ["tlp:clear"]


def test_visible_to_user_sync_excludes_amber_without_db():
    user = _make_user(clearance="tlp:amber")
    items = [
        {"id": str(uuid.uuid4()), "tlp": "tlp:clear"},
        {"id": str(uuid.uuid4()), "tlp": "tlp:green"},
        {"id": str(uuid.uuid4()), "tlp": "tlp:amber"},
    ]
    visible = visible_to_user_sync(items, user)
    # The sync fast-path conservatively drops AMBER+ because it can't check grants.
    assert {i["tlp"] for i in visible} == {"tlp:clear", "tlp:green"}
