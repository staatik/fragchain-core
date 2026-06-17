"""F-002 — object-level authorization on assessment endpoints.

Two layers:

1. Unit tests against ``fragchain.assessments.access`` directly with a
   stubbed session. These prove the access predicate accepts only the
   four allowed paths (creator, elevated tier, explicit grant, TLP).
2. Router-level integration tests that wire the real access helper into
   the FastAPI router and confirm each endpoint returns 404 when the
   caller is not authorized.

The router tests don't go through a real DB. They build a fake async
session with ``MagicMock`` and ``AsyncMock`` so the helper sees the
target ``CoverageAssessment`` row but can't reach the rest of the
schema. ``has_explicit_grant`` is monkeypatched.
"""
from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fragchain.api.middleware.tlp_filter import require_authenticated
from fragchain.api.routers import assessments as router_mod
from fragchain.api.routers.assessments import router
from fragchain.assessments.access import (
    filter_assessments_for_user,
    load_assessment_for_read,
    load_assessment_for_write,
)
from fragchain.assessments.service import AssessmentNotFoundError
from fragchain.db.session import get_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_assessment_row(
    *,
    creator_id: uuid.UUID,
    tlp: str = "tlp:clear",
    assessment_id: uuid.UUID | None = None,
) -> Any:
    from datetime import datetime, timezone

    row = MagicMock()
    row.id = assessment_id or uuid.uuid4()
    row.cve_id = uuid.uuid4()
    row.creator_id = creator_id
    row.initial_trigger = {"kind": "cve_id", "value": "CVE-2026-1"}
    row.context_note = None
    row.state = "created"
    row.completed_at = None
    row.tlp = tlp
    row.embargo_until = None
    row.created_at = datetime.now(tz=timezone.utc)
    row.updated_at = row.created_at
    return row


def _make_session_returning(row: Any | None) -> Any:
    """Build a session mock whose ``execute`` returns a result that
    resolves ``scalar_one_or_none()`` to ``row`` (None → row missing).
    """
    session = MagicMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = row
    session.execute = AsyncMock(return_value=result)
    return session


def _user(
    *,
    user_id: uuid.UUID | None = None,
    tier: str = "authenticated",
    clearance: str = "tlp:green",
) -> Any:
    u = MagicMock()
    u.id = user_id or uuid.uuid4()
    u.tier = tier
    u.clearance_level = clearance
    return u


def _patch_grant(monkeypatch: pytest.MonkeyPatch, *, allow: bool) -> None:
    """Patch ``has_explicit_grant`` everywhere the access helper might
    resolve it from. ``access.py`` does a lazy import inside the function
    so we have to patch the source module."""

    async def _impl(session, user_id, entity_id):  # noqa: ANN001
        return allow

    monkeypatch.setattr("fragchain.security.tlp.has_explicit_grant", _impl)


# ---------------------------------------------------------------------------
# Unit tests — access.py directly
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_creator_can_read_own_assessment() -> None:
    creator_id = uuid.uuid4()
    row = _make_assessment_row(creator_id=creator_id)
    session = _make_session_returning(row)
    user = _user(user_id=creator_id)

    got = await load_assessment_for_read(session, row.id, user=user)
    assert got is row


@pytest.mark.asyncio
async def test_creator_can_write_own_assessment() -> None:
    creator_id = uuid.uuid4()
    row = _make_assessment_row(creator_id=creator_id)
    session = _make_session_returning(row)
    user = _user(user_id=creator_id)

    got = await load_assessment_for_write(session, row.id, user=user)
    assert got is row


@pytest.mark.asyncio
async def test_non_owner_gets_404_not_403(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F-002 path 5: existence is not disclosed; access denials look
    identical to missing rows on the wire."""
    _patch_grant(monkeypatch, allow=False)
    row = _make_assessment_row(creator_id=uuid.uuid4())
    session = _make_session_returning(row)
    other_user = _user()  # different user_id

    with pytest.raises(AssessmentNotFoundError):
        await load_assessment_for_read(session, row.id, user=other_user)


@pytest.mark.asyncio
async def test_missing_row_returns_404() -> None:
    session = _make_session_returning(None)
    with pytest.raises(AssessmentNotFoundError):
        await load_assessment_for_read(session, uuid.uuid4(), user=_user())


@pytest.mark.asyncio
async def test_maintainer_can_read_any_assessment() -> None:
    row = _make_assessment_row(creator_id=uuid.uuid4())
    session = _make_session_returning(row)
    maintainer = _user(tier="maintainer")

    got = await load_assessment_for_read(session, row.id, user=maintainer)
    assert got is row


@pytest.mark.asyncio
async def test_admin_tier_can_read_any_assessment() -> None:
    row = _make_assessment_row(creator_id=uuid.uuid4())
    session = _make_session_returning(row)
    admin = _user(tier="admin")

    got = await load_assessment_for_read(session, row.id, user=admin)
    assert got is row


@pytest.mark.asyncio
async def test_explicit_grant_allows_non_creator_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = _make_assessment_row(creator_id=uuid.uuid4(), tlp="tlp:amber")
    session = _make_session_returning(row)
    user = _user(clearance="tlp:amber")

    _patch_grant(monkeypatch, allow=True)
    got = await load_assessment_for_read(session, row.id, user=user)
    assert got is row


@pytest.mark.asyncio
async def test_non_creator_without_grant_is_404_regardless_of_tlp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assessments are private workspaces — tlp:clear does NOT make them
    readable to other authenticated users. Only the creator, an elevated
    tier, or an explicit grant opens the assessment to a non-creator.
    """
    _patch_grant(monkeypatch, allow=False)

    for tlp_value in ("tlp:clear", "tlp:green", "tlp:amber", "tlp:red"):
        row = _make_assessment_row(creator_id=uuid.uuid4(), tlp=tlp_value)
        session = _make_session_returning(row)
        with pytest.raises(AssessmentNotFoundError):
            await load_assessment_for_read(
                session, row.id, user=_user(clearance=tlp_value)
            )


@pytest.mark.asyncio
async def test_filter_excludes_unauthorized_assessments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_grant(monkeypatch, allow=False)
    creator_id = uuid.uuid4()
    user = _user(user_id=creator_id)
    mine = _make_assessment_row(creator_id=creator_id)
    theirs = _make_assessment_row(creator_id=uuid.uuid4())
    session = MagicMock()

    visible = await filter_assessments_for_user(
        session, [mine, theirs], user=user
    )
    assert visible == [mine]


# ---------------------------------------------------------------------------
# Router-level integration tests — real access helper, fake DB session
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _deny_grants(monkeypatch: pytest.MonkeyPatch) -> None:
    """Router-level tests default to "no grants exist" so the only path
    that opens a non-creator request is the elevated tier check. Tests
    that want to allow a grant patch this themselves.

    Without this fixture the lazy ``has_explicit_grant`` import in
    access.py would hit the real implementation, which tries to read
    from the fake MagicMock session and returns truthy by accident.
    """

    async def _no(session, user_id, entity_id):  # noqa: ANN001
        return False

    monkeypatch.setattr("fragchain.security.tlp.has_explicit_grant", _no)


def _build_app(
    user: Any,
    asmt_row: Any | None,
) -> FastAPI:
    """Build a test app whose DB session returns ``asmt_row`` from any
    CoverageAssessment fetch. ``user`` is injected as the authenticated
    caller.
    """
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    session = _make_session_returning(asmt_row)

    async def _db() -> Any:
        yield session

    async def _auth() -> Any:
        return user

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[require_authenticated] = _auth
    return app


def test_unauthenticated_get_returns_401() -> None:
    """Sanity baseline: no auth header → 401, not 200, not 404."""
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get(f"/api/v1/assessments/{uuid.uuid4()}")
    assert resp.status_code == 401


def test_non_owner_get_returns_404() -> None:
    creator_id = uuid.uuid4()
    other = _user()  # different user_id
    row = _make_assessment_row(creator_id=creator_id)
    app = _build_app(other, row)

    client = TestClient(app)
    resp = client.get(f"/api/v1/assessments/{row.id}")
    assert resp.status_code == 404


def test_creator_get_returns_200() -> None:
    creator_id = uuid.uuid4()
    creator = _user(user_id=creator_id)
    row = _make_assessment_row(creator_id=creator_id)
    app = _build_app(creator, row)

    client = TestClient(app)
    resp = client.get(f"/api/v1/assessments/{row.id}")
    assert resp.status_code == 200


def test_non_owner_close_returns_404() -> None:
    row = _make_assessment_row(creator_id=uuid.uuid4())
    other = _user()
    app = _build_app(other, row)

    client = TestClient(app)
    resp = client.post(
        f"/api/v1/assessments/{row.id}/close", json={}
    )
    assert resp.status_code == 404


def test_non_owner_add_source_returns_404() -> None:
    row = _make_assessment_row(creator_id=uuid.uuid4())
    other = _user()
    app = _build_app(other, row)

    client = TestClient(app)
    resp = client.post(
        f"/api/v1/assessments/{row.id}/sources",
        json={"kind": "free_text", "content": "evil"},
    )
    assert resp.status_code == 404


def test_non_owner_list_sources_returns_404() -> None:
    row = _make_assessment_row(creator_id=uuid.uuid4())
    other = _user()
    app = _build_app(other, row)

    client = TestClient(app)
    resp = client.get(f"/api/v1/assessments/{row.id}/sources")
    assert resp.status_code == 404


def test_non_owner_delete_source_returns_404() -> None:
    row = _make_assessment_row(creator_id=uuid.uuid4())
    other = _user()
    app = _build_app(other, row)

    client = TestClient(app)
    resp = client.request(
        "DELETE",
        f"/api/v1/assessments/{row.id}/sources/{uuid.uuid4()}",
        json={"rationale": "test"},
    )
    assert resp.status_code == 404


def test_non_owner_run_loop_returns_404() -> None:
    row = _make_assessment_row(creator_id=uuid.uuid4())
    other = _user()
    app = _build_app(other, row)

    client = TestClient(app)
    resp = client.post(
        f"/api/v1/assessments/{row.id}/loops/1/run", json={}
    )
    assert resp.status_code == 404


def test_non_owner_list_loop_versions_returns_404() -> None:
    row = _make_assessment_row(creator_id=uuid.uuid4())
    other = _user()
    app = _build_app(other, row)

    client = TestClient(app)
    resp = client.get(f"/api/v1/assessments/{row.id}/loops/1")
    assert resp.status_code == 404


def test_non_owner_use_existing_chain_returns_404() -> None:
    row = _make_assessment_row(creator_id=uuid.uuid4())
    other = _user()
    app = _build_app(other, row)

    client = TestClient(app)
    resp = client.post(
        f"/api/v1/assessments/{row.id}/use-existing-chain",
        json={"chain_id": str(uuid.uuid4())},
    )
    assert resp.status_code == 404


def test_list_endpoint_filters_unauthorized_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The list endpoint must call the per-row filter so an analyst can't
    enumerate other analysts' assessments.

    The service is stubbed to return two rows (mine + theirs) and we
    confirm only mine is in the response. The real filter logic is
    exercised in ``test_filter_excludes_unauthorized_assessments``; this
    test verifies the router wires it in correctly.
    """
    creator = _user()
    mine = _make_assessment_row(creator_id=creator.id, tlp="tlp:clear")
    theirs = _make_assessment_row(creator_id=uuid.uuid4(), tlp="tlp:clear")
    app = _build_app(creator, mine)

    from datetime import datetime, timezone

    for row in (mine, theirs):
        row.initial_trigger = {"kind": "cve_id", "value": "CVE-2026-1"}
        row.context_note = None
        row.state = "created"
        row.completed_at = None
        row.created_at = datetime.now(tz=timezone.utc)
        row.updated_at = row.created_at

    async def _list(**kwargs: Any) -> list[Any]:  # noqa: ARG001
        return [mine, theirs]

    monkeypatch.setattr(
        router_mod,
        "_assessment_service_factory",
        lambda s: MagicMock(list=AsyncMock(side_effect=_list)),
    )

    async def _grant_no(session, user_id, entity_id):  # noqa: ANN001
        return False

    monkeypatch.setattr(
        "fragchain.security.tlp.has_explicit_grant", _grant_no
    )

    client = TestClient(app)
    resp = client.get("/api/v1/assessments")
    assert resp.status_code == 200
    body = resp.json()
    returned_ids = {entry["id"] for entry in body}
    assert str(mine.id) in returned_ids
    assert str(theirs.id) not in returned_ids
