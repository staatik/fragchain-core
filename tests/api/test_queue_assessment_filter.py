"""Smoke tests for GET /api/v1/queue with assessment_id filter + new fields.

Also covers the F-009 / SAST S-001 cross-tenant access fix: any caller that
supplies ``?assessment_id=<uuid>`` must have read access to that assessment
(creator, elevated tier, or explicit grant) before the manager runs the
filter. Unauthorized callers receive an empty list — not 404 — so the
endpoint's list-shape contract is preserved AND existence is not disclosed
(the same response is returned for "doesn't exist" and "exists but not
yours").
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fragchain.api.middleware.tlp_filter import (
    require_authenticated,
    require_maintainer,
)
from fragchain.api.routers.queue import router
from fragchain.db.session import get_db
from fragchain.queue.manager import QueueItemView


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


_GLOBAL_USER_ID = uuid.uuid4()  # stable per-test fixture user; overridden per case.


@pytest.fixture
def app() -> FastAPI:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def _fake_db() -> Any:
        yield None

    async def _fake_user() -> Any:
        return MagicMock(
            username="analyst@example.com",
            id=_GLOBAL_USER_ID,
            tier="authenticated",
            clearance_level="tlp:green",
        )

    app.dependency_overrides[get_db] = _fake_db
    app.dependency_overrides[require_authenticated] = _fake_user
    app.dependency_overrides[require_maintainer] = _fake_user
    return app


def _set_user(
    app: FastAPI,
    *,
    user_id: uuid.UUID,
    tier: str = "authenticated",
    clearance: str = "tlp:green",
) -> MagicMock:
    """Override the require_authenticated dependency with a specific identity."""
    user = MagicMock(
        username="analyst@example.com",
        id=user_id,
        tier=tier,
        clearance_level=clearance,
    )

    async def _user_dep() -> Any:
        return user

    app.dependency_overrides[require_authenticated] = _user_dep
    return user


def _patch_assessment_row(
    *,
    creator_id: uuid.UUID,
    assessment_id: uuid.UUID,
    tlp: str = "tlp:clear",
) -> Any:
    """Build a CoverageAssessment-shaped mock that the access helper accepts."""
    row = MagicMock()
    row.id = assessment_id
    row.creator_id = creator_id
    row.tlp = tlp
    row.embargo_until = None
    return row


def _override_access_load(
    monkeypatch: pytest.MonkeyPatch,
    *,
    raises: bool,
):
    """Replace ``load_assessment_for_read`` as imported into the queue router."""
    from fragchain.assessments.service import AssessmentNotFoundError

    calls: list[uuid.UUID] = []

    async def _loader(db: Any, assessment_id: uuid.UUID, *, user: Any) -> Any:  # noqa: ANN001
        calls.append(assessment_id)
        if raises:
            raise AssessmentNotFoundError(str(assessment_id))
        return _patch_assessment_row(
            creator_id=user.id,
            assessment_id=assessment_id,
        )

    # Patch at the queue router's import site so the dependency-injected helper
    # is what we control.
    monkeypatch.setattr(
        "fragchain.api.routers.queue.load_assessment_for_read",
        _loader,
    )
    return calls


def _override_session(app: FastAPI, session: Any) -> None:
    async def _gen() -> Any:
        yield session

    app.dependency_overrides[get_db] = _gen


def _view(
    *,
    assessment_id: uuid.UUID | None,
    low_detectability_override: bool = False,
    superseded_by_assessment_id: uuid.UUID | None = None,
) -> QueueItemView:
    return QueueItemView(
        id=uuid.uuid4(),
        sigma_rule_id=uuid.uuid4(),
        priority="medium",
        priority_score=50,
        priority_reason=None,
        assigned_to=None,
        status="pending",
        created_at=datetime.now(tz=timezone.utc),
        completed_at=None,
        title="r1",
        rule_status="generated",
        origin="fragchain",
        technique_ids=["T1059"],
        logsource_profile="linux-auditd",
        detection_level="high",
        tlp="tlp:clear",
        cve_id=uuid.uuid4(),
        cve_textual_id="CVE-2026-43284",
        chain_id=uuid.uuid4(),
        review_notes=None,
        git_pr_url=None,
        assessment_id=assessment_id,
        low_detectability_override=low_detectability_override,
        superseded_by_assessment_id=superseded_by_assessment_id,
    )


def test_get_queue_filters_by_assessment_id(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Filter-passthrough test — assumes access is granted (the
    cross-tenant block is tested below in
    ``test_queue_cross_tenant_assessment_id_returns_empty``)."""
    session = AsyncMock()
    target_asmt = uuid.uuid4()
    matching_view = _view(assessment_id=target_asmt)
    _override_access_load(monkeypatch, raises=False)  # F-009: caller has access

    with patch(
        "fragchain.api.routers.queue.QueueManager.list_items",
        new=AsyncMock(return_value=[matching_view]),
    ) as li, patch(
        "fragchain.api.routers.queue._filter_visible_views",
        new=AsyncMock(side_effect=lambda req, db, views: views),
    ):
        _override_session(app, session)
        client = TestClient(app)
        resp = client.get(
            f"/api/v1/queue?assessment_id={target_asmt}",
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["assessment_id"] == str(target_asmt)
    # Verify the manager call received the filter.
    li.assert_awaited_once()
    kwargs = li.await_args.kwargs
    assert kwargs.get("assessment_id") == target_asmt


def test_get_queue_response_includes_new_fields(app: FastAPI) -> None:
    session = AsyncMock()
    asmt = uuid.uuid4()
    superseded_by = uuid.uuid4()
    view = _view(
        assessment_id=asmt,
        low_detectability_override=True,
        superseded_by_assessment_id=superseded_by,
    )

    with patch(
        "fragchain.api.routers.queue.QueueManager.list_items",
        new=AsyncMock(return_value=[view]),
    ), patch(
        "fragchain.api.routers.queue._filter_visible_views",
        new=AsyncMock(side_effect=lambda req, db, views: views),
    ):
        _override_session(app, session)
        client = TestClient(app)
        resp = client.get("/api/v1/queue")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    item = body["items"][0]
    assert item["assessment_id"] == str(asmt)
    assert item["low_detectability_override"] is True
    assert item["superseded_by_assessment_id"] == str(superseded_by)


# ---------------------------------------------------------------------------
# F-009 / SAST S-001: cross-tenant assessment_id access control
# ---------------------------------------------------------------------------


def test_queue_cross_tenant_assessment_id_returns_empty(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SAST S-001: an authenticated user supplying another user's
    assessment_id receives an empty list — and the manager is never
    invoked, so no enumeration happens.
    """
    other_user_assessment = uuid.uuid4()
    _set_user(app, user_id=uuid.uuid4())  # Caller is NOT the assessment owner.
    calls = _override_access_load(monkeypatch, raises=True)

    list_items = AsyncMock()  # Should NEVER be awaited.
    with patch(
        "fragchain.api.routers.queue.QueueManager.list_items",
        new=list_items,
    ), patch(
        "fragchain.api.routers.queue._filter_visible_views",
        new=AsyncMock(side_effect=lambda req, db, views: views),
    ):
        _override_session(app, AsyncMock())
        client = TestClient(app)
        resp = client.get(
            f"/api/v1/queue?assessment_id={other_user_assessment}",
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body == {"total": 0, "items": []}
    list_items.assert_not_awaited()
    # Access predicate was consulted exactly once with the supplied UUID.
    assert calls == [other_user_assessment]


def test_queue_owner_can_filter_by_own_assessment_id(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The assessment owner still gets the normal filtered list."""
    owner_id = uuid.uuid4()
    own_assessment = uuid.uuid4()
    _set_user(app, user_id=owner_id)
    _override_access_load(monkeypatch, raises=False)

    view = _view(assessment_id=own_assessment)
    with patch(
        "fragchain.api.routers.queue.QueueManager.list_items",
        new=AsyncMock(return_value=[view]),
    ) as li, patch(
        "fragchain.api.routers.queue._filter_visible_views",
        new=AsyncMock(side_effect=lambda req, db, views: views),
    ):
        _override_session(app, AsyncMock())
        client = TestClient(app)
        resp = client.get(
            f"/api/v1/queue?assessment_id={own_assessment}",
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 1
    li.assert_awaited_once()
    assert li.await_args.kwargs.get("assessment_id") == own_assessment


def test_queue_maintainer_can_filter_by_any_assessment_id(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Maintainers bypass the creator check (matches F-002 semantics)."""
    _set_user(app, user_id=uuid.uuid4(), tier="maintainer")
    _override_access_load(monkeypatch, raises=False)
    other_assessment = uuid.uuid4()

    view = _view(assessment_id=other_assessment)
    with patch(
        "fragchain.api.routers.queue.QueueManager.list_items",
        new=AsyncMock(return_value=[view]),
    ) as li, patch(
        "fragchain.api.routers.queue._filter_visible_views",
        new=AsyncMock(side_effect=lambda req, db, views: views),
    ):
        _override_session(app, AsyncMock())
        client = TestClient(app)
        resp = client.get(
            f"/api/v1/queue?assessment_id={other_assessment}",
        )

    assert resp.status_code == 200
    li.assert_awaited_once()


def test_queue_no_assessment_id_skips_access_check(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without ``?assessment_id``, no access check is performed — the
    endpoint's broad listing behaviour is unchanged.
    """
    _set_user(app, user_id=uuid.uuid4())
    calls = _override_access_load(monkeypatch, raises=True)  # would fail if called

    view = _view(assessment_id=None)
    with patch(
        "fragchain.api.routers.queue.QueueManager.list_items",
        new=AsyncMock(return_value=[view]),
    ), patch(
        "fragchain.api.routers.queue._filter_visible_views",
        new=AsyncMock(side_effect=lambda req, db, views: views),
    ):
        _override_session(app, AsyncMock())
        client = TestClient(app)
        resp = client.get("/api/v1/queue")

    assert resp.status_code == 200
    assert calls == []  # access helper never consulted


def test_queue_unknown_assessment_id_returns_empty(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Random / non-existent assessment_id is indistinguishable from
    'exists but not yours' — both return empty list, manager untouched.
    """
    _set_user(app, user_id=uuid.uuid4())
    _override_access_load(monkeypatch, raises=True)  # missing rows raise too

    list_items = AsyncMock()
    with patch(
        "fragchain.api.routers.queue.QueueManager.list_items",
        new=list_items,
    ), patch(
        "fragchain.api.routers.queue._filter_visible_views",
        new=AsyncMock(side_effect=lambda req, db, views: views),
    ):
        _override_session(app, AsyncMock())
        client = TestClient(app)
        resp = client.get(f"/api/v1/queue?assessment_id={uuid.uuid4()}")

    assert resp.status_code == 200
    assert resp.json() == {"total": 0, "items": []}
    list_items.assert_not_awaited()
