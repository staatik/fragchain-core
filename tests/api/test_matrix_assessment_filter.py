"""Smoke tests for GET /api/v1/matrix with assessment_id filter.

Also covers F-009 / SAST S-003: when ``?assessment_id=<uuid>`` is passed,
the caller must have read access to that assessment before MatrixCache is
consulted. Unauthorized callers get an empty matrix (the dict still has
the requested filter values but no per-technique coverage) — both to
preserve the endpoint's dict-shape contract AND to avoid existence
enumeration via 404 timing.
"""
from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fragchain.api.middleware.tlp_filter import require_authenticated
from fragchain.api.routers.coverage import router
from fragchain.coverage.matrix import MatrixFilters
from fragchain.db.session import get_db


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app() -> FastAPI:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def _fake_db() -> Any:
        yield None

    async def _fake_user() -> Any:
        return MagicMock(
            username="analyst@example.com",
            id=uuid.uuid4(),
            tier="authenticated",
            clearance_level="tlp:green",
        )

    app.dependency_overrides[get_db] = _fake_db
    app.dependency_overrides[require_authenticated] = _fake_user
    return app


def _set_user(
    app: FastAPI,
    *,
    user_id: uuid.UUID,
    tier: str = "authenticated",
    clearance: str = "tlp:green",
) -> MagicMock:
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


def _override_access_load(
    monkeypatch: pytest.MonkeyPatch,
    *,
    raises: bool,
):
    """Replace ``load_assessment_for_read`` as imported into the coverage router."""
    from fragchain.assessments.service import AssessmentNotFoundError

    calls: list[uuid.UUID] = []

    async def _loader(db: Any, assessment_id: uuid.UUID, *, user: Any) -> Any:  # noqa: ANN001
        calls.append(assessment_id)
        if raises:
            raise AssessmentNotFoundError(str(assessment_id))
        row = MagicMock()
        row.id = assessment_id
        row.creator_id = user.id
        return row

    monkeypatch.setattr(
        "fragchain.api.routers.coverage.load_assessment_for_read",
        _loader,
    )
    return calls


def _override_session(app: FastAPI, session: Any) -> None:
    async def _gen() -> Any:
        yield session

    app.dependency_overrides[get_db] = _gen


def test_get_matrix_forwards_assessment_id_to_filter(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """assessment_id query param flows into MatrixFilters and through to MatrixCache.

    Assumes the caller has access — the cross-tenant block is covered
    by ``test_matrix_cross_tenant_assessment_id_returns_empty`` below.
    """
    session = AsyncMock()
    target_asmt = uuid.uuid4()
    _override_access_load(monkeypatch, raises=False)  # F-009: access granted

    captured: dict[str, Any] = {}

    async def fake_get_matrix_data(_db: Any, filters: MatrixFilters) -> Any:
        captured["assessment_id"] = filters.assessment_id
        captured["framework"] = filters.framework
        data = MagicMock()
        data.to_dict.return_value = {
            "data": "ok",
            "filters_applied": {
                "framework": filters.framework,
                "assessment_id": (
                    str(filters.assessment_id) if filters.assessment_id else None
                ),
            },
        }
        return data

    with patch(
        "fragchain.api.routers.coverage.MatrixCache",
    ) as cache_cls:
        cache_inst = MagicMock()
        cache_inst.get_matrix_data = AsyncMock(side_effect=fake_get_matrix_data)
        cache_inst.close = AsyncMock()
        cache_cls.return_value = cache_inst

        _override_session(app, session)
        client = TestClient(app)
        resp = client.get(f"/api/v1/matrix?assessment_id={target_asmt}")

    assert resp.status_code == 200, resp.text
    assert captured["assessment_id"] == target_asmt
    body = resp.json()
    assert body["filters_applied"]["assessment_id"] == str(target_asmt)


def test_get_matrix_without_assessment_id_filter(app: FastAPI) -> None:
    """assessment_id is None when query param absent → no narrowing."""
    session = AsyncMock()

    captured: dict[str, Any] = {}

    async def fake_get_matrix_data(_db: Any, filters: MatrixFilters) -> Any:
        captured["assessment_id"] = filters.assessment_id
        data = MagicMock()
        data.to_dict.return_value = {"data": "ok"}
        return data

    with patch(
        "fragchain.api.routers.coverage.MatrixCache",
    ) as cache_cls:
        cache_inst = MagicMock()
        cache_inst.get_matrix_data = AsyncMock(side_effect=fake_get_matrix_data)
        cache_inst.close = AsyncMock()
        cache_cls.return_value = cache_inst

        _override_session(app, session)
        client = TestClient(app)
        resp = client.get("/api/v1/matrix")

    assert resp.status_code == 200
    assert captured["assessment_id"] is None


# ---------------------------------------------------------------------------
# F-009 / SAST S-003: cross-tenant matrix-filter access control
# ---------------------------------------------------------------------------


def test_matrix_cross_tenant_assessment_id_returns_empty(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SAST S-003: an authenticated user supplying another user's
    assessment_id receives an empty matrix — MatrixCache must NOT be
    consulted, so technique-gap shape isn't leaked.
    """
    other_user_assessment = uuid.uuid4()
    _set_user(app, user_id=uuid.uuid4())
    calls = _override_access_load(monkeypatch, raises=True)

    cache_cls = MagicMock()
    cache_inst = MagicMock()
    cache_inst.get_matrix_data = AsyncMock()  # would-not-be-called
    cache_inst.close = AsyncMock()
    cache_cls.return_value = cache_inst

    with patch("fragchain.api.routers.coverage.MatrixCache", cache_cls):
        _override_session(app, AsyncMock())
        client = TestClient(app)
        resp = client.get(
            f"/api/v1/matrix?assessment_id={other_user_assessment}",
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Empty-matrix contract: keep filter values present, no coverage data.
    assert body.get("techniques", []) == []
    assert body.get("total_techniques", 0) == 0
    cache_inst.get_matrix_data.assert_not_awaited()
    assert calls == [other_user_assessment]


def test_matrix_owner_can_filter_by_own_assessment_id(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The assessment owner still gets the full filtered matrix."""
    owner_id = uuid.uuid4()
    own_assessment = uuid.uuid4()
    _set_user(app, user_id=owner_id)
    _override_access_load(monkeypatch, raises=False)

    captured: dict[str, Any] = {}

    async def fake_get_matrix_data(_db: Any, filters: MatrixFilters) -> Any:
        captured["assessment_id"] = filters.assessment_id
        data = MagicMock()
        data.to_dict.return_value = {"data": "ok"}
        return data

    cache_cls = MagicMock()
    cache_inst = MagicMock()
    cache_inst.get_matrix_data = AsyncMock(side_effect=fake_get_matrix_data)
    cache_inst.close = AsyncMock()
    cache_cls.return_value = cache_inst

    with patch("fragchain.api.routers.coverage.MatrixCache", cache_cls):
        _override_session(app, AsyncMock())
        client = TestClient(app)
        resp = client.get(
            f"/api/v1/matrix?assessment_id={own_assessment}",
        )

    assert resp.status_code == 200, resp.text
    assert captured["assessment_id"] == own_assessment


def test_matrix_maintainer_can_filter_by_any_assessment_id(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Maintainers bypass the creator check."""
    _set_user(app, user_id=uuid.uuid4(), tier="maintainer")
    _override_access_load(monkeypatch, raises=False)
    other_assessment = uuid.uuid4()

    cache_cls = MagicMock()
    cache_inst = MagicMock()
    cache_inst.get_matrix_data = AsyncMock(
        return_value=MagicMock(to_dict=MagicMock(return_value={"data": "ok"}))
    )
    cache_inst.close = AsyncMock()
    cache_cls.return_value = cache_inst

    with patch("fragchain.api.routers.coverage.MatrixCache", cache_cls):
        _override_session(app, AsyncMock())
        client = TestClient(app)
        resp = client.get(
            f"/api/v1/matrix?assessment_id={other_assessment}",
        )

    assert resp.status_code == 200
    cache_inst.get_matrix_data.assert_awaited_once()


def test_matrix_no_assessment_id_skips_access_check(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without ``?assessment_id``, no access check runs — the unfiltered
    matrix call is unchanged.
    """
    _set_user(app, user_id=uuid.uuid4())
    calls = _override_access_load(monkeypatch, raises=True)  # would-fail-if-called

    cache_cls = MagicMock()
    cache_inst = MagicMock()
    cache_inst.get_matrix_data = AsyncMock(
        return_value=MagicMock(to_dict=MagicMock(return_value={"data": "ok"}))
    )
    cache_inst.close = AsyncMock()
    cache_cls.return_value = cache_inst

    with patch("fragchain.api.routers.coverage.MatrixCache", cache_cls):
        _override_session(app, AsyncMock())
        client = TestClient(app)
        resp = client.get("/api/v1/matrix")

    assert resp.status_code == 200
    assert calls == []
    cache_inst.get_matrix_data.assert_awaited_once()


def test_matrix_unknown_assessment_id_returns_empty(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Random / non-existent assessment_id is indistinguishable from
    'exists but not yours' — both return empty matrix.
    """
    _set_user(app, user_id=uuid.uuid4())
    _override_access_load(monkeypatch, raises=True)

    cache_cls = MagicMock()
    cache_inst = MagicMock()
    cache_inst.get_matrix_data = AsyncMock()
    cache_inst.close = AsyncMock()
    cache_cls.return_value = cache_inst

    with patch("fragchain.api.routers.coverage.MatrixCache", cache_cls):
        _override_session(app, AsyncMock())
        client = TestClient(app)
        resp = client.get(f"/api/v1/matrix?assessment_id={uuid.uuid4()}")

    assert resp.status_code == 200
    cache_inst.get_matrix_data.assert_not_awaited()
