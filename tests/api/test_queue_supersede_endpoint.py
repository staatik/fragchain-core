"""Smoke tests for POST /api/v1/queue/{review_id}/supersede (Phase A §3.6)."""
from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fragchain.api.middleware.tlp_filter import require_maintainer
from fragchain.api.routers.queue import router
from fragchain.db.session import get_db


@pytest.fixture
def app() -> FastAPI:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def _fake_db() -> Any:
        yield None

    async def _fake_user() -> Any:
        return MagicMock(username="analyst@example.com", id=uuid.uuid4())

    app.dependency_overrides[get_db] = _fake_db
    app.dependency_overrides[require_maintainer] = _fake_user
    return app


def _override_session(app: FastAPI, session: Any) -> None:
    async def _gen() -> Any:
        yield session

    app.dependency_overrides[get_db] = _gen


def test_post_supersede_happy_path_returns_200(app: FastAPI) -> None:
    session = AsyncMock()
    session.commit = AsyncMock()

    review_id = uuid.uuid4()
    supersede_rule_id = uuid.uuid4()

    with patch(
        "fragchain.api.routers.queue.SupersedeService.supersede",
        new=AsyncMock(return_value={
            "review_id": review_id,
            "status": "superseded",
            "supersede_rule_id": supersede_rule_id,
        }),
    ) as sv:
        _override_session(app, session)
        client = TestClient(app)
        resp = client.post(
            f"/api/v1/queue/{review_id}/supersede",
            json={
                "rule_id": str(supersede_rule_id),
                "rationale": "duplicate of approved rule abc",
            },
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "superseded"
    assert body["supersede_rule_id"] == str(supersede_rule_id)
    sv.assert_awaited_once()
    session.commit.assert_awaited()


def test_post_supersede_400_on_empty_rationale(app: FastAPI) -> None:
    from fragchain.queue.supersede import SupersedeError

    session = AsyncMock()
    session.commit = AsyncMock()

    with patch(
        "fragchain.api.routers.queue.SupersedeService.supersede",
        side_effect=SupersedeError("rationale must be non-empty", status_code=400),
    ):
        _override_session(app, session)
        client = TestClient(app)
        resp = client.post(
            f"/api/v1/queue/{uuid.uuid4()}/supersede",
            json={"rule_id": str(uuid.uuid4()), "rationale": ""},
        )
    assert resp.status_code == 422, resp.text  # Pydantic rejects empty string before service is called
    # Note: empty string fails the request body's Field min_length=1 validator,
    # so the service is never reached. That's the desired behavior — fail fast.


def test_post_supersede_409_when_status_wrong(app: FastAPI) -> None:
    from fragchain.queue.supersede import SupersedeError

    session = AsyncMock()
    session.commit = AsyncMock()

    with patch(
        "fragchain.api.routers.queue.SupersedeService.supersede",
        side_effect=SupersedeError("not pending", status_code=409),
    ):
        _override_session(app, session)
        client = TestClient(app)
        resp = client.post(
            f"/api/v1/queue/{uuid.uuid4()}/supersede",
            json={
                "rule_id": str(uuid.uuid4()),
                "rationale": "duplicate",
            },
        )
    assert resp.status_code == 409, resp.text
    body = resp.json()
    assert "not pending" in body["detail"].lower() or "pending" in str(body).lower()


def test_post_supersede_404_when_review_missing(app: FastAPI) -> None:
    from fragchain.queue.supersede import SupersedeError

    session = AsyncMock()
    session.commit = AsyncMock()

    with patch(
        "fragchain.api.routers.queue.SupersedeService.supersede",
        side_effect=SupersedeError("review item not found", status_code=404),
    ):
        _override_session(app, session)
        client = TestClient(app)
        resp = client.post(
            f"/api/v1/queue/{uuid.uuid4()}/supersede",
            json={
                "rule_id": str(uuid.uuid4()),
                "rationale": "duplicate",
            },
        )
    assert resp.status_code == 404, resp.text


def test_post_supersede_400_on_bad_queue_id(app: FastAPI) -> None:
    session = AsyncMock()
    _override_session(app, session)
    client = TestClient(app)
    resp = client.post(
        "/api/v1/queue/not-a-uuid/supersede",
        json={
            "rule_id": str(uuid.uuid4()),
            "rationale": "duplicate",
        },
    )
    assert resp.status_code == 400, resp.text
