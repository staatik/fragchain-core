"""Router smoke tests for /api/v1/coverage/benchmarks/runs (Phase A §3.2)."""
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
from fragchain.api.routers.coverage_benchmarks import router
from fragchain.db.session import get_db


def _fake_user() -> Any:
    return MagicMock(
        username="maintainer@example.com",
        id=uuid.uuid4(),
        tier="maintainer",
        is_anonymous=False,
    )


@pytest.fixture
def app() -> FastAPI:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    # The router carries `require_authenticated` / `require_maintainer`
    # dependencies on every endpoint (anonymous LLM spend was a HIGH audit
    # finding). Tests that assert the happy path override them with a fake
    # maintainer user; the anonymous-rejection test uses a bare app without
    # these overrides.
    app.dependency_overrides[require_authenticated] = _fake_user
    app.dependency_overrides[require_maintainer] = _fake_user
    return app


def _override_session(app: FastAPI, session: Any) -> None:
    async def _gen() -> Any:
        yield session

    app.dependency_overrides[get_db] = _gen


def _fake_run_row(run_id: uuid.UUID, run_label: str = "phase-a") -> MagicMock:
    started = datetime.now(tz=timezone.utc)
    return MagicMock(
        id=run_id,
        run_label=run_label,
        started_at=started,
        completed_at=started,
        total_pairs=2,
        true_positives=1,
        false_positives=0,
        true_negatives=1,
        false_negatives=0,
        precision_score=1.0,
        recall_score=1.0,
        f1_score=1.0,
        notes="unit test",
    )


def test_post_runs_triggers_benchmark_and_returns_detail(app: FastAPI) -> None:
    session = MagicMock()
    run_id = uuid.uuid4()
    row = _fake_run_row(run_id)

    # Stub session.execute(...) to return the row for the post-write SELECT.
    sel_result = MagicMock()
    sel_result.scalar_one.return_value = row
    session.execute = AsyncMock(return_value=sel_result)

    fake_benchmark = MagicMock(
        run_id=run_id, run_label="phase-a", total_pairs=2,
        true_positives=1, false_positives=0, true_negatives=1,
        false_negatives=0, precision=1.0, recall=1.0, f1=1.0,
    )

    _override_session(app, session)
    with patch(
        "fragchain.api.routers.coverage_benchmarks.run_benchmark",
        new=AsyncMock(return_value=fake_benchmark),
    ), patch(
        "fragchain.api.routers.coverage_benchmarks.CoverageMapper"
    ):
        client = TestClient(app)
        resp = client.post(
            "/api/v1/coverage/benchmarks/runs",
            json={"run_label": "phase-a", "notes": "unit test"},
        )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["run_label"] == "phase-a"
    assert body["precision"] == 1.0
    assert body["total_pairs"] == 2


def test_get_runs_lists_summary(app: FastAPI) -> None:
    session = MagicMock()
    row_a = _fake_run_row(uuid.uuid4(), run_label="baseline")
    row_b = _fake_run_row(uuid.uuid4(), run_label="phase-a")

    list_result = MagicMock()
    list_scalars = MagicMock()
    list_scalars.all.return_value = [row_b, row_a]
    list_result.scalars.return_value = list_scalars
    session.execute = AsyncMock(return_value=list_result)

    _override_session(app, session)
    client = TestClient(app)
    resp = client.get("/api/v1/coverage/benchmarks/runs")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    labels = [r["run_label"] for r in body]
    assert labels == ["phase-a", "baseline"]


def test_get_run_by_id_returns_detail(app: FastAPI) -> None:
    session = MagicMock()
    run_id = uuid.uuid4()
    row = _fake_run_row(run_id, run_label="phase-a")

    sel_result = MagicMock()
    sel_result.scalar_one_or_none.return_value = row
    session.execute = AsyncMock(return_value=sel_result)

    _override_session(app, session)
    client = TestClient(app)
    resp = client.get(f"/api/v1/coverage/benchmarks/runs/{run_id}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["id"] == str(run_id)
    assert body["true_positives"] == 1
    assert body["notes"] == "unit test"


def test_get_run_by_id_404_when_missing(app: FastAPI) -> None:
    session = MagicMock()
    sel_result = MagicMock()
    sel_result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=sel_result)

    _override_session(app, session)
    client = TestClient(app)
    resp = client.get(f"/api/v1/coverage/benchmarks/runs/{uuid.uuid4()}")
    assert resp.status_code == 404, resp.text


def test_anonymous_post_runs_returns_401() -> None:
    """Regression for the HIGH audit finding: the cost-bearing POST must
    reject anonymous callers. No middleware is mounted on this bare app, so
    `require_maintainer` sees `request.state.user is None` and raises 401.
    """
    bare_app = FastAPI()
    bare_app.include_router(router, prefix="/api/v1")
    client = TestClient(bare_app)
    resp = client.post(
        "/api/v1/coverage/benchmarks/runs",
        json={"run_label": "should-not-run", "notes": "no auth"},
    )
    assert resp.status_code == 401, resp.text


def test_anonymous_get_runs_returns_401() -> None:
    """Read endpoints require authentication too — they list run metadata
    that includes labels and notes operators may consider sensitive."""
    bare_app = FastAPI()
    bare_app.include_router(router, prefix="/api/v1")
    client = TestClient(bare_app)
    resp = client.get("/api/v1/coverage/benchmarks/runs")
    assert resp.status_code == 401, resp.text


