"""Router tests using FastAPI TestClient with overridden DB + auth deps."""
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
from fragchain.db.session import get_db


@pytest.fixture
def actor_id() -> uuid.UUID:
    return uuid.uuid4()


@pytest.fixture(autouse=True)
def _bypass_access_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-002: stub the router's access helpers so happy-path tests don't
    need to seed real CoverageAssessment rows.

    The dedicated tests in ``test_router_access.py`` exercise the real
    access checks. Tests here focus on endpoint plumbing (status codes,
    response shapes), not authorization.
    """

    async def _allow_read(session, assessment_id, *, user):  # noqa: ANN001
        stub = MagicMock()
        stub.id = assessment_id
        stub.creator_id = getattr(user, "id", uuid.uuid4())
        stub.tlp = "tlp:clear"
        return stub

    async def _allow_write(session, assessment_id, *, user):  # noqa: ANN001
        return await _allow_read(session, assessment_id, user=user)

    async def _allow_list(session, rows, *, user):  # noqa: ANN001
        return list(rows)

    monkeypatch.setattr(router_mod, "_load_assessment_for_read", _allow_read)
    monkeypatch.setattr(router_mod, "_load_assessment_for_write", _allow_write)
    monkeypatch.setattr(router_mod, "_filter_assessments_for_user", _allow_list)


@pytest.fixture
def app(actor_id: uuid.UUID) -> FastAPI:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def _fake_db() -> Any:
        # Per-test overrides set the actual session.
        yield None

    async def _fake_user() -> Any:
        return MagicMock(id=actor_id, tier="authenticated", clearance_level="tlp:green")

    app.dependency_overrides[get_db] = _fake_db
    app.dependency_overrides[require_authenticated] = _fake_user
    return app


def _override_session(app: FastAPI, session: Any) -> None:
    async def _gen() -> Any:
        yield session

    app.dependency_overrides[get_db] = _gen


def test_post_assessments_creates_and_returns_201(
    app: FastAPI, actor_id: uuid.UUID
) -> None:
    session = MagicMock()
    # Stub services via monkeypatch on the router module would be heavy;
    # instead simulate via execute/add returning the expected shape.
    # We'll patch the AssessmentService class via dependency override.
    cve_uuid = uuid.uuid4()
    asmt_row = MagicMock()
    asmt_row.id = uuid.uuid4()
    asmt_row.cve_id = cve_uuid
    asmt_row.creator_id = actor_id
    asmt_row.initial_trigger = {"kind": "cve_id", "value": "CVE-2026-1234"}
    asmt_row.context_note = None
    asmt_row.state = "created"
    asmt_row.completed_at = None
    asmt_row.tlp = "tlp:clear"
    from datetime import datetime, timezone
    asmt_row.created_at = datetime.now(tz=timezone.utc)
    asmt_row.updated_at = asmt_row.created_at

    async def _create(req, *, creator_id):  # noqa: ANN001
        return asmt_row

    async def _find(cve_id):  # noqa: ANN001
        return None

    from fragchain.api.routers import assessments as router_mod

    router_mod._assessment_service_factory = lambda s: MagicMock(create=AsyncMock(side_effect=_create))
    router_mod._chain_reuse_factory = lambda s: MagicMock(find_existing_chain=AsyncMock(side_effect=_find))

    _override_session(app, session)
    client = TestClient(app)
    resp = client.post(
        "/api/v1/assessments",
        json={
            "trigger": {"kind": "cve_id", "value": "CVE-2026-1234"},
            "cve_id": str(cve_uuid),
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["assessment"]["cve_id"] == str(cve_uuid)
    assert body["existing_chain"] is None


def test_post_sources_returns_201_and_dispatches_embedding(
    app: FastAPI, actor_id: uuid.UUID
) -> None:
    from fragchain.api.routers import assessments as router_mod

    src_row = MagicMock()
    src_row.id = uuid.uuid4()
    src_row.assessment_id = uuid.uuid4()
    src_row.kind = "free_text"
    src_row.title = None
    src_row.size_bytes = 11
    src_row.content_hash = "a" * 64
    src_row.tlp = "tlp:clear"
    src_row.embedding_status = "pending"
    from datetime import datetime, timezone
    src_row.pasted_at = datetime.now(tz=timezone.utc)

    async def _create(asmt_id, req, *, actor_id):  # noqa: ANN001
        return src_row

    router_mod._source_service_factory = lambda s: MagicMock(create=AsyncMock(side_effect=_create))

    _override_session(app, MagicMock())
    client = TestClient(app)
    resp = client.post(
        f"/api/v1/assessments/{src_row.assessment_id}/sources",
        json={"kind": "free_text", "content": "hello world"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["id"] == str(src_row.id)


def test_post_loops_runs_and_returns_run(app: FastAPI, actor_id: uuid.UUID) -> None:
    from datetime import datetime, timezone

    from fragchain.api.routers import assessments as router_mod

    run_row = MagicMock()
    run_row.id = uuid.uuid4()
    run_row.assessment_id = uuid.uuid4()
    run_row.loop_number = 1
    run_row.version = 1
    run_row.status = "running"
    run_row.is_active = True
    run_row.output = None
    run_row.gate_result = None
    run_row.override_rationale = None
    run_row.embedding_warned = False
    run_row.model = None
    run_row.cost_usd = None
    run_row.latency_ms = None
    run_row.error = None
    run_row.started_at = datetime.now(tz=timezone.utc)
    run_row.completed_at = None

    async def _begin_run(asmt_id, loop, *, override_rationale):  # noqa: ANN001
        return run_row

    router_mod._orchestrator_factory = lambda s: MagicMock(
        begin_run=AsyncMock(side_effect=_begin_run)
    )

    import fragchain.worker.tasks.run_assessment_loop as task_mod

    task_mod.run_assessment_loop = MagicMock()
    task_mod.run_assessment_loop.delay = lambda rid: None

    session = MagicMock()
    session.commit = AsyncMock()
    _override_session(app, session)
    client = TestClient(app)
    resp = client.post(
        f"/api/v1/assessments/{run_row.assessment_id}/loops/1/run",
        json={},
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "running"
    assert body["loop_number"] == 1


def test_post_use_existing_chain_returns_synth_loop1(
    app: FastAPI, actor_id: uuid.UUID
) -> None:
    from fragchain.api.routers import assessments as router_mod

    run_row = MagicMock()
    run_row.id = uuid.uuid4()
    run_row.assessment_id = uuid.uuid4()
    run_row.loop_number = 1
    run_row.version = 1
    run_row.status = "succeeded"
    run_row.is_active = True
    run_row.output = {"kind": "imported_from_chain", "chain_id": str(uuid.uuid4())}
    run_row.gate_result = None
    run_row.override_rationale = None
    run_row.embedding_warned = False
    run_row.model = None
    run_row.cost_usd = 0
    run_row.latency_ms = 0
    run_row.error = None
    from datetime import datetime, timezone
    run_row.started_at = datetime.now(tz=timezone.utc)
    run_row.completed_at = run_row.started_at

    async def _use(asmt_id, chain_id):  # noqa: ANN001
        return run_row

    router_mod._chain_reuse_factory = lambda s: MagicMock(use_as_start=AsyncMock(side_effect=_use))

    _override_session(app, MagicMock())
    client = TestClient(app)
    chain_id = uuid.uuid4()
    resp = client.post(
        f"/api/v1/assessments/{run_row.assessment_id}/use-existing-chain",
        json={"chain_id": str(chain_id)},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["loop_number"] == 1
    assert body["output"]["kind"] == "imported_from_chain"


# ---------------------------------------------------------------------------
# GET /assessments/{id}/detectability (Phase 1, ADR-0004)
# ---------------------------------------------------------------------------


def test_get_detectability_returns_active_classification(app: FastAPI) -> None:
    from datetime import datetime, timezone

    row = MagicMock()
    row.id = uuid.uuid4()
    row.assessment_id = uuid.uuid4()
    row.loop_run_id = uuid.uuid4()
    row.detectability_class = "control_only"
    row.confidence = 0.6
    row.gate_passed = False
    row.payload = {"rationale": "patch instead", "skipped_artifacts": []}
    row.model = "m"
    row.created_at = datetime.now(tz=timezone.utc)

    session = MagicMock()
    execute_result = MagicMock()
    execute_result.scalar_one_or_none.return_value = row
    session.execute = AsyncMock(return_value=execute_result)

    _override_session(app, session)
    client = TestClient(app)
    resp = client.get(f"/api/v1/assessments/{row.assessment_id}/detectability")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["detectability_class"] == "control_only"
    assert body["confidence"] == 0.6
    assert body["gate_passed"] is False
    assert body["payload"]["rationale"] == "patch instead"


def test_get_detectability_404_when_absent(app: FastAPI) -> None:
    session = MagicMock()
    execute_result = MagicMock()
    execute_result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=execute_result)

    _override_session(app, session)
    client = TestClient(app)
    resp = client.get(f"/api/v1/assessments/{uuid.uuid4()}/detectability")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /assessments/{id}/artifact-plan (Phase 2, ADR-0004 §3)
# ---------------------------------------------------------------------------


def test_get_artifact_plan_returns_active_plan(app: FastAPI) -> None:
    from datetime import datetime, timezone

    row = MagicMock()
    row.id = uuid.uuid4()
    row.assessment_id = uuid.uuid4()
    row.detectability_assessment_id = uuid.uuid4()
    row.loop_run_id = uuid.uuid4()
    row.mode = "compatibility"
    row.sigma_planned = False
    row.plan = {
        "recommended": [{"type": "mitigation_plan", "reason": "r", "priority": 1,
                         "prerequisites": []}],
        "skipped": [{"type": "sigma_rule", "reason": "control-only"}],
        "required_inputs": [],
        "confidence": 0.6,
        "policy_version": "v1",
        "policy_adjustments": [],
    }
    row.observed = {"rules_generated": 2, "sigma_generated": True, "diverged": True,
                    "observed_at": "2026-06-09T00:00:00+00:00"}
    row.policy_version = "v1"
    row.created_at = datetime.now(tz=timezone.utc)

    session = MagicMock()
    execute_result = MagicMock()
    execute_result.scalar_one_or_none.return_value = row
    session.execute = AsyncMock(return_value=execute_result)

    _override_session(app, session)
    client = TestClient(app)
    resp = client.get(f"/api/v1/assessments/{row.assessment_id}/artifact-plan")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["sigma_planned"] is False
    assert body["mode"] == "compatibility"
    assert body["plan"]["skipped"][0]["type"] == "sigma_rule"
    assert body["observed"]["diverged"] is True


def test_get_artifact_plan_404_when_absent(app: FastAPI) -> None:
    session = MagicMock()
    execute_result = MagicMock()
    execute_result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=execute_result)

    _override_session(app, session)
    client = TestClient(app)
    resp = client.get(f"/api/v1/assessments/{uuid.uuid4()}/artifact-plan")
    assert resp.status_code == 404


def test_run_loop_dispatches_and_returns_running(app: FastAPI) -> None:
    from datetime import datetime, timezone

    from fragchain.api.routers import assessments as router_mod

    running = MagicMock()
    running.id = uuid.uuid4()
    running.assessment_id = uuid.uuid4()
    running.loop_number = 2
    running.version = 1
    running.status = "running"
    running.is_active = True
    running.output = None
    running.gate_result = None
    running.override_rationale = None
    running.embedding_warned = False
    running.model = None
    running.cost_usd = None
    running.latency_ms = None
    running.error = None
    running.started_at = datetime.now(tz=timezone.utc)
    running.completed_at = None

    orch = MagicMock()
    orch.begin_run = AsyncMock(return_value=running)
    router_mod._orchestrator_factory = lambda s: orch

    dispatched = {}
    import fragchain.worker.tasks.run_assessment_loop as task_mod

    task_mod.run_assessment_loop = MagicMock()
    task_mod.run_assessment_loop.delay = lambda rid: dispatched.setdefault("run_id", rid)

    session = MagicMock()
    session.commit = AsyncMock()
    _override_session(app, session)
    client = TestClient(app)
    resp = client.post(f"/api/v1/assessments/{running.assessment_id}/loops/2/run", json={})
    assert resp.status_code == 202, resp.text
    assert resp.json()["status"] == "running"
    assert dispatched["run_id"] == str(running.id)


def test_run_loop_illegal_transition_409(app: FastAPI) -> None:
    from fragchain.api.routers import assessments as router_mod
    from fragchain.assessments.orchestrator import InvalidLoopTransitionError

    orch = MagicMock()
    orch.begin_run = AsyncMock(side_effect=InvalidLoopTransitionError("nope"))
    router_mod._orchestrator_factory = lambda s: orch

    session = MagicMock()
    session.commit = AsyncMock()
    _override_session(app, session)
    client = TestClient(app)
    resp = client.post(f"/api/v1/assessments/{uuid.uuid4()}/loops/3/run", json={})
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# POST/GET /assessments/{id}/artifacts (Phase 2b)
# ---------------------------------------------------------------------------


def _artifact_row(**over: Any) -> MagicMock:
    from datetime import datetime, timezone

    row = MagicMock()
    row.id = uuid.uuid4()
    row.assessment_id = uuid.uuid4()
    row.artifact_plan_id = None
    row.artifact_type = "mitigation_plan"
    row.version = 1
    row.is_active = True
    row.plan_recommended = False
    row.status = "generating"
    row.validation_status = "not_validated"
    row.content = None
    row.model = None
    row.cost_usd = None
    row.error = None
    row.created_at = datetime.now(tz=timezone.utc)
    row.completed_at = None
    for k, v in over.items():
        setattr(row, k, v)
    return row


def test_post_artifact_dispatches_and_returns_202(app: FastAPI) -> None:
    from fragchain.api.routers import assessments as router_mod

    row = _artifact_row()

    async def _fake_begin(session, *, assessment_id, artifact_type):  # noqa: ANN001
        row.assessment_id = assessment_id
        return row

    router_mod._begin_generation = _fake_begin

    dispatched = {}
    import fragchain.worker.tasks.generate_artifact as task_mod

    task_mod.generate_artifact = MagicMock()
    task_mod.generate_artifact.delay = (
        lambda rid: dispatched.setdefault("artifact_id", rid)
    )

    session = MagicMock()
    session.commit = AsyncMock()
    _override_session(app, session)
    client = TestClient(app)
    resp = client.post(
        f"/api/v1/assessments/{row.assessment_id}/artifacts",
        json={"artifact_type": "mitigation_plan"},
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "generating"
    assert body["artifact_type"] == "mitigation_plan"
    assert dispatched["artifact_id"] == str(row.id)


def test_post_artifact_unknown_type_422(app: FastAPI) -> None:
    session = MagicMock()
    _override_session(app, session)
    client = TestClient(app)
    resp = client.post(
        f"/api/v1/assessments/{uuid.uuid4()}/artifacts",
        json={"artifact_type": "sigma_rule"},
    )
    assert resp.status_code == 422


def test_post_artifact_already_generating_409(app: FastAPI) -> None:
    from fragchain.api.routers import assessments as router_mod
    from fragchain.assessments.artifact_generation import (
        ArtifactAlreadyGeneratingError,
    )

    async def _conflict(session, *, assessment_id, artifact_type):  # noqa: ANN001
        raise ArtifactAlreadyGeneratingError("already generating")

    router_mod._begin_generation = _conflict

    session = MagicMock()
    session.commit = AsyncMock()
    _override_session(app, session)
    client = TestClient(app)
    resp = client.post(
        f"/api/v1/assessments/{uuid.uuid4()}/artifacts",
        json={"artifact_type": "telemetry_contract"},
    )
    assert resp.status_code == 409


def test_get_artifacts_lists_rows(app: FastAPI) -> None:
    asmt_id = uuid.uuid4()
    rows = [
        _artifact_row(assessment_id=asmt_id, status="generated",
                      content={"title": "T", "summary": "S",
                               "sections": [{"heading": "H", "items": ["i"]}],
                               "assumptions": [], "limitations": [],
                               "references": [], "confidence": 0.5}),
        _artifact_row(assessment_id=asmt_id, is_active=False, version=1),
    ]
    result = MagicMock()
    result.scalars.return_value.all.return_value = rows

    session = MagicMock()
    session.execute = AsyncMock(return_value=result)
    _override_session(app, session)
    client = TestClient(app)
    resp = client.get(f"/api/v1/assessments/{asmt_id}/artifacts")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body) == 2
    assert body[0]["content"]["title"] == "T"
    assert body[1]["is_active"] is False


def test_get_artifacts_empty_returns_200_list(app: FastAPI) -> None:
    result = MagicMock()
    result.scalars.return_value.all.return_value = []
    session = MagicMock()
    session.execute = AsyncMock(return_value=result)
    _override_session(app, session)
    client = TestClient(app)
    resp = client.get(f"/api/v1/assessments/{uuid.uuid4()}/artifacts")
    assert resp.status_code == 200
    assert resp.json() == []
