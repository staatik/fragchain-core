"""Unit tests for SupersedeService (Phase A §3.6)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.db.models import AuditLog, CoverageBenchmark
from fragchain.queue.supersede import SupersedeError, SupersedeService


def _queue_row(*, status: str = "pending") -> MagicMock:
    return MagicMock(
        id=uuid.uuid4(),
        sigma_rule_id=uuid.uuid4(),
        status=status,
        completed_at=None,
        supersede_rule_id=None,
        supersede_rationale=None,
    )


def _rule_row(
    *, rid: uuid.UUID | None = None,
    technique_ids: list[str] | None = None,
    chain_id: uuid.UUID | None = None,
    cve_id: uuid.UUID | None = None,
) -> MagicMock:
    return MagicMock(
        id=rid or uuid.uuid4(),
        chain_id=chain_id or uuid.uuid4(),
        cve_id=cve_id or uuid.uuid4(),
        technique_ids=technique_ids or ["T1059"],
    )


def _coverage_row(*, covering: list[uuid.UUID] | None = None) -> MagicMock:
    return MagicMock(covering_rule_ids=covering or [])


def _mk_session_with_dispatch(items: dict[type, Any]) -> AsyncMock:
    """AsyncMock session whose .get(model, key) dispatches by class name."""
    session = AsyncMock()
    async def _get(model: type, key: Any) -> Any:
        return items.get(model.__name__)
    session.get.side_effect = _get
    return session


@pytest.mark.asyncio
async def test_supersede_happy_path_updates_queue_writes_benchmark_and_coverage():
    queue_item = _queue_row(status="pending")
    rule = _rule_row(rid=queue_item.sigma_rule_id)
    existing_rule_id = uuid.uuid4()
    existing_rule = _rule_row(rid=existing_rule_id)
    coverage = _coverage_row(covering=[])

    # session.get(ReviewQueueItem, ...) → queue_item
    # session.get(SigmaRule, queue.sigma_rule_id) → rule
    # session.get(SigmaRule, existing_rule_id) → existing_rule

    session = AsyncMock()
    session.add = MagicMock()  # session.add is sync in SQLAlchemy; avoids RuntimeWarning
    rule_lookup: dict[uuid.UUID, Any] = {
        queue_item.sigma_rule_id: rule,
        existing_rule_id: existing_rule,
    }
    async def _get(model: type, key: Any) -> Any:
        if model.__name__ == "ReviewQueueItem":
            return queue_item
        if model.__name__ == "SigmaRule":
            return rule_lookup.get(key)
        return None
    session.get.side_effect = _get

    # session.execute(...) is hit for the coverage_map lookup (one call per
    # technique). Return the coverage row, then None for any subsequent call.
    cov_result = MagicMock()
    cov_result.scalar_one_or_none.return_value = coverage
    session.execute = AsyncMock(return_value=cov_result)

    svc = SupersedeService(session)
    result = await svc.supersede(
        review_id=queue_item.id,
        supersede_rule_id=existing_rule_id,
        rationale="duplicate of an existing approved rule",
        actor_username="analyst@example.com",
        actor_id=None,
    )

    # Queue closed
    assert queue_item.status == "superseded"
    assert queue_item.supersede_rule_id == existing_rule_id
    assert queue_item.supersede_rationale == "duplicate of an existing approved rule"
    assert queue_item.completed_at is not None

    # Coverage updated — existing_rule_id added to covering
    assert existing_rule_id in coverage.covering_rule_ids

    # session.add called once per technique (CoverageBenchmark) + once for AuditLog
    add_calls = session.add.call_args_list
    # rule.technique_ids has 1 entry → 1 CoverageBenchmark row + 1 AuditLog row
    assert len(add_calls) == 2
    benchmark_rows = [c.args[0] for c in add_calls if isinstance(c.args[0], CoverageBenchmark)]
    assert len(benchmark_rows) == 1
    benchmark_row = benchmark_rows[0]
    assert benchmark_row.cve_id == rule.cve_id
    assert benchmark_row.technique_id == "T1059"
    assert benchmark_row.rule_id == existing_rule_id
    assert benchmark_row.expected_verdict == "covered"
    assert benchmark_row.source == "supersede"
    assert benchmark_row.labeled_by == "analyst@example.com"

    # Returned dict
    assert result["review_id"] == queue_item.id
    assert result["status"] == "superseded"
    assert result["supersede_rule_id"] == existing_rule_id


@pytest.mark.asyncio
async def test_supersede_writes_one_benchmark_row_per_technique_when_rule_has_multiple_tids():
    queue_item = _queue_row()
    rule = _rule_row(
        rid=queue_item.sigma_rule_id, technique_ids=["T1059", "T1078"],
    )
    existing_rule_id = uuid.uuid4()
    existing_rule = _rule_row(rid=existing_rule_id)
    coverage = _coverage_row(covering=[])

    session = AsyncMock()
    session.add = MagicMock()  # session.add is sync in SQLAlchemy; avoids RuntimeWarning
    async def _get(model: type, key: Any) -> Any:
        if model.__name__ == "ReviewQueueItem":
            return queue_item
        if model.__name__ == "SigmaRule":
            return existing_rule if key == existing_rule_id else rule
        return None
    session.get.side_effect = _get

    cov_result = MagicMock()
    cov_result.scalar_one_or_none.return_value = coverage
    session.execute = AsyncMock(return_value=cov_result)

    svc = SupersedeService(session)
    await svc.supersede(
        review_id=queue_item.id,
        supersede_rule_id=existing_rule_id,
        rationale="x",
        actor_username="a@b.c",
        actor_id=None,
    )

    # 2 technique_ids → 2 CoverageBenchmark rows + 1 AuditLog row
    assert len(session.add.call_args_list) == 3
    benchmark_calls = [c for c in session.add.call_args_list if isinstance(c.args[0], CoverageBenchmark)]
    assert len(benchmark_calls) == 2
    tids = {c.args[0].technique_id for c in benchmark_calls}
    assert tids == {"T1059", "T1078"}


@pytest.mark.asyncio
async def test_supersede_writes_audit_log_for_status_transition():
    """Confirms a single AuditLog row is written with correct fields (CLAUDE.md §19)."""
    actor_id = uuid.uuid4()
    queue_item = _queue_row(status="pending")
    rule = _rule_row(rid=queue_item.sigma_rule_id)
    existing_rule_id = uuid.uuid4()
    existing_rule = _rule_row(rid=existing_rule_id)
    coverage = _coverage_row(covering=[])

    session = AsyncMock()
    session.add = MagicMock()  # session.add is sync in SQLAlchemy; avoids RuntimeWarning
    rule_lookup: dict[uuid.UUID, Any] = {
        queue_item.sigma_rule_id: rule,
        existing_rule_id: existing_rule,
    }
    async def _get(model: type, key: Any) -> Any:
        if model.__name__ == "ReviewQueueItem":
            return queue_item
        if model.__name__ == "SigmaRule":
            return rule_lookup.get(key)
        return None
    session.get.side_effect = _get

    cov_result = MagicMock()
    cov_result.scalar_one_or_none.return_value = coverage
    session.execute = AsyncMock(return_value=cov_result)

    svc = SupersedeService(session)
    await svc.supersede(
        review_id=queue_item.id,
        supersede_rule_id=existing_rule_id,
        rationale="duplicate — covered by existing rule",
        actor_username="analyst@example.com",
        actor_id=actor_id,
    )

    # Exactly one AuditLog row must be written
    audit_calls = [c for c in session.add.call_args_list if isinstance(c.args[0], AuditLog)]
    assert len(audit_calls) == 1

    audit_row: AuditLog = audit_calls[0].args[0]
    assert audit_row.entity_id == queue_item.id
    assert "superseded" in audit_row.action
    assert audit_row.before == {"status": "pending"}
    assert audit_row.after["status"] == "superseded"
    assert audit_row.after["supersede_rule_id"] == str(existing_rule_id)
    assert audit_row.actor == actor_id


@pytest.mark.asyncio
async def test_supersede_rejects_unknown_review_item():
    session = AsyncMock()
    async def _get(model: type, key: Any) -> Any:
        return None  # nothing exists
    session.get.side_effect = _get

    svc = SupersedeService(session)
    with pytest.raises(SupersedeError) as exc_info:
        await svc.supersede(
            review_id=uuid.uuid4(),
            supersede_rule_id=uuid.uuid4(),
            rationale="x", actor_username="a", actor_id=None,
        )
    assert "not found" in str(exc_info.value).lower()
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_supersede_rejects_when_queue_item_not_pending():
    queue_item = _queue_row(status="superseded")
    session = AsyncMock()
    async def _get(model: type, key: Any) -> Any:
        if model.__name__ == "ReviewQueueItem":
            return queue_item
        return None
    session.get.side_effect = _get

    svc = SupersedeService(session)
    with pytest.raises(SupersedeError) as exc_info:
        await svc.supersede(
            review_id=queue_item.id,
            supersede_rule_id=uuid.uuid4(),
            rationale="x", actor_username="a", actor_id=None,
        )
    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_supersede_rejects_unknown_existing_rule():
    queue_item = _queue_row()
    queued_rule = _rule_row(rid=queue_item.sigma_rule_id)
    session = AsyncMock()
    async def _get(model: type, key: Any) -> Any:
        if model.__name__ == "ReviewQueueItem":
            return queue_item
        if model.__name__ == "SigmaRule":
            # queued rule resolves; the supersede target does NOT
            return queued_rule if key == queue_item.sigma_rule_id else None
        return None
    session.get.side_effect = _get

    svc = SupersedeService(session)
    with pytest.raises(SupersedeError) as exc_info:
        await svc.supersede(
            review_id=queue_item.id,
            supersede_rule_id=uuid.uuid4(),
            rationale="x", actor_username="a", actor_id=None,
        )
    assert exc_info.value.status_code == 404
    assert "supersede" in str(exc_info.value).lower() or "rule" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_supersede_rejects_empty_rationale():
    svc = SupersedeService(AsyncMock())
    with pytest.raises(SupersedeError) as exc_info:
        await svc.supersede(
            review_id=uuid.uuid4(),
            supersede_rule_id=uuid.uuid4(),
            rationale="   ",
            actor_username="a", actor_id=None,
        )
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_supersede_rejects_oversized_rationale():
    svc = SupersedeService(AsyncMock())
    with pytest.raises(SupersedeError) as exc_info:
        await svc.supersede(
            review_id=uuid.uuid4(),
            supersede_rule_id=uuid.uuid4(),
            rationale="x" * 300,  # > 200 char cap per §3.6
            actor_username="a", actor_id=None,
        )
    assert exc_info.value.status_code == 400
