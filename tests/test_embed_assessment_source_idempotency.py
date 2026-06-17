"""F-013 / SAST S-018 — embed_assessment_source is idempotent on retry.

The Celery task previously re-ran the embedder + overwrote Qdrant on
every invocation. A Redis blip → Celery retry → second LLM embedding
call → operator billed twice for the same source.

The fix short-circuits when the source row is already in
``embedding_status='embedded'`` — no embedder call, no Qdrant write,
no double LLM spend. Status is set AFTER the Qdrant upsert succeeds,
so a crash before the status flip leaves the row in the pending state
and the next retry re-runs (correct behavior — that's the only path
where re-embedding is actually needed).
"""
from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.worker.tasks import embed_assessment_source as task_mod


@pytest.fixture
def src_row() -> MagicMock:
    """Build an AssessmentSource-shaped mock the task can read."""
    row = MagicMock()
    row.id = uuid.uuid4()
    row.assessment_id = uuid.uuid4()
    row.content = "vendor advisory body…"
    row.title = "Vendor advisory"
    row.tlp = "tlp:clear"
    row.embedding_status = "pending"
    row.embedding_error = None
    row.deleted_at = None
    return row


def _wire_session(monkeypatch: pytest.MonkeyPatch, src: Any) -> MagicMock:
    """Replace the task's session context manager so its `select` query
    returns ``src`` and `session.commit` is a mock we can assert on."""
    session = MagicMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = src
    session.execute = AsyncMock(return_value=result)
    session.commit = AsyncMock()

    class _CM:
        async def __aenter__(self) -> Any:
            return session

        async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
            return False

    monkeypatch.setattr(task_mod, "_sessionmaker", lambda: _CM())
    return session


def _wire_embedder_and_qdrant(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[MagicMock, MagicMock]:
    """Replace the embedder + qdrant factories with spies."""
    embedder = MagicMock()
    embedder.embed = AsyncMock(return_value=[[0.1, 0.2, 0.3]])
    qdrant = MagicMock()
    qdrant.upsert = AsyncMock()

    monkeypatch.setattr(task_mod, "_get_embedder", lambda: embedder)
    monkeypatch.setattr(task_mod, "_get_qdrant", lambda: qdrant)
    return embedder, qdrant


@pytest.mark.asyncio
async def test_first_run_embeds_and_marks_status(
    monkeypatch: pytest.MonkeyPatch, src_row: MagicMock
) -> None:
    """Baseline: a freshly-pending source gets embedded + status flips."""
    session = _wire_session(monkeypatch, src_row)
    embedder, qdrant = _wire_embedder_and_qdrant(monkeypatch)

    result = await task_mod._run(str(src_row.id))

    assert result == {"status": "embedded"}
    embedder.embed.assert_awaited_once_with([src_row.content])
    qdrant.upsert.assert_awaited_once()
    assert src_row.embedding_status == "embedded"
    session.commit.assert_awaited()


@pytest.mark.asyncio
async def test_retry_after_successful_embed_is_a_noop(
    monkeypatch: pytest.MonkeyPatch, src_row: MagicMock
) -> None:
    """SAST S-018: a source already in ``embedding_status='embedded'``
    must NOT re-run the embedder. Celery retries on broker hiccups
    cannot double-spend."""
    src_row.embedding_status = "embedded"
    _wire_session(monkeypatch, src_row)
    embedder, qdrant = _wire_embedder_and_qdrant(monkeypatch)

    result = await task_mod._run(str(src_row.id))

    assert result["status"] == "already_embedded"
    embedder.embed.assert_not_awaited()
    qdrant.upsert.assert_not_awaited()


@pytest.mark.asyncio
async def test_retry_after_failed_embed_does_re_run(
    monkeypatch: pytest.MonkeyPatch, src_row: MagicMock
) -> None:
    """A row in ``embedding_status='failed'`` is fair game for retry —
    the previous attempt didn't reach Qdrant. The retry must call the
    embedder so we can recover."""
    src_row.embedding_status = "failed"
    src_row.embedding_error = "previous error"
    _wire_session(monkeypatch, src_row)
    embedder, qdrant = _wire_embedder_and_qdrant(monkeypatch)

    result = await task_mod._run(str(src_row.id))

    assert result == {"status": "embedded"}
    embedder.embed.assert_awaited_once()
    qdrant.upsert.assert_awaited_once()


@pytest.mark.asyncio
async def test_pending_status_retries(
    monkeypatch: pytest.MonkeyPatch, src_row: MagicMock
) -> None:
    """Pending status is the normal first-run case — must NOT short-circuit."""
    src_row.embedding_status = "pending"
    _wire_session(monkeypatch, src_row)
    embedder, qdrant = _wire_embedder_and_qdrant(monkeypatch)

    await task_mod._run(str(src_row.id))

    embedder.embed.assert_awaited_once()


@pytest.mark.asyncio
async def test_missing_source_returns_missing_without_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the source row doesn't exist (e.g., deleted while task in
    flight), the task returns 'missing' without touching the embedder.
    """
    _wire_session(monkeypatch, None)
    embedder, qdrant = _wire_embedder_and_qdrant(monkeypatch)

    result = await task_mod._run(str(uuid.uuid4()))

    assert result["status"] == "missing"
    embedder.embed.assert_not_awaited()


@pytest.mark.asyncio
async def test_deleted_source_skips_embedding(
    monkeypatch: pytest.MonkeyPatch, src_row: MagicMock
) -> None:
    """Soft-deleted sources are skipped (pre-existing behavior — confirms
    no regression from the new idempotency check)."""
    from datetime import datetime, timezone

    src_row.deleted_at = datetime.now(tz=timezone.utc)
    _wire_session(monkeypatch, src_row)
    embedder, qdrant = _wire_embedder_and_qdrant(monkeypatch)

    result = await task_mod._run(str(src_row.id))

    assert result["status"] == "deleted_skip"
    embedder.embed.assert_not_awaited()
