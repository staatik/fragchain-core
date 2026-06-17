"""Embedding task tests — mocks the embedder + Qdrant + DB session."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fragchain.worker.tasks.embed_assessment_source import _run
from fragchain.db.models import AssessmentSource


@pytest.fixture
def src() -> AssessmentSource:
    return AssessmentSource(
        id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        kind="free_text",
        content="some text to embed",
        content_hash="a" * 64,
        size_bytes=18,
        pasted_by=uuid.uuid4(),
        embedding_status="pending",
    )


@pytest.mark.asyncio
async def test_run_embeds_and_marks_embedded(src: AssessmentSource) -> None:
    session = MagicMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    fetch = MagicMock(); fetch.scalar_one_or_none.return_value = src
    session.execute.return_value = fetch

    embedder = AsyncMock()
    embedder.embed.return_value = [[0.1] * 768]

    qdrant = MagicMock()
    qdrant.upsert = AsyncMock()

    with patch(
        "fragchain.worker.tasks.embed_assessment_source._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.embed_assessment_source._get_embedder",
        return_value=embedder,
    ), patch(
        "fragchain.worker.tasks.embed_assessment_source._get_qdrant",
        return_value=qdrant,
    ):
        sm.return_value.__aenter__.return_value = session
        await _run(str(src.id))

    assert src.embedding_status == "embedded"
    assert src.embedding_error is None
    qdrant.upsert.assert_awaited()
    session.commit.assert_awaited()


@pytest.mark.asyncio
async def test_run_stores_chunk_text_in_qdrant_payload(src: AssessmentSource) -> None:
    """Each upserted point must carry its chunk text so Loop 2 RAG can feed
    the source prose to the LLM (F1). Embedding IDs without text is the bug."""
    session = MagicMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    fetch = MagicMock(); fetch.scalar_one_or_none.return_value = src
    session.execute.return_value = fetch

    embedder = AsyncMock()
    embedder.embed.side_effect = lambda texts: [[0.1] * 768 for _ in texts]

    qdrant = MagicMock()
    qdrant.upsert = AsyncMock()

    with patch(
        "fragchain.worker.tasks.embed_assessment_source._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.embed_assessment_source._get_embedder",
        return_value=embedder,
    ), patch(
        "fragchain.worker.tasks.embed_assessment_source._get_qdrant",
        return_value=qdrant,
    ):
        sm.return_value.__aenter__.return_value = session
        await _run(str(src.id))

    points = qdrant.upsert.await_args.kwargs["points"]
    assert len(points) >= 1
    for point in points:
        text = point["payload"].get("text")
        assert text, "every point payload must carry non-empty chunk text"
        assert text in src.content


@pytest.mark.asyncio
async def test_run_marks_failed_on_embedder_error(src: AssessmentSource) -> None:
    session = MagicMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    fetch = MagicMock(); fetch.scalar_one_or_none.return_value = src
    session.execute.return_value = fetch

    embedder = AsyncMock()
    embedder.embed.side_effect = RuntimeError("embedder boom")

    with patch(
        "fragchain.worker.tasks.embed_assessment_source._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.embed_assessment_source._get_embedder",
        return_value=embedder,
    ), patch(
        "fragchain.worker.tasks.embed_assessment_source._get_qdrant",
        return_value=MagicMock(),
    ):
        sm.return_value.__aenter__.return_value = session
        await _run(str(src.id))

    assert src.embedding_status == "failed"
    assert "embedder boom" in (src.embedding_error or "")
    session.commit.assert_awaited()


@pytest.mark.asyncio
async def test_run_publishes_source_embedded_event(monkeypatch, src) -> None:
    session = MagicMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    fetch = MagicMock(); fetch.scalar_one_or_none.return_value = src
    session.execute.return_value = fetch

    embedder = AsyncMock()
    embedder.embed.return_value = [[0.1] * 768]

    qdrant = MagicMock()
    qdrant.upsert = AsyncMock()

    emitted: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "fragchain.worker.tasks.embed_assessment_source.emit_event",
        lambda t, p: emitted.append((t, p)),
    )

    with patch(
        "fragchain.worker.tasks.embed_assessment_source._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.embed_assessment_source._get_embedder",
        return_value=embedder,
    ), patch(
        "fragchain.worker.tasks.embed_assessment_source._get_qdrant",
        return_value=qdrant,
    ):
        sm.return_value.__aenter__.return_value = session
        await _run(str(src.id))

    types = [t for t, _ in emitted]
    assert "assessment.source.embedded" in types
    payload = next(p for t, p in emitted if t == "assessment.source.embedded")
    assert payload["source_id"] == str(src.id)
    assert payload["assessment_id"] == str(src.assessment_id)
    assert payload["status"] == "embedded"


@pytest.mark.asyncio
async def test_run_publishes_failed_status_when_embedder_fails(monkeypatch, src) -> None:
    session = MagicMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    fetch = MagicMock(); fetch.scalar_one_or_none.return_value = src
    session.execute.return_value = fetch

    embedder = AsyncMock()
    embedder.embed.side_effect = RuntimeError("boom")

    emitted: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "fragchain.worker.tasks.embed_assessment_source.emit_event",
        lambda t, p: emitted.append((t, p)),
    )

    with patch(
        "fragchain.worker.tasks.embed_assessment_source._sessionmaker"
    ) as sm, patch(
        "fragchain.worker.tasks.embed_assessment_source._get_embedder",
        return_value=embedder,
    ), patch(
        "fragchain.worker.tasks.embed_assessment_source._get_qdrant",
        return_value=MagicMock(),
    ):
        sm.return_value.__aenter__.return_value = session
        await _run(str(src.id))

    payload = next(p for t, p in emitted if t == "assessment.source.embedded")
    assert payload["status"] == "failed"
