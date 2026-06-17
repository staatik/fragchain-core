from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from qdrant_client import AsyncQdrantClient

from fragchain.assessments.loops.rag import RagSearcher, RagHit


def _qdrant_with_points(points: list) -> AsyncMock:
    """A Qdrant mock spec'd to the real client so a removed API (e.g. the
    1.18-removed ``.search``) raises AttributeError instead of silently
    returning a mock. ``query_points`` returns a response with ``.points``."""
    qdrant = AsyncMock(spec=AsyncQdrantClient)
    qdrant.query_points.return_value = MagicMock(points=points)
    return qdrant


@pytest.mark.asyncio
async def test_rag_search_scopes_by_assessment_id_in_filter():
    embedder = AsyncMock()
    embedder.embed.return_value = [[0.1] * 768]
    qdrant = _qdrant_with_points([
        MagicMock(id="point-1", score=0.9,
                  payload={"assessment_id": "a1", "source_id": "s1",
                           "kind": "assessment_source", "title": "t"}),
    ])

    asmt_id = uuid.uuid4()
    searcher = RagSearcher(
        embedder=embedder, qdrant=qdrant, assessment_id=asmt_id,
    )

    hits = await searcher.search("what process spawns?", k=5)

    qdrant.query_points.assert_awaited_once()
    call_kwargs = qdrant.query_points.await_args.kwargs
    assert call_kwargs["collection_name"] == "source_chunks"
    assert call_kwargs["limit"] == 5
    assert call_kwargs["query_filter"] == {
        "must": [
            {"key": "assessment_id", "match": {"value": str(asmt_id)}},
            {"key": "kind", "match": {"value": "assessment_source"}},
        ]
    }
    assert hits == [
        RagHit(point_id="point-1", source_id="s1", title="t", score=0.9),
    ]


@pytest.mark.asyncio
async def test_rag_search_carries_chunk_text_from_payload():
    embedder = AsyncMock()
    embedder.embed.return_value = [[0.1] * 768]
    qdrant = _qdrant_with_points([
        MagicMock(id="point-1", score=0.9,
                  payload={"assessment_id": "a1", "source_id": "s1",
                           "kind": "assessment_source", "title": "t",
                           "text": "java.exe spawns cmd.exe when ldap:// is fetched"}),
    ])

    searcher = RagSearcher(
        embedder=embedder, qdrant=qdrant, assessment_id=uuid.uuid4(),
    )
    hits = await searcher.search("what process spawns?", k=5)

    assert hits[0].text == "java.exe spawns cmd.exe when ldap:// is fetched"


@pytest.mark.asyncio
async def test_rag_search_returns_empty_when_no_hits():
    embedder = AsyncMock()
    embedder.embed.return_value = [[0.1] * 768]
    qdrant = _qdrant_with_points([])

    searcher = RagSearcher(
        embedder=embedder, qdrant=qdrant, assessment_id=uuid.uuid4(),
    )
    assert await searcher.search("q", k=3) == []
