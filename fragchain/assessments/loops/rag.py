"""RAG helper scoped to one assessment's pasted sources."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RagHit:
    point_id: str
    source_id: str
    title: str | None
    score: float
    text: str = ""


class RagSearcher:
    def __init__(
        self,
        *,
        embedder: Any,
        qdrant: Any,
        assessment_id: uuid.UUID,
    ) -> None:
        self._embedder = embedder
        self._qdrant = qdrant
        self._assessment_id = assessment_id

    async def search(self, query: str, *, k: int) -> list[RagHit]:
        vectors = await self._embedder.embed([query])
        if not vectors:
            return []
        response = await self._qdrant.query_points(
            collection_name="source_chunks",
            query=vectors[0],
            limit=k,
            with_payload=True,
            query_filter={
                "must": [
                    {
                        "key": "assessment_id",
                        "match": {"value": str(self._assessment_id)},
                    },
                    {
                        "key": "kind",
                        "match": {"value": "assessment_source"},
                    },
                ]
            },
        )
        hits: list[RagHit] = []
        for hit in response.points:
            payload = getattr(hit, "payload", {}) or {}
            hits.append(
                RagHit(
                    point_id=str(getattr(hit, "id", "")),
                    source_id=str(payload.get("source_id", "")),
                    title=payload.get("title"),
                    score=float(getattr(hit, "score", 0.0)),
                    text=str(payload.get("text", "")),
                )
            )
        return hits
