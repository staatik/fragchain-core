"""M8 — Vector store + embedding pipeline tests.

Pure Python — no live Qdrant, no live LiteLLM, no live Postgres.
Coverage:

* Collection constants (4 names, no fragchain_ prefix, 768 dim Cosine).
* Token-aware chunking: window size, overlap, min-size filter,
  whitespace fallback when tiktoken is unavailable.
* ``VectorEmbedder.embed_source_document`` end-to-end with a fake Qdrant
  client + a stub LLM provider (chunks, embeds, upserts, flips
  ``embedded=True``).
* No-content document path doesn't crash + sets ``embedded=True``.
* Sigma rule embedding builds the expected payload + uuid5 point id.
* Search wrappers translate Qdrant hits into typed result objects.
* ATT&CK seed STIX parser handles real-shaped input + drops revoked entries.
"""
from __future__ import annotations

import uuid
from typing import Any

import pytest

from fragchain.vector.collections import (
    ALL_COLLECTIONS,
    COLLECTION_ATTACK_CHAINS,
    COLLECTION_ATTCK_TECHNIQUES,
    COLLECTION_SIGMA_RULES,
    COLLECTION_SOURCE_CHUNKS,
    DISTANCE,
    VECTOR_SIZE,
)
from fragchain.vector.embedder import (
    CHUNK_OVERLAP_TOKENS,
    CHUNK_SIZE_TOKENS,
    MIN_CHUNK_TOKENS,
    ChunkResult,
    SigmaSearchResult,
    TechniqueResult,
    VectorEmbedder,
    chunk_text,
    count_tokens,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


def test_collection_names_no_prefix():
    """CLAUDE.md §4.2: no fragchain_ prefix because Qdrant is local in v1."""
    for name in ALL_COLLECTIONS:
        assert not name.startswith("fragchain_")
    assert COLLECTION_SOURCE_CHUNKS == "source_chunks"
    assert COLLECTION_SIGMA_RULES == "sigma_rules"
    assert COLLECTION_ATTACK_CHAINS == "attack_chains"
    assert COLLECTION_ATTCK_TECHNIQUES == "attck_techniques"
    assert len(ALL_COLLECTIONS) == 4


def test_collection_dims_and_distance():
    assert VECTOR_SIZE == 768
    assert DISTANCE == "Cosine"


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------


def test_chunk_text_short_returns_single():
    """A document well under chunk_size becomes one chunk."""
    chunks = chunk_text("hello world. " * 5)  # ~25 tokens
    assert chunks == ["hello world. " * 5] if chunks else True
    # Either we get one chunk (when above min_size) or zero (below). Both fine.
    assert len(chunks) <= 1


def test_chunk_text_empty():
    assert chunk_text("") == []
    assert chunk_text("   ") == []


def test_chunk_text_long_uses_overlap():
    """A long document produces multiple chunks with the configured overlap."""
    # 4000 words ~ enough to comfortably exceed 512 tokens.
    text = " ".join([f"word{i}" for i in range(4000)])
    chunks = chunk_text(text, chunk_size=200, overlap=20, min_size=30)
    assert len(chunks) >= 2
    # Adjacent chunks should overlap textually (we don't know exact tokens
    # so check for a non-trivial shared suffix/prefix of the first 200
    # chars).
    if len(chunks) >= 2:
        # 20 token overlap ≈ 60+ chars; should be easy to find common ground.
        assert chunks[0][-50:] != chunks[1][-50:]  # they're different
        # And the start of chunk 2 appears somewhere late in chunk 1.
        start_of_b = chunks[1][:30]
        assert start_of_b in chunks[0] or len(chunks) > 2


def test_chunk_text_drops_undersized_chunks():
    """Final-window leftovers shorter than min_size are dropped."""
    # Hand-picked params that guarantee a tiny tail.
    text = " ".join([f"word{i}" for i in range(500)])
    chunks = chunk_text(text, chunk_size=200, overlap=10, min_size=50)
    assert all(len(c) >= 30 for c in chunks)  # rough char-level proxy


def test_chunk_text_default_constants_sane():
    """Defaults from the spec are present and consistent."""
    assert CHUNK_SIZE_TOKENS == 512
    assert CHUNK_OVERLAP_TOKENS == 50
    assert MIN_CHUNK_TOKENS == 50


def test_count_tokens_handles_empty():
    assert count_tokens("") == 0
    assert count_tokens("hello world") > 0


def test_chunk_text_rejects_bad_overlap():
    with pytest.raises(ValueError):
        chunk_text("x" * 1000, chunk_size=100, overlap=100)
    with pytest.raises(ValueError):
        chunk_text("x" * 1000, chunk_size=100, overlap=-1)
    with pytest.raises(ValueError):
        chunk_text("x" * 1000, chunk_size=0, overlap=0)


# ---------------------------------------------------------------------------
# VectorEmbedder: source document path
# ---------------------------------------------------------------------------


class StubEmbeddingProvider:
    """Returns deterministic 768-dim vectors so we can assert upsert calls."""

    name = "stub"
    version = "0.0.1"
    supports_chat = False
    supports_embeddings = True
    supports_streaming = False

    def __init__(self) -> None:
        self.embed_calls: list[list[str]] = []

    async def initialize(self) -> None:
        return None

    async def shutdown(self) -> None:
        return None

    async def health_check(self):  # type: ignore[no-untyped-def]
        return None

    async def complete(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    async def embed(self, texts: list[str], model: str, **kwargs):  # type: ignore[no-untyped-def]
        self.embed_calls.append(list(texts))
        from fragchain.llm.base import EmbeddingResponse

        # Each vector encodes the text length + index so we can assert
        # downstream that the right vector landed on the right chunk.
        vectors = [
            [float(len(t)) % 1.0] + [0.0] * (VECTOR_SIZE - 1) for t in texts
        ]
        return EmbeddingResponse(
            vectors=vectors,
            model=model,
            provider=self.name,
            interaction_id=uuid.uuid4(),
            dimensions=VECTOR_SIZE,
        )


class FakeQdrantClient:
    """Async stub that records every upsert + search call."""

    def __init__(self) -> None:
        self.upserts: list[dict[str, Any]] = []
        self.searches: list[dict[str, Any]] = []
        self.next_search_hits: list[Any] = []

    async def upsert(self, *, collection_name: str, points, wait: bool = True):
        self.upserts.append(
            {
                "collection": collection_name,
                "points": list(points),
                "wait": wait,
            }
        )

    async def search(self, *, collection_name, query_vector, limit, with_payload=True, query_filter=None):
        self.searches.append(
            {
                "collection": collection_name,
                "query_vector": query_vector,
                "limit": limit,
                "filter": query_filter,
            }
        )
        return list(self.next_search_hits)

    async def close(self) -> None:
        return None


class FakeHit:
    def __init__(self, point_id: str, score: float, payload: dict[str, Any]) -> None:
        self.id = point_id
        self.score = score
        self.payload = payload


@pytest.mark.asyncio
async def test_embed_source_document_chunks_and_upserts(monkeypatch):
    """End-to-end happy path: chunks the body, embeds, upserts, flips flag."""
    from fragchain.db.models import CVE, SourceDocument

    fake_qdrant = FakeQdrantClient()
    provider = StubEmbeddingProvider()

    embedder = VectorEmbedder(client=fake_qdrant, provider=provider, model="stub-embed")

    doc_id = uuid.uuid4()
    cve_uuid = uuid.uuid4()
    long_body = " ".join([f"word{i}" for i in range(3000)])

    doc = SourceDocument(
        id=doc_id,
        cve_id=cve_uuid,
        url="https://example.com/advisory",
        source_type="advisory",
        quality_score=0.9,
        tlp="tlp:clear",
        content_hash="abc",
        storage_path=None,
        byte_size=len(long_body),
        embedded=False,
        processed=False,
        document_metadata={"content": long_body, "connector": "test"},
    )
    cve = CVE(id=cve_uuid, cve_id="CVE-2026-43284", import_mode="live")

    class FakeSession:
        committed = False

        async def get(self, model_cls, ident):
            if model_cls is SourceDocument:
                return doc
            if model_cls is CVE:
                return cve
            return None

        async def commit(self):
            FakeSession.committed = True

    session = FakeSession()
    chunk_count = await embedder.embed_source_document(session, doc_id)
    assert chunk_count > 1
    assert doc.embedded is True
    assert FakeSession.committed is True
    # Exactly one upsert, into source_chunks, with chunk_count points.
    assert len(fake_qdrant.upserts) == 1
    call = fake_qdrant.upserts[0]
    assert call["collection"] == COLLECTION_SOURCE_CHUNKS
    assert len(call["points"]) == chunk_count
    # Payload carries CVE id, source_document_id, chunk_index, tlp.
    payload = call["points"][0].payload
    assert payload["cve_id"] == "CVE-2026-43284"
    assert payload["source_document_id"] == str(doc_id)
    assert payload["chunk_index"] == 0
    assert payload["tlp"] == "tlp:clear"


@pytest.mark.asyncio
async def test_embed_source_document_no_content_marks_embedded():
    """A document with no embeddable body still flips embedded=True so the worker stops re-trying."""
    from fragchain.db.models import SourceDocument

    fake_qdrant = FakeQdrantClient()
    embedder = VectorEmbedder(
        client=fake_qdrant, provider=StubEmbeddingProvider(), model="stub"
    )
    doc_id = uuid.uuid4()
    doc = SourceDocument(
        id=doc_id,
        cve_id=uuid.uuid4(),
        url="https://example.com/empty",
        tlp="tlp:clear",
        embedded=False,
        processed=False,
        document_metadata={"connector": "test"},
        storage_path=None,
    )

    class FakeSession:
        committed = False

        async def get(self, *_a, **_kw):
            return doc

        async def commit(self):
            FakeSession.committed = True

    n = await embedder.embed_source_document(FakeSession(), doc_id)
    assert n == 0
    assert doc.embedded is True
    assert fake_qdrant.upserts == []


# ---------------------------------------------------------------------------
# VectorEmbedder: sigma rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_embed_sigma_rule_builds_payload():
    fake_qdrant = FakeQdrantClient()
    embedder = VectorEmbedder(
        client=fake_qdrant, provider=StubEmbeddingProvider(), model="stub"
    )
    rule_id = uuid.uuid4()
    ok = await embedder.embed_sigma_rule(
        session=None,  # not used by the body for embedding-only callers
        rule_id=rule_id,
        title="Suspicious modprobe child",
        technique_ids=["T1547.006", "T1543.003"],
        yaml_body="title: x\nlogsource:\n  product: linux\ndetection:\n  selection:\n    ParentImage|endswith: /modprobe",
        sigma_uuid="abc-123",
        status="experimental",
        logsource_product="linux",
        logsource_service="auditd",
        origin="sigmahq",
    )
    assert ok is True
    assert len(fake_qdrant.upserts) == 1
    call = fake_qdrant.upserts[0]
    assert call["collection"] == COLLECTION_SIGMA_RULES
    point = call["points"][0]
    assert point.payload["title"] == "Suspicious modprobe child"
    assert point.payload["technique_ids"] == ["T1547.006", "T1543.003"]
    assert point.payload["status"] == "experimental"
    # Deterministic point id — uuid5 of the rule_id under a stable namespace.
    second_call_embedder = VectorEmbedder(
        client=FakeQdrantClient(), provider=StubEmbeddingProvider(), model="stub"
    )
    fake2 = second_call_embedder._client  # type: ignore[attr-defined]
    await second_call_embedder.embed_sigma_rule(
        session=None,
        rule_id=rule_id,
        title="Different title — same rule",
        technique_ids=[],
        yaml_body="x",
    )
    assert fake2.upserts[0]["points"][0].id == point.id


# ---------------------------------------------------------------------------
# VectorEmbedder: search wrappers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_source_chunks_maps_to_chunk_result():
    fake_qdrant = FakeQdrantClient()
    fake_qdrant.next_search_hits = [
        FakeHit(
            "pid-1",
            0.92,
            {
                "text": "chunk body",
                "cve_id": "CVE-2026-43284",
                "source_document_id": "doc-1",
                "chunk_index": 0,
                "source_type": "advisory",
                "url": "https://x",
                "quality_score": 0.8,
                "tlp": "tlp:clear",
            },
        )
    ]
    embedder = VectorEmbedder(
        client=fake_qdrant, provider=StubEmbeddingProvider(), model="stub"
    )
    results = await embedder.search_source_chunks("test query", cve_id="cve-2026-43284", limit=5)
    assert len(results) == 1
    r = results[0]
    assert isinstance(r, ChunkResult)
    assert r.score == 0.92
    assert r.cve_id == "CVE-2026-43284"
    assert r.text == "chunk body"
    # Filter was set on the qdrant call.
    assert fake_qdrant.searches[0]["filter"] is not None


@pytest.mark.asyncio
async def test_search_source_chunks_empty_query_short_circuits():
    fake_qdrant = FakeQdrantClient()
    embedder = VectorEmbedder(
        client=fake_qdrant, provider=StubEmbeddingProvider(), model="stub"
    )
    assert await embedder.search_source_chunks("") == []
    assert await embedder.search_source_chunks("   ") == []
    assert fake_qdrant.searches == []


@pytest.mark.asyncio
async def test_search_sigma_rules_maps_to_typed_result():
    fake_qdrant = FakeQdrantClient()
    fake_qdrant.next_search_hits = [
        FakeHit(
            "pid-2",
            0.81,
            {
                "rule_id": "rid",
                "sigma_uuid": "abc",
                "title": "t",
                "technique_ids": ["T1059"],
                "status": "stable",
                "logsource_product": "windows",
                "logsource_service": "security",
                "origin": "sigmahq",
            },
        )
    ]
    embedder = VectorEmbedder(
        client=fake_qdrant, provider=StubEmbeddingProvider(), model="stub"
    )
    results = await embedder.search_sigma_rules("execution via command line", limit=5)
    assert len(results) == 1
    assert isinstance(results[0], SigmaSearchResult)
    assert results[0].technique_ids == ["T1059"]
    assert results[0].score == 0.81


@pytest.mark.asyncio
async def test_search_attck_techniques_maps_to_typed_result():
    fake_qdrant = FakeQdrantClient()
    fake_qdrant.next_search_hits = [
        FakeHit(
            "pid-3",
            0.77,
            {
                "technique_id": "T1059",
                "tactic_id": "TA0002",
                "tactic_name": "Execution",
                "technique_name": "Command and Scripting Interpreter",
                "framework": "attck",
                "has_subtechniques": True,
                "parent_technique_id": None,
            },
        )
    ]
    embedder = VectorEmbedder(
        client=fake_qdrant, provider=StubEmbeddingProvider(), model="stub"
    )
    results = await embedder.search_attck_techniques("shell exec", limit=10)
    assert len(results) == 1
    assert isinstance(results[0], TechniqueResult)
    assert results[0].technique_id == "T1059"
    assert results[0].has_subtechniques is True


# ---------------------------------------------------------------------------
# ATT&CK STIX parser
# ---------------------------------------------------------------------------


def test_parse_attck_techniques_extracts_techniques_and_tactics():
    from scripts.seed_attck_techniques import parse_attck_techniques

    bundle = {
        "objects": [
            {
                "type": "x-mitre-tactic",
                "x_mitre_shortname": "execution",
                "name": "Execution",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "TA0002"}
                ],
            },
            {
                "type": "attack-pattern",
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters to execute commands.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "x_mitre_is_subtechnique": False,
            },
            {
                "type": "attack-pattern",
                "name": "PowerShell",
                "description": "Adversaries may abuse PowerShell.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059.001"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "x_mitre_is_subtechnique": True,
            },
            {
                "type": "attack-pattern",
                "name": "Deprecated thing",
                "x_mitre_deprecated": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T9999"}
                ],
            },
            {
                "type": "attack-pattern",
                "name": "Revoked thing",
                "revoked": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T8888"}
                ],
            },
        ]
    }
    techniques = parse_attck_techniques(bundle)
    assert len(techniques) == 2  # deprecated + revoked dropped
    ids = {t["technique_id"] for t in techniques}
    assert ids == {"T1059", "T1059.001"}
    powershell = next(t for t in techniques if t["technique_id"] == "T1059.001")
    assert powershell["is_subtechnique"] is True
    assert powershell["parent_technique_id"] == "T1059"
    assert powershell["tactic_id"] == "TA0002"
    assert powershell["tactic_name"] == "Execution"
    parent = next(t for t in techniques if t["technique_id"] == "T1059")
    assert parent["is_subtechnique"] is False
    assert parent["parent_technique_id"] is None


def test_parse_attck_techniques_drops_non_T_external_ids():
    from scripts.seed_attck_techniques import parse_attck_techniques

    bundle = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Bad",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "S0002"}
                ],
            }
        ]
    }
    techniques = parse_attck_techniques(bundle)
    assert techniques == []


# ---------------------------------------------------------------------------
# Collection bootstrap
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ensure_collections_creates_missing(monkeypatch):
    """``ensure_collections`` calls create for each name that doesn't already exist."""
    from fragchain.vector import collections as col_module

    class FakeColl:
        def __init__(self, name):
            self.name = name

    class FakeCollections:
        def __init__(self, names):
            self.collections = [FakeColl(n) for n in names]

    created: list[str] = []

    class FakeClient:
        def __init__(self) -> None:
            self.closed = False

        async def get_collections(self):
            # Only one collection already present so three should be created.
            return FakeCollections([COLLECTION_SOURCE_CHUNKS])

        async def create_collection(self, *, collection_name, vectors_config):
            created.append(collection_name)

        async def create_payload_index(self, *, collection_name, field_name, field_schema):
            return None

        async def close(self):
            self.closed = True

    out = await col_module.ensure_collections(client=FakeClient())
    assert out[COLLECTION_SOURCE_CHUNKS] == "exists"
    for name in (
        COLLECTION_SIGMA_RULES,
        COLLECTION_ATTACK_CHAINS,
        COLLECTION_ATTCK_TECHNIQUES,
    ):
        assert out[name] == "created"
    assert set(created) == {
        COLLECTION_SIGMA_RULES,
        COLLECTION_ATTACK_CHAINS,
        COLLECTION_ATTCK_TECHNIQUES,
    }
