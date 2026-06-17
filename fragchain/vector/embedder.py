"""Embedding pipeline + RAG search (M8).

The ``VectorEmbedder`` is the single seam between the LLM provider (M5) and
Qdrant. Two flavours of work happen here:

  * **Writes** — chunk + embed + upsert ``source_chunks`` / ``sigma_rules`` /
    ``attck_techniques``. Called from Celery tasks and the ATT&CK seed.

  * **Reads** — three named search helpers consumed by M11 (chain synthesis
    RAG retrieval), M14 (coverage mapping), and the ATT&CK Matrix screen.

Chunking is deterministic — same document in, same chunks out — so a
re-embed overwrites prior vectors at the same point IDs (uuid5 over
``source_document_id:chunk_index``). M11 / M14 can therefore call this any
number of times without worrying about duplicates.

Token counting uses ``tiktoken`` with the OpenAI-compatible ``cl100k_base``
encoding. Falls back to a rough whitespace estimator if tiktoken isn't
installed — produces slightly more / fewer chunks but never crashes.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.config import get_settings
from fragchain.db.models import CVE, SourceDocument
from fragchain.llm import get_registry
from fragchain.vector.collections import (
    COLLECTION_ATTACK_CHAINS,
    COLLECTION_ATTCK_TECHNIQUES,
    COLLECTION_SIGMA_RULES,
    COLLECTION_SOURCE_CHUNKS,
    VECTOR_SIZE,
    get_qdrant_client,
)

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Tuning constants
# ---------------------------------------------------------------------------

CHUNK_SIZE_TOKENS: int = 512
"""Target chunk size in tokens (cl100k_base). 512 lands comfortably inside
nomic-embed-text's 2048 context, leaves room for overlap, and matches the
M8 spec."""

CHUNK_OVERLAP_TOKENS: int = 50
"""Sliding overlap so a sentence that straddles a chunk boundary still
appears intact in one of the two neighbours."""

MIN_CHUNK_TOKENS: int = 50
"""Chunks shorter than this are dropped — they're usually trailing whitespace
or boilerplate that pollutes RAG retrieval."""


# Stable namespaces for deterministic point ids. uuid5 is content-addressed
# so a re-embed of the same source doc / rule overwrites the same Qdrant
# point ids — no orphaned vectors.
_NS_SOURCE_CHUNK = uuid.UUID("e7c1b0e6-3a8a-4b2e-8c7a-1f3b9a4d5e6f")
_NS_SIGMA_RULE = uuid.UUID("a1b2c3d4-e5f6-4789-9012-3456789abcde")
_NS_ATTCK = uuid.UUID("12345678-1234-5678-1234-567812345678")
_NS_CHAIN = uuid.UUID("87654321-4321-8765-4321-876543218765")


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ChunkResult:
    """One hit from ``search_source_chunks``."""

    point_id: str
    score: float
    text: str
    cve_id: str | None
    source_document_id: str | None
    chunk_index: int | None
    source_type: str | None
    url: str | None
    quality_score: float | None
    tlp: str


@dataclass
class SigmaSearchResult:
    """One hit from ``search_sigma_rules``."""

    point_id: str
    score: float
    rule_id: str | None
    sigma_uuid: str | None
    title: str | None
    technique_ids: list[str]
    status: str | None
    logsource_product: str | None
    logsource_service: str | None
    origin: str | None


@dataclass
class TechniqueResult:
    """One hit from ``search_attck_techniques``."""

    point_id: str
    score: float
    technique_id: str
    tactic_id: str | None
    tactic_name: str | None
    technique_name: str | None
    framework: str
    has_subtechniques: bool
    parent_technique_id: str | None


# ---------------------------------------------------------------------------
# Tokenizer (best-effort)
# ---------------------------------------------------------------------------


_ENCODER: Any | None = None
_ENCODER_FAILED: bool = False


def _get_encoder() -> Any | None:
    """Lazy-load the cl100k_base encoder. ``None`` if tiktoken is unavailable.

    Cached after first call. If tiktoken raises (offline install, missing
    encoding data) we permanently fall back to the whitespace estimator —
    re-trying every call would spam logs.
    """
    global _ENCODER, _ENCODER_FAILED
    if _ENCODER is not None or _ENCODER_FAILED:
        return _ENCODER
    try:
        import tiktoken  # type: ignore[import-not-found]

        _ENCODER = tiktoken.get_encoding("cl100k_base")
    except Exception as exc:  # noqa: BLE001
        _ENCODER_FAILED = True
        logger.info("vector.tiktoken.unavailable", error=str(exc))
        return None
    return _ENCODER


def _encode(text: str) -> list[int]:
    enc = _get_encoder()
    if enc is None:
        # ~4 chars per token (English-text heuristic). Used only for chunking
        # math — embeddings don't care about the token ids themselves.
        return list(range(max(1, len(text) // 4)))
    return enc.encode(text, disallowed_special=())


def _decode(tokens: list[int]) -> str:
    enc = _get_encoder()
    if enc is None:
        # No real decode possible — the heuristic isn't reversible.
        # Caller must use the slice strategy below (which keeps a parallel
        # char-offset list) instead of relying on _decode in the fallback path.
        raise RuntimeError("tiktoken unavailable — cannot decode tokens")
    return enc.decode(tokens)


def count_tokens(text: str) -> int:
    """Token count for ``text`` under cl100k_base (or whitespace estimate)."""
    if not text:
        return 0
    return len(_encode(text))


def chunk_text(
    text: str,
    *,
    chunk_size: int = CHUNK_SIZE_TOKENS,
    overlap: int = CHUNK_OVERLAP_TOKENS,
    min_size: int = MIN_CHUNK_TOKENS,
) -> list[str]:
    """Split ``text`` into sliding-window chunks of approximately ``chunk_size`` tokens.

    Drops chunks shorter than ``min_size`` so RAG retrieval doesn't return
    boilerplate fragments. When tiktoken is unavailable, falls back to a
    char-based slice with the same effective behaviour (slightly less
    accurate token counting).
    """
    if not text or not text.strip():
        return []
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if overlap < 0 or overlap >= chunk_size:
        raise ValueError("overlap must be >=0 and < chunk_size")

    enc = _get_encoder()
    if enc is not None:
        tokens = enc.encode(text, disallowed_special=())
        if len(tokens) <= chunk_size:
            return [text] if len(tokens) >= min_size else []
        out: list[str] = []
        step = chunk_size - overlap
        i = 0
        while i < len(tokens):
            slice_tokens = tokens[i : i + chunk_size]
            if len(slice_tokens) < min_size:
                break
            out.append(enc.decode(slice_tokens))
            if i + chunk_size >= len(tokens):
                break
            i += step
        return out

    # Char-based fallback: 4 chars ≈ 1 token. Mirrors the windowing math but
    # operates on characters directly.
    chars_per_token = 4
    target_chars = chunk_size * chars_per_token
    overlap_chars = overlap * chars_per_token
    min_chars = min_size * chars_per_token
    if len(text) <= target_chars:
        return [text] if len(text) >= min_chars else []
    out = []
    step = target_chars - overlap_chars
    i = 0
    while i < len(text):
        slice_chars = text[i : i + target_chars]
        if len(slice_chars) < min_chars:
            break
        out.append(slice_chars)
        if i + target_chars >= len(text):
            break
        i += step
    return out


# ---------------------------------------------------------------------------
# Content resolution
# ---------------------------------------------------------------------------


async def _resolve_document_content(doc: SourceDocument) -> str | None:
    """Pull the embeddable text body for one source document.

    Looks in two places, in order:

      1. ``document_metadata["content"]`` (M6 stores small bodies inline).
      2. MinIO at ``storage_path`` (when M6 / a connector stored a large body).

    Returns ``None`` if neither has anything — the caller logs + skips the
    document. Connectors that pass references-only documents (no body) will
    legitimately land here.
    """
    meta = doc.document_metadata or {}
    content = meta.get("content") if isinstance(meta, dict) else None
    if isinstance(content, str) and content.strip():
        return content
    if isinstance(content, (dict, list)):
        # Some connectors hand structured JSON; embed the stringified form so
        # the embedding picks up keys + values.
        try:
            return json.dumps(content, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return None
    excerpt = meta.get("excerpt") if isinstance(meta, dict) else None
    if isinstance(excerpt, str) and excerpt.strip():
        return excerpt
    description = meta.get("description") if isinstance(meta, dict) else None
    if isinstance(description, str) and description.strip():
        return description

    if doc.storage_path:
        try:
            from fragchain.storage.minio import get_json

            # storage_path is "{bucket}/{object_name}"; the helper expects only
            # the object name (and uses the configured bucket by default).
            _, object_name = doc.storage_path.split("/", 1)
            payload = await get_json(object_name)
            if isinstance(payload, dict):
                for key in ("content", "text", "body", "excerpt"):
                    val = payload.get(key)
                    if isinstance(val, str) and val.strip():
                        return val
                # Last-ditch: dump the whole payload as a string.
                return json.dumps(payload, ensure_ascii=False, default=str)
            if isinstance(payload, str):
                return payload
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "vector.document.minio_read_failed",
                document_id=str(doc.id),
                storage_path=doc.storage_path,
                error=str(exc),
            )
    return None


# ---------------------------------------------------------------------------
# VectorEmbedder
# ---------------------------------------------------------------------------


class VectorEmbedder:
    """High-level embedding + search facade. One instance per worker / request.

    Holds a Qdrant client and reaches into the global LLM provider registry
    for embeddings. Caller is responsible for ``close()`` (or ``async with``)
    to release the Qdrant HTTP pool.
    """

    def __init__(
        self,
        *,
        client: Any | None = None,
        provider: Any | None = None,
        model: str | None = None,
    ) -> None:
        self._client = client
        self._owns_client = client is None
        self._provider = provider
        self._model = model

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "VectorEmbedder":
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        if self._client is not None and self._owns_client:
            try:
                await self._client.close()
            except Exception:  # noqa: BLE001
                pass
            self._client = None

    def _qdrant(self):
        if self._client is None:
            self._client = get_qdrant_client()
        return self._client

    def _embed_model(self) -> str:
        if self._model:
            return self._model
        return get_settings().LITELLM_EMBEDDING_MODEL

    async def _embed_texts(self, texts: list[str]) -> list[list[float]]:
        """Run a batch through the default embedding provider."""
        if not texts:
            return []
        if self._provider is None:
            self._provider = get_registry().get_default_embedding_provider()
        if self._provider is None:
            raise RuntimeError(
                "No embedding-capable LLM provider registered — install fragchain-provider-litellm"
            )
        resp = await self._provider.embed(texts, self._embed_model())
        return list(resp.vectors)

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    async def embed_source_document(
        self,
        session: AsyncSession,
        source_doc_id: uuid.UUID | str,
    ) -> int:
        """Chunk + embed + upsert one source document. Returns chunk count.

        Idempotent: re-embedding the same document overwrites the same point
        ids (uuid5 over ``source_document_id:chunk_index``). On a no-content
        document the row is flipped to ``embedded=True`` anyway with a
        ``last_embed_chunks=0`` note in metadata, so a worker doesn't keep
        retrying it forever.
        """
        from qdrant_client import models as qm

        doc_uuid = uuid.UUID(str(source_doc_id))
        doc = await session.get(SourceDocument, doc_uuid)
        if doc is None:
            logger.warning("vector.embed.doc_not_found", document_id=str(source_doc_id))
            return 0

        content = await _resolve_document_content(doc)
        if content is None:
            logger.info(
                "vector.embed.no_content", document_id=str(doc.id), cve_id=str(doc.cve_id)
            )
            doc.embedded = True
            doc.processed = True
            await session.commit()
            return 0

        chunks = chunk_text(content)
        if not chunks:
            logger.info(
                "vector.embed.no_chunks",
                document_id=str(doc.id),
                tokens=count_tokens(content),
            )
            doc.embedded = True
            doc.processed = True
            await session.commit()
            return 0

        try:
            vectors = await self._embed_texts(chunks)
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "vector.embed.provider_failed",
                document_id=str(doc.id),
                error=str(exc),
            )
            raise

        cve = await session.get(CVE, doc.cve_id)
        cve_textual_id = cve.cve_id if cve is not None else None

        points = []
        for i, (chunk, vec) in enumerate(zip(chunks, vectors, strict=True)):
            point_id = str(uuid.uuid5(_NS_SOURCE_CHUNK, f"{doc.id}:{i}"))
            payload = {
                "cve_id": cve_textual_id,
                "cve_uuid": str(doc.cve_id),
                "source_document_id": str(doc.id),
                "chunk_index": i,
                "quality_score": (
                    float(doc.quality_score) if doc.quality_score is not None else None
                ),
                "source_type": doc.source_type,
                "url": doc.url,
                "tlp": doc.tlp,
                "text": chunk,
            }
            points.append(
                qm.PointStruct(id=point_id, vector=vec, payload=payload)
            )

        client = self._qdrant()
        await client.upsert(
            collection_name=COLLECTION_SOURCE_CHUNKS,
            points=points,
            wait=True,
        )

        doc.embedded = True
        doc.processed = True
        await session.commit()
        logger.info(
            "vector.embed.source_document",
            document_id=str(doc.id),
            cve_id=cve_textual_id,
            chunks=len(chunks),
        )
        return len(chunks)

    async def embed_sigma_rule(
        self,
        session: AsyncSession,
        rule_id: uuid.UUID | str,
        *,
        title: str,
        technique_ids: list[str],
        yaml_body: str,
        sigma_uuid: str | None = None,
        status: str | None = None,
        logsource_product: str | None = None,
        logsource_service: str | None = None,
        origin: str | None = None,
    ) -> bool:
        """Embed one Sigma rule for semantic coverage matching (called by M12+).

        The caller supplies the rule's fields explicitly — there's no
        ``sigma_rules`` ORM model in M8, M12 owns the schema. Embeds
        ``title + technique_ids + yaml[:500]`` per the kickoff. Returns
        ``True`` on success.
        """
        from qdrant_client import models as qm

        rule_uuid = uuid.UUID(str(rule_id))
        embed_text = "\n".join(
            [
                f"title: {title}",
                f"techniques: {', '.join(technique_ids)}",
                yaml_body[:500],
            ]
        )
        try:
            vectors = await self._embed_texts([embed_text])
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "vector.embed.sigma_rule_failed",
                rule_id=str(rule_id),
                error=str(exc),
            )
            raise
        if not vectors:
            return False

        payload = {
            "rule_id": str(rule_uuid),
            "sigma_uuid": sigma_uuid,
            "title": title,
            "technique_ids": list(technique_ids),
            "status": status,
            "logsource_product": logsource_product,
            "logsource_service": logsource_service,
            "origin": origin,
        }
        point_id = str(uuid.uuid5(_NS_SIGMA_RULE, str(rule_uuid)))
        client = self._qdrant()
        await client.upsert(
            collection_name=COLLECTION_SIGMA_RULES,
            points=[qm.PointStruct(id=point_id, vector=vectors[0], payload=payload)],
            wait=True,
        )
        logger.info(
            "vector.embed.sigma_rule",
            rule_id=str(rule_uuid),
            techniques=len(technique_ids),
        )
        return True

    async def upsert_technique(
        self,
        *,
        technique_id: str,
        technique_name: str,
        tactic_id: str | None,
        tactic_name: str | None,
        description: str,
        framework: str = "attck",
        has_subtechniques: bool = False,
        parent_technique_id: str | None = None,
    ) -> bool:
        """Embed + upsert one ATT&CK technique. Called by ``seed_attck_techniques``.

        Point id is uuid5 over ``framework:technique_id`` so re-running the
        seed doesn't duplicate techniques across runs.
        """
        from qdrant_client import models as qm

        embed_text = "\n".join(
            [
                f"{technique_id}: {technique_name}",
                f"tactic: {tactic_name or tactic_id or ''}",
                description,
            ]
        )
        vectors = await self._embed_texts([embed_text])
        if not vectors:
            return False
        payload = {
            "technique_id": technique_id,
            "tactic_id": tactic_id,
            "tactic_name": tactic_name,
            "technique_name": technique_name,
            "framework": framework,
            "has_subtechniques": bool(has_subtechniques),
            "parent_technique_id": parent_technique_id,
            "description": description[:1000],
        }
        point_id = str(uuid.uuid5(_NS_ATTCK, f"{framework}:{technique_id}"))
        client = self._qdrant()
        await client.upsert(
            collection_name=COLLECTION_ATTCK_TECHNIQUES,
            points=[qm.PointStruct(id=point_id, vector=vectors[0], payload=payload)],
            wait=True,
        )
        return True

    async def upsert_chain_summary(
        self,
        *,
        chain_id: uuid.UUID | str,
        cve_id: str,
        summary: str,
        overall_confidence: float,
        technique_ids: list[str],
    ) -> bool:
        """Embed an attack-chain summary into ``attack_chains`` (called by M11)."""
        from qdrant_client import models as qm

        chain_uuid = uuid.UUID(str(chain_id))
        vectors = await self._embed_texts([summary])
        if not vectors:
            return False
        payload = {
            "chain_id": str(chain_uuid),
            "cve_id": cve_id,
            "overall_confidence": float(overall_confidence),
            "technique_ids": list(technique_ids),
        }
        point_id = str(uuid.uuid5(_NS_CHAIN, str(chain_uuid)))
        client = self._qdrant()
        await client.upsert(
            collection_name=COLLECTION_ATTACK_CHAINS,
            points=[qm.PointStruct(id=point_id, vector=vectors[0], payload=payload)],
            wait=True,
        )
        return True

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def search_source_chunks(
        self,
        query: str,
        *,
        cve_id: str | None = None,
        limit: int = 20,
    ) -> list[ChunkResult]:
        """Semantic search over ``source_chunks``.

        When ``cve_id`` (textual CVE-YYYY-NNNN form) is set, scope the search
        to that CVE — M11 calls this with the CVE under synthesis to keep RAG
        retrieval focused.
        """
        from qdrant_client import models as qm

        if not query or not query.strip():
            return []
        vectors = await self._embed_texts([query])
        if not vectors:
            return []
        flt = None
        if cve_id:
            flt = qm.Filter(
                must=[
                    qm.FieldCondition(
                        key="cve_id",
                        match=qm.MatchValue(value=cve_id.upper()),
                    )
                ]
            )
        client = self._qdrant()
        response = await client.query_points(
            collection_name=COLLECTION_SOURCE_CHUNKS,
            query=vectors[0],
            query_filter=flt,
            limit=limit,
            with_payload=True,
        )
        hits = response.points
        return [
            ChunkResult(
                point_id=str(h.id),
                score=float(h.score),
                text=(h.payload or {}).get("text", ""),
                cve_id=(h.payload or {}).get("cve_id"),
                source_document_id=(h.payload or {}).get("source_document_id"),
                chunk_index=(h.payload or {}).get("chunk_index"),
                source_type=(h.payload or {}).get("source_type"),
                url=(h.payload or {}).get("url"),
                quality_score=(h.payload or {}).get("quality_score"),
                tlp=(h.payload or {}).get("tlp", "tlp:clear"),
            )
            for h in hits
        ]

    async def search_sigma_rules(
        self,
        description: str,
        *,
        limit: int = 5,
    ) -> list[SigmaSearchResult]:
        """Semantic search over ``sigma_rules`` (M14 coverage Phase 2)."""
        if not description or not description.strip():
            return []
        vectors = await self._embed_texts([description])
        if not vectors:
            return []
        client = self._qdrant()
        response = await client.query_points(
            collection_name=COLLECTION_SIGMA_RULES,
            query=vectors[0],
            limit=limit,
            with_payload=True,
        )
        hits = response.points
        return [
            SigmaSearchResult(
                point_id=str(h.id),
                score=float(h.score),
                rule_id=(h.payload or {}).get("rule_id"),
                sigma_uuid=(h.payload or {}).get("sigma_uuid"),
                title=(h.payload or {}).get("title"),
                technique_ids=list((h.payload or {}).get("technique_ids") or []),
                status=(h.payload or {}).get("status"),
                logsource_product=(h.payload or {}).get("logsource_product"),
                logsource_service=(h.payload or {}).get("logsource_service"),
                origin=(h.payload or {}).get("origin"),
            )
            for h in hits
        ]

    async def search_attck_techniques(
        self,
        query: str,
        *,
        limit: int = 10,
    ) -> list[TechniqueResult]:
        """Semantic search over ``attck_techniques`` (used by M14 + matrix UI)."""
        if not query or not query.strip():
            return []
        vectors = await self._embed_texts([query])
        if not vectors:
            return []
        client = self._qdrant()
        response = await client.query_points(
            collection_name=COLLECTION_ATTCK_TECHNIQUES,
            query=vectors[0],
            limit=limit,
            with_payload=True,
        )
        hits = response.points
        return [
            TechniqueResult(
                point_id=str(h.id),
                score=float(h.score),
                technique_id=(h.payload or {}).get("technique_id", ""),
                tactic_id=(h.payload or {}).get("tactic_id"),
                tactic_name=(h.payload or {}).get("tactic_name"),
                technique_name=(h.payload or {}).get("technique_name"),
                framework=(h.payload or {}).get("framework", "attck"),
                has_subtechniques=bool((h.payload or {}).get("has_subtechniques")),
                parent_technique_id=(h.payload or {}).get("parent_technique_id"),
            )
            for h in hits
        ]

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    async def count_in_collection(self, collection: str) -> int:
        """Return the point count in ``collection`` (0 if missing / error)."""
        try:
            client = self._qdrant()
            resp = await client.count(collection_name=collection, exact=False)
            return int(getattr(resp, "count", 0))
        except Exception as exc:  # noqa: BLE001
            logger.info("vector.count_failed", collection=collection, error=str(exc))
            return 0


# ---------------------------------------------------------------------------
# Convenience: pending-embedding queue draining
# ---------------------------------------------------------------------------


async def embed_pending_documents_for_cve(
    session: AsyncSession,
    cve_id: uuid.UUID,
    *,
    embedder: VectorEmbedder | None = None,
) -> int:
    """Embed every ``embedded=False`` source document on ``cve_id``.

    Returns the number of documents embedded (chunks total are logged
    per-doc). Used by ``enrich_cve`` to drain the embedding queue inline.
    """
    rows = (
        await session.execute(
            select(SourceDocument).where(
                SourceDocument.cve_id == cve_id,
                SourceDocument.embedded.is_(False),
            )
        )
    ).scalars().all()
    if not rows:
        return 0
    own_embedder = embedder is None
    if embedder is None:
        embedder = VectorEmbedder()
    try:
        embedded = 0
        for doc in rows:
            try:
                await embedder.embed_source_document(session, doc.id)
                embedded += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "vector.embed.doc_failed",
                    document_id=str(doc.id),
                    error=str(exc),
                )
        return embedded
    finally:
        if own_embedder:
            await embedder.close()


__all__ = [
    "CHUNK_OVERLAP_TOKENS",
    "CHUNK_SIZE_TOKENS",
    "ChunkResult",
    "MIN_CHUNK_TOKENS",
    "SigmaSearchResult",
    "TechniqueResult",
    "VECTOR_SIZE",
    "VectorEmbedder",
    "chunk_text",
    "count_tokens",
    "embed_pending_documents_for_cve",
]
