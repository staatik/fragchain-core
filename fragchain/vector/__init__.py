"""Vector store + embedding pipeline (M8).

Public surface importers should depend on. Concrete collection names live in
``fragchain.vector.collections``; the high-level RAG / search API is the
``VectorEmbedder`` class. Tests + admin endpoints reach in for the raw
helpers (``chunk_text``, ``ensure_collections``, etc.).
"""

from fragchain.vector.collections import (
    ALL_COLLECTIONS,
    COLLECTION_ATTACK_CHAINS,
    COLLECTION_ATTCK_TECHNIQUES,
    COLLECTION_SIGMA_RULES,
    COLLECTION_SOURCE_CHUNKS,
    DISTANCE,
    VECTOR_SIZE,
    ensure_collections,
    get_collections_info,
    get_qdrant_client,
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
    embed_pending_documents_for_cve,
)

__all__ = [
    "ALL_COLLECTIONS",
    "CHUNK_OVERLAP_TOKENS",
    "CHUNK_SIZE_TOKENS",
    "COLLECTION_ATTACK_CHAINS",
    "COLLECTION_ATTCK_TECHNIQUES",
    "COLLECTION_SIGMA_RULES",
    "COLLECTION_SOURCE_CHUNKS",
    "ChunkResult",
    "DISTANCE",
    "MIN_CHUNK_TOKENS",
    "SigmaSearchResult",
    "TechniqueResult",
    "VECTOR_SIZE",
    "VectorEmbedder",
    "chunk_text",
    "count_tokens",
    "embed_pending_documents_for_cve",
    "ensure_collections",
    "get_collections_info",
    "get_qdrant_client",
]
