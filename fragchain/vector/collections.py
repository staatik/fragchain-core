"""Qdrant collection lifecycle (M8).

Owns the four collections the engine uses for RAG retrieval and similarity
search:

  * ``source_chunks``    — embedded slices of source documents (RAG input for
                            chain synthesis in M11).
  * ``sigma_rules``      — embedded existing Sigma rules (semantic coverage
                            match in M14).
  * ``attack_chains``    — embedded chain summaries (cross-CVE chain reuse).
  * ``attck_techniques`` — embedded MITRE ATT&CK technique descriptions
                            (used by M14 and the ATT&CK Matrix screen).

All four are 768 dimensions, Cosine distance — matching the
``nomic-embed-text`` model the operator wires LiteLLM to in v1
(CLAUDE.md §4.1). Qdrant runs LOCAL to Server 3 in v1: no ``fragchain_``
collection prefix (CLAUDE.md §4.2). The bootstrap helper here is called
once at API startup from the lifespan hook; idempotent.

The module also exposes a slim async wrapper around ``AsyncQdrantClient`` so
the rest of the engine never reaches into ``qdrant_client.models`` directly.
"""
from __future__ import annotations

import structlog

from fragchain.config import get_settings

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Collection registry
# ---------------------------------------------------------------------------

VECTOR_SIZE: int = 768
"""Embedding dimension. Tied to LITELLM_EMBEDDING_MODEL — operators changing
the embedding model must also change this constant and drop the collections.
"""

DISTANCE: str = "Cosine"
"""Cosine distance, per CLAUDE.md §4.2 / M8 spec."""


# Collection names — no ``fragchain_`` prefix (Qdrant is local in v1).
COLLECTION_SOURCE_CHUNKS = "source_chunks"
COLLECTION_SIGMA_RULES = "sigma_rules"
COLLECTION_ATTACK_CHAINS = "attack_chains"
COLLECTION_ATTCK_TECHNIQUES = "attck_techniques"

ALL_COLLECTIONS: tuple[str, ...] = (
    COLLECTION_SOURCE_CHUNKS,
    COLLECTION_SIGMA_RULES,
    COLLECTION_ATTACK_CHAINS,
    COLLECTION_ATTCK_TECHNIQUES,
)


# Payload indexed fields per collection. Qdrant lets you query payloads
# without an index but filtered searches on hundreds of thousands of points
# get slow without them. Listed here so future modules know which fields are
# pre-indexed for filter pushdown.
PAYLOAD_INDEXES: dict[str, list[tuple[str, str]]] = {
    COLLECTION_SOURCE_CHUNKS: [
        ("cve_id", "keyword"),
        ("source_document_id", "keyword"),
        ("source_type", "keyword"),
        ("tlp", "keyword"),
    ],
    COLLECTION_SIGMA_RULES: [
        ("rule_id", "keyword"),
        ("sigma_uuid", "keyword"),
        ("technique_ids", "keyword"),
        ("status", "keyword"),
        ("logsource_product", "keyword"),
    ],
    COLLECTION_ATTACK_CHAINS: [
        ("chain_id", "keyword"),
        ("cve_id", "keyword"),
        ("technique_ids", "keyword"),
    ],
    COLLECTION_ATTCK_TECHNIQUES: [
        ("technique_id", "keyword"),
        ("tactic_id", "keyword"),
        ("framework", "keyword"),
        ("parent_technique_id", "keyword"),
    ],
}


# ---------------------------------------------------------------------------
# Client factory
# ---------------------------------------------------------------------------


def get_qdrant_client():  # -> AsyncQdrantClient (typed via lazy import)
    """Return a configured ``AsyncQdrantClient`` instance.

    Caller owns the lifecycle — pass ``async with`` or remember to ``close()``
    on shutdown. We do NOT keep a process-wide singleton because Qdrant's
    HTTP client uses one underlying httpx pool per instance and reuse across
    test runs is risky (the test fixtures need clean state).
    """
    from qdrant_client import AsyncQdrantClient

    settings = get_settings()
    api_key = settings.QDRANT_API_KEY.get_secret_value() or None
    return AsyncQdrantClient(
        host=settings.QDRANT_HOST,
        port=settings.QDRANT_PORT,
        api_key=api_key,
        https=False,
        timeout=30.0,
    )


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------


async def ensure_collections(client=None) -> dict[str, str]:
    """Create any missing Qdrant collections. Idempotent.

    Returns a ``{name: status}`` map where status is ``"created"``,
    ``"exists"``, or ``"error"``. Errors are logged but never propagate — a
    Qdrant outage at startup must not block the API from coming up (the
    embedding pipeline will surface the issue the next time it runs).
    """
    from qdrant_client import models as qm

    own_client = client is None
    if client is None:
        client = get_qdrant_client()
    out: dict[str, str] = {}
    try:
        existing = {c.name for c in (await client.get_collections()).collections}
        for name in ALL_COLLECTIONS:
            if name in existing:
                out[name] = "exists"
                continue
            try:
                await client.create_collection(
                    collection_name=name,
                    vectors_config=qm.VectorParams(
                        size=VECTOR_SIZE, distance=qm.Distance.COSINE
                    ),
                )
                out[name] = "created"
                logger.info(
                    "qdrant.collection.created",
                    collection=name,
                    size=VECTOR_SIZE,
                    distance=DISTANCE,
                )
            except Exception as exc:  # noqa: BLE001
                out[name] = "error"
                logger.warning(
                    "qdrant.collection.create_failed",
                    collection=name,
                    error=str(exc),
                )
                continue
            # Best-effort payload indexes. A missing index isn't fatal —
            # filters still work, just slower.
            for field_name, schema in PAYLOAD_INDEXES.get(name, []):
                try:
                    await client.create_payload_index(
                        collection_name=name,
                        field_name=field_name,
                        field_schema=schema,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.info(
                        "qdrant.payload_index.skipped",
                        collection=name,
                        field=field_name,
                        error=str(exc),
                    )
    except Exception as exc:  # noqa: BLE001
        logger.warning("qdrant.bootstrap.failed", error=str(exc))
    finally:
        if own_client:
            try:
                await client.close()
            except Exception:  # noqa: BLE001
                pass
    return out


async def get_collections_info(client=None) -> list[dict[str, object]]:
    """Stats for every FragChain collection (admin endpoint).

    Returns a list of dicts shaped for the API response. Missing collections
    surface as ``status="missing"`` rather than raising — the admin UI can
    then offer a "create" button (which is just ``ensure_collections``).
    """
    own_client = client is None
    if client is None:
        client = get_qdrant_client()
    out: list[dict[str, object]] = []
    try:
        # Resolve which collections actually exist in this Qdrant instance.
        try:
            existing = {c.name for c in (await client.get_collections()).collections}
        except Exception as exc:  # noqa: BLE001
            logger.warning("qdrant.list_collections_failed", error=str(exc))
            return [
                {"name": n, "status": "error", "error": str(exc)} for n in ALL_COLLECTIONS
            ]
        for name in ALL_COLLECTIONS:
            if name not in existing:
                out.append({"name": name, "status": "missing"})
                continue
            try:
                info = await client.get_collection(collection_name=name)
                count = await client.count(collection_name=name, exact=False)
                out.append(
                    {
                        "name": name,
                        "status": "ok",
                        "points_count": int(getattr(count, "count", 0)),
                        "vectors_size": VECTOR_SIZE,
                        "distance": DISTANCE,
                        "indexed_only_count": getattr(info, "indexed_vectors_count", None),
                    }
                )
            except Exception as exc:  # noqa: BLE001
                out.append({"name": name, "status": "error", "error": str(exc)})
    finally:
        if own_client:
            try:
                await client.close()
            except Exception:  # noqa: BLE001
                pass
    return out


__all__ = [
    "ALL_COLLECTIONS",
    "COLLECTION_ATTACK_CHAINS",
    "COLLECTION_ATTCK_TECHNIQUES",
    "COLLECTION_SIGMA_RULES",
    "COLLECTION_SOURCE_CHUNKS",
    "DISTANCE",
    "PAYLOAD_INDEXES",
    "VECTOR_SIZE",
    "ensure_collections",
    "get_collections_info",
    "get_qdrant_client",
]
