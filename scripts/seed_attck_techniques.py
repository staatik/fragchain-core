"""Seed the MITRE ATT&CK Enterprise corpus into Qdrant + Postgres (M8).

Run inside the API container with Postgres + Qdrant + LiteLLM up:

    python -m scripts.seed_attck_techniques

What this does:

  1. Downloads the canonical ``enterprise-attack.json`` STIX bundle from
     MITRE's public GitHub mirror.
  2. Parses every technique + sub-technique (attack-pattern objects). Skips
     revoked / deprecated entries.
  3. Embeds each technique through the configured LLM provider
     (LiteLLM → ``LITELLM_EMBEDDING_MODEL``).
  4. Upserts each embedding into the ``attck_techniques`` Qdrant collection
     (point id is uuid5 over ``framework:technique_id``).
  5. Upserts one ``coverage_map`` row per technique with
     ``coverage_status='no_data'`` so the ATT&CK Matrix screen has a full
     grid from day one — even before any chain or rule has been ingested.

Idempotent. Re-running:
  * Qdrant upsert overwrites on stable point ids — no duplicates.
  * Postgres upsert uses ``ON CONFLICT DO UPDATE`` on
    ``(technique_id, framework)``.
  * If the Qdrant collection already has > ``MIN_TECHNIQUES`` points and
    Postgres already has > ``MIN_TECHNIQUES`` rows, exits early with no
    network traffic. Pass ``--force`` to re-embed anyway.

Environment overrides:
  * ``ATTCK_BUNDLE_URL`` — point at an internal mirror if you can't reach
    github.com from the API container.
  * ``ATTCK_BUNDLE_PATH`` — read from a local file instead (useful in
    air-gapped deployments).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.db.models import CoverageMap
from fragchain.db.session import dispose_engine, get_sessionmaker
from fragchain.llm import bootstrap_providers_for_scripts
from fragchain.vector.collections import (
    COLLECTION_ATTCK_TECHNIQUES,
    ensure_collections,
    get_qdrant_client,
)
from fragchain.vector.embedder import VectorEmbedder

logger = structlog.get_logger(__name__)


DEFAULT_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

MIN_TECHNIQUES = 100
"""If both Qdrant + Postgres already hold this many techniques the script
exits early. Catches the common "re-seed an already-seeded deployment"
case without making the operator pass --force."""


# ---------------------------------------------------------------------------
# STIX parsing
# ---------------------------------------------------------------------------


def _kill_chain_phases_to_tactic(phases: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    """First mitre-attack kill chain phase → (tactic_id, tactic_name).

    Tactics in the STIX bundle are encoded as kill_chain_phase entries with
    ``kill_chain_name=mitre-attack``. The phase_name is the lowercase
    tactic name (``persistence``, ``privilege-escalation``, …); the
    corresponding tactic_id (``TA0003``, ``TA0004``) lives on a separate
    x-mitre-tactic object — we'll resolve it via the tactic_map built from
    the same bundle.
    """
    for phase in phases or []:
        if phase.get("kill_chain_name") != "mitre-attack":
            continue
        return None, phase.get("phase_name")
    return None, None


def _external_attck_id(obj: dict[str, Any]) -> str | None:
    """Pull the mitre-attack external_id (``T1078`` / ``T1078.003`` / ``TA0001``)."""
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            ext = ref.get("external_id")
            if isinstance(ext, str):
                return ext
    return None


def _build_tactic_lookup(stix: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    """Build ``{phase_name: {id, name}}`` from x-mitre-tactic objects.

    Phase names ('persistence', 'privilege-escalation') come from kill chain
    phases on attack-patterns. The tactic_id ('TA0003') lives on the matching
    ``x-mitre-tactic`` object's ``x_mitre_shortname`` + external reference.
    """
    out: dict[str, dict[str, str]] = {}
    for obj in stix:
        if obj.get("type") != "x-mitre-tactic":
            continue
        shortname = obj.get("x_mitre_shortname")
        ext_id = _external_attck_id(obj)
        name = obj.get("name")
        if not shortname:
            continue
        out[shortname] = {
            "tactic_id": ext_id or "",
            "tactic_name": name or shortname,
        }
    return out


def parse_attck_techniques(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Walk the STIX bundle and produce a flat list of technique dicts.

    Drops revoked + deprecated entries. Sub-technique parent linkage is set
    by string-suffix matching on the technique_id (``T1059.001`` → parent
    ``T1059``).
    """
    objects = bundle.get("objects", []) or []
    tactic_lookup = _build_tactic_lookup(objects)
    techniques: list[dict[str, Any]] = []

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
            continue
        ext_id = _external_attck_id(obj)
        if not ext_id or not ext_id.startswith("T"):
            continue
        _t_id_unused, phase_name = _kill_chain_phases_to_tactic(
            obj.get("kill_chain_phases", [])
        )
        tactic_meta = tactic_lookup.get(phase_name or "", {})

        is_sub = bool(obj.get("x_mitre_is_subtechnique", False))
        parent_id: str | None = None
        if is_sub and "." in ext_id:
            parent_id = ext_id.split(".", 1)[0]

        techniques.append(
            {
                "technique_id": ext_id,
                "technique_name": obj.get("name") or ext_id,
                "tactic_id": tactic_meta.get("tactic_id") or None,
                "tactic_name": tactic_meta.get("tactic_name") or phase_name,
                "description": (obj.get("description") or "")[:8000],
                "is_subtechnique": is_sub,
                "parent_technique_id": parent_id,
            }
        )
    return techniques


# ---------------------------------------------------------------------------
# Bundle fetch
# ---------------------------------------------------------------------------


async def fetch_bundle(url: str | None = None, path: str | None = None) -> dict[str, Any]:
    """Load the STIX bundle from local disk or HTTP. ``path`` wins if set."""
    path = path or os.getenv("ATTCK_BUNDLE_PATH")
    if path:
        logger.info("attck.bundle.local", path=path)
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    url = url or os.getenv("ATTCK_BUNDLE_URL") or DEFAULT_BUNDLE_URL
    logger.info("attck.bundle.fetch", url=url)
    async with httpx.AsyncClient(timeout=120.0) as http:
        r = await http.get(url)
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


async def has_techniques_in_qdrant() -> int:
    """Return how many points are already in ``attck_techniques``."""
    client = get_qdrant_client()
    try:
        resp = await client.count(
            collection_name=COLLECTION_ATTCK_TECHNIQUES, exact=False
        )
        return int(getattr(resp, "count", 0))
    except Exception:  # noqa: BLE001
        return 0
    finally:
        try:
            await client.close()
        except Exception:  # noqa: BLE001
            pass


async def count_coverage_rows(session: AsyncSession) -> int:
    """Postgres count of rows in coverage_map."""
    from sqlalchemy import func

    result = await session.execute(select(func.count()).select_from(CoverageMap))
    return int(result.scalar_one())


async def upsert_coverage_row(
    session: AsyncSession, technique: dict[str, Any]
) -> None:
    """Insert-or-update one coverage_map row, keyed by (technique_id, framework).

    Status defaults to ``no_data`` only on insert — re-running the seed
    against an already-mapped row must not stomp M14's coverage status.
    """
    stmt = pg_insert(CoverageMap).values(
        technique_id=technique["technique_id"],
        sub_technique_id=(
            technique["technique_id"] if technique["is_subtechnique"] else None
        ),
        tactic_id=technique.get("tactic_id"),
        tactic_name=technique.get("tactic_name"),
        technique_name=technique.get("technique_name"),
        framework="attck",
        description=technique.get("description"),
        has_subtechniques=False,  # set in a second pass below
        parent_technique_id=technique.get("parent_technique_id"),
    )
    # Update the descriptive columns (technique names change between
    # ATT&CK releases) but preserve operational columns (coverage_status,
    # covering_rule_ids, chain_cve_ids). Those are M14's territory.
    stmt = stmt.on_conflict_do_update(
        constraint="uq_coverage_map_technique_framework",
        set_={
            "tactic_id": stmt.excluded.tactic_id,
            "tactic_name": stmt.excluded.tactic_name,
            "technique_name": stmt.excluded.technique_name,
            "description": stmt.excluded.description,
            "parent_technique_id": stmt.excluded.parent_technique_id,
            "sub_technique_id": stmt.excluded.sub_technique_id,
        },
    )
    await session.execute(stmt)


async def mark_parents_have_subtechniques(
    session: AsyncSession, techniques: list[dict[str, Any]]
) -> None:
    """Flip ``has_subtechniques=true`` on every parent that has at least one sub."""
    parents = {t["parent_technique_id"] for t in techniques if t.get("parent_technique_id")}
    if not parents:
        return
    rows = await session.execute(
        select(CoverageMap).where(
            CoverageMap.framework == "attck",
            CoverageMap.technique_id.in_(parents),
        )
    )
    for row in rows.scalars().all():
        row.has_subtechniques = True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def seed(force: bool = False, batch_size: int = 16) -> dict[str, int]:
    """End-to-end seed. Returns ``{parsed, embedded, upserted, skipped}``."""
    # Standalone scripts don't get the FastAPI lifespan, so the LLM
    # provider registry is empty by default — that left every embedding
    # call returning ``None`` and silently failing into Qdrant (Phase 4
    # audit C0a). Bootstrap once before VectorEmbedder construction.
    await bootstrap_providers_for_scripts()
    # Ensure collections exist first so the first upsert doesn't fail with
    # 'collection does not exist'.
    await ensure_collections()

    sm = get_sessionmaker()
    async with sm() as session:
        if not force:
            qdrant_count = await has_techniques_in_qdrant()
            pg_count = await count_coverage_rows(session)
            if qdrant_count >= MIN_TECHNIQUES and pg_count >= MIN_TECHNIQUES:
                logger.info(
                    "attck.seed.skipped",
                    reason="already_populated",
                    qdrant_count=qdrant_count,
                    pg_count=pg_count,
                )
                return {
                    "parsed": 0,
                    "embedded": 0,
                    "upserted": 0,
                    "skipped": qdrant_count,
                }

        bundle = await fetch_bundle()
        techniques = parse_attck_techniques(bundle)
        logger.info("attck.seed.parsed", count=len(techniques))

        # 1) Postgres pass: every technique becomes a coverage_map row.
        for t in techniques:
            await upsert_coverage_row(session, t)
        await session.flush()
        await mark_parents_have_subtechniques(session, techniques)
        await session.commit()

        # 2) Qdrant pass: embed in batches. We embed via the VectorEmbedder
        # which routes through the LLM provider registry — same path the
        # runtime embed pipeline uses.
        async with VectorEmbedder() as embedder:
            embedded = 0
            for i in range(0, len(techniques), batch_size):
                batch = techniques[i : i + batch_size]
                for t in batch:
                    try:
                        ok = await embedder.upsert_technique(
                            technique_id=t["technique_id"],
                            technique_name=t["technique_name"],
                            tactic_id=t.get("tactic_id"),
                            tactic_name=t.get("tactic_name"),
                            description=t.get("description") or "",
                            framework="attck",
                            has_subtechniques=False,
                            parent_technique_id=t.get("parent_technique_id"),
                        )
                        if ok:
                            embedded += 1
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "attck.seed.technique_failed",
                            technique_id=t.get("technique_id"),
                            error=str(exc),
                        )

        return {
            "parsed": len(techniques),
            "embedded": embedded,
            "upserted": len(techniques),
            "skipped": 0,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-embed even if Qdrant + Postgres already look populated",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=16,
        help="Batch size for embedding calls (default 16)",
    )
    args = parser.parse_args(argv)

    async def _run_and_dispose() -> dict[str, int]:
        try:
            return await seed(force=args.force, batch_size=args.batch_size)
        finally:
            await dispose_engine()

    # Single event loop for the whole lifecycle so asyncpg's connection-close
    # coroutines see the same loop they were created on (Phase 4 audit C0c).
    out = asyncio.run(_run_and_dispose())
    print(
        f"ATT&CK seed complete: parsed={out['parsed']} "
        f"embedded={out['embedded']} upserted={out['upserted']} "
        f"skipped={out['skipped']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
