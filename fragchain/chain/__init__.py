"""Attack chain schema (M10) + synthesis pipeline (M11).

Two public surfaces here:

  * The Pydantic schema (``AttackChain`` / ``ChainTTP`` / ``SourceRef``) —
    every chain-producing or chain-consuming module imports from here.
  * The synthesis pipeline (``ChainGenerator``) — driven by the
    ``synthesize_chain`` Celery task and the
    ``POST /api/v1/cves/{cve_id}/resynthesize`` endpoint.
"""
from fragchain.security.embargo import EmbargoedTable, register_embargoed_table

# Register the M10 table for embargo auto-release. M2's `release_embargoed_content`
# Celery task walks this registry every 5 min; mirrors the M6 wiring in
# `fragchain/ingest/__init__.py`. Without this, an embargoed chain stays TLP:RED
# forever even after `embargo_until` passes (Phase 4 audit C1 / D1).
register_embargoed_table(
    EmbargoedTable(table="attack_chains", entity_type="attack_chain")
)

from fragchain.chain.generator import (
    ChainGenerationError,
    ChainGenerator,
    CVENotReadyError,
    GenerationOutcome,
    MAX_VALIDATION_RETRIES,
    RAG_CONTEXT_TOKEN_BUDGET,
    RAG_RESULT_LIMIT,
)
from fragchain.chain.schema import (
    AttackChain,
    ChainTTP,
    Framework,
    SourceRef,
    SUB_TECHNIQUE_ID_PATTERN,
    TACTIC_ID_PATTERN,
    TECHNIQUE_ID_PATTERN,
)

__all__ = [
    "AttackChain",
    "ChainGenerationError",
    "ChainGenerator",
    "ChainTTP",
    "CVENotReadyError",
    "Framework",
    "GenerationOutcome",
    "MAX_VALIDATION_RETRIES",
    "RAG_CONTEXT_TOKEN_BUDGET",
    "RAG_RESULT_LIMIT",
    "SUB_TECHNIQUE_ID_PATTERN",
    "SourceRef",
    "TACTIC_ID_PATTERN",
    "TECHNIQUE_ID_PATTERN",
]
