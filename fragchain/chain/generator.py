"""Attack chain synthesis pipeline (M11).

This is the heart of the platform: given a CVE that's reached
``processing_status='synthesizing'``, produce a validated ``AttackChain`` and
persist it to ``attack_chains`` + ``chain_ttps``.

Pipeline (mirrors CLAUDE.md §12 and the M11 module spec):

  1. **Commons check** — if any configured commons source already has a chain
     for this CVE, project it into the local schema and skip the LLM entirely.
     Cost-free hit on a community-validated chain is always preferable to a
     fresh LLM run.
  2. **Context load** — pull the CVE row, attached source documents, and CTID
     attack patterns out of Postgres.
  3. **RAG retrieval** — semantic search ``source_chunks`` (M8) scoped to this
     CVE for ~20 high-quality excerpts.
  4. **Context budgeting** — sort excerpts by quality and fill up to ~55k
     tokens, leaving room for the system prompt + structured fields + the
     model's output budget.
  5. **Prompt resolution** — load the active ``chain_generation`` template via
     :class:`ABTestRouter` (M9) so an in-flight A/B experiment is honoured.
  6. **LLM call** — talk to M5 ``LiteLLMProvider`` with the rendered system +
     user prompts. ``interaction_type=CHAIN_GENERATION``, ``entity_type='cve'``
     so the audit trail in ``llm_interactions`` is searchable.
  7. **Parse + validate** — strip code-fence markers, JSON-parse, validate
     against the :class:`AttackChain` Pydantic schema (M10).
  8. **Retry on validation failure** — append the validation errors as
     feedback and re-prompt the model, up to two retries. After that we raise
     :class:`ChainGenerationError`.
  9. **TLP propagation** — set ``chain.tlp = max(explicit, max(source.tlp))``
     so the chain inherits the most restrictive classification touching it.
 10. **Persistence** — write one ``attack_chains`` row + N ``chain_ttps``
     rows in a single transaction, then queue ``map_coverage`` (M14).

The generator is provider-agnostic at the call site — it consumes a
``LLMProvider`` injected via the registry. Tests replace the registry with a
stub.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

import structlog
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.chain.schema import AttackChain, ChainTTP, SourceRef
from fragchain.config import get_settings
from fragchain.db.models import (
    CVE,
    AttackChainRow,
    ChainTTPRow,
    SourceDocument,
)
from fragchain.llm import (
    InteractionType,
    LLMError,
    LLMProvider,
    get_registry,
)
from fragchain.prompts import ABTestRouter
from fragchain.security.tlp import TLP, max_tlp

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Hard upper bound on the document-context block we hand to the model. Leaves
# room for the system prompt (~1-2k), structured fields (~1-2k), and the
# model's output (~8-16k) inside a 128k-context model. Operators on tighter
# contexts can configure a smaller cap via the chain_generation prompt.
RAG_CONTEXT_TOKEN_BUDGET: int = 55_000

# Hits to pull from Qdrant per RAG round. The budgeter then drops anything
# that doesn't fit the token budget after sorting by quality.
RAG_RESULT_LIMIT: int = 20

# Validation retry budget. Three attempts total: the initial call + 2 retries
# that feed Pydantic errors back into the prompt.
MAX_VALIDATION_RETRIES: int = 2


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ChainGenerationError(Exception):
    """Raised when synthesis can't produce a valid chain.

    Carries a ``stage`` field (``commons_check``, ``llm_call``, ``validation``,
    ``persist``) and the underlying error so the Celery task can record it on
    ``cves.processing_error`` with the right ``processing_stage``.
    """

    def __init__(self, message: str, *, stage: str, cause: Exception | None = None) -> None:
        super().__init__(message)
        self.stage = stage
        self.cause = cause


class CVENotReadyError(ChainGenerationError):
    """The CVE isn't in a state the generator is willing to process."""

    def __init__(self, cve_id: str, current_status: str | None) -> None:
        super().__init__(
            f"CVE {cve_id} not ready for synthesis (status={current_status!r})",
            stage="precondition",
        )
        self.cve_id = cve_id
        self.current_status = current_status


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class GenerationOutcome:
    """What the generator returns to the caller.

    ``source_origin`` is the same value persisted on the row; ``commons_chain_id``
    is set on a commons hit and ``None`` on a fresh LLM synthesis. ``chain_id``
    is the UUID of the new ``attack_chains`` row.
    """

    chain_id: uuid.UUID
    cve_id: str
    source_origin: str  # 'local' | 'commons'
    commons_chain_id: str | None
    overall_confidence: float
    tlp: TLP
    llm_skipped: bool
    interaction_id: uuid.UUID | None = None
    validation_attempts: int = 0
    technique_ids: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_CODE_FENCE_RE = re.compile(
    r"^\s*```(?:json|JSON)?\s*\n(?P<body>.*?)\n```\s*$",
    re.DOTALL,
)


def _strip_json_fences(text: str) -> str:
    """Extract the JSON payload from a model response.

    Handles ` ```json ... ``` `, ` ``` ... ``` `, and naked JSON. Falls back
    to slicing between the first ``{`` and the last ``}`` if no fence is
    present and there's prose around the JSON.
    """
    if not text:
        return text
    stripped = text.strip()
    match = _CODE_FENCE_RE.match(stripped)
    if match:
        return match.group("body").strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped
    # Last-resort: pull the largest {...} span. Handles "Here is the chain: { ... }."
    first = stripped.find("{")
    last = stripped.rfind("}")
    if first != -1 and last != -1 and last > first:
        return stripped[first : last + 1]
    return stripped


def _approx_tokens(text: str) -> int:
    """Cheap token estimator — 4 chars ≈ 1 token (English text heuristic).

    Avoids importing tiktoken here so the generator stays fast on the prompt-
    building hot path. The token budget is approximate by design.
    """
    if not text:
        return 0
    return max(1, len(text) // 4)


def _format_references_block(documents: list[SourceDocument]) -> str:
    """Render the list of attached documents as a model-friendly references list.

    Each line includes the URL (the model is told to cite from these only),
    source type, and quality score so the LLM can rank source credibility.
    """
    if not documents:
        return "(no references available — base the chain on the CVE description and CVSS metadata only)"
    lines: list[str] = []
    for doc in documents:
        url = doc.url or "(no url)"
        kind = doc.source_type or "other"
        quality = float(doc.quality_score) if doc.quality_score is not None else 0.5
        lines.append(f"- [{kind} q={quality:.2f}] {url}")
    return "\n".join(lines)


def _format_affected_products(value: Any) -> str:
    if not value:
        return "(none recorded)"
    try:
        return json.dumps(value, indent=2, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def _format_attack_patterns(patterns: list[Any]) -> str:
    """Render CTID attack-pattern hints as a one-line summary per entry."""
    if not patterns:
        return "(no CTID attack patterns available)"
    lines: list[str] = []
    for entry in patterns:
        if isinstance(entry, dict):
            tid = entry.get("technique_id") or entry.get("id") or "?"
            name = entry.get("name") or entry.get("technique_name") or ""
            tactic = entry.get("tactic") or entry.get("tactic_id") or ""
            lines.append(f"- {tid} {name} [{tactic}]".strip())
        else:
            lines.append(f"- {entry}")
    return "\n".join(lines)


def _budget_rag_chunks(
    chunks: list[Any],
    *,
    token_budget: int = RAG_CONTEXT_TOKEN_BUDGET,
) -> list[Any]:
    """Sort RAG chunks by quality, then fill until we exceed ``token_budget``.

    Items missing ``quality_score`` are treated as 0.5 (neutral). Ties keep
    Qdrant's original score-based order so the top semantic match always
    wins among equal-quality docs.
    """
    if not chunks:
        return []

    def key(c: Any) -> tuple[float, float]:
        q = getattr(c, "quality_score", None)
        s = getattr(c, "score", None) or 0.0
        return (float(q) if q is not None else 0.5, float(s))

    ranked = sorted(chunks, key=key, reverse=True)
    out: list[Any] = []
    total = 0
    for c in ranked:
        text = getattr(c, "text", "") or ""
        cost = _approx_tokens(text)
        if total + cost > token_budget and out:
            break
        out.append(c)
        total += cost
    return out


def _format_rag_block(chunks: list[Any]) -> str:
    """Render selected RAG chunks as numbered, attributed excerpts."""
    if not chunks:
        return "(no RAG excerpts retrieved)"
    parts: list[str] = []
    for i, c in enumerate(chunks, start=1):
        url = getattr(c, "url", None) or "(unknown source)"
        kind = getattr(c, "source_type", None) or "other"
        quality = getattr(c, "quality_score", None)
        text = (getattr(c, "text", "") or "").strip()
        header = f"[#{i}] {kind} {url}"
        if quality is not None:
            header += f" (quality {float(quality):.2f})"
        parts.append(f"{header}\n{text}")
    return "\n\n".join(parts)


def _coerce_tlp(value: Any) -> TLP:
    if value is None or value == "":
        return TLP.CLEAR
    if isinstance(value, TLP):
        return value
    try:
        return TLP.parse(str(value))
    except ValueError:
        return TLP.CLEAR


def _propagate_chain_tlp(
    *,
    explicit: TLP | str | None,
    documents: list[SourceDocument],
    rag_hits: list[Any],
) -> TLP:
    """Compute the chain's effective TLP per CLAUDE.md §8.

    Chain TLP = max(explicit, max(source.tlp for source in sources)). The
    documents list contributes its row-level TLP; RAG hits contribute the
    TLP that landed on the Qdrant chunk's payload.
    """
    levels: list[TLP | str | None] = [explicit]
    for doc in documents:
        levels.append(doc.tlp)
    for hit in rag_hits:
        levels.append(getattr(hit, "tlp", None))
    return max_tlp(*levels)


def _sources_used_from_documents(documents: list[SourceDocument]) -> list[dict[str, Any]]:
    """Build a ``sources_used`` list of dicts from the attached documents.

    Returned shape matches ``SourceRef`` exactly so callers can validate it
    through the Pydantic model or store it straight to JSONB.
    """
    out: list[dict[str, Any]] = []
    for doc in documents:
        if not doc.url:
            continue
        excerpt = ""
        meta = doc.document_metadata or {}
        if isinstance(meta, dict):
            for key in ("excerpt", "summary", "description"):
                value = meta.get(key)
                if isinstance(value, str) and value.strip():
                    excerpt = value.strip()
                    break
            if not excerpt:
                content = meta.get("content")
                if isinstance(content, str) and content.strip():
                    excerpt = content.strip()[:240]
        out.append(
            {
                "url": doc.url,
                "source_type": doc.source_type or "other",
                "quality_score": float(doc.quality_score) if doc.quality_score is not None else 0.5,
                "excerpt_summary": excerpt or f"{doc.source_type or 'reference'} for {doc.url}",
            }
        )
    return out


def _validation_feedback(error: ValidationError) -> str:
    """Render a ``ValidationError`` as a concise, actionable feedback block.

    Up to ten errors are surfaced verbatim; further ones are summarised so we
    don't blow the retry-prompt up to thousands of tokens.
    """
    errors = error.errors()
    head = errors[:10]
    lines = ["Your previous JSON failed schema validation. Errors:"]
    for err in head:
        loc = ".".join(str(p) for p in err.get("loc", ()))
        msg = err.get("msg", "")
        lines.append(f"  - {loc}: {msg}")
    if len(errors) > 10:
        lines.append(f"  ... and {len(errors) - 10} more")
    lines.append(
        "Re-emit the AttackChain JSON object with these issues fixed. "
        "Output ONLY the JSON object — no prose, no fences."
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Commons projection
# ---------------------------------------------------------------------------


def _project_commons_chain(
    *,
    commons_data: dict[str, Any],
    cve_textual_id: str,
    source_id: str,
) -> AttackChain:
    """Coerce a commons chain JSON into a local ``AttackChain``.

    Commons chains are validated at import time (M7) but we re-validate here
    because the commons schema might evolve independently. Setting
    ``source_origin='commons'`` and ``commons_chain_id`` is the M10-required
    bookkeeping for "this didn't come from our LLM".

    Forward-compatibility note: :class:`AttackChain` runs with
    ``extra='forbid'`` so a fresh LLM payload that adds a field is rejected
    loudly. Commons feeds, by contrast, are owned by upstream maintainers and
    may carry extra metadata (e.g. ``provenance``) that this engine version
    doesn't model yet. We strip unknown top-level keys before validation so
    a forward-compatible commons payload doesn't crash synthesis, and pair
    that with the ``force_skip_commons`` fallback in
    :meth:`ChainGenerator.generate` so a validation failure on a malformed
    commons row cannot recurse forever (Phase 5 audit L3).
    """
    data = dict(commons_data)  # shallow copy so we don't mutate the JSONB
    data["cve_id"] = cve_textual_id
    data["source_origin"] = "commons"
    data["commons_chain_id"] = f"{source_id}:{cve_textual_id}@{data.get('version', 1)}"
    # Hand-validated commons chains land with provider='human' / model='ground-truth'.
    data.setdefault("provider", "human")
    data.setdefault("model", "ground-truth")
    allowed_keys = set(AttackChain.model_fields)
    projected = {k: v for k, v in data.items() if k in allowed_keys}
    return AttackChain.model_validate(projected)


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


class ChainGenerator:
    """RAG-augmented attack-chain synthesizer.

    Construct once per task with an :class:`AsyncSession`. The generator is
    not thread-safe — Celery hands each invocation its own session, which is
    the contract the worker tasks already follow.

    Dependencies are injected so unit tests can pass stubs:

      * ``commons_client`` — :class:`fragchain.commons.CommonsClient` for the
        skip-LLM check. Default constructs the real one.
      * ``embedder`` — :class:`fragchain.vector.VectorEmbedder` for the RAG
        retrieval. Default constructs a fresh embedder that talks to Qdrant
        and the registered embedding provider.
      * ``provider`` — :class:`LLMProvider` for ``complete()``. Default pulls
        the chat-default from the registry.
      * ``router`` — :class:`ABTestRouter` for prompt selection. Default
        constructs one over ``session``.
    """

    def __init__(
        self,
        session: AsyncSession,
        *,
        commons_client: Any | None = None,
        embedder: Any | None = None,
        provider: LLMProvider | None = None,
        router: ABTestRouter | None = None,
        model: str | None = None,
    ) -> None:
        self._session = session
        self._commons_client = commons_client
        self._embedder = embedder
        self._provider = provider
        self._router = router
        self._model = model

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def generate(
        self,
        cve_id: str | uuid.UUID,
        *,
        force_skip_commons: bool = False,
    ) -> GenerationOutcome:
        """Run the full pipeline for one CVE. Returns a :class:`GenerationOutcome`.

        ``cve_id`` may be the textual ``CVE-YYYY-NNNN`` form or the CVE row's
        UUID. The state machine transitions are owned by the Celery task wrapper
        — this method does not mutate ``processing_status``.

        ``force_skip_commons`` is the recursion guard used by
        :meth:`_persist_commons_hit` when projecting a commons hit fails
        validation: setting it to True skips :meth:`_check_commons` and goes
        straight to LLM synthesis, so the fallback can never re-find the same
        commons row and recurse (Phase 5 audit L3 / Phase 4 audit D5).
        """
        cve = await self._load_cve(cve_id)
        if cve is None:
            raise ChainGenerationError(
                f"CVE {cve_id!r} not found", stage="precondition"
            )

        # 1. Commons check ------------------------------------------------
        if not force_skip_commons:
            commons_hit = await self._check_commons(cve.cve_id)
            if commons_hit is not None:
                return await self._persist_commons_hit(cve, commons_hit)

        # 2. Context load + 3. RAG + 4. Budget ---------------------------
        documents = await self._load_documents(cve)
        rag_hits = await self._rag_retrieve(cve)
        budgeted = _budget_rag_chunks(rag_hits)

        # 5. Prompt resolution -------------------------------------------
        selection = await self._select_prompt(cve)

        # 6+7+8. LLM call with validation retries ------------------------
        rendered_user = self._render_user_prompt(
            template=selection.template.user_template,
            cve=cve,
            documents=documents,
            rag_hits=budgeted,
        )
        parsed_chain, interaction_id, attempts = await self._call_with_retries(
            cve=cve,
            system_prompt=selection.template.system_prompt,
            initial_user_prompt=rendered_user,
            prompt_template_id=selection.template.id,
            prompt_version=selection.template.version,
        )

        # 9. TLP propagation ---------------------------------------------
        propagated = _propagate_chain_tlp(
            explicit=parsed_chain.tlp,
            documents=documents,
            rag_hits=budgeted,
        )

        # Force the source attribution + provenance fields on the chain so
        # downstream consumers never have to guess.
        finalised = parsed_chain.model_copy(
            update={
                "cve_id": cve.cve_id,
                "tlp": propagated,
                "source_origin": "local",
                "commons_chain_id": None,
                "provider": self._provider_name(),
                "model": self._model_alias(),
                "prompt_template_id": selection.template.id,
            }
        )
        # Backfill sources_used from attached documents when the model omitted them.
        if not finalised.sources_used and documents:
            finalised = finalised.model_copy(
                update={
                    "sources_used": [
                        SourceRef.model_validate(s)
                        for s in _sources_used_from_documents(documents)
                    ]
                }
            )

        # 10. Persistence -----------------------------------------------
        return await self._persist(
            cve=cve,
            chain=finalised,
            interaction_id=interaction_id,
            attempts=attempts,
        )

    # ------------------------------------------------------------------
    # Pipeline stages
    # ------------------------------------------------------------------

    async def _load_cve(self, cve_id: str | uuid.UUID) -> CVE | None:
        if isinstance(cve_id, uuid.UUID):
            return await self._session.get(CVE, cve_id)
        try:
            cve_uuid = uuid.UUID(str(cve_id))
        except (ValueError, TypeError):
            cve_uuid = None
        if cve_uuid is not None:
            row = await self._session.get(CVE, cve_uuid)
            if row is not None:
                return row
        result = await self._session.execute(
            select(CVE).where(CVE.cve_id == str(cve_id).upper())
        )
        return result.scalar_one_or_none()

    async def _check_commons(self, cve_textual_id: str) -> Any | None:
        client = self._commons_client
        if client is None:
            from fragchain.commons import CommonsClient

            client = CommonsClient(self._session)
        try:
            return await client.check_chain_exists(cve_textual_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "chain.commons_check_failed",
                cve_id=cve_textual_id,
                error=str(exc),
            )
            return None

    async def _load_documents(self, cve: CVE) -> list[SourceDocument]:
        result = await self._session.execute(
            select(SourceDocument)
            .where(SourceDocument.cve_id == cve.id)
            .order_by(SourceDocument.created_at.asc())
        )
        return list(result.scalars().all())

    async def _rag_retrieve(self, cve: CVE) -> list[Any]:
        """Pull RAG chunks for ``cve`` from Qdrant.

        We construct a synthesis-flavoured query rather than re-using the
        bare CVE id — embeddings on a CVE description bias the search toward
        the parts of source documents that describe exploitation, which is
        what the chain pipeline cares about.
        """
        query = f"{cve.cve_id} exploitation TTPs"
        embedder = self._embedder
        if embedder is None:
            from fragchain.vector import VectorEmbedder

            embedder = VectorEmbedder()
            self._embedder = embedder
        try:
            return await embedder.search_source_chunks(
                query=query,
                cve_id=cve.cve_id,
                limit=RAG_RESULT_LIMIT,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "chain.rag_retrieval_failed",
                cve_id=cve.cve_id,
                error=str(exc),
            )
            return []

    async def _select_prompt(self, cve: CVE) -> Any:
        router = self._router
        if router is None:
            router = ABTestRouter(self._session)
            self._router = router
        selection = await router.select_variant(
            "chain_generation",
            target_model=self._model_alias(),
            target_provider=self._provider_name(),
            routing_key=cve.cve_id,
        )
        if selection is None:
            raise ChainGenerationError(
                "No active chain_generation prompt template",
                stage="prompt_resolution",
            )
        return selection

    def _provider_name(self) -> str:
        provider = self._provider
        if provider is None:
            provider = get_registry().get_default_chat_provider()
            if provider is None:
                raise ChainGenerationError(
                    "No chat-capable LLM provider registered "
                    "(install fragchain-provider-litellm)",
                    stage="prompt_resolution",
                )
            self._provider = provider
        return provider.name

    def _model_alias(self) -> str:
        if self._model:
            return self._model
        return get_settings().LITELLM_CHAT_MODEL

    def _render_user_prompt(
        self,
        *,
        template: str,
        cve: CVE,
        documents: list[SourceDocument],
        rag_hits: list[Any],
    ) -> str:
        """Fill the configured prompt template's placeholders.

        Uses :py:meth:`str.format_map` with a :class:`_SafeMap` so the
        template can reference variables we don't supply without crashing —
        the rendered output keeps the literal ``{unknown_var}`` so the
        operator sees the typo on the next eval run.
        """
        kev = "yes" if cve.cisa_kev else "no"
        epss = float(cve.epss_score) if cve.epss_score is not None else 0.0
        attackerkb = (
            float(cve.attackerkb_score)
            if cve.attackerkb_score is not None
            else 0.0
        )
        cvss = float(cve.cvss_score) if cve.cvss_score is not None else 0.0
        description = (cve.description or "").strip()
        if not description:
            # Transitional fallback for rows imported before the
            # ``cves.description`` column existed (migration 0019): the manual
            # endpoint used to stuff the body into raw_connector_data.raw.description.
            raw = cve.raw_connector_data if isinstance(cve.raw_connector_data, dict) else {}
            legacy = raw.get("description")
            if not isinstance(legacy, str):
                legacy_raw = raw.get("raw") if isinstance(raw.get("raw"), dict) else {}
                legacy = legacy_raw.get("description") if isinstance(legacy_raw, dict) else None
            if isinstance(legacy, str):
                description = legacy.strip()
        # Final fallback: search attached documents for a description.
        if not description and documents:
            for doc in documents:
                m = doc.document_metadata or {}
                if isinstance(m, dict):
                    candidate = m.get("description") or m.get("excerpt") or m.get("summary")
                    if isinstance(candidate, str) and candidate.strip():
                        description = candidate
                        break

        attack_patterns_text = _format_attack_patterns(
            list(cve.ctid_techniques or [])
        )
        references_text = _format_references_block(documents)
        rag_text = _format_rag_block(rag_hits)
        values: dict[str, str] = {
            "cve_id": cve.cve_id,
            "cve_description": description or "(no description available)",
            "cvss_score": f"{cvss:.1f}" if cvss else "0.0",
            "cvss_vector": cve.cvss_vector or "(none)",
            "epss_score": f"{epss:.4f}" if epss else "0.0",
            "kev": kev,
            "attackerkb_score": f"{attackerkb:.2f}" if attackerkb else "0.0",
            "affected_products": _format_affected_products(cve.affected_products),
            "attack_patterns": attack_patterns_text,
            "ctid_techniques": attack_patterns_text,
            "references": references_text,
            "rag_context": rag_text,
        }
        try:
            return template.format_map(_SafeMap(values))
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "chain.prompt_render_failed",
                cve_id=cve.cve_id,
                error=str(exc),
            )
            # Fall back to a hand-built prompt so a templating bug doesn't
            # block synthesis.
            return _fallback_user_prompt(values)

    async def _call_with_retries(
        self,
        *,
        cve: CVE,
        system_prompt: str,
        initial_user_prompt: str,
        prompt_template_id: uuid.UUID,
        prompt_version: int,
    ) -> tuple[AttackChain, uuid.UUID | None, int]:
        """Call the LLM, validate, and re-prompt on validation failure.

        Returns ``(parsed_chain, interaction_id, attempts)`` on success.
        Raises :class:`ChainGenerationError` after :data:`MAX_VALIDATION_RETRIES`
        validation failures or any non-recoverable LLM error.
        """
        provider = self._provider
        if provider is None:
            provider = get_registry().get_default_chat_provider()
            if provider is None:
                raise ChainGenerationError(
                    "No chat-capable LLM provider registered",
                    stage="llm_call",
                )
            self._provider = provider

        user_prompt = initial_user_prompt
        last_validation_error: ValidationError | None = None
        last_interaction_id: uuid.UUID | None = None
        for attempt in range(MAX_VALIDATION_RETRIES + 1):
            try:
                response = await provider.complete(
                    system=system_prompt,
                    prompt=user_prompt,
                    model=self._model_alias(),
                    interaction_type=InteractionType.CHAIN_GENERATION,
                    entity_type="cve",
                    entity_id=cve.id,
                    prompt_template_id=prompt_template_id,
                    prompt_version=prompt_version,
                )
            except LLMError as exc:
                logger.exception(
                    "chain.llm_call_failed",
                    cve_id=cve.cve_id,
                    attempt=attempt + 1,
                    error=str(exc),
                )
                raise ChainGenerationError(
                    f"LLM call failed: {exc}",
                    stage="llm_call",
                    cause=exc,
                ) from exc
            last_interaction_id = response.interaction_id

            raw_text = response.text or ""
            payload_text = _strip_json_fences(raw_text)
            try:
                payload = json.loads(payload_text)
            except json.JSONDecodeError as exc:
                logger.info(
                    "chain.parse_failed",
                    cve_id=cve.cve_id,
                    attempt=attempt + 1,
                    error=str(exc),
                )
                if attempt >= MAX_VALIDATION_RETRIES:
                    raise ChainGenerationError(
                        f"Model produced non-JSON output after {attempt + 1} attempts",
                        stage="validation",
                        cause=exc,
                    ) from exc
                user_prompt = (
                    f"{initial_user_prompt}\n\n---\n"
                    f"Your previous response could not be parsed as JSON: {exc}.\n"
                    "Re-emit the AttackChain JSON object only."
                )
                continue

            # Force the cve_id on the payload so the model can't drift.
            if isinstance(payload, dict):
                payload["cve_id"] = cve.cve_id
            try:
                parsed = AttackChain.model_validate(payload)
            except ValidationError as exc:
                last_validation_error = exc
                logger.info(
                    "chain.validation_failed",
                    cve_id=cve.cve_id,
                    attempt=attempt + 1,
                    error_count=len(exc.errors()),
                )
                if attempt >= MAX_VALIDATION_RETRIES:
                    raise ChainGenerationError(
                        f"Chain schema validation failed after {attempt + 1} attempts "
                        f"({len(exc.errors())} errors)",
                        stage="validation",
                        cause=exc,
                    ) from exc
                feedback = _validation_feedback(exc)
                user_prompt = f"{initial_user_prompt}\n\n---\n{feedback}"
                continue

            return parsed, last_interaction_id, attempt + 1

        # Unreachable — every branch returns or raises.
        raise ChainGenerationError(
            "validation retry loop exited without result",
            stage="validation",
            cause=last_validation_error,
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def _persist(
        self,
        *,
        cve: CVE,
        chain: AttackChain,
        interaction_id: uuid.UUID | None,
        attempts: int,
    ) -> GenerationOutcome:
        """Write the chain to ``attack_chains`` + ``chain_ttps`` and queue M14."""
        chain_id = await self._insert_chain_rows(
            cve=cve, chain=chain, version=await self._next_version(cve.id)
        )
        try:
            await self._session.commit()
        except Exception as exc:  # noqa: BLE001
            await self._session.rollback()
            raise ChainGenerationError(
                f"Failed to persist chain: {exc}",
                stage="persist",
                cause=exc,
            ) from exc

        # Best-effort chain summary embed for cross-CVE reuse (M8 helper).
        await self._upsert_chain_summary(chain_id=chain_id, chain=chain)
        # Queue M14 — best-effort, the budget tick is the safety net.
        self._queue_map_coverage(chain_id)
        # Emit the synthesis event so M19 / future WS subscribers see it.
        try:
            from fragchain.notifications import emit_event

            emit_event(
                "chain_generated",
                {
                    "cve_id": cve.cve_id,
                    "chain_id": str(chain_id),
                    "confidence": float(chain.overall_confidence),
                    "source_origin": chain.source_origin,
                    "tlp": str(chain.tlp),
                    "llm_skipped": False,
                    "validation_attempts": attempts,
                },
                # F-010: opt into per-event visibility filtering so the
                # bus only delivers this event to subscribers cleared for
                # the chain's effective TLP.
                tlp=str(chain.tlp),
                entity_id=chain_id,
                embargoed=bool(getattr(chain, "embargo_until", None)),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("chain.emit_event_failed", error=str(exc))

        logger.info(
            "chain.generated",
            cve_id=cve.cve_id,
            chain_id=str(chain_id),
            ttps=len(chain.chain),
            tlp=str(chain.tlp),
            overall_confidence=float(chain.overall_confidence),
            validation_attempts=attempts,
        )
        return GenerationOutcome(
            chain_id=chain_id,
            cve_id=cve.cve_id,
            source_origin="local",
            commons_chain_id=None,
            overall_confidence=float(chain.overall_confidence),
            tlp=chain.tlp,
            llm_skipped=False,
            interaction_id=interaction_id,
            validation_attempts=attempts,
            technique_ids=[ttp.technique_id for ttp in chain.chain],
        )

    async def _persist_commons_hit(
        self, cve: CVE, hit: Any
    ) -> GenerationOutcome:
        """Project a commons hit into a local chain row and queue M14."""
        try:
            chain = _project_commons_chain(
                commons_data=hit.data,
                cve_textual_id=cve.cve_id,
                source_id=str(hit.source_id),
            )
        except ValidationError as exc:
            # Commons chain didn't pass our schema — fall through to LLM.
            # Pass ``force_skip_commons=True`` so the recursive call cannot
            # re-find the same commons hit and recurse indefinitely
            # (Phase 5 audit L3 / Phase 4 audit D5).
            logger.warning(
                "chain.commons_payload_invalid",
                cve_id=cve.cve_id,
                source=hit.source_name,
                error=str(exc),
            )
            return await self.generate(cve.id, force_skip_commons=True)

        chain_id = await self._insert_chain_rows(
            cve=cve, chain=chain, version=await self._next_version(cve.id)
        )
        try:
            await self._session.commit()
        except Exception as exc:  # noqa: BLE001
            await self._session.rollback()
            raise ChainGenerationError(
                f"Failed to persist commons chain: {exc}",
                stage="persist",
                cause=exc,
            ) from exc

        await self._upsert_chain_summary(chain_id=chain_id, chain=chain)
        self._queue_map_coverage(chain_id)
        try:
            from fragchain.notifications import emit_event

            emit_event(
                "chain_skipped_using_commons",
                {
                    "cve_id": cve.cve_id,
                    "chain_id": str(chain_id),
                    "commons_source": hit.source_name,
                    "commons_source_id": str(hit.source_id),
                    "commons_chain_id": chain.commons_chain_id,
                    "tlp": str(chain.tlp),
                },
                # F-010: opt into per-event visibility filtering.
                tlp=str(chain.tlp),
                entity_id=chain_id,
                embargoed=bool(getattr(chain, "embargo_until", None)),
            )
            emit_event(
                "chain_generated",
                {
                    "cve_id": cve.cve_id,
                    "chain_id": str(chain_id),
                    "confidence": float(chain.overall_confidence),
                    "source_origin": "commons",
                    "tlp": str(chain.tlp),
                    "llm_skipped": True,
                },
                tlp=str(chain.tlp),
                entity_id=chain_id,
                embargoed=bool(getattr(chain, "embargo_until", None)),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("chain.emit_event_failed", error=str(exc))

        logger.info(
            "chain.commons_hit",
            cve_id=cve.cve_id,
            chain_id=str(chain_id),
            source=hit.source_name,
            source_id=str(hit.source_id),
        )
        return GenerationOutcome(
            chain_id=chain_id,
            cve_id=cve.cve_id,
            source_origin="commons",
            commons_chain_id=chain.commons_chain_id,
            overall_confidence=float(chain.overall_confidence),
            tlp=chain.tlp,
            llm_skipped=True,
            interaction_id=None,
            validation_attempts=0,
            technique_ids=[ttp.technique_id for ttp in chain.chain],
        )

    async def _next_version(self, cve_pk: uuid.UUID) -> int:
        """Pick the next chain version for ``cve_pk``.

        Reads the current max version + 1 — UNIQUE(cve_id, version) on the
        table guarantees the bump doesn't collide. Concurrent synthesis on
        the same CVE will lose at commit time and the loser can retry.
        """
        result = await self._session.execute(
            select(AttackChainRow.version)
            .where(AttackChainRow.cve_id == cve_pk)
            .order_by(AttackChainRow.version.desc())
            .limit(1)
        )
        current = result.scalar_one_or_none()
        return int(current or 0) + 1

    async def _insert_chain_rows(
        self,
        *,
        cve: CVE,
        chain: AttackChain,
        version: int,
    ) -> uuid.UUID:
        """Insert one ``attack_chains`` row + N ``chain_ttps`` rows.

        Returns the new ``attack_chains.id``. The session is left dirty —
        the caller commits.
        """
        chain_json = chain.model_dump(mode="json")
        # Strip top-level metadata that lives in dedicated columns; chain[] is
        # what M14 / M20 read from JSONB. Keep the JSONB self-contained so a
        # reader can reconstruct the Pydantic model from the column alone.
        row = AttackChainRow(
            cve_id=cve.id,
            version=version,
            model=chain.model,
            provider=chain.provider,
            prompt_template_id=chain.prompt_template_id,
            overall_confidence=Decimal(str(round(float(chain.overall_confidence), 2))),
            chain=chain_json["chain"],
            sources_used=chain_json.get("sources_used", []),
            predicted_impact=chain.predicted_impact,
            detection_gaps=list(chain.detection_gaps),
            tlp=str(chain.tlp),
            embargo_until=chain.embargo_until,
            status="draft",
            source_origin=chain.source_origin,
            commons_chain_id=chain.commons_chain_id,
            created_at=datetime.now(tz=timezone.utc),
        )
        self._session.add(row)
        await self._session.flush()

        for ttp in chain.chain:
            self._session.add(
                ChainTTPRow(
                    chain_id=row.id,
                    seq_order=ttp.seq_order,
                    tactic=ttp.tactic,
                    tactic_id=ttp.tactic_id,
                    technique_id=ttp.technique_id,
                    technique_name=ttp.technique_name,
                    sub_technique_id=ttp.sub_technique_id,
                    framework=ttp.framework,
                    confidence=Decimal(str(round(float(ttp.confidence), 2))),
                    preconditions=list(ttp.preconditions),
                    detection_opportunity=ttp.detection_opportunity,
                    source_refs=[s.model_dump(mode="json") for s in ttp.source_refs],
                )
            )
        await self._session.flush()
        return row.id

    async def _upsert_chain_summary(
        self, *, chain_id: uuid.UUID, chain: AttackChain
    ) -> None:
        """Embed a chain summary into Qdrant ``attack_chains`` for cross-CVE reuse.

        Failure here is best-effort — a missing Qdrant must not roll back the
        chain row.
        """
        try:
            embedder = self._embedder
            if embedder is None:
                from fragchain.vector import VectorEmbedder

                embedder = VectorEmbedder()
                self._embedder = embedder
            summary = " | ".join(
                [
                    f"{chain.cve_id}",
                    chain.predicted_impact[:200],
                    *(
                        f"{ttp.technique_id} {ttp.technique_name}"
                        for ttp in chain.chain
                    ),
                ]
            )
            await embedder.upsert_chain_summary(
                chain_id=chain_id,
                cve_id=chain.cve_id,
                summary=summary,
                overall_confidence=float(chain.overall_confidence),
                technique_ids=[t.technique_id for t in chain.chain],
            )
        except Exception as exc:  # noqa: BLE001
            logger.info(
                "chain.summary_embed_failed",
                chain_id=str(chain_id),
                error=str(exc),
            )

    def _queue_map_coverage(self, chain_id: uuid.UUID) -> None:
        """Dispatch the M14 coverage-mapping task. Best-effort — never raises."""
        try:
            from fragchain.worker.celery import celery_app

            celery_app.send_task(
                "fragchain.worker.tasks.map_coverage",
                kwargs={"chain_id": str(chain_id)},
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "chain.queue_map_coverage_failed",
                chain_id=str(chain_id),
                error=str(exc),
            )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class _SafeMap(dict):
    """``dict`` subclass that returns ``{key}`` literal for missing keys.

    Used with :py:meth:`str.format_map` so a prompt template referencing a
    placeholder we didn't supply leaves the literal in place rather than
    raising :class:`KeyError`. The operator sees the typo on the rendered
    prompt and can fix the template.
    """

    def __missing__(self, key: str) -> str:  # type: ignore[override]
        return "{" + key + "}"


def _fallback_user_prompt(values: dict[str, str]) -> str:
    """Plain fallback prompt if the configured template fails to render.

    The fallback covers the four placeholder shapes used by the v1 default
    prompt (`prompts/chain_v1.user.txt`) so synthesis still produces useful
    output if an operator-edited template has a broken placeholder.
    """
    lines = [
        f"CVE under analysis: {values.get('cve_id', '')}",
        "",
        "Description:",
        values.get("cve_description", "(no description available)"),
        "",
        f"CVSS: {values.get('cvss_score', '0.0')} ({values.get('cvss_vector', '')})",
        f"EPSS: {values.get('epss_score', '0.0')}",
        f"CISA KEV: {values.get('kev', 'no')}",
        f"AttackerKB score: {values.get('attackerkb_score', '0.0')}",
        "",
        "Affected products:",
        values.get("affected_products", "(none recorded)"),
        "",
        "References (cite only from these):",
        values.get("references", "(no references available)"),
        "",
        "RAG context:",
        values.get("rag_context", "(no RAG excerpts retrieved)"),
        "",
        f"Task: produce the AttackChain JSON object for {values.get('cve_id', '')} "
        "following the schema and rules in the system prompt. Output ONLY the JSON object.",
    ]
    return "\n".join(lines)


__all__ = [
    "ChainGenerationError",
    "ChainGenerator",
    "CVENotReadyError",
    "GenerationOutcome",
    "MAX_VALIDATION_RETRIES",
    "RAG_CONTEXT_TOKEN_BUDGET",
    "RAG_RESULT_LIMIT",
]
