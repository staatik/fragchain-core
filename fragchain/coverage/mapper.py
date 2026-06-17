"""Coverage mapper — two-phase ATT&CK technique vs Sigma rule comparison (M14).

For each :class:`AttackChainRow`, this module walks the chain's TTPs and
answers one question per technique: do we already have a detection rule that
covers it?

Two phases, in order:

  * **Phase 1 — exact ATT&CK tag match (PostgreSQL).** Sigma rules with
    ``technique_ids @> ARRAY[<technique_id>]`` and ``status='merged'`` are
    treated as direct coverage. Cheap. Deterministic.

  * **Phase 2 — semantic match (Qdrant + cheap LLM verify).** For techniques
    that came up empty in Phase 1, search the ``sigma_rules`` Qdrant
    collection (M8's embedder) for rules whose semantics resemble the
    technique, then ask the LLM (via M5) ``yes | partial | no`` for each
    candidate. Batched ``asyncio.gather`` (max 10 in flight) so a slow LLM
    doesn't serialise the loop.

The output of one ``map_coverage(chain_id)`` run is:

  * Updated rows in ``coverage_map`` — ``coverage_status``,
    ``covering_rule_ids`` (UUID[]) and ``chain_cve_ids`` (UUID[]) for every
    technique in the chain.
  * Priority scores per gap (CLAUDE.md §12) carried in the returned
    :class:`CoverageReport` so M15's rule generator can pick the right
    queue order.
  * Invalidation of the Redis matrix cache (best-effort).
  * Emission of ``coverage_mapped`` + ``matrix_updated`` events.

Failure modes are bounded — a single bad Qdrant hit or LLM timeout never
takes down the whole run. The mapper logs and continues; the next call
overwrites whatever stale state remains.
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.db.models import (
    CVE,
    AttackChainRow,
    ChainTTPRow,
    CoverageMap,
    SigmaRule,
    SourceDocument,
)
from fragchain.llm import InteractionType
from fragchain.llm.structured import StructuredOutputError, structured_complete

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Tuning constants
# ---------------------------------------------------------------------------

SEMANTIC_SCORE_THRESHOLD: float = 0.75
"""Minimum Qdrant similarity score for a rule to enter the LLM verify path.

Below this the rule and the technique are too dissimilar — sending the pair
through the LLM would burn budget on near-certain ``no`` verdicts."""

SEMANTIC_RESULT_LIMIT: int = 5
"""Top-N rules per uncovered technique returned by ``search_sigma_rules``."""

LLM_VERIFY_PARALLELISM: int = 10
"""Maximum concurrent LLM verify calls in Phase 2.

Bounded with ``asyncio.Semaphore`` so a 200-TTP chain with five candidates
each (1000 LLM calls) doesn't slam the provider with all of them at once."""

LLM_VERIFY_TEMPERATURE: float = 0.0
"""The verify call is deterministic by design — a non-zero temperature would
flip ``yes``/``no`` verdicts unpredictably."""

LLM_VERIFY_MAX_TOKENS: int = 16
"""``yes | partial | no`` plus minor formatting fits comfortably under 16
tokens. Cap saves on token spend."""

LLM_VERIFY_TIMEOUT_SECONDS: float = 20.0
"""Per-call wall-clock budget for the verify path. A slow backend should not
block the rest of the loop."""

LLM_VERIFY_SAMPLES: int = 1
"""Number of ``structured_complete`` samples per verify call.

Chat-LLM verification is now an opt-in precision layer (see
``COVERAGE_LLM_VERIFY_ENABLED``); when enabled we use a single sample to keep
the call count and token spend bounded. A real assessment once fired 1,428
``coverage_verify`` calls at 3 samples each — a single sample is the cost-aware
default."""

LLM_VERIFY_SYSTEM_PROMPT: str = (
    "You decide whether a Sigma detection rule covers an ATT&CK technique for "
    "a specific CVE. Respond with a JSON object matching the VerifyVerdict schema: "
    '{"verdict": "<yes|partial|no>", "one_line_reason": "<brief reason>"}. '
    "verdict meanings: "
    "'yes' = rule would fire on THIS CVE's specific exploitation; "
    "'partial' = rule covers the technique but targets a different product or CVE; "
    "'no' = rule does not cover this exploitation. "
    "JSON only. No explanation outside the JSON object."
)


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------


@dataclass
class CoverageStatus:
    """One technique's coverage outcome inside a :class:`CoverageReport`."""

    technique_id: str
    technique_name: str | None
    tactic_id: str | None
    tactic_name: str | None
    seq_order: int
    coverage_status: str  # "covered" | "partial" | "gap"
    covering_rule_ids: list[uuid.UUID] = field(default_factory=list)
    partial_rule_ids: list[uuid.UUID] = field(default_factory=list)
    priority_score: int = 0
    detection_opportunity: str | None = None


@dataclass
class CoverageReport:
    """Result of one ``CoverageMapper.map_coverage(chain_id)`` run."""

    chain_id: uuid.UUID
    cve_id: uuid.UUID
    cve_textual_id: str | None
    framework: str
    statuses: list[CoverageStatus] = field(default_factory=list)
    covered_count: int = 0
    partial_count: int = 0
    gap_count: int = 0
    llm_verify_calls: int = 0
    llm_verify_yes: int = 0
    llm_verify_partial: int = 0
    llm_verify_no: int = 0
    duration_ms: int = 0

    def gap_techniques(self) -> list[CoverageStatus]:
        return [s for s in self.statuses if s.coverage_status == "gap"]

    def top_gaps(self, n: int = 5) -> list[CoverageStatus]:
        return sorted(self.gap_techniques(), key=lambda s: -s.priority_score)[:n]


class VerifyVerdict(BaseModel):
    """Phase A §3.3 verify schema. Used by both Phase 1.5 and Phase 2.

    - ``yes``: the rule's detection logic would fire on THIS CVE's specific exploitation.
    - ``partial``: the rule covers the technique but targets a different product or CVE.
    - ``no``: the rule does not cover this exploitation.
    """

    model_config = ConfigDict(extra="forbid")

    verdict: str = Field(pattern="^(yes|partial|no)$")
    one_line_reason: str = Field(min_length=1, max_length=200)


@dataclass
class _CandidateHit:
    """One Qdrant candidate awaiting LLM verification."""

    technique_id: str
    technique_name: str | None
    tactic_id: str | None
    tactic_name: str | None
    rule_id: uuid.UUID
    rule_title: str | None
    rule_yaml_excerpt: str | None
    qdrant_score: float


@dataclass
class _VerifyOutcome:
    """LLM verdict on one candidate."""

    technique_id: str
    rule_id: uuid.UUID
    verdict: str  # "yes" | "partial" | "no"  (structured path never emits "error"; legacy _normalise_verdict path may)
    one_line_reason: str | None = None


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CoverageMappingError(Exception):
    """Top-level mapper failure (chain missing, persistence aborted, etc.)."""

    def __init__(self, message: str, *, stage: str) -> None:
        super().__init__(message)
        self.stage = stage


# ---------------------------------------------------------------------------
# Mapper
# ---------------------------------------------------------------------------


class CoverageMapper:
    """Run the two-phase coverage comparison for one :class:`AttackChainRow`.

    Constructor wires optional collaborators so tests can pass stubs:

      * ``embedder`` — :class:`fragchain.vector.VectorEmbedder` for Phase 2.
      * ``provider`` — anything with the M5 ``LLMProvider.complete`` shape.
      * ``model`` — chat model alias for the verify call (defaults to
        ``settings.LITELLM_CHAT_MODEL``).
      * ``matrix_cache`` — :class:`MatrixCache` for invalidation.
      * ``semantic_threshold`` / ``parallelism`` — for tuning.
    """

    def __init__(
        self,
        session: AsyncSession,
        *,
        embedder: Any | None = None,
        provider: Any | None = None,
        model: str | None = None,
        matrix_cache: Any | None = None,
        semantic_threshold: float = SEMANTIC_SCORE_THRESHOLD,
        result_limit: int = SEMANTIC_RESULT_LIMIT,
        parallelism: int = LLM_VERIFY_PARALLELISM,
        llm_verify_enabled: bool | None = None,
        verify_max_calls: int | None = None,
    ) -> None:
        from fragchain.config import get_settings

        settings = get_settings()
        self.session = session
        self._embedder = embedder
        self._provider = provider
        self._model = model
        self._matrix_cache = matrix_cache
        self._semantic_threshold = semantic_threshold
        self._result_limit = result_limit
        self._parallelism = max(1, parallelism)
        # Chat-LLM verification is opt-in (see CLAUDE.md / Phase A). When the
        # caller doesn't override, resolve from settings.
        self._llm_verify_enabled = (
            settings.COVERAGE_LLM_VERIFY_ENABLED
            if llm_verify_enabled is None
            else llm_verify_enabled
        )
        self._verify_max_calls = (
            settings.COVERAGE_VERIFY_MAX_CALLS
            if verify_max_calls is None
            else verify_max_calls
        )
        self._verify_calls_made = 0
        self._cve: Any | None = None  # cached per map_coverage() run

    # ------------------------------------------------------------------
    # Public entry
    # ------------------------------------------------------------------

    async def map_coverage(self, chain_id: uuid.UUID | str) -> CoverageReport:
        """Walk every TTP in ``chain_id``, classify, persist, return a report."""
        started = datetime.now(timezone.utc)
        chain_uuid = _coerce_uuid(chain_id)
        if chain_uuid is None:
            raise CoverageMappingError(
                f"invalid chain id {chain_id!r}", stage="load"
            )

        chain = await self.session.get(AttackChainRow, chain_uuid)
        if chain is None:
            raise CoverageMappingError(
                f"chain {chain_uuid} not found", stage="load"
            )

        ttps = await self._load_ttps(chain.id)
        if not ttps:
            raise CoverageMappingError(
                f"chain {chain.id} has no TTPs", stage="load"
            )

        cve = await self.session.get(CVE, chain.cve_id)
        if cve is None:
            raise CoverageMappingError(
                f"chain {chain.id} references missing CVE {chain.cve_id}",
                stage="load",
            )
        self._cve = cve  # cache for _verify_one calls in this run

        framework = ttps[0].framework or "attck"

        # Phase 1 — exact match. Returns rule ids per TTP.
        phase1: dict[str, list[uuid.UUID]] = {}
        for ttp in ttps:
            if not ttp.technique_id:
                continue
            phase1[ttp.technique_id] = await self._phase1_exact_match(
                ttp.technique_id
            )

        # Phase 1.5 — verify each exact-tag match against the CVE. Iterated per
        # TTP (not gathered) so the inner-helper's parallelism semaphore caps
        # concurrent verify calls; a follow-up could merge all rule_ids across
        # TTPs into a single gather for lower wall-time.
        #
        # Gated: chat-LLM verification is opt-in. When disabled, exact tag
        # matches stay covered as-is (the embedding/exact signal is the
        # default) and we never spend a verify call here.
        phase1_5_partial: dict[str, list[uuid.UUID]] = {}
        if self._llm_verify_enabled:
            for ttp in ttps:
                tid = ttp.technique_id
                if not tid:
                    continue
                kept, partial_1_5 = await self._phase1_5_verify_tag_match(
                    ttp=ttp, rule_ids=phase1.get(tid, []),
                )
                phase1[tid] = kept
                if partial_1_5:
                    phase1_5_partial[tid] = partial_1_5

        # Phase 2 — semantic.
        #
        # When LLM verify is ON, the legacy behaviour holds: only run semantic
        # search for techniques still uncovered after Phase 1's exact tag match.
        #
        # When LLM verify is OFF, coverage is decided by embedding similarity to
        # THIS chain's behaviour — a bare tag match alone no longer counts
        # (CLAUDE.md / locked decision). So run semantic collection+verify for
        # every technique, including those Phase 1 tag-matched.
        verify_on = self._llm_verify_enabled
        if verify_on:
            phase2_input = [
                ttp
                for ttp in ttps
                if ttp.technique_id and not phase1.get(ttp.technique_id)
            ]
        else:
            phase2_input = [ttp for ttp in ttps if ttp.technique_id]
        candidates = await self._phase2_collect_candidates(phase2_input)
        ttps_by_tid = {t.technique_id: t for t in phase2_input if t.technique_id}
        verdicts = await self._phase2_verify(candidates, ttps_by_tid)
        verify_counts = _count_verdicts(verdicts)

        # Group phase 2 verdicts back to (technique_id) → covering / partial.
        phase2_by_tid: dict[str, dict[str, list[uuid.UUID]]] = {}
        for v in verdicts:
            bucket = phase2_by_tid.setdefault(
                v.technique_id, {"yes": [], "partial": []}
            )
            if v.verdict == "yes":
                bucket["yes"].append(v.rule_id)
            elif v.verdict == "partial":
                bucket["partial"].append(v.rule_id)

        # POC source detection happens once per CVE.
        has_poc = await self._has_poc_source(chain.cve_id)
        # Shared-gap counts: how many *other* CVEs already mapped this
        # technique to a gap. Subtract self if the row already lists this
        # CVE (re-run) so the "+5 × count of other CVEs sharing this gap"
        # rule counts *other* CVEs, never this one.
        shared_gap_uuids = await self._shared_gap_counts(
            [t.technique_id for t in ttps if t.technique_id]
        )
        shared_gap_counts: dict[str, int] = {}
        for tid, uuids in shared_gap_uuids.items():
            count = len(uuids)
            if chain.cve_id in uuids:
                count -= 1
            shared_gap_counts[tid] = max(0, count)

        statuses: list[CoverageStatus] = []
        for ttp in ttps:
            if not ttp.technique_id:
                continue
            tid = ttp.technique_id
            exact_rules = phase1.get(tid, [])
            partial_buckets = phase2_by_tid.get(tid, {"yes": [], "partial": []})
            phase2_yes = partial_buckets["yes"]
            phase2_partial = partial_buckets["partial"]

            # When verify is ON, an exact tag match (Phase 1) seeds coverage.
            # When verify is OFF, coverage must come from a semantic match
            # (phase2_yes) — a bare tag match alone no longer covers.
            covering: list[uuid.UUID] = list(exact_rules) if verify_on else []
            partial: list[uuid.UUID] = []
            if phase2_yes:
                covering.extend(r for r in phase2_yes if r not in covering)
            phase1_5_for_tid = phase1_5_partial.get(tid, [])
            if phase1_5_for_tid:
                partial.extend(r for r in phase1_5_for_tid if r not in covering and r not in partial)
            if phase2_partial:
                partial.extend(r for r in phase2_partial if r not in covering and r not in partial)

            if covering:
                status = "covered"
            elif partial:
                status = "partial"
            else:
                status = "gap"

            priority = _calculate_priority(
                cve=cve,
                seq_order=ttp.seq_order,
                has_poc=has_poc,
                shared_count=shared_gap_counts.get(tid, 0) if status == "gap" else 0,
            )

            statuses.append(
                CoverageStatus(
                    technique_id=tid,
                    technique_name=ttp.technique_name,
                    tactic_id=ttp.tactic_id,
                    tactic_name=ttp.tactic,
                    seq_order=ttp.seq_order,
                    coverage_status=status,
                    covering_rule_ids=covering,
                    partial_rule_ids=partial,
                    priority_score=priority,
                    detection_opportunity=ttp.detection_opportunity,
                )
            )

        # Persist coverage_map rows.
        await self._persist_statuses(statuses, framework, chain.cve_id)
        await self.session.commit()

        # Best-effort cache + event side effects.
        await self._invalidate_matrix_cache(framework)
        self._emit_coverage_mapped(chain, cve, statuses)
        self._emit_matrix_updated(framework, statuses)

        elapsed = int(
            (datetime.now(timezone.utc) - started).total_seconds() * 1000
        )
        report = CoverageReport(
            chain_id=chain.id,
            cve_id=chain.cve_id,
            cve_textual_id=cve.cve_id,
            framework=framework,
            statuses=statuses,
            covered_count=sum(1 for s in statuses if s.coverage_status == "covered"),
            partial_count=sum(1 for s in statuses if s.coverage_status == "partial"),
            gap_count=sum(1 for s in statuses if s.coverage_status == "gap"),
            llm_verify_calls=len(verdicts),
            llm_verify_yes=verify_counts["yes"],
            llm_verify_partial=verify_counts["partial"],
            llm_verify_no=verify_counts["no"],
            duration_ms=elapsed,
        )
        logger.info(
            "coverage.mapped",
            chain_id=str(chain.id),
            cve_id=cve.cve_id,
            covered=report.covered_count,
            partial=report.partial_count,
            gap=report.gap_count,
            llm_verify_calls=report.llm_verify_calls,
            duration_ms=elapsed,
        )
        return report

    async def predict_verdict_for_pair(
        self,
        cve_id: uuid.UUID,
        technique_id: str,
        rule_id: uuid.UUID,
    ) -> str:
        """Score one (cve, technique, rule) triple — used by the coverage benchmark.

        Returns one of ``"covered"``, ``"partial"``, ``"no_match"``. The single
        verify call mirrors Phase 1.5 / Phase 2: a CVE-grounded
        ``structured_complete`` against ``VerifyVerdict``.

        Returns ``"no_match"`` if either side of the pair is missing in the DB,
        or if no LLM provider is available.

        NOTE: not safe for concurrent calls — each invocation clobbers
        ``self._cve`` before the verify call.
        """
        from types import SimpleNamespace

        cve = await self.session.get(CVE, cve_id)
        if cve is None:
            logger.info("benchmark.predict.missing_cve", cve_id=str(cve_id))
            return "no_match"
        rule = await self.session.get(SigmaRule, rule_id)
        if rule is None:
            logger.info("benchmark.predict.missing_rule", rule_id=str(rule_id))
            return "no_match"

        self._cve = cve  # _verify_one reads from here

        provider = self._provider or self._default_provider()
        if provider is None:
            logger.info("benchmark.predict.no_provider")
            return "no_match"

        excerpt = await self._load_rule_yaml_excerpt(rule_id)
        candidate = _CandidateHit(
            technique_id=technique_id,
            technique_name=None,
            tactic_id=None,
            tactic_name=None,
            rule_id=rule_id,
            rule_title=getattr(rule, "title", None),
            rule_yaml_excerpt=excerpt,
            qdrant_score=1.0,
        )
        ttp = SimpleNamespace(
            technique_id=technique_id,
            technique_name=None,
            tactic_id=None,
            tactic=None,
            detection_opportunity=None,
        )

        outcome = await self._verify_one(provider, candidate, ttp=ttp)
        if outcome.verdict == "yes":
            return "covered"
        if outcome.verdict == "partial":
            return "partial"
        return "no_match"

    # ------------------------------------------------------------------
    # Phase 1 — exact ATT&CK tag match
    # ------------------------------------------------------------------

    async def _phase1_exact_match(self, technique_id: str) -> list[uuid.UUID]:
        """Return UUIDs of merged Sigma rules with this technique tag."""
        stmt = (
            select(SigmaRule.id)
            .where(SigmaRule.status == "merged")
            .where(SigmaRule.technique_ids.contains([technique_id]))
        )
        rows = (await self.session.execute(stmt)).scalars().all()
        return list(rows)

    # ------------------------------------------------------------------
    # Phase 1.5 — verify each exact-tag match against the CVE
    # ------------------------------------------------------------------

    async def _phase1_5_verify_tag_match(
        self,
        *,
        ttp: ChainTTPRow,
        rule_ids: list[uuid.UUID],
    ) -> tuple[list[uuid.UUID], list[uuid.UUID]]:
        """Verify each Phase 1 exact-tag match against the CVE.

        Returns (kept_covered, demoted_partial). Dropped 'no' verdicts are
        simply absent from both lists.

        NOTE: each rule_id triggers ``_verify_one``, which is a 3-sample
        ``structured_complete`` call. Cost scales with tag-match density —
        a chain with N TTPs and M phase-1 rules each runs ``N×M×3`` LLM
        calls in this stage.
        """
        if not rule_ids:
            return [], []
        provider = self._provider or self._default_provider()
        if provider is None:
            # No LLM available → preserve legacy behavior (all tag matches keep).
            logger.info("coverage.phase1_5.no_provider")
            return list(rule_ids), []

        kept: list[uuid.UUID] = []
        partial: list[uuid.UUID] = []
        sem = asyncio.Semaphore(self._parallelism)

        async def _one(rid: uuid.UUID) -> None:
            excerpt = await self._load_rule_yaml_excerpt(rid)
            candidate = _CandidateHit(
                technique_id=ttp.technique_id,
                technique_name=ttp.technique_name,
                tactic_id=ttp.tactic_id,
                tactic_name=ttp.tactic,
                rule_id=rid,
                rule_title=None,
                rule_yaml_excerpt=excerpt,
                qdrant_score=1.0,  # synthetic — Phase 1 had no score
            )
            async with sem:
                outcome = await self._verify_one(provider, candidate, ttp=ttp)
            if outcome.verdict == "yes":
                kept.append(rid)
            elif outcome.verdict == "partial":
                partial.append(rid)
            # 'no' → drop

        await asyncio.gather(*(_one(rid) for rid in rule_ids))
        return kept, partial

    # ------------------------------------------------------------------
    # Phase 2 — semantic search + cheap LLM verify
    # ------------------------------------------------------------------

    async def _phase2_collect_candidates(
        self, uncovered: list[ChainTTPRow]
    ) -> list[_CandidateHit]:
        if not uncovered:
            return []
        embedder = self._embedder
        if embedder is None:
            embedder = self._default_embedder()
        if embedder is None:
            # No Qdrant / embedder configured — Phase 2 is a no-op. Phase 1
            # results still drive coverage, so this is degradation not failure.
            logger.info("coverage.phase2.no_embedder")
            return []

        seen_pairs: set[tuple[str, uuid.UUID]] = set()
        candidates: list[_CandidateHit] = []
        for ttp in uncovered:
            tid = ttp.technique_id
            if not tid:
                continue
            cve = self._cve
            product_summary = _affected_product_summary(cve.affected_products)
            query = (
                f"CVE {cve.cve_id} affects {product_summary or 'unknown product'}: "
                f"{cve.title or ''}. "
                f"Technique {tid} {ttp.technique_name or ''}. "
                f"Detection opportunity: {ttp.detection_opportunity or '(none)'}"
            ).strip()
            try:
                hits = await embedder.search_sigma_rules(
                    query, limit=self._result_limit
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "coverage.phase2.search_failed",
                    technique_id=tid,
                    error=str(exc),
                )
                continue
            for hit in hits:
                if hit.score < self._semantic_threshold:
                    continue
                rule_uuid = _coerce_uuid(hit.rule_id)
                if rule_uuid is None:
                    continue
                # Skip rules that already tag the technique — those land in
                # Phase 1 anyway (or would, if status != merged).
                if hit.technique_ids and tid in hit.technique_ids:
                    continue
                key = (tid, rule_uuid)
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                yaml_excerpt = await self._load_rule_yaml_excerpt(rule_uuid)
                candidates.append(
                    _CandidateHit(
                        technique_id=tid,
                        technique_name=ttp.technique_name,
                        tactic_id=ttp.tactic_id,
                        tactic_name=ttp.tactic,
                        rule_id=rule_uuid,
                        rule_title=hit.title,
                        rule_yaml_excerpt=yaml_excerpt,
                        qdrant_score=hit.score,
                    )
                )
        return candidates

    async def _phase2_verify(
        self,
        candidates: list[_CandidateHit],
        ttps_by_tid: dict[str, ChainTTPRow],
    ) -> list[_VerifyOutcome]:
        if not candidates:
            return []
        # Gated: when chat-LLM verification is disabled, the embedding signal is
        # the default. Candidates entering here are already filtered to
        # score >= threshold, so treat each as covered ("yes") without any LLM
        # call.
        if not self._llm_verify_enabled:
            return [
                _VerifyOutcome(
                    technique_id=c.technique_id,
                    rule_id=c.rule_id,
                    verdict="yes",
                    one_line_reason="embedding match (llm verify disabled)",
                )
                for c in candidates
            ]
        provider = self._provider
        if provider is None:
            provider = self._default_provider()
        if provider is None:
            logger.info("coverage.phase2.no_provider")
            return []

        semaphore = asyncio.Semaphore(self._parallelism)

        async def _one(candidate: _CandidateHit) -> _VerifyOutcome:
            ttp = ttps_by_tid.get(candidate.technique_id)
            if ttp is None:
                logger.warning(
                    "coverage.phase2.missing_ttp_context",
                    technique_id=candidate.technique_id,
                )
                return _VerifyOutcome(
                    technique_id=candidate.technique_id,
                    rule_id=candidate.rule_id,
                    verdict="no",
                    one_line_reason="missing ttp context",
                )
            async with semaphore:
                return await self._verify_one(provider, candidate, ttp=ttp)

        return list(await asyncio.gather(*(_one(c) for c in candidates)))

    async def _verify_one(
        self, provider: Any, candidate: _CandidateHit, *, ttp: ChainTTPRow
    ) -> _VerifyOutcome:
        # Gated: cap the number of chat-LLM verify calls per mapper run. Once
        # the budget is spent, fall back to a deterministic "yes" (the
        # embedding/exact signal already put this pair in the verify path).
        if self._verify_calls_made >= self._verify_max_calls:
            return _VerifyOutcome(
                technique_id=candidate.technique_id,
                rule_id=candidate.rule_id,
                verdict="yes",
                one_line_reason="verify call cap reached (llm verify capped)",
            )
        self._verify_calls_made += 1
        cve = self._cve  # populated in map_coverage
        product_summary = _affected_product_summary(cve.affected_products)
        cve_block = (
            f"CVE: {cve.cve_id}\n"
            f"Title: {cve.title or '(none)'}\n"
            f"Affected product: {product_summary or '(unknown)'}\n"
            f"Description (truncated):\n{(cve.description or '')[:500]}\n"
        )
        detection_opp = ttp.detection_opportunity or "(none recorded)"
        user_prompt = (
            f"{cve_block}\n"
            f"Technique: {candidate.technique_id} {candidate.technique_name or ''}\n"
            f"Tactic: {candidate.tactic_name or candidate.tactic_id or 'unknown'}\n"
            f"Detection opportunity (from TTP): {detection_opp}\n\n"
            f"Sigma rule title: {candidate.rule_title or '(untitled)'}\n"
            f"Sigma rule detection (truncated):\n"
            f"{candidate.rule_yaml_excerpt or '(no body)'}\n\n"
            "Question: does this Sigma rule's detection logic specifically detect "
            f"the exploitation of {cve.cve_id} via technique {candidate.technique_id}?\n"
            "- Answer 'yes' if the rule would fire on this CVE's specific exploitation.\n"
            "- Answer 'partial' if it covers the technique but targets a different "
            "product or different CVE.\n"
            "- Answer 'no' otherwise.\n"
        )
        try:
            result = await structured_complete(
                provider=provider,
                system=LLM_VERIFY_SYSTEM_PROMPT,
                user=user_prompt,
                model=self._model or self._default_model(),
                schema=VerifyVerdict,
                interaction_type=InteractionType.COVERAGE_VERIFY,
                entity_type="sigma_rule",
                entity_id=candidate.rule_id,
                n_samples=LLM_VERIFY_SAMPLES,
                max_repair_attempts=2,
                temperature=LLM_VERIFY_TEMPERATURE,
                timeout_seconds=LLM_VERIFY_TIMEOUT_SECONDS,
            )
        except (StructuredOutputError, asyncio.TimeoutError) as exc:
            logger.warning(
                "coverage.phase2.verify_failed",
                technique_id=candidate.technique_id,
                rule_id=str(candidate.rule_id),
                error=str(exc),
            )
            return _VerifyOutcome(
                technique_id=candidate.technique_id,
                rule_id=candidate.rule_id,
                verdict="no",  # conservative on failure: don't mark "covered"
                one_line_reason=f"verify failed: {exc!s}",
            )

        return _VerifyOutcome(
            technique_id=candidate.technique_id,
            rule_id=candidate.rule_id,
            verdict=result.value.verdict,
            one_line_reason=result.value.one_line_reason,
        )

    async def _load_rule_yaml_excerpt(self, rule_id: uuid.UUID) -> str | None:
        rule = await self.session.get(SigmaRule, rule_id)
        if rule is None or not rule.sigma_yaml:
            return None
        # First 1500 chars is enough for the LLM to judge the detection block
        # without blowing the prompt budget.
        return rule.sigma_yaml[:1500]

    # ------------------------------------------------------------------
    # POC + shared-gap helpers (used by priority scoring)
    # ------------------------------------------------------------------

    async def _has_poc_source(self, cve_uuid: uuid.UUID) -> bool:
        stmt = (
            select(SourceDocument.id)
            .where(SourceDocument.cve_id == cve_uuid)
            .where(SourceDocument.source_type == "poc")
            .limit(1)
        )
        row = (await self.session.execute(stmt)).first()
        return row is not None

    async def _shared_gap_counts(
        self, technique_ids: list[str]
    ) -> dict[str, list[uuid.UUID]]:
        """Return ``{technique_id: [chain_cve_uuid, ...]}`` for techniques
        currently flagged ``gap``.

        Caller subtracts self from the list when scoring so the "+5 ×
        count of other CVEs sharing this gap" rule actually counts
        *other* CVEs (the row already contains this CVE on a re-run).
        """
        if not technique_ids:
            return {}
        stmt = select(
            CoverageMap.technique_id, CoverageMap.chain_cve_ids
        ).where(
            CoverageMap.technique_id.in_(technique_ids),
            CoverageMap.coverage_status == "gap",
        )
        rows = (await self.session.execute(stmt)).all()
        out: dict[str, list[uuid.UUID]] = {}
        for tid, ids in rows:
            out[tid] = [uuid.UUID(str(i)) for i in (ids or [])]
        return out

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def _persist_statuses(
        self,
        statuses: list[CoverageStatus],
        framework: str,
        cve_uuid: uuid.UUID,
    ) -> None:
        for s in statuses:
            row = await self._get_coverage_row(s.technique_id, framework)
            if row is None:
                row = CoverageMap(
                    technique_id=s.technique_id,
                    technique_name=s.technique_name,
                    tactic_id=s.tactic_id,
                    tactic_name=s.tactic_name,
                    framework=framework,
                )
                self.session.add(row)
            # Merge covering rules: prior coverage from other chains stays,
            # this chain's contribution is appended (unique).
            covering_set: set[uuid.UUID] = {
                uuid.UUID(str(r)) for r in (row.covering_rule_ids or [])
            }
            for rid in s.covering_rule_ids:
                covering_set.add(rid)
            for rid in s.partial_rule_ids:
                covering_set.add(rid)
            row.covering_rule_ids = sorted(covering_set, key=str)

            chain_cves: set[uuid.UUID] = {
                uuid.UUID(str(c)) for c in (row.chain_cve_ids or [])
            }
            chain_cves.add(cve_uuid)
            row.chain_cve_ids = sorted(chain_cves, key=str)
            row.chain_cve_count = len(chain_cves)

            # KEV propagation: if any CVE in chain_cve_ids is in cisa_kev,
            # flip kev_exposed and bump kev_cve_count.
            kev_count = await self._count_kev_cves(list(chain_cves))
            row.kev_cve_count = kev_count
            row.kev_exposed = kev_count > 0

            row.coverage_status = s.coverage_status
            row.last_refreshed = datetime.now(timezone.utc)
            # Don't trample seed-time descriptive columns
            # (technique_name / tactic_name / tactic_id) when present.
            if not row.technique_name and s.technique_name:
                row.technique_name = s.technique_name
            if not row.tactic_id and s.tactic_id:
                row.tactic_id = s.tactic_id
            if not row.tactic_name and s.tactic_name:
                row.tactic_name = s.tactic_name

    async def _get_coverage_row(
        self, technique_id: str, framework: str
    ) -> CoverageMap | None:
        stmt = (
            select(CoverageMap)
            .where(CoverageMap.technique_id == technique_id)
            .where(CoverageMap.framework == framework)
            .limit(1)
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def _count_kev_cves(self, cve_uuids: list[uuid.UUID]) -> int:
        if not cve_uuids:
            return 0
        stmt = (
            select(CVE.id)
            .where(CVE.id.in_(cve_uuids))
            .where(CVE.cisa_kev.is_(True))
        )
        rows = (await self.session.execute(stmt)).scalars().all()
        return len(list(rows))

    # ------------------------------------------------------------------
    # Cache + events
    # ------------------------------------------------------------------

    async def _invalidate_matrix_cache(self, framework: str) -> None:
        cache = self._matrix_cache
        if cache is None:
            from fragchain.coverage.matrix import MatrixCache

            cache = MatrixCache()
        try:
            await cache.invalidate(framework=framework)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "coverage.cache.invalidate_failed",
                framework=framework,
                error=str(exc),
            )

    def _emit_coverage_mapped(
        self,
        chain: AttackChainRow,
        cve: CVE,
        statuses: list[CoverageStatus],
    ) -> None:
        try:
            from fragchain.notifications import emit_event

            top_gaps = [
                {
                    "technique_id": s.technique_id,
                    "technique_name": s.technique_name,
                    "priority_score": s.priority_score,
                }
                for s in sorted(
                    [s for s in statuses if s.coverage_status == "gap"],
                    key=lambda s: -s.priority_score,
                )[:5]
            ]
            emit_event(
                "coverage_mapped",
                {
                    "chain_id": str(chain.id),
                    "cve_id": cve.cve_id,
                    "covered": sum(
                        1 for s in statuses if s.coverage_status == "covered"
                    ),
                    "partial": sum(
                        1 for s in statuses if s.coverage_status == "partial"
                    ),
                    "gap": sum(
                        1 for s in statuses if s.coverage_status == "gap"
                    ),
                    "top_gaps": top_gaps,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("coverage.event.emit_failed", error=str(exc))

    def _emit_matrix_updated(
        self, framework: str, statuses: list[CoverageStatus]
    ) -> None:
        try:
            from fragchain.notifications import emit_event

            emit_event(
                "matrix_updated",
                {
                    "framework": framework,
                    "techniques": [s.technique_id for s in statuses],
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("coverage.event.emit_failed", error=str(exc))

    # ------------------------------------------------------------------
    # Lazy collaborators
    # ------------------------------------------------------------------

    def _default_embedder(self) -> Any | None:
        try:
            from fragchain.vector import VectorEmbedder

            return VectorEmbedder()
        except Exception as exc:  # noqa: BLE001
            logger.info("coverage.embedder.unavailable", error=str(exc))
            return None

    def _default_provider(self) -> Any | None:
        try:
            from fragchain.llm import get_registry

            return get_registry().get_default_chat_provider()
        except Exception as exc:  # noqa: BLE001
            logger.info("coverage.provider.unavailable", error=str(exc))
            return None

    def _default_model(self) -> str:
        from fragchain.config import get_settings

        return get_settings().LITELLM_CHAT_MODEL

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _load_ttps(self, chain_id: uuid.UUID) -> list[ChainTTPRow]:
        stmt = (
            select(ChainTTPRow)
            .where(ChainTTPRow.chain_id == chain_id)
            .order_by(ChainTTPRow.seq_order.asc())
        )
        return list((await self.session.execute(stmt)).scalars().all())


# ---------------------------------------------------------------------------
# Pure helpers (unit-test friendly)
# ---------------------------------------------------------------------------


def _affected_product_summary(affected_products: Any) -> str | None:
    """Render a short product label from the heterogeneous ``affected_products`` JSONB.

    Connector ingest stores a ``list[str]`` (NVD2-style vendor/product strings),
    while the manual-CVE submission body stores a ``list[dict]`` with explicit
    ``vendor`` / ``product`` keys. Both shapes coexist on real rows. Returns
    ``None`` when the column is empty or unparseable so the prompt's
    ``or 'unknown product'`` branch fires.
    """
    if not affected_products:
        return None
    items = affected_products if isinstance(affected_products, list) else [affected_products]
    if not items:
        return None
    first = items[0]
    if isinstance(first, str):
        return first.strip() or None
    if isinstance(first, dict):
        parts = [str(first.get(k)) for k in ("vendor", "product") if first.get(k)]
        if parts:
            return " ".join(parts)
        for v in first.values():
            if isinstance(v, str) and v.strip():
                return v.strip()
    return None


def _coerce_uuid(value: Any) -> uuid.UUID | None:
    if isinstance(value, uuid.UUID):
        return value
    if value is None:
        return None
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        return None


def _normalise_verdict(raw: str) -> str:
    """Map an LLM ``yes | partial | no`` response to a canonical token."""
    if not isinstance(raw, str):
        return "error"
    text_value = raw.strip().lower()
    if not text_value:
        return "error"
    # The model may surround the answer with punctuation / a period; pick the
    # first matching token.
    for token in ("partial", "yes", "no"):
        if text_value == token or text_value.startswith(token + " ") or text_value.startswith(token + "."):
            return token
    if "partial" in text_value:
        return "partial"
    if "yes" in text_value:
        return "yes"
    if "no" in text_value:
        return "no"
    return "error"


def _count_verdicts(verdicts: list[_VerifyOutcome]) -> dict[str, int]:
    return {
        "yes": sum(1 for v in verdicts if v.verdict == "yes"),
        "partial": sum(1 for v in verdicts if v.verdict == "partial"),
        "no": sum(1 for v in verdicts if v.verdict == "no"),
        "error": sum(1 for v in verdicts if v.verdict == "error"),
    }


def _calculate_priority(
    *,
    cve: CVE,
    seq_order: int,
    has_poc: bool,
    shared_count: int,
) -> int:
    """Per-gap priority score per CLAUDE.md §12.

    Components (all additive):

      * +30 if CISA KEV
      * +20 if CVSS ≥ 9.0
      * +20 if EPSS ≥ 0.50, else +15 if EPSS ≥ 0.20
      * +15 if a PoC source document exists
      * +10 if AttackerKB score ≥ 3.5
      * +10 if ``seq_order`` ≤ 3 (early-chain stage)
      * +5 × ``shared_count`` (other CVEs already gapping this technique)

    EPSS is mutually exclusive: a CVE with EPSS=0.6 lands in the 0.50 bucket
    (+20), not both buckets. Reading the spec strictly as "+20 if ≥ 0.5,
    +15 if ≥ 0.2" would double-count CVEs above 0.5.
    """
    score = 0
    if cve.cisa_kev:
        score += 30
    cvss = _as_float(cve.cvss_score)
    if cvss is not None and cvss >= 9.0:
        score += 20
    epss = _as_float(cve.epss_score)
    if epss is not None and epss >= 0.50:
        score += 20
    elif epss is not None and epss >= 0.20:
        score += 15
    if has_poc:
        score += 15
    akb = _as_float(cve.attackerkb_score)
    if akb is not None and akb >= 3.5:
        score += 10
    if seq_order <= 3:
        score += 10
    if shared_count > 0:
        # ``shared_count`` includes self when the row already lists this
        # CVE in chain_cve_ids; subtract one to count *other* CVEs only.
        # We can't tell in this helper whether self is in the count, so the
        # caller passes already-adjusted values when needed. For Phase 1
        # we conservatively count what came back from the DB and add the
        # +5 multiplier — the spec says "shared with this gap".
        score += 5 * shared_count
    return score


def _as_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


__all__ = [
    "CoverageMapper",
    "CoverageMappingError",
    "CoverageReport",
    "CoverageStatus",
    "LLM_VERIFY_PARALLELISM",
    "SEMANTIC_RESULT_LIMIT",
    "SEMANTIC_SCORE_THRESHOLD",
    "VerifyVerdict",
    "_calculate_priority",
    "_count_verdicts",
    "_normalise_verdict",
]
