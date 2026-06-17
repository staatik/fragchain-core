"""Deterministic chain-synthesis bridge (spec §5.5).

Maps Loop 1's vuln_class -> ordered TTPs via the curated tables, assigns
Loop 2's indicators to TTPs by category relevance, computes confidence
from indicator density, and persists an ``AttackChainRow`` +
``ChainTTPRow[]``. Hard-supersedes any prior active chain for the same CVE.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.mapping import TTPMapping, VulnClassMapper
from fragchain.chain.schema import TACTIC_ID_PATTERN, TECHNIQUE_ID_PATTERN
from fragchain.db.models import AttackChainRow, ChainTTPRow

logger = structlog.get_logger(__name__)


class ChainSynthesisError(Exception):
    """Raised when the bridge cannot synthesize a chain (e.g. unknown vuln_class)."""


# Generic exploitation chain used when no curated vuln_class mapping exists.
# T1190 (Initial Access) -> T1203 (Execution), reusing the EXACT tactic_id /
# tactic / technique_name strings from the seed (mapping_seeds.py) so the
# fallback chain is consistent with curated rows. Low base_confidence because
# the TTPs are inferred, not evidence-backed; this flows through to a
# low overall_confidence so analysts can spot fallback chains.
_FALLBACK_TTPS: list[TTPMapping] = [
    TTPMapping(
        technique_id="T1190",
        tactic_id="TA0001",
        tactic="Initial Access",
        technique_name="Exploit Public-Facing Application",
        seq_order=1,
        base_confidence=0.4,
        notes="generic fallback (vuln_class unmapped)",
    ),
    TTPMapping(
        technique_id="T1203",
        tactic_id="TA0002",
        tactic="Execution",
        technique_name="Exploitation for Client Execution",
        seq_order=2,
        base_confidence=0.4,
        notes="generic fallback (vuln_class unmapped)",
    ),
]


class ChainSynthesizer:
    def __init__(
        self,
        session: AsyncSession,
        *,
        mapper: VulnClassMapper,
    ) -> None:
        self._session = session
        self._mapper = mapper

    async def synthesize(
        self,
        *,
        cve_id: uuid.UUID,
        cve_textual_id: str,
        assessment_id: uuid.UUID,
        vuln_profile: dict[str, Any],
        indicators: dict[str, list[dict[str, Any]]],
        prompt_template_id: uuid.UUID | None,
        model: str,
    ) -> AttackChainRow:
        vuln_class = vuln_profile.get("vuln_class", "")
        ttps = await self._mapper.ttps_for_vuln_class(vuln_class)
        is_fallback = not ttps
        if is_fallback:
            # No curated mapping: synthesize a generic exploitation chain and
            # flag it for analyst review instead of dead-ending the assessment.
            ttps = list(_FALLBACK_TTPS)
            logger.info(
                "assessment.chain_synthesis_fallback",
                assessment_id=str(assessment_id),
                cve_id=cve_textual_id,
                vuln_class=vuln_class,
            )

        await self._supersede_prior_active(cve_id, assessment_id)
        version = await self._next_version(cve_id)

        chain_ttps, ttp_confidences = await self._build_ttps(
            ttps, indicators, is_fallback=is_fallback
        )
        overall = round(
            sum(ttp_confidences) / max(len(ttp_confidences), 1), 2
        )
        _validate_chain(chain_ttps, overall, vuln_class)

        # The legacy ``chain`` JSONB column (NOT NULL) holds the serialized TTP
        # list, mirroring the normalized ChainTTPRow children. Populate it so
        # the INSERT satisfies the not-null constraint.
        chain_json = [_serialize_ttp(t) for t in chain_ttps]

        detection_gaps = (
            [
                f"generic TTP mapping — vuln_class '{vuln_class}' "
                "unmapped; review TTPs"
            ]
            if is_fallback
            else []
        )

        chain = AttackChainRow(
            cve_id=cve_id,
            version=version,
            model=model,
            provider="litellm",
            prompt_template_id=prompt_template_id,
            overall_confidence=overall,
            chain=chain_json,
            predicted_impact=vuln_profile.get("expected_impact", ""),
            detection_gaps=detection_gaps,
            sources_used=[],
            tlp="tlp:clear",
            source_origin="assessment",
            assessment_id=assessment_id,
            behavioral_indicators=_flatten_indicators(indicators),
        )
        self._session.add(chain)
        await self._session.flush()  # populate chain.id

        for ttp in chain_ttps:
            ttp.chain_id = chain.id
            self._session.add(ttp)

        logger.info(
            "assessment.chain_synthesized",
            assessment_id=str(assessment_id),
            cve_id=cve_textual_id,
            ttp_count=len(chain_ttps),
            overall_confidence=overall,
        )
        return chain

    async def _supersede_prior_active(
        self, cve_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        result = await self._session.execute(
            select(AttackChainRow)
            .where(AttackChainRow.cve_id == cve_id)
            .where(AttackChainRow.superseded_at.is_(None))
        )
        # Supersede every currently-active chain, not just one. If two ever
        # coexist (legacy data, or a row from the dormant LLM-only generator
        # which has no supersede logic), clearing only the first would leave a
        # second active row and the new insert would violate
        # uq_attack_chains_active_per_cve.
        now = datetime.now(tz=timezone.utc)
        for prior in result.scalars().all():
            prior.superseded_at = now
            prior.superseded_by_assessment_id = assessment_id

    async def _next_version(self, cve_id: uuid.UUID) -> int:
        """Next chain version for the CVE: ``max(existing version) + 1``.

        attack_chains has a NON-partial ``UNIQUE(cve_id, version)`` constraint
        that applies to ALL rows regardless of superseded state, so a fresh
        synthesis cannot reuse ``version=1`` once any chain (active or
        superseded) exists for the CVE. Mirrors the assessment_loop_run
        versioning idiom — the prior active row is superseded separately
        (``_supersede_prior_active``); the version monotonically increases.
        """
        from fragchain.assessments.active_rows import next_version

        return await next_version(
            self._session,
            AttackChainRow,
            AttackChainRow.cve_id == cve_id,
        )

    async def _build_ttps(
        self,
        ttps: list[TTPMapping],
        indicators: dict[str, list[dict[str, Any]]],
        *,
        is_fallback: bool = False,
    ) -> tuple[list[ChainTTPRow], list[float]]:
        rows: list[ChainTTPRow] = []
        confidences: list[float] = []
        for ttp in ttps:
            relevance = await self._mapper.categories_for_ttp(
                ttp.technique_id
            )
            per_ttp_indicators: list[dict[str, Any]] = []
            for cat, weight in relevance.items():
                for ind in indicators.get(cat, []):
                    per_ttp_indicators.append(
                        {**ind, "category": cat, "relevance_weight": weight}
                    )
            density = _weighted_density(per_ttp_indicators)
            if is_fallback:
                # A fallback chain means we could NOT map the vuln_class to
                # curated TTPs — the technique list is inferred, not
                # evidence-backed. Indicator density (which reflects evidence
                # for the *behavior*, not for *these guessed TTPs*) must not
                # boost it, or a "review TTPs" chain reads as high-confidence.
                # Keep it pinned at the low base so analysts can spot it.
                confidence = round(ttp.base_confidence, 2)
            else:
                # Density boost (0.20 per unit of weighted indicator score)
                # lets well-evidenced TTPs overcome modest base-confidence
                # gaps. With base_confidence already in [0,1], the min() clamp
                # dominates for any TTP with a couple of high-confidence
                # indicator matches.
                confidence = round(
                    min(1.0, ttp.base_confidence + 0.20 * density), 2
                )
            rows.append(
                ChainTTPRow(
                    seq_order=ttp.seq_order,
                    tactic=ttp.tactic,
                    tactic_id=ttp.tactic_id,
                    technique_id=ttp.technique_id,
                    technique_name=ttp.technique_name,
                    framework="attck",
                    confidence=confidence,
                    preconditions=[],
                    detection_opportunity=ttp.notes or "",
                    source_refs=[],
                    behavioral_indicators=per_ttp_indicators or None,
                )
            )
            confidences.append(confidence)
        return rows, confidences


def _validate_chain(
    chain_ttps: list[ChainTTPRow],
    overall_confidence: float,
    vuln_class: str,
) -> None:
    """Validate the synthesized chain's structural invariants before persist.

    The full Pydantic ``AttackChain`` schema (chain/schema.py) models the
    LLM/commons path and *requires* non-empty ``preconditions`` and
    ``source_refs`` plus ``source_origin in {'local','commons'}`` — none of
    which fit the deterministic assessment bridge (empty refs,
    ``source_origin='assessment'``). So we don't round-trip through it; we
    assert the invariants that DO apply to an assessment chain and raise
    ``ChainSynthesisError`` (fail before persist) on violation.
    """
    if not chain_ttps:
        raise ChainSynthesisError(
            f"synthesized empty chain for vuln_class {vuln_class!r}"
        )
    if not 0.0 <= overall_confidence <= 1.0:
        raise ChainSynthesisError(
            f"overall_confidence {overall_confidence} out of [0,1]"
        )
    seq_orders = [t.seq_order for t in chain_ttps]
    if seq_orders != list(range(1, len(seq_orders) + 1)):
        raise ChainSynthesisError(
            f"chain seq_order must be 1..N sequential; got {seq_orders}"
        )
    for t in chain_ttps:
        if not TECHNIQUE_ID_PATTERN.match(t.technique_id):
            raise ChainSynthesisError(
                f"invalid technique_id {t.technique_id!r}"
            )
        if not TACTIC_ID_PATTERN.match(t.tactic_id):
            raise ChainSynthesisError(f"invalid tactic_id {t.tactic_id!r}")
        if not 0.0 <= float(t.confidence) <= 1.0:
            raise ChainSynthesisError(
                f"confidence {t.confidence} for {t.technique_id} out of [0,1]"
            )


def _serialize_ttp(t: ChainTTPRow) -> dict[str, Any]:
    """Serialize a ChainTTPRow into the legacy ``chain`` JSONB shape."""
    return {
        "seq_order": t.seq_order,
        "tactic": t.tactic,
        "tactic_id": t.tactic_id,
        "technique_id": t.technique_id,
        "technique_name": t.technique_name,
        "sub_technique_id": getattr(t, "sub_technique_id", None),
        "framework": t.framework,
        "confidence": float(t.confidence),
        "preconditions": t.preconditions or [],
        "detection_opportunity": t.detection_opportunity,
        "source_refs": t.source_refs or [],
        "behavioral_indicators": t.behavioral_indicators or [],
    }


def _flatten_indicators(
    indicators: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    flat: list[dict[str, Any]] = []
    for cat, items in indicators.items():
        for ind in items:
            flat.append({**ind, "category": cat})
    return flat


def _weighted_density(per_ttp: list[dict[str, Any]]) -> float:
    if not per_ttp:
        return 0.0
    score = 0.0
    for ind in per_ttp:
        score += float(ind.get("confidence", 0.0)) * float(
            ind.get("relevance_weight", 1.0)
        )
    return score
