"""Loop 3 — Detection Engineering.

Wraps the existing :class:`fragchain.rules.generator.RuleGenerator`. The
heavy lifting (pySigma validation, multi-profile fan-out, exact-hash
dedup, review_queue persistence) stays in ``rules/generator.py``; this
loop loads the assessment's active chain and asks the generator to fill
all gaps with ``assessment_id`` + ``low_detectability_override`` propagated
into the review-queue rows.
"""
from __future__ import annotations

from typing import Any, Callable

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.loops.base import LoopContext
from fragchain.db.models import AttackChainRow

logger = structlog.get_logger(__name__)


class _NoActiveChainError(RuntimeError):
    """Loop 3 cannot run without an active AttackChainRow for the CVE."""


class Loop3:
    def __init__(
        self,
        session: AsyncSession,
        *,
        rule_generator_factory: Callable[[AsyncSession], Any],
    ) -> None:
        self._session = session
        self._factory = rule_generator_factory

    async def run(
        self,
        ctx: LoopContext,
        *,
        low_detectability_override: bool = False,
        gated_class: str | None = None,
    ) -> dict[str, Any]:
        result = await self._session.execute(
            select(AttackChainRow)
            .where(AttackChainRow.cve_id == ctx.cve_id)
            .where(AttackChainRow.superseded_at.is_(None))
            .where(AttackChainRow.assessment_id == ctx.assessment_id)
        )
        chain = result.scalars().first()
        if chain is None:
            raise _NoActiveChainError(
                f"no active assessment-produced chain for assessment "
                f"{ctx.assessment_id}"
            )

        # Phase 2c gate: when the orchestrator has decided this classification's
        # class is a skip class (insufficient_information / control_only), do NOT
        # generate Sigma — return a gated "no reliable detection" output instead.
        # The decision was made on the CLASS upstream, never on sigma_planned.
        if gated_class is not None:
            from fragchain.assessments.gating import gated_loop3_output

            logger.info(
                "assessment.loop3.gated",
                assessment_id=str(ctx.assessment_id),
                detectability_class=gated_class,
                chain_id=str(chain.id),
            )
            return gated_loop3_output(gated_class, chain_id=chain.id)

        generator = self._factory(self._session)
        report = await generator.generate_all_gaps(
            chain_id=chain.id,
            assessment_id=ctx.assessment_id,
            low_detectability_override=low_detectability_override,
        )

        rules_summary = [
            {
                "rule_id": str(getattr(r, "rule_id", None)),
                "title": getattr(r, "title", None),
                "technique_id": getattr(r, "technique_id", None),
                "profile_name": getattr(r, "profile_name", None),
                "level": getattr(r, "level", None),
                "logsource": {
                    "product": getattr(r, "logsource_product", None),
                    "service": getattr(r, "logsource_service", None),
                },
            }
            for r in (report.rules or [])
        ]
        logger.info(
            "assessment.loop3.completed",
            assessment_id=str(ctx.assessment_id),
            rule_count=len(rules_summary),
            chain_id=str(chain.id),
        )
        # Wave 1a T8b: surface the generator's chat model + summed LLM cost
        # for the orchestrator's loop-run cost columns. Guarded because test
        # doubles stub the report with MagicMock.
        report_model = getattr(report, "model", None)
        report_cost = getattr(report, "cost_usd", None)
        return {
            "chain_id": str(chain.id),
            "rules": rules_summary,
            "_llm": {
                "model": report_model if isinstance(report_model, str) else None,
                "cost_usd": (
                    float(report_cost)
                    if isinstance(report_cost, (int, float))
                    and not isinstance(report_cost, bool)
                    else None
                ),
            },
            # Phase 2 divergence observation needs to distinguish "planned
            # Sigma but zero gaps existed" (legitimate, not divergence) from
            # "planned Sigma but generation produced nothing".
            "gaps_processed": getattr(report, "gaps_processed", None),
            "top_priority": report.top_priority() if callable(
                getattr(report, "top_priority", None)
            ) else None,
        }
