"""Loop 1 — Vulnerability Analysis.

Single-shot LLM call via :func:`fragchain.llm.structured.structured_complete`.
Pre-checks the prompt token budget and drops lowest-priority sources first
so we never trip the provider's context limit.

The mapping back to :class:`AttackChainRow` is owned by the Phase 4
chain-synthesis bridge; this loop emits only :class:`Loop1Output`.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.loops.base import (
    LoopContext,
    resolve_chat_model,
    resolve_chat_provider,
)
from fragchain.assessments.loops.schemas import Loop1Output
from fragchain.assessments.loops.token_budget import (
    SourceForBudget,
    truncate_sources_to_budget,
)
from fragchain.config import get_settings
from fragchain.llm.base import InteractionType, LLMProvider
from fragchain.llm.structured import structured_complete

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class _WrappedSource:
    idx: int
    content: str


class Loop1:
    def __init__(
        self,
        session: AsyncSession,
        *,
        prompt_store: Any,
        model: str | None = None,
        prompt_token_budget: int = 50_000,
        provider: LLMProvider | None = None,
    ) -> None:
        self._session = session
        self._prompt_store = prompt_store
        self._model_override = model
        self._budget = prompt_token_budget
        self._provider = provider

    async def run(self, ctx: LoopContext) -> dict[str, Any]:
        selection = await self._prompt_store.get_active(
            task_type="vuln_analysis",
            target_model=self._model_override or "*",
            target_provider="*",
        )

        wrapped = [
            _WrappedSource(idx=i, content=content)
            for i, content in enumerate(ctx.source_contents)
        ]
        kept, dropped = truncate_sources_to_budget(
            wrapped,
            budget_tokens=self._budget,
            extractor=lambda w: SourceForBudget(
                id=str(w.idx),
                content=w.content,
                pasted_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                injection_risk_score=None,
            ),
        )

        joined = "\n\n---\n\n".join(
            f"[source {i + 1}]\n{w.content}"
            for i, w in enumerate(kept)
        )
        user_text = selection.user_template.format(
            cve_id=ctx.cve_textual_id,
            cvss="",
            sources=joined,
        )

        model = resolve_chat_model(self._model_override, selection.target_model)
        provider = resolve_chat_provider(self._provider)

        result = await structured_complete(
            provider=provider,
            system=selection.system_prompt,
            user=user_text,
            model=model,
            schema=Loop1Output,
            interaction_type=InteractionType.ASSESSMENT_LOOP_1,
            entity_type="coverage_assessment",
            entity_id=ctx.assessment_id,
            prompt_template_id=selection.id,
            prompt_version=selection.version,
            timeout_seconds=get_settings().LLM_STRUCTURED_TIMEOUT_SECONDS,
        )

        payload = result.value.model_dump(mode="json")
        # Wave 1a T8b: surface model + accumulated cost so the orchestrator
        # can fill AssessmentLoopRun.model / cost_usd at finalize.
        payload["_llm"] = {"model": model, "cost_usd": result.cost_usd}
        if dropped:
            payload["_truncation"] = {
                "dropped_count": len(dropped),
                "kept_count": len(kept),
            }
            logger.warning(
                "loop1.sources_truncated",
                assessment_id=str(ctx.assessment_id),
                dropped=len(dropped),
            )
        return payload
