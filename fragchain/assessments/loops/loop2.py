"""Loop 2 — Threat Intel (bulk-then-gap orchestration).

Two passes max. Bulk pass dispatches one RAG query per Loop 1 detection
question in parallel; concatenated results feed a single ``structured_complete``
call. If the result has fewer non-empty categories than the gate threshold and
budget remains, a gap pass dispatches focused RAG queries for empty categories
and re-asks the model. The gate evaluation itself stays in the orchestrator
(``evaluate_detectability_gate`` from Plan A).
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any, Callable

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.loops.base import (
    LoopContext,
    resolve_chat_model,
    resolve_chat_provider,
)
from fragchain.assessments.loops.rag import RagHit, RagSearcher
from fragchain.assessments.loops.schemas import Loop2Output, ObservableCategory
from fragchain.config import get_settings
from fragchain.llm.base import InteractionType, LLMProvider
from fragchain.llm.structured import StructuredResult, structured_complete

logger = structlog.get_logger(__name__)


_MAX_PASSES = 2


class Loop2:
    def __init__(
        self,
        session: AsyncSession,
        *,
        prompt_store: Any,
        rag_searcher: RagSearcher | None = None,
        rag_builder: Callable[[uuid.UUID], RagSearcher] | None = None,
        model: str | None = None,
        min_categories_for_gate: int = 3,
        max_rag_calls: int = 8,
        provider: LLMProvider | None = None,
    ) -> None:
        if rag_searcher is None and rag_builder is None:
            raise ValueError(
                "Loop2 requires either rag_searcher or rag_builder"
            )
        self._session = session
        self._prompt_store = prompt_store
        self._rag = rag_searcher
        self._rag_builder = rag_builder
        self._model = model
        self._gate_min = min_categories_for_gate
        self._max_rag = max_rag_calls
        self._provider = provider

    async def run(self, ctx: LoopContext) -> dict[str, Any]:
        loop1 = ctx.prior_outputs.get(1) or {}
        questions = loop1.get("detection_questions", [])
        if not questions:
            raise ValueError(
                "Loop 2 requires Loop 1 output with detection_questions"
            )

        # Resolve the per-assessment RagSearcher. Tests inject one at
        # construction; production uses ``rag_builder`` because the
        # worker doesn't know the assessment_id at orchestrator build
        # time. We store the resolved instance on ``self._rag`` so the
        # helper methods (which still read ``self._rag``) keep working.
        if self._rag is None:
            assert self._rag_builder is not None  # __init__ guard
            self._rag = self._rag_builder(ctx.assessment_id)

        selection = await self._prompt_store.get_active(
            task_type="threat_intel",
            target_model=self._model or "*",
            target_provider="*",
        )
        model = resolve_chat_model(self._model, selection.target_model)
        provider = resolve_chat_provider(self._provider)

        rag_budget = {"used": 0}
        # Per-pass wall-clock bound. From settings (not a module constant)
        # so it stays >= the structured timeout the inner call uses — see
        # the LOOP2_PASS_TIMEOUT_SECONDS comment in fragchain/config.py.
        pass_timeout_s = get_settings().LOOP2_PASS_TIMEOUT_SECONDS

        bulk_hits = await self._dispatch_rag(
            queries=[q["question"] for q in questions],
            k=5,
            budget=rag_budget,
        )
        bulk_result = await asyncio.wait_for(
            self._call(
                selection=selection,
                questions=questions,
                hits=bulk_hits,
                pass_hint="",
                model=model,
                ctx=ctx,
                provider=provider,
            ),
            timeout=pass_timeout_s,
        )
        bulk_out = bulk_result.value
        cost_total = bulk_result.cost_usd
        passes = 1

        # Loop2Output normalizes keys to .value strings (Task 2.1).
        filled = {
            cat for cat, vals in bulk_out.indicators.items() if vals
        }
        empty = [
            cat for cat in ObservableCategory if cat.value not in filled
        ]

        out = bulk_out
        if (
            len(filled) < self._gate_min
            and empty
            and passes < _MAX_PASSES
            and rag_budget["used"] < self._max_rag
        ):
            gap_queries = [
                self._gap_query(cat, questions) for cat in empty
            ]
            gap_hits = await self._dispatch_rag(
                queries=gap_queries, k=3, budget=rag_budget,
            )
            try:
                gap_result = await asyncio.wait_for(
                    self._call(
                        selection=selection,
                        questions=questions,
                        hits=bulk_hits + gap_hits,
                        pass_hint=(
                            "Gap pass — empty categories so far: "
                            f"{', '.join(c.value for c in empty)}. "
                            "Re-emit the FULL indicator object, this time "
                            "including evidence-grounded indicators for any "
                            "of the empty categories that the new excerpts "
                            "support."
                        ),
                        model=model,
                        ctx=ctx,
                        provider=provider,
                    ),
                    timeout=pass_timeout_s,
                )
                out = gap_result.value
                cost_total += gap_result.cost_usd
                passes = 2
            except asyncio.TimeoutError:
                logger.warning(
                    "loop2.gap_pass_timeout",
                    assessment_id=str(ctx.assessment_id),
                )

        payload = out.model_dump(mode="json")
        payload["_passes"] = passes
        payload["_rag_calls"] = rag_budget["used"]
        # Wave 1a T8b: model + cost summed across both passes, for the
        # orchestrator to copy onto AssessmentLoopRun at finalize.
        payload["_llm"] = {"model": model, "cost_usd": cost_total}
        return payload

    # -------------------------------------------------------------------

    async def _dispatch_rag(
        self,
        *,
        queries: list[str],
        k: int,
        budget: dict[str, int],
    ) -> list[RagHit]:
        remaining = self._max_rag - budget["used"]
        usable = queries[:max(remaining, 0)]
        if not usable:
            return []
        coros = [self._rag.search(q, k=k) for q in usable]
        results = await asyncio.gather(*coros, return_exceptions=True)
        budget["used"] += len(usable)

        flat: list[RagHit] = []
        seen_keys: set[str] = set()
        for res in results:
            if isinstance(res, Exception):
                logger.warning("loop2.rag_call_failed", error=str(res))
                continue
            for hit in res:
                key = f"{hit.source_id}:{hit.point_id}"
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                flat.append(hit)
        return flat

    async def _call(
        self,
        *,
        selection: Any,
        questions: list[dict[str, Any]],
        hits: list[RagHit],
        pass_hint: str,
        model: str,
        ctx: LoopContext,
        provider: LLMProvider,
    ) -> "StructuredResult[Loop2Output]":
        rag_text = "\n\n".join(
            f"[chunk_id={h.point_id} source_id={h.source_id} "
            f"title={h.title or ''}] (score={h.score:.2f})\n{h.text}".rstrip()
            for h in hits
        ) or "(no excerpts)"
        questions_text = "\n".join(
            f"- {q['id']} [{q['category']}]: {q['question']}"
            for q in questions
        )
        user_text = selection.user_template.format(
            detection_questions=questions_text,
            rag_results=rag_text,
            pass_hint=pass_hint,
        )
        result = await structured_complete(
            provider=provider,
            system=selection.system_prompt,
            user=user_text,
            model=model,
            schema=Loop2Output,
            interaction_type=InteractionType.ASSESSMENT_LOOP_2,
            entity_type="coverage_assessment",
            entity_id=ctx.assessment_id,
            prompt_template_id=selection.id,
            prompt_version=selection.version,
            timeout_seconds=get_settings().LLM_STRUCTURED_TIMEOUT_SECONDS,
        )
        # Return the full StructuredResult so run() can accumulate per-pass
        # cost (Wave 1a T8b) — callers read .value for the parsed output.
        return result

    @staticmethod
    def _gap_query(
        cat: ObservableCategory, questions: list[dict[str, Any]]
    ) -> str:
        # Prefer the Loop 1 question whose category matches.
        for q in questions:
            if q.get("category") == cat.value:
                return q["question"]
        return f"observable indicators for {cat.value} category"
