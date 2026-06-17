"""Single source of truth for constructing a LoopOrchestrator.

Both the API endpoint (inline, in the request lifecycle) and the Celery worker
need an identically-wired orchestrator. This was duplicated across two
factories with a "touch both" warning; it now lives here once.
"""
from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.assessments.chain_synthesis import ChainSynthesizer
from fragchain.assessments.mapping import VulnClassMapper
from fragchain.assessments.orchestrator import LoopOrchestrator
from fragchain.assessments.rule_supersession import RuleSuperseder
from fragchain.config import get_settings
from fragchain.vector.collections import get_qdrant_client


class _EmbedderShim:
    """Adapter exposing ``async embed(texts)`` for RagSearcher."""

    async def embed(self, texts: list[str]) -> list[list[float]]:
        from fragchain.vector.embedder import VectorEmbedder

        async with VectorEmbedder() as ve:
            return await ve._embed_texts(texts)  # noqa: SLF001


def build_orchestrator(session: AsyncSession) -> LoopOrchestrator:
    """Build a fully-wired :class:`LoopOrchestrator`.

    Uses lazy imports for Celery-dependent modules so test environments
    that have no broker configured don't blow up on import.
    """
    from fragchain.assessments.artifact_router import ArtifactRouter
    from fragchain.assessments.detectability import DetectabilityClassifier
    from fragchain.assessments.loops.loop1 import Loop1
    from fragchain.assessments.loops.loop2 import Loop2
    from fragchain.assessments.loops.loop3 import Loop3
    from fragchain.assessments.loops.rag import RagSearcher
    from fragchain.prompts.store import PromptStore
    from fragchain.rules.generator import RuleGenerator

    def _dispatch_coverage(chain_id_str: str) -> None:
        from fragchain.worker.tasks.coverage import map_coverage

        map_coverage.delay(chain_id_str)

    prompt_store = PromptStore(session)
    embedder = _EmbedderShim()
    qdrant = get_qdrant_client()
    gate_min = get_settings().GATE_MIN_CATEGORIES

    def _rag_builder(assessment_id: uuid.UUID) -> RagSearcher:
        return RagSearcher(
            embedder=embedder,
            qdrant=qdrant,
            assessment_id=assessment_id,
        )

    loop1 = Loop1(session, prompt_store=prompt_store)
    loop2 = Loop2(
        session,
        prompt_store=prompt_store,
        rag_searcher=None,
        rag_builder=_rag_builder,
        min_categories_for_gate=gate_min,
    )
    loop3 = Loop3(
        session,
        rule_generator_factory=lambda s: RuleGenerator(s),
    )

    return LoopOrchestrator(
        session,
        loop1=loop1,
        loop2=loop2,
        loop3=loop3,
        gate_min_categories=gate_min,
        chain_synthesizer=ChainSynthesizer(
            session, mapper=VulnClassMapper(session)
        ),
        rule_superseder=RuleSuperseder(session),
        coverage_dispatcher=_dispatch_coverage,
        detectability_classifier=DetectabilityClassifier(
            session, prompt_store=prompt_store
        ),
        artifact_router=ArtifactRouter(session),
    )
