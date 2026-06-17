"""Prompt management package (M9).

Public surface used by the engine + tests:

  * :class:`PromptStore` — resolve / read / version-bump prompt templates.
  * :class:`PromptEvaluator` — benchmark a template against a ground-truth set.
  * :class:`ABTestRouter` — pick A/B variants for live traffic.

The engine never imports prompt strings directly. Every call site routes
through ``ABTestRouter.select_variant()`` (or ``PromptStore.get_active()``
when A/B routing isn't relevant). See CLAUDE.md §15 for the design rules.
"""
from __future__ import annotations

from fragchain.prompts.ab import ABSelection, ABTestRouter
from fragchain.prompts.eval import (
    BenchmarkCase,
    BenchmarkLoadError,
    BenchmarkNotFoundError,
    BenchmarkSet,
    CaseResult,
    EvaluationError,
    GroundTruthMissingError,
    PromptEvaluator,
    list_benchmarks,
    load_benchmark,
)
from fragchain.prompts.store import (
    PromptNotFoundError,
    PromptStore,
    PromptTemplateView,
    WILDCARD,
)

__all__ = [
    "ABSelection",
    "ABTestRouter",
    "BenchmarkCase",
    "BenchmarkLoadError",
    "BenchmarkNotFoundError",
    "BenchmarkSet",
    "CaseResult",
    "EvaluationError",
    "GroundTruthMissingError",
    "PromptEvaluator",
    "PromptNotFoundError",
    "PromptStore",
    "PromptTemplateView",
    "WILDCARD",
    "list_benchmarks",
    "load_benchmark",
]
