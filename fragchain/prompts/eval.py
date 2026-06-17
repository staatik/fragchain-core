"""PromptEvaluator — benchmark a prompt template against ground-truth chains (M9).

Runs the LLM with the prompt under test, parses the JSON answer, and scores
it against a hand-validated ground-truth chain. The four metrics persisted
on ``prompt_evaluations`` are:

  * ``technique_overlap`` — |truth ∩ predicted| / |truth ∪ predicted|
    (Jaccard). Captures both missing techniques and hallucinated ones.

  * ``ordering_consistency`` — longest-common-subsequence ratio of the
    predicted technique sequence to the truth sequence. 1.0 means the
    chain steps are in the same order; smaller means scrambled.

  * ``hallucination_count`` — count of predicted technique_ids that don't
    appear in the truth. Raw integer rather than a ratio so the operator
    can see "1 hallucination" vs "5 hallucinations" directly.

  * ``cost_per_run`` / ``avg_latency_ms`` — averaged across cases × iterations.

A benchmark set is a JSON file in ``benchmarks/`` shaped like::

    {
      "name": "dirty_frag_groundtruth",
      "description": "...",
      "iterations_per_case": 1,
      "cases": [
        {
          "id": "CVE-2026-43284",
          "ground_truth_path": "chains/CVE-2026-43284.json",
          "variables": { "cve_id": "...", "cve_description": "...", ... }
        }
      ]
    }

The ground-truth file is the canonical attack-chain JSON M10 will land. For
this module we only need its ``chain[].technique_id`` list; the evaluator
tolerates either a list of TTPs or the full M10 schema.

Providers are pluggable. ``PromptEvaluator.run()`` defaults to the registered
chat provider but accepts an explicit ``provider`` so tests can inject a
deterministic stub without spinning up LiteLLM.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.config import get_settings
from fragchain.db.models import PromptEvaluation, PromptTemplate
from fragchain.llm import InteractionType, LLMProvider, get_registry
from fragchain.prompts.store import PromptStore

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Benchmark loading
# ---------------------------------------------------------------------------


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _benchmarks_dir() -> Path:
    return _project_root() / "benchmarks"


@dataclass
class BenchmarkCase:
    id: str
    ground_truth_path: str
    variables: dict[str, Any] = field(default_factory=dict)


@dataclass
class BenchmarkSet:
    name: str
    description: str
    cases: list[BenchmarkCase]
    iterations_per_case: int = 1

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BenchmarkSet":
        cases = [
            BenchmarkCase(
                id=str(c["id"]),
                ground_truth_path=str(c["ground_truth_path"]),
                variables=dict(c.get("variables") or {}),
            )
            for c in data.get("cases", [])
        ]
        return cls(
            name=str(data["name"]),
            description=str(data.get("description", "")),
            cases=cases,
            iterations_per_case=int(data.get("iterations_per_case", 1) or 1),
        )


def list_benchmarks() -> list[dict[str, Any]]:
    """Return one summary per JSON file in ``benchmarks/``.

    Used by ``GET /api/v1/prompts/benchmarks``. Tolerates malformed files so
    a stray JSON parse error doesn't sink the whole endpoint.
    """
    out: list[dict[str, Any]] = []
    bench_dir = _benchmarks_dir()
    if not bench_dir.exists():
        return out
    for path in sorted(bench_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
            out.append(
                {
                    "name": data.get("name", path.stem),
                    "description": data.get("description", ""),
                    "case_count": len(data.get("cases", []) or []),
                    "iterations_per_case": int(data.get("iterations_per_case", 1) or 1),
                    "path": str(path.relative_to(_project_root())),
                }
            )
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("prompt.benchmark.load_failed", path=str(path), error=str(exc))
            out.append(
                {
                    "name": path.stem,
                    "description": "",
                    "case_count": 0,
                    "iterations_per_case": 0,
                    "path": str(path.relative_to(_project_root())),
                    "error": str(exc),
                }
            )
    return out


def load_benchmark(name: str) -> BenchmarkSet:
    """Load ``benchmarks/{name}.json`` and return the parsed set."""
    path = _benchmarks_dir() / f"{name}.json"
    if not path.exists():
        raise BenchmarkNotFoundError(name)
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkLoadError(f"failed to load benchmark {name!r}: {exc}") from exc
    return BenchmarkSet.from_dict(data)


def _load_ground_truth(rel_path: str) -> list[str]:
    """Read a ground-truth chain file and return the ordered technique_ids.

    Tolerates two shapes:
      * the canonical M10 chain object (``{"chain": [{"technique_id": "..."}]}``)
      * a shortcut ``{"technique_ids": ["T1078", "T1068", ...]}`` so a
        benchmark can ship without the full M10 JSON.
    """
    abs_path = _project_root() / rel_path
    if not abs_path.exists():
        raise GroundTruthMissingError(rel_path)
    try:
        data = json.loads(abs_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkLoadError(
            f"failed to load ground truth {rel_path!r}: {exc}"
        ) from exc

    if isinstance(data, dict) and isinstance(data.get("chain"), list):
        ids: list[str] = []
        for ttp in data["chain"]:
            tid = ttp.get("technique_id") if isinstance(ttp, dict) else None
            if isinstance(tid, str):
                ids.append(tid)
        return ids
    if isinstance(data, dict) and isinstance(data.get("technique_ids"), list):
        return [str(x) for x in data["technique_ids"] if isinstance(x, (str, int))]
    raise BenchmarkLoadError(
        f"ground truth {rel_path!r} has neither `chain` nor `technique_ids` array"
    )


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def _extract_techniques_from_output(text: str) -> list[str]:
    """Pull technique IDs out of model output. Tolerates JSON or freeform text.

    Preferred path: parse the text as JSON and walk the ``chain`` array. If
    that fails, fall back to a regex sweep for T#### / T####.### tokens —
    that's the worst case where the model wrapped the JSON in prose. The
    fallback preserves order of first occurrence.
    """
    text = (text or "").strip()
    if not text:
        return []
    # Try direct JSON parse first.
    parsed = _try_parse_json(text)
    if parsed is not None:
        chain = _walk_for_chain(parsed)
        if chain is not None:
            ids: list[str] = []
            for ttp in chain:
                if isinstance(ttp, dict):
                    tid = ttp.get("technique_id")
                    if isinstance(tid, str):
                        ids.append(tid)
            if ids:
                return ids
    # Fallback: regex sweep preserving first-occurrence order.
    seen: list[str] = []
    seen_set: set[str] = set()
    for match in _TECHNIQUE_RE.finditer(text):
        token = match.group(0)
        if token not in seen_set:
            seen.append(token)
            seen_set.add(token)
    return seen


def _try_parse_json(text: str) -> Any | None:
    # Strip ```json ... ``` fences if present.
    fenced = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL | re.IGNORECASE)
    if fenced:
        try:
            return json.loads(fenced.group(1))
        except json.JSONDecodeError:
            pass
    # Try the whole string.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try to find the first '{' and parse from there to the last '}'.
    first = text.find("{")
    last = text.rfind("}")
    if first != -1 and last > first:
        try:
            return json.loads(text[first : last + 1])
        except json.JSONDecodeError:
            pass
    return None


def _walk_for_chain(obj: Any) -> list[Any] | None:
    if isinstance(obj, list) and obj and isinstance(obj[0], dict) and "technique_id" in obj[0]:
        return obj
    if isinstance(obj, dict):
        chain = obj.get("chain")
        if isinstance(chain, list):
            return chain
        # one-level nesting: e.g. {"attack_chain": {"chain": [...]}}
        for value in obj.values():
            if isinstance(value, dict):
                nested = value.get("chain")
                if isinstance(nested, list):
                    return nested
    return None


def _jaccard(truth: list[str], predicted: list[str]) -> float:
    t = set(truth)
    p = set(predicted)
    if not t and not p:
        return 1.0
    union = t | p
    if not union:
        return 0.0
    return len(t & p) / len(union)


def _lcs_ratio(truth: list[str], predicted: list[str]) -> float:
    """Longest-common-subsequence length / max(len(truth), len(predicted))."""
    if not truth and not predicted:
        return 1.0
    if not truth or not predicted:
        return 0.0
    m, n = len(truth), len(predicted)
    # Classic O(mn) LCS — sequences are short (≤ ~20 TTPs).
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if truth[i - 1] == predicted[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    lcs_len = dp[m][n]
    return lcs_len / max(m, n)


def _hallucinations(truth: list[str], predicted: list[str]) -> int:
    """Count of predicted technique IDs absent from truth."""
    truth_set = set(truth)
    return sum(1 for p in predicted if p not in truth_set)


@dataclass
class CaseResult:
    case_id: str
    iteration: int
    technique_overlap: float
    ordering_consistency: float
    hallucination_count: int
    cost_usd: float
    latency_ms: int
    predicted: list[str]
    truth: list[str]
    output_excerpt: str
    error: str | None = None


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------


class PromptEvaluator:
    """Run a benchmark set against a prompt template and persist the scores."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def run(
        self,
        template_id: uuid.UUID,
        benchmark_set: str,
        *,
        provider: LLMProvider | None = None,
        model: str | None = None,
        evaluated_by: str | None = None,
        store_result: bool = True,
    ) -> PromptEvaluation:
        """Evaluate ``template_id`` against ``benchmark_set``.

        ``provider`` defaults to the registered chat provider; pass an
        explicit one (e.g. a fake) for tests. ``model`` defaults to
        ``settings.LITELLM_CHAT_MODEL``. The returned ``PromptEvaluation``
        is also persisted unless ``store_result=False``.
        """
        template = await self._session.get(PromptTemplate, template_id)
        if template is None:
            from fragchain.prompts.store import PromptNotFoundError

            raise PromptNotFoundError(template_id)

        bench = load_benchmark(benchmark_set)

        if provider is None:
            registry = get_registry()
            provider = registry.get_default_chat_provider()
            if provider is None:
                raise EvaluationError(
                    "no chat provider available — install fragchain-provider-litellm or pass one explicitly"
                )

        if model is None:
            model = get_settings().LITELLM_CHAT_MODEL

        case_results: list[CaseResult] = []
        for case in bench.cases:
            truth = _load_ground_truth(case.ground_truth_path)
            for iteration in range(bench.iterations_per_case):
                result = await self._run_case(
                    template=template,
                    case=case,
                    iteration=iteration,
                    truth=truth,
                    provider=provider,
                    model=model,
                )
                case_results.append(result)

        eval_row = _summarize(
            template_id=template.id,
            benchmark_name=bench.name,
            case_results=case_results,
            evaluated_by=evaluated_by,
        )

        if store_result:
            self._session.add(eval_row)
            await self._session.commit()
            logger.info(
                "prompt.evaluation.complete",
                template_id=str(template_id),
                benchmark=bench.name,
                cases=len(bench.cases),
                iterations=bench.iterations_per_case,
                technique_overlap=float(eval_row.technique_overlap or 0),
                ordering_consistency=float(eval_row.ordering_consistency or 0),
                hallucination_count=eval_row.hallucination_count,
            )

        return eval_row

    async def _run_case(
        self,
        *,
        template: PromptTemplate,
        case: BenchmarkCase,
        iteration: int,
        truth: list[str],
        provider: LLMProvider,
        model: str,
    ) -> CaseResult:
        user_prompt = _render(template.user_template or "", case.variables)
        system_prompt = template.system_prompt or ""
        try:
            response = await provider.complete(
                system=system_prompt,
                prompt=user_prompt,
                model=model,
                interaction_type=InteractionType.CHAIN_GENERATION,
                prompt_template_id=template.id,
                prompt_version=int(template.version),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "prompt.evaluation.case_failed",
                template_id=str(template.id),
                case_id=case.id,
                iteration=iteration,
                error=str(exc),
            )
            return CaseResult(
                case_id=case.id,
                iteration=iteration,
                technique_overlap=0.0,
                ordering_consistency=0.0,
                hallucination_count=0,
                cost_usd=0.0,
                latency_ms=0,
                predicted=[],
                truth=truth,
                output_excerpt="",
                error=str(exc),
            )

        predicted = _extract_techniques_from_output(response.text)
        overlap = _jaccard(truth, predicted)
        ordering = _lcs_ratio(truth, predicted)
        hallucinations = _hallucinations(truth, predicted)
        cost = float(response.usage.cost_usd or 0.0)
        latency = int(response.latency_ms or 0)
        excerpt = (response.text or "")[:500]
        return CaseResult(
            case_id=case.id,
            iteration=iteration,
            technique_overlap=overlap,
            ordering_consistency=ordering,
            hallucination_count=hallucinations,
            cost_usd=cost,
            latency_ms=latency,
            predicted=predicted,
            truth=truth,
            output_excerpt=excerpt,
        )

    @staticmethod
    async def load(
        session: AsyncSession, evaluation_id: uuid.UUID
    ) -> PromptEvaluation | None:
        return await session.get(PromptEvaluation, evaluation_id)

    @staticmethod
    async def list_for_template(
        session: AsyncSession, template_id: uuid.UUID
    ) -> list[PromptEvaluation]:
        stmt = (
            select(PromptEvaluation)
            .where(PromptEvaluation.prompt_template_id == template_id)
            .order_by(PromptEvaluation.evaluated_at.desc())
        )
        return list((await session.execute(stmt)).scalars().all())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _render(template: str, variables: dict[str, Any]) -> str:
    """Format a user_template safely.

    Uses ``str.format_map`` with a defaulting dict so unknown placeholders
    don't raise — they pass through as ``{placeholder}`` literally. This
    matches the philosophy of "don't blow up if a benchmark omits a
    variable", and the engine can still log the unfilled slot.
    """

    class _Defaulting(dict):
        def __missing__(self, key: str) -> str:  # type: ignore[override]
            return "{" + key + "}"

    try:
        return template.format_map(_Defaulting(variables))
    except (IndexError, KeyError, ValueError):
        # Bad format strings shouldn't crash an eval — return the raw text.
        return template


def _summarize(
    *,
    template_id: uuid.UUID,
    benchmark_name: str,
    case_results: list[CaseResult],
    evaluated_by: str | None,
) -> PromptEvaluation:
    if not case_results:
        return PromptEvaluation(
            prompt_template_id=template_id,
            benchmark_set=benchmark_name,
            technique_overlap=Decimal("0.00"),
            ordering_consistency=Decimal("0.00"),
            hallucination_count=0,
            cost_per_run=Decimal("0.0000"),
            avg_latency_ms=0,
            sample_outputs=[],
            evaluated_by=evaluated_by,
        )

    n = len(case_results)
    avg_overlap = sum(r.technique_overlap for r in case_results) / n
    avg_ordering = sum(r.ordering_consistency for r in case_results) / n
    total_hallucinations = sum(r.hallucination_count for r in case_results)
    avg_cost = sum(r.cost_usd for r in case_results) / n
    avg_latency = int(sum(r.latency_ms for r in case_results) / n)
    sample = [
        {
            "case_id": r.case_id,
            "iteration": r.iteration,
            "technique_overlap": round(r.technique_overlap, 4),
            "ordering_consistency": round(r.ordering_consistency, 4),
            "hallucination_count": r.hallucination_count,
            "cost_usd": round(r.cost_usd, 6),
            "latency_ms": r.latency_ms,
            "predicted": r.predicted,
            "truth": r.truth,
            "output_excerpt": r.output_excerpt,
            "error": r.error,
        }
        for r in case_results[:5]
    ]
    return PromptEvaluation(
        prompt_template_id=template_id,
        benchmark_set=benchmark_name,
        technique_overlap=Decimal(format(avg_overlap, ".2f")),
        ordering_consistency=Decimal(format(avg_ordering, ".2f")),
        hallucination_count=int(total_hallucinations),
        cost_per_run=Decimal(format(avg_cost, ".4f")),
        avg_latency_ms=avg_latency,
        sample_outputs=sample,
        evaluated_by=evaluated_by,
    )


class EvaluationError(Exception):
    """Raised when an evaluation can't run (e.g. no provider)."""


class BenchmarkNotFoundError(Exception):
    def __init__(self, name: str) -> None:
        super().__init__(f"benchmark {name!r} not found")
        self.name = name


class BenchmarkLoadError(Exception):
    """Benchmark file present but unparseable / malformed."""


class GroundTruthMissingError(Exception):
    def __init__(self, rel_path: str) -> None:
        super().__init__(f"ground truth file missing: {rel_path}")
        self.rel_path = rel_path


__all__ = [
    "BenchmarkCase",
    "BenchmarkLoadError",
    "BenchmarkNotFoundError",
    "BenchmarkSet",
    "CaseResult",
    "EvaluationError",
    "GroundTruthMissingError",
    "PromptEvaluator",
    "list_benchmarks",
    "load_benchmark",
]
