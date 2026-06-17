# fragchain/llm/structured.py
"""Structured-output utility — LLM call → Pydantic-validated value.

Phase A §3.1. A thin helper, not a module-with-state:

- ``n_samples=1`` → one call, parse with ``schema.model_validate_json``;
  on ``ValidationError`` retry with the prior response and the
  validation error appended to the user prompt, up to
  ``max_repair_attempts``.
- ``n_samples>=2`` → run N calls in parallel at ``temperature=0``, parse
  each, return field-level majority consensus with
  ``confidence = agreement_ratio``.
- Every underlying call still logs to ``llm_interactions`` and MinIO
  via the existing provider path (M5).
- On all-samples-fail → raise :class:`StructuredOutputError`. The caller
  decides degradation (skip / conservative default / propagate).
"""
from __future__ import annotations

import asyncio
import uuid
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

import structlog
from pydantic import BaseModel, ValidationError

from fragchain.llm.base import InteractionType, LLMProvider

logger = structlog.get_logger(__name__)


T = TypeVar("T", bound=BaseModel)

# Default upper bound on completion tokens for structured calls. Generous
# enough for the largest structured payloads (Loop 2 indicators across 7
# categories, multi-selection rule YAML) but bounded so a degenerate prompt
# can't run up unbounded cost/latency. Callers may override per call.
DEFAULT_MAX_TOKENS = 8192


class StructuredOutputError(RuntimeError):
    """Raised when no sample validated against the schema."""


def _response_cost(resp: Any) -> float:
    """Best-effort per-call cost from an LLMResponse. 0.0 when unknown.

    Guarded with isinstance because test doubles routinely stub ``usage``
    with MagicMock — only a real numeric cost accumulates.
    """
    usage = getattr(resp, "usage", None)
    cost = getattr(usage, "cost_usd", None) if usage is not None else None
    if isinstance(cost, (int, float)) and not isinstance(cost, bool):
        return float(cost)
    return 0.0


@dataclass
class StructuredResult(Generic[T]):
    value: T
    confidence: float
    samples: list[T] = field(default_factory=list)
    attempts: int = 1
    cost_usd: float = 0.0


async def structured_complete(
    *,
    provider: LLMProvider,
    system: str,
    user: str,
    model: str,
    schema: type[T],
    interaction_type: InteractionType,
    n_samples: int = 1,
    max_repair_attempts: int = 2,
    temperature: float = 0.0,
    max_tokens: int | None = DEFAULT_MAX_TOKENS,
    timeout_seconds: float = 30.0,
    entity_type: str | None = None,
    entity_id: uuid.UUID | None = None,
    prompt_template_id: uuid.UUID | None = None,
    prompt_version: int | None = None,
) -> StructuredResult[T]:
    if n_samples < 1:
        raise ValueError("n_samples must be >= 1")

    if n_samples == 1:
        return await _single_with_repair(
            provider=provider, system=system, user=user, model=model,
            schema=schema, interaction_type=interaction_type,
            max_repair_attempts=max_repair_attempts,
            temperature=temperature, max_tokens=max_tokens,
            timeout_seconds=timeout_seconds,
            entity_type=entity_type, entity_id=entity_id,
            prompt_template_id=prompt_template_id,
            prompt_version=prompt_version,
        )
    return await _voted(
        provider=provider, system=system, user=user, model=model,
        schema=schema, interaction_type=interaction_type,
        n_samples=n_samples, temperature=temperature,
        max_tokens=max_tokens,
        timeout_seconds=timeout_seconds,
        entity_type=entity_type, entity_id=entity_id,
        prompt_template_id=prompt_template_id,
        prompt_version=prompt_version,
    )


async def _single_with_repair(
    *,
    provider: LLMProvider,
    system: str,
    user: str,
    model: str,
    schema: type[T],
    interaction_type: InteractionType,
    max_repair_attempts: int,
    temperature: float,
    max_tokens: int | None,
    timeout_seconds: float,
    entity_type: str | None,
    entity_id: uuid.UUID | None,
    prompt_template_id: uuid.UUID | None,
    prompt_version: int | None,
) -> StructuredResult[T]:
    current_user = user
    last_validation_error: str | None = None
    last_timeout_error: str | None = None
    last_text: str = ""
    # validation_attempts counts only attempts that reached the parse stage
    # (i.e. genuine repair-needing failures). Timeout failures do NOT consume
    # repair budget; they are tracked separately with the same budget cap so
    # a permanently-unreachable provider cannot loop forever.
    validation_attempts = 0
    timeout_attempts = 0
    total_attempts = 0
    timeout_budget = max_repair_attempts + 1
    cost_total = 0.0

    while validation_attempts <= max_repair_attempts:
        if timeout_attempts >= timeout_budget:
            break
        total_attempts += 1
        try:
            resp = await asyncio.wait_for(
                provider.complete(
                    system, current_user, model,
                    interaction_type=interaction_type,
                    entity_type=entity_type, entity_id=entity_id,
                    prompt_template_id=prompt_template_id,
                    prompt_version=prompt_version,
                    temperature=temperature,
                    max_tokens=max_tokens,
                ),
                timeout=timeout_seconds,
            )
        except asyncio.TimeoutError:
            timeout_attempts += 1
            last_timeout_error = f"timeout after {timeout_seconds}s"
            logger.warning(
                "structured.timeout",
                timeout_attempt=timeout_attempts,
                validation_attempt=validation_attempts,
            )
            continue

        # Every completed call cost money — including ones whose output
        # then fails validation (Wave 1a T8a).
        cost_total += _response_cost(resp)
        last_text = resp.text
        try:
            value = schema.model_validate_json(_strip_fences(resp.text))
            return StructuredResult(
                value=value, confidence=1.0,
                samples=[value], attempts=total_attempts, cost_usd=cost_total,
            )
        except ValidationError as exc:
            last_validation_error = exc.json()
            validation_attempts += 1
            logger.info(
                "structured.repair_retry",
                validation_attempt=validation_attempts,
                error_summary=str(exc)[:200],
            )
            current_user = _repair_prompt(user, last_text, exc)

    if last_validation_error and not last_timeout_error:
        msg = f"validation failed after {total_attempts} attempts: {last_validation_error}"
    elif last_timeout_error and not last_validation_error:
        msg = f"all {total_attempts} attempts timed out (last: {last_timeout_error})"
    else:
        msg = (
            f"no valid output after {total_attempts} attempts "
            f"(last validation: {last_validation_error}; last timeout: {last_timeout_error})"
        )
    raise StructuredOutputError(msg)


async def _voted(
    *,
    provider: LLMProvider,
    system: str,
    user: str,
    model: str,
    schema: type[T],
    interaction_type: InteractionType,
    n_samples: int,
    temperature: float,
    max_tokens: int | None,
    timeout_seconds: float,
    entity_type: str | None,
    entity_id: uuid.UUID | None,
    prompt_template_id: uuid.UUID | None,
    prompt_version: int | None,
) -> StructuredResult[T]:
    async def _one() -> Any:
        return await asyncio.wait_for(
            provider.complete(
                system, user, model,
                interaction_type=interaction_type,
                entity_type=entity_type, entity_id=entity_id,
                prompt_template_id=prompt_template_id,
                prompt_version=prompt_version,
                temperature=temperature,
                max_tokens=max_tokens,
            ),
            timeout=timeout_seconds,
        )

    responses = await asyncio.gather(
        *[_one() for _ in range(n_samples)],
        return_exceptions=True,
    )

    parsed: list[T] = []
    cost_total = 0.0
    for resp in responses:
        if isinstance(resp, Exception):
            logger.warning("structured.sample_failed", error=str(resp))
            continue
        # Completed samples cost money even if they fail to parse (T8a).
        cost_total += _response_cost(resp)
        try:
            parsed.append(schema.model_validate_json(_strip_fences(resp.text)))
        except ValidationError as exc:
            logger.info("structured.sample_invalid", error=str(exc)[:200])

    if not parsed:
        raise StructuredOutputError(
            f"no valid samples among {n_samples} attempts"
        )

    counts = Counter(s.model_dump_json() for s in parsed)
    top_json, top_n = counts.most_common(1)[0]
    consensus = schema.model_validate_json(top_json)
    return StructuredResult(
        value=consensus,
        confidence=top_n / n_samples,
        samples=parsed,
        attempts=n_samples,
        cost_usd=cost_total,
    )


def _strip_fences(text: str) -> str:
    """Strip ```json fences a model sometimes adds despite instructions."""
    t = text.strip()
    if t.startswith("```"):
        # remove opening fence (optionally with language tag) and trailing fence
        first_nl = t.find("\n")
        if first_nl != -1:
            t = t[first_nl + 1:]
        if t.endswith("```"):
            t = t[:-3]
    return t.strip()


def _repair_prompt(original_user: str, last_response: str, exc: ValidationError) -> str:
    err_block = exc.json(indent=2)
    return (
        f"{original_user}\n\n"
        "Your previous response failed schema validation. "
        "The errors are:\n"
        f"```\n{err_block}\n```\n\n"
        "Your previous response was:\n"
        f"```\n{last_response}\n```\n\n"
        "Emit a corrected response that satisfies the schema. JSON only."
    )
