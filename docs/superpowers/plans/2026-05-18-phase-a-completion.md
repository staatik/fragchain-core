# Phase A Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the missing Phase A pieces enumerated in [docs/architecture/PHASE_A_STATUS_AUDIT.md](../../architecture/PHASE_A_STATUS_AUDIT.md) so Plan C ([docs/superpowers/plans/2026-05-18-plan-c-assessment-real-loops.md](2026-05-18-plan-c-assessment-real-loops.md)) can build on a complete Phase A foundation. End state: `structured_complete` exists, the mapper uses CVE-grounded prompts with Phase 1.5 tag-verify, operators can run the coverage benchmark from CLI or API, and analysts can click "Supersede" on a similar-rule.

**Architecture:** Four sequential phases that each ship a working slice. Phase 1 is a new `fragchain/llm/structured.py` module. Phase 2 edits `fragchain/coverage/mapper.py` in place. Phase 3 adds a new Celery-callable runner script + a thin FastAPI router. Phase 4 wires a new queue endpoint + service method.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2.0 async, Pydantic v2, Celery (Phase 3 uses Celery delay), the existing `LiteLLMProvider`, pytest + AsyncMock (no real Postgres in unit tests — matches the project convention).

---

## Hard Prerequisites

- Plan A backend foundation landed (migration 0017, `fragchain/assessments/` module). Verified: yes (current `main`).
- Migration `0016_coverage_verification` landed (benchmark tables, `mapper_version` column, exact-hash dedup at rule-gen time, similar-rules data path). Verified: yes per audit §2.1–§2.4.
- `LiteLLMProvider.complete()` is the only LLM path used. No direct Anthropic/OpenAI SDK usage.

---

## Reference: Spec Cross-Reference

| Spec section | Plan phase |
|---|---|
| [COVERAGE_VERIFICATION_DESIGN.md §3.1](../../architecture/COVERAGE_VERIFICATION_DESIGN.md#31-structured-output-utility) | Phase 1 |
| §3.3 — mapper prompt changes (Qdrant query, verify prompt, Phase 1.5 tag-verify) | Phase 2 |
| §3.2 — benchmark runner CLI + endpoints | Phase 3 |
| §3.6 — manual Supersede analyst action | Phase 4 |

Out of scope:
- Chain generator migration to `structured_complete` (audit §2.9; legacy path stays dormant per assessment design §4.8).
- `scripts/backfill_content_hash.py` (audit §2.10; non-blocker, ship when convenient).
- Semantic dedup, exploit-analysis stage, prompt template Management UI — these are Phase B, not Phase A.

---

## File Map

**New files (production):**

| Path | Responsibility |
|---|---|
| `fragchain/llm/structured.py` | `structured_complete()` + `StructuredResult` + `StructuredOutputError` |
| `scripts/run_coverage_benchmark.py` | CLI runner: re-maps every labeled `(cve, technique, rule)` and records P/R/F1 into `coverage_benchmark_runs` |
| `fragchain/api/routers/coverage_benchmarks.py` | FastAPI router: `POST/GET /api/v1/coverage/benchmarks/runs[/{id}]` |
| `fragchain/queue/supersede.py` | `SupersedeService.supersede(rule_id, prior_rule_id, rationale, actor)` — writes a `coverage_benchmark` row + adjusts coverage status |

**Modified files (production):**

| Path | Modification |
|---|---|
| `fragchain/llm/__init__.py` | Re-export `structured_complete`, `StructuredResult`, `StructuredOutputError` |
| `fragchain/coverage/mapper.py` | (a) CVE-grounded Qdrant query in `_phase2_collect_candidates`; (b) expanded `_verify_one` prompt with CVE + affected_product + detection_opportunity; (c) new `_phase1_5_verify_tag_match` between `_phase1_exact_match` and Phase 2 |
| `fragchain/api/main.py` | Register `coverage_benchmarks` router |
| `fragchain/api/routers/queue.py` | Add `POST /api/v1/queue/{rule_id}/supersede` endpoint |

**New files (tests):**

| Path | Covers |
|---|---|
| `tests/llm/test_structured.py` | `structured_complete` happy path, repair retry, n_samples voting, all-fail behavior |
| `tests/coverage/test_mapper_phase_a_prompts.py` | CVE-grounded query, expanded verify prompt, Phase 1.5 tag-verify behavior |
| `tests/scripts/test_run_coverage_benchmark.py` | Runner script computes P/R/F1 and writes run row |
| `tests/api/test_coverage_benchmarks_router.py` | Endpoint smoke tests |
| `tests/queue/test_supersede.py` | Service writes benchmark row + adjusts coverage status |
| `tests/api/test_queue_supersede_endpoint.py` | Endpoint smoke test |

---

## Conventions (read before starting)

- **TDD.** Every task adds the failing test first.
- **Async everywhere.** Match existing patterns in `fragchain/llm/litellm_provider.py` and `fragchain/coverage/mapper.py`.
- **No real Postgres in unit tests.** Use `AsyncMock` for `AsyncSession`. Match Plan A test style.
- **No real LLM calls in tests.** Patch `LiteLLMProvider.complete` via `unittest.mock.patch`.
- **Imports:** `from __future__ import annotations` at the top of every new Python file.
- **Logging:** `structlog.get_logger(__name__)`. No `print`.
- **Commits:** one per task. Conventional commits: `feat(llm): ...`, `feat(coverage): ...`, `feat(api): ...`, `test(...): ...`.

---

## Phase Index

| Phase | Scope | Depends on |
|---|---|---|
| 1 | `structured_complete` utility | — |
| 2 | Mapper prompt updates (CVE-grounded query, expanded verify, Phase 1.5 tag-verify) | Phase 1 (the new verify call goes through `structured_complete`) |
| 3 | Benchmark runner CLI + endpoints | Phase 2 (the runner exercises the updated mapper) |
| 4 | Manual Supersede analyst action | — (independent of 1-3) |

Phases 1, 2, 3 are sequential. Phase 4 is independent and can land in parallel with any of the others.

---

## Phase 1 — `structured_complete` Utility

Goal: A single shared utility for "LLM call → Pydantic-validated response, with optional repair retry and majority-vote sampling." Used by Plan C Loop 1 + Loop 2, and (eventually) by the mapper's Phase 2 verify call in Phase 2 of this plan.

### Task 1.1: Schemas + error class

**Files:**
- Create: `fragchain/llm/structured.py`
- Test: `tests/llm/test_structured.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/llm/test_structured.py
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import BaseModel, ConfigDict

from fragchain.llm.structured import (
    StructuredOutputError,
    StructuredResult,
    structured_complete,
)


class _Toy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    count: int


def _mk_provider(text_responses: list[str]) -> AsyncMock:
    """Build a fake LLMProvider whose .complete returns sequential texts."""
    provider = AsyncMock()
    responses = [
        MagicMock(text=t, model="m", interaction_id=None,
                  usage=MagicMock(total_tokens=10),
                  latency_ms=1, finish_reason="stop", raw={})
        for t in text_responses
    ]
    provider.complete.side_effect = responses
    return provider


@pytest.mark.asyncio
async def test_n_samples_1_happy_path_returns_parsed_value():
    provider = _mk_provider(['{"name": "x", "count": 3}'])
    result = await structured_complete(
        provider=provider, system="S", user="U", model="m",
        schema=_Toy, interaction_type="OTHER", n_samples=1,
    )
    assert isinstance(result, StructuredResult)
    assert result.value == _Toy(name="x", count=3)
    assert result.confidence == 1.0
    assert result.attempts == 1
    provider.complete.assert_awaited_once()


@pytest.mark.asyncio
async def test_n_samples_1_repair_retry_on_validation_error():
    # First response is invalid JSON; second succeeds.
    provider = _mk_provider([
        '{"name": "x"}',  # missing count → ValidationError
        '{"name": "x", "count": 5}',
    ])
    result = await structured_complete(
        provider=provider, system="S", user="U", model="m",
        schema=_Toy, interaction_type="OTHER",
        n_samples=1, max_repair_attempts=2,
    )
    assert result.value.count == 5
    assert result.attempts == 2
    assert provider.complete.await_count == 2
    # Second call's user prompt MUST include the prior validation error so the
    # model knows what to fix.
    second_user = provider.complete.await_args_list[1].args[1]
    assert "count" in second_user
    assert "Field required" in second_user or "validation" in second_user.lower()


@pytest.mark.asyncio
async def test_n_samples_1_raises_after_exhausted_repair():
    provider = _mk_provider(['{"bad": true}'] * 3)
    with pytest.raises(StructuredOutputError) as exc_info:
        await structured_complete(
            provider=provider, system="S", user="U", model="m",
            schema=_Toy, interaction_type="OTHER",
            n_samples=1, max_repair_attempts=2,
        )
    assert "validation" in str(exc_info.value).lower()
    # initial + 2 repair attempts = 3
    assert provider.complete.await_count == 3


@pytest.mark.asyncio
async def test_n_samples_3_majority_vote():
    # Two agree on count=5, one is count=99 → consensus is 5 with 2/3 agreement.
    provider = _mk_provider([
        '{"name": "x", "count": 5}',
        '{"name": "x", "count": 5}',
        '{"name": "x", "count": 99}',
    ])
    result = await structured_complete(
        provider=provider, system="S", user="U", model="m",
        schema=_Toy, interaction_type="OTHER", n_samples=3,
    )
    assert result.value.count == 5
    assert result.confidence == pytest.approx(2 / 3, rel=1e-3)
    assert len(result.samples) == 3
    assert provider.complete.await_count == 3


@pytest.mark.asyncio
async def test_n_samples_3_all_invalid_raises():
    provider = _mk_provider(['{"bad": true}'] * 3)
    with pytest.raises(StructuredOutputError):
        await structured_complete(
            provider=provider, system="S", user="U", model="m",
            schema=_Toy, interaction_type="OTHER", n_samples=3,
        )
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/llm/test_structured.py -v`
Expected: `ModuleNotFoundError: No module named 'fragchain.llm.structured'`.

- [ ] **Step 3: Implement `structured_complete`**

```python
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
import json
import uuid
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

import structlog
from pydantic import BaseModel, ValidationError

from fragchain.llm.base import InteractionType, LLMProvider

logger = structlog.get_logger(__name__)


T = TypeVar("T", bound=BaseModel)


class StructuredOutputError(RuntimeError):
    """Raised when no sample validated against the schema."""


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
            temperature=temperature, timeout_seconds=timeout_seconds,
            entity_type=entity_type, entity_id=entity_id,
            prompt_template_id=prompt_template_id,
            prompt_version=prompt_version,
        )
    return await _voted(
        provider=provider, system=system, user=user, model=model,
        schema=schema, interaction_type=interaction_type,
        n_samples=n_samples, temperature=temperature,
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
    timeout_seconds: float,
    entity_type: str | None,
    entity_id: uuid.UUID | None,
    prompt_template_id: uuid.UUID | None,
    prompt_version: int | None,
) -> StructuredResult[T]:
    current_user = user
    last_error: str | None = None
    last_text: str = ""
    attempts = 0
    cost_total = 0.0

    for attempt in range(max_repair_attempts + 1):
        attempts += 1
        try:
            resp = await asyncio.wait_for(
                provider.complete(
                    system, current_user, model,
                    interaction_type=interaction_type,
                    entity_type=entity_type, entity_id=entity_id,
                    prompt_template_id=prompt_template_id,
                    prompt_version=prompt_version,
                    temperature=temperature,
                ),
                timeout=timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            last_error = f"timeout after {timeout_seconds}s"
            logger.warning("structured.timeout", attempt=attempt)
            continue

        last_text = resp.text
        try:
            value = schema.model_validate_json(_strip_fences(resp.text))
            return StructuredResult(
                value=value, confidence=1.0,
                samples=[value], attempts=attempts, cost_usd=cost_total,
            )
        except ValidationError as exc:
            last_error = exc.json()
            logger.info(
                "structured.repair_retry",
                attempt=attempt, error_summary=str(exc)[:200],
            )
            current_user = _repair_prompt(user, last_text, exc)

    raise StructuredOutputError(
        f"validation failed after {attempts} attempts: {last_error}"
    )


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
    timeout_seconds: float,
    entity_type: str | None,
    entity_id: uuid.UUID | None,
    prompt_template_id: uuid.UUID | None,
    prompt_version: int | None,
) -> StructuredResult[T]:
    async def _one():
        return await asyncio.wait_for(
            provider.complete(
                system, user, model,
                interaction_type=interaction_type,
                entity_type=entity_type, entity_id=entity_id,
                prompt_template_id=prompt_template_id,
                prompt_version=prompt_version,
                temperature=temperature,
            ),
            timeout=timeout_seconds,
        )

    responses = await asyncio.gather(
        *[_one() for _ in range(n_samples)],
        return_exceptions=True,
    )

    parsed: list[T] = []
    for resp in responses:
        if isinstance(resp, Exception):
            logger.warning("structured.sample_failed", error=str(resp))
            continue
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
        cost_usd=0.0,
    )


def _strip_fences(text: str) -> str:
    """Strip ```json fences a model sometimes adds despite instructions."""
    t = text.strip()
    if t.startswith("```"):
        # remove opening fence (optionally with language tag) and trailing fence
        first_nl = t.find("\n")
        if first_nl != -1:
            t = t[first_nl + 1 :]
        if t.endswith("```"):
            t = t[: -3]
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
```

- [ ] **Step 4: Re-export from `fragchain/llm/__init__.py`**

Add to the existing exports:

```python
from fragchain.llm.structured import (
    StructuredOutputError,
    StructuredResult,
    structured_complete,
)

__all__ = [
    # ... existing ...
    "StructuredOutputError",
    "StructuredResult",
    "structured_complete",
]
```

- [ ] **Step 5: Run test to confirm pass**

Run: `pytest tests/llm/test_structured.py -v`
Expected: PASS, 5 tests.

- [ ] **Step 6: Commit**

```bash
git add fragchain/llm/structured.py fragchain/llm/__init__.py tests/llm/test_structured.py
git commit -m "feat(llm): structured_complete utility for Pydantic-validated LLM calls"
```

---

## Phase 2 — Mapper Prompt Updates (§3.3)

Goal: Three edits to `fragchain/coverage/mapper.py` so coverage mapping reflects CVE-specific exploitation, not just technique semantics:

1. **Qdrant query** (in `_phase2_collect_candidates`): include the CVE description, affected product, and the TTP's `detection_opportunity`.
2. **Verify prompt** (in `_verify_one`): include the same CVE context + ask for `yes`/`partial`/`no` distinguishing same-CVE coverage from same-technique-different-CVE coverage.
3. **New Phase 1.5 tag-verify**: between `_phase1_exact_match` and Phase 2, run the same verify call on every Phase 1 exact-tag match. Demote `partial` matches to a separate bucket; drop `no` matches entirely.

The verify call goes through Phase 1's `structured_complete(schema=VerifyVerdict, n_samples=3)` — majority vote across 3 samples at temp=0.

### Task 2.1: Add `VerifyVerdict` schema + plumb `cve` into `_verify_one`

**Files:**
- Modify: `fragchain/coverage/mapper.py`
- Modify or create: `tests/coverage/test_mapper_phase_a_prompts.py`

- [ ] **Step 1: Read the current `_verify_one` shape**

Run: `sed -n '485,540p' fragchain/coverage/mapper.py`
Note the existing prompt text and the return type (`_VerifyOutcome`).

- [ ] **Step 2: Write the failing test**

```python
# tests/coverage/test_mapper_phase_a_prompts.py
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fragchain.coverage.mapper import (
    CoverageMapper,
    VerifyVerdict,
    _CandidateHit,
)


def _hit(*, tid="T1059", cve_text="CVE about deserialization rce in log4j",
         affected="Apache Log4j", detection_opp="watch for jndi:ldap lookups"):
    return _CandidateHit(
        technique_id=tid, technique_name="CSI", tactic_id="TA0002",
        tactic_name="Execution", rule_id=uuid.uuid4(),
        rule_title="r1", rule_yaml_excerpt="detection: ...",
        qdrant_score=0.85,
    )


@pytest.mark.asyncio
async def test_verify_one_includes_cve_context_in_prompt():
    """Phase A §3.3: verify prompt must include CVE description, affected_product, detection_opportunity."""
    captured: dict = {}

    async def _fake_structured(*, system, user, **kwargs):
        captured["system"] = system
        captured["user"] = user
        return MagicMock(
            value=VerifyVerdict(verdict="yes", one_line_reason="match"),
            confidence=1.0, samples=[], attempts=1, cost_usd=0.0,
        )

    cve = MagicMock(
        cve_id="CVE-2026-43284",
        title="Apache Log4j JNDI lookup vulnerability",
        description="A deserialization RCE in log4j JNDI handler...",
        affected_product="Apache Log4j 2.x",
    )
    ttp = MagicMock(
        technique_id="T1059", technique_name="CSI",
        tactic_id="TA0002", tactic="Execution",
        detection_opportunity="watch for jndi:ldap lookups from java.exe",
    )

    mapper = CoverageMapper.__new__(CoverageMapper)
    mapper._provider = AsyncMock()
    mapper._model = None
    mapper._cve = cve  # mapper now caches the CVE row for the run

    with patch(
        "fragchain.coverage.mapper.structured_complete", new=_fake_structured,
    ):
        outcome = await mapper._verify_one(mapper._provider, _hit(), ttp=ttp)

    assert "CVE-2026-43284" in captured["user"]
    assert "Apache Log4j" in captured["user"]
    assert "jndi:ldap lookups" in captured["user"]
    assert outcome.verdict == "yes"


@pytest.mark.asyncio
async def test_verify_verdict_schema_partial_means_same_technique_different_cve():
    """Schema docstring must distinguish partial from yes/no clearly."""
    v = VerifyVerdict(verdict="partial", one_line_reason="covers technique but different CVE")
    assert v.verdict == "partial"
    assert v.one_line_reason
```

- [ ] **Step 3: Run test to confirm failure**

Run: `pytest tests/coverage/test_mapper_phase_a_prompts.py -v -k verify`
Expected: FAIL — `VerifyVerdict` not exported, `_verify_one` doesn't accept `ttp=`, no `structured_complete` import in mapper.

- [ ] **Step 4: Modify the mapper**

In `fragchain/coverage/mapper.py`:

(a) Add the schema near the existing dataclasses:

```python
from pydantic import BaseModel, ConfigDict, Field

class VerifyVerdict(BaseModel):
    """Phase A §3.3 verify schema. Used by both Phase 1.5 and Phase 2."""
    model_config = ConfigDict(extra="forbid")

    verdict: str = Field(pattern="^(yes|partial|no)$")
    one_line_reason: str = Field(min_length=1, max_length=200)
```

(b) Import `structured_complete`:

```python
from fragchain.llm.structured import StructuredOutputError, structured_complete
```

(c) Rewrite `_verify_one` to take the CVE row + the TTP (caller already has both) and call `structured_complete`:

```python
async def _verify_one(
    self, provider: Any, candidate: _CandidateHit, *, ttp: ChainTTPRow,
) -> _VerifyOutcome:
    cve = self._cve  # populated in map_coverage, see (e) below
    cve_block = (
        f"CVE: {cve.cve_id}\n"
        f"Title: {cve.title}\n"
        f"Affected product: {cve.affected_product or '(unknown)'}\n"
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
        "Also emit a one-line reason for the verdict."
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
            n_samples=3,
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
```

(d) Extend `_VerifyOutcome` dataclass (near top of mapper.py) to carry `one_line_reason: str` if it doesn't already. Confirm via `grep -n "_VerifyOutcome" fragchain/coverage/mapper.py`; add the field if missing and persist it on the coverage_status row in `_persist_statuses`.

(e) In `map_coverage`, cache the CVE row on `self._cve` after loading it for the chain (the existing code already fetches the CVE for prompt context; if it doesn't, add a `self._cve = await self._load_cve_for_chain(chain_id)` line).

- [ ] **Step 5: Run test to confirm pass**

Run: `pytest tests/coverage/test_mapper_phase_a_prompts.py -v -k verify`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add fragchain/coverage/mapper.py tests/coverage/test_mapper_phase_a_prompts.py
git commit -m "feat(coverage): Phase A verify prompt + VerifyVerdict schema"
```

### Task 2.2: CVE-grounded Qdrant query

**Files:**
- Modify: `fragchain/coverage/mapper.py` (`_phase2_collect_candidates`)
- Modify: `tests/coverage/test_mapper_phase_a_prompts.py`

- [ ] **Step 1: Write the failing test**

```python
@pytest.mark.asyncio
async def test_phase2_query_includes_cve_context():
    """Qdrant query must include CVE id, affected product, technique, detection_opportunity."""
    cve = MagicMock(
        cve_id="CVE-2026-43284",
        title="log4j JNDI rce",
        affected_product="Apache Log4j 2.x",
    )
    ttp = MagicMock(
        technique_id="T1059", technique_name="CSI",
        tactic="Execution", tactic_id="TA0002",
        detection_opportunity="watch for jndi:ldap lookups",
    )

    captured_queries: list[str] = []

    embedder = AsyncMock()
    async def _search(query, limit):
        captured_queries.append(query)
        return []
    embedder.search_sigma_rules.side_effect = _search

    mapper = CoverageMapper.__new__(CoverageMapper)
    mapper._embedder = embedder
    mapper._result_limit = 20
    mapper._semantic_threshold = 0.5
    mapper._cve = cve

    with patch.object(CoverageMapper, "_load_rule_yaml_excerpt",
                      new=AsyncMock(return_value="")):
        await mapper._phase2_collect_candidates([ttp])

    assert captured_queries
    q = captured_queries[0]
    assert "CVE-2026-43284" in q
    assert "Apache Log4j" in q
    assert "T1059" in q
    assert "jndi:ldap lookups" in q
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/coverage/test_mapper_phase_a_prompts.py -v -k phase2_query`
Expected: FAIL.

- [ ] **Step 3: Replace the query construction**

In `_phase2_collect_candidates`, replace:

```python
query = (
    f"{tid} {ttp.technique_name or ''} detection in {tactic_label}"
).strip()
```

with:

```python
cve = self._cve
query = (
    f"CVE {cve.cve_id} affects {cve.affected_product or 'unknown product'}: "
    f"{cve.title or ''}. "
    f"Technique {tid} {ttp.technique_name or ''}. "
    f"Detection opportunity: {ttp.detection_opportunity or '(none)'}"
).strip()
```

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/coverage/test_mapper_phase_a_prompts.py -v -k phase2_query`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add fragchain/coverage/mapper.py tests/coverage/test_mapper_phase_a_prompts.py
git commit -m "feat(coverage): CVE-grounded Qdrant query in Phase 2"
```

### Task 2.3: New Phase 1.5 — tag-verify Phase 1 matches

**Files:**
- Modify: `fragchain/coverage/mapper.py`
- Modify: `tests/coverage/test_mapper_phase_a_prompts.py`

- [ ] **Step 1: Write the failing test**

```python
@pytest.mark.asyncio
async def test_phase_1_5_verify_demotes_partial_and_drops_no():
    """Phase 1.5 (new): verify each exact-tag match. yes→keep, partial→demote, no→drop."""
    cve = MagicMock(cve_id="CVE-X", title="x", description="x",
                    affected_product="prod")
    ttp = MagicMock(technique_id="T1059", technique_name="CSI",
                    tactic="Execution", tactic_id="TA0002",
                    detection_opportunity="")

    rid_yes = uuid.uuid4()
    rid_partial = uuid.uuid4()
    rid_no = uuid.uuid4()

    verdicts_by_rule = {
        rid_yes: "yes", rid_partial: "partial", rid_no: "no",
    }

    async def _fake_structured(*, system, user, **kwargs):
        # Extract which rule by sigma_rule context — the rule_id was placed
        # in entity_id by _verify_one. Easiest path: switch on rule body text.
        for rid, verdict in verdicts_by_rule.items():
            if str(rid) in user:
                return MagicMock(
                    value=VerifyVerdict(
                        verdict=verdict, one_line_reason="test",
                    ),
                    confidence=1.0, samples=[], attempts=1, cost_usd=0.0,
                )
        raise AssertionError("unmatched verify call")

    mapper = CoverageMapper.__new__(CoverageMapper)
    mapper._provider = AsyncMock()
    mapper._model = None
    mapper._cve = cve

    async def _load_excerpt(rid):
        return f"detection for {rid}"

    with patch.object(
        CoverageMapper, "_load_rule_yaml_excerpt", new=_load_excerpt,
    ), patch(
        "fragchain.coverage.mapper.structured_complete", new=_fake_structured,
    ):
        kept, partials = await mapper._phase1_5_verify_tag_match(
            ttp=ttp,
            rule_ids=[rid_yes, rid_partial, rid_no],
        )

    assert kept == [rid_yes]
    assert partials == [rid_partial]
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/coverage/test_mapper_phase_a_prompts.py -v -k phase_1_5`
Expected: FAIL — `_phase1_5_verify_tag_match` does not exist.

- [ ] **Step 3: Add the helper and wire it into `map_coverage`**

Add to `CoverageMapper`:

```python
async def _phase1_5_verify_tag_match(
    self,
    *,
    ttp: ChainTTPRow,
    rule_ids: list[uuid.UUID],
) -> tuple[list[uuid.UUID], list[uuid.UUID]]:
    """Verify each Phase 1 exact-tag match against the CVE.

    Returns (kept_covered, demoted_partial). Dropped 'no' verdicts are
    simply absent from both lists.
    """
    if not rule_ids:
        return [], []
    provider = self._provider or self._default_provider()
    if provider is None:
        # No LLM available → preserve legacy behavior (all tag matches keep).
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
```

In `map_coverage`, after the existing Phase 1 loop (`phase1[ttp.technique_id] = await self._phase1_exact_match(...)`), add Phase 1.5:

```python
phase1_5_partial: dict[str, list[uuid.UUID]] = {}
for ttp in ttps:
    tid = ttp.technique_id
    if not tid:
        continue
    kept, partial = await self._phase1_5_verify_tag_match(
        ttp=ttp, rule_ids=phase1.get(tid, []),
    )
    phase1[tid] = kept
    if partial:
        phase1_5_partial[tid] = partial
```

Then merge `phase1_5_partial` into the existing `partial_buckets` in the per-TTP grouping loop. Confirm the existing aggregation code path by reading `map_coverage` around the "Group phase 2 verdicts back to (technique_id) → covering / partial" section.

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/coverage/test_mapper_phase_a_prompts.py -v -k phase_1_5`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add fragchain/coverage/mapper.py tests/coverage/test_mapper_phase_a_prompts.py
git commit -m "feat(coverage): Phase 1.5 tag-verify before claiming exact-tag matches"
```

---

## Phase 3 — Benchmark Runner CLI + Endpoints

Goal: Run the labeled `coverage_benchmark` set against the current mapper and persist confusion-matrix + P/R/F1 into `coverage_benchmark_runs`. Expose a thin API on top so operators can trigger and inspect runs from `curl`.

### Task 3.1: Runner core (importable from both CLI and API)

**Files:**
- Create: `fragchain/coverage/benchmark.py`
- Test: `tests/coverage/test_benchmark.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/coverage/test_benchmark.py
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.coverage.benchmark import (
    BenchmarkResult,
    compute_confusion_matrix,
    run_benchmark,
)


def test_confusion_matrix_counts_correctly():
    predictions = [
        ("covered", "covered"),    # TP
        ("covered", "no_match"),   # FP
        ("no_match", "covered"),   # FN
        ("no_match", "no_match"),  # TN
        ("partial", "partial"),    # TP (partial counted as positive)
        ("partial", "no_match"),   # FP
    ]
    cm = compute_confusion_matrix(predictions)
    assert cm.true_positives == 3
    assert cm.false_positives == 2
    assert cm.false_negatives == 1
    assert cm.true_negatives == 1
    assert cm.precision == pytest.approx(3 / 5)
    assert cm.recall == pytest.approx(3 / 4)


def test_confusion_matrix_handles_zero_predictions():
    cm = compute_confusion_matrix([])
    assert cm.precision == 0.0
    assert cm.recall == 0.0
    assert cm.f1 == 0.0


@pytest.mark.asyncio
async def test_run_benchmark_persists_a_run_row_with_metrics():
    session = AsyncMock()
    # Stub the labeled-set fetch: two pairs, mapper predicts one correctly.
    labeled = [
        MagicMock(cve_id=uuid.uuid4(), technique_id="T1059",
                  rule_id=uuid.uuid4(), expected_verdict="covered"),
        MagicMock(cve_id=uuid.uuid4(), technique_id="T1059",
                  rule_id=uuid.uuid4(), expected_verdict="no_match"),
    ]
    fetch = MagicMock()
    fetch_scalars = MagicMock()
    fetch_scalars.all.return_value = labeled
    fetch.scalars.return_value = fetch_scalars
    session.execute.return_value = fetch

    # Stub the mapper: predict "covered" for both → 1 TP, 1 FP.
    mapper = AsyncMock()
    mapper.predict_verdict_for_pair.return_value = "covered"

    result = await run_benchmark(
        session=session, mapper=mapper, run_label="test-run",
        notes="unit test",
    )

    assert isinstance(result, BenchmarkResult)
    assert result.run_label == "test-run"
    assert result.total_pairs == 2
    assert result.true_positives == 1
    assert result.false_positives == 1
    # session.add should have been called once with the run row.
    add_calls = session.add.call_args_list
    assert len(add_calls) == 1
    session.commit.assert_awaited()
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/coverage/test_benchmark.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Implement the runner core**

```python
# fragchain/coverage/benchmark.py
"""Coverage benchmark runner — measure mapper P/R/F1 against labeled ground truth.

Phase A §3.2. Loaded by both the CLI script and the `POST /api/v1/coverage/
benchmarks/runs` endpoint. Treats both ``covered`` and ``partial`` as positive
predictions; ``no_match`` is the negative class.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.db.models import CoverageBenchmarkRow, CoverageBenchmarkRun

logger = structlog.get_logger(__name__)


_POSITIVE_VERDICTS = frozenset({"covered", "partial"})


@dataclass
class ConfusionMatrix:
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class BenchmarkResult:
    run_id: uuid.UUID
    run_label: str
    total_pairs: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float


def compute_confusion_matrix(
    predictions: list[tuple[str, str]],
) -> ConfusionMatrix:
    """Take a list of ``(predicted_verdict, expected_verdict)`` tuples."""
    cm = ConfusionMatrix()
    for predicted, expected in predictions:
        pred_pos = predicted in _POSITIVE_VERDICTS
        exp_pos = expected in _POSITIVE_VERDICTS
        if pred_pos and exp_pos:
            cm.true_positives += 1
        elif pred_pos and not exp_pos:
            cm.false_positives += 1
        elif not pred_pos and exp_pos:
            cm.false_negatives += 1
        else:
            cm.true_negatives += 1
    return cm


async def run_benchmark(
    *,
    session: AsyncSession,
    mapper: Any,
    run_label: str,
    notes: str | None = None,
    prompt_template_id: uuid.UUID | None = None,
    semantic_threshold: float | None = None,
) -> BenchmarkResult:
    """Re-map every labeled pair and persist a `coverage_benchmark_runs` row.

    ``mapper`` must expose
    ``async predict_verdict_for_pair(cve_id, technique_id, rule_id) -> str``.
    """
    labeled = (
        await session.execute(select(CoverageBenchmarkRow))
    ).scalars().all()

    predictions: list[tuple[str, str]] = []
    for row in labeled:
        try:
            verdict = await mapper.predict_verdict_for_pair(
                row.cve_id, row.technique_id, row.rule_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "benchmark.predict_failed",
                cve_id=str(row.cve_id), technique_id=row.technique_id,
                rule_id=str(row.rule_id), error=str(exc),
            )
            verdict = "no_match"  # conservative on error
        predictions.append((verdict, row.expected_verdict))

    cm = compute_confusion_matrix(predictions)
    started = datetime.now(tz=timezone.utc)

    run = CoverageBenchmarkRun(
        run_label=run_label,
        prompt_template_id=prompt_template_id,
        semantic_threshold=semantic_threshold,
        started_at=started,
        completed_at=started,
        total_pairs=len(labeled),
        true_positives=cm.true_positives,
        false_positives=cm.false_positives,
        true_negatives=cm.true_negatives,
        false_negatives=cm.false_negatives,
        precision_score=round(cm.precision, 4),
        recall_score=round(cm.recall, 4),
        f1_score=round(cm.f1, 4),
        notes=notes,
    )
    session.add(run)
    await session.commit()
    await session.refresh(run)

    return BenchmarkResult(
        run_id=run.id, run_label=run.run_label,
        total_pairs=run.total_pairs,
        true_positives=run.true_positives,
        false_positives=run.false_positives,
        true_negatives=run.true_negatives,
        false_negatives=run.false_negatives,
        precision=float(run.precision_score),
        recall=float(run.recall_score),
        f1=float(run.f1_score),
    )
```

> **`mapper.predict_verdict_for_pair` contract:** the runner depends on a public method that maps one labeled pair to one verdict. `CoverageMapper` currently exposes `map_coverage(chain_id)` (whole-chain). Add a thin public method `async predict_verdict_for_pair(cve_id, technique_id, rule_id) -> str` to `fragchain/coverage/mapper.py` that loads the rule + cve, runs the same Phase 1.5/Phase 2 verify against the single candidate, and returns `covered` / `partial` / `no_match`. This is a 30-line addition; copy the existing `_verify_one` invocation pattern. Add a test under `tests/coverage/test_mapper_phase_a_prompts.py`.

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/coverage/test_benchmark.py -v`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add fragchain/coverage/benchmark.py tests/coverage/test_benchmark.py
git commit -m "feat(coverage): benchmark runner core (P/R/F1 over labeled set)"
```

### Task 3.2: CLI script `scripts/run_coverage_benchmark.py`

**Files:**
- Create: `scripts/run_coverage_benchmark.py`
- Test: `tests/scripts/test_run_coverage_benchmark.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/scripts/test_run_coverage_benchmark.py
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from scripts.run_coverage_benchmark import main_async


@pytest.mark.asyncio
async def test_cli_invokes_run_benchmark_with_label():
    session = AsyncMock()

    @asynccontextmanager_compat
    async def _sm():
        yield session

    fake_result = AsyncMock()
    with patch(
        "scripts.run_coverage_benchmark._sessionmaker", new=_sm,
    ), patch(
        "scripts.run_coverage_benchmark.run_benchmark",
        new=AsyncMock(return_value=fake_result),
    ) as rb, patch(
        "scripts.run_coverage_benchmark.CoverageMapper",
    ):
        await main_async(["--label", "test-run"])

    rb.assert_awaited_once()
    kwargs = rb.await_args.kwargs
    assert kwargs["run_label"] == "test-run"
```

(Where `asynccontextmanager_compat` is the helper used in other Plan A/B scripts for the test session.)

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/scripts/test_run_coverage_benchmark.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Implement the CLI**

```python
# scripts/run_coverage_benchmark.py
"""Run the coverage benchmark against the labeled set.

Usage: docker compose exec api python -m scripts.run_coverage_benchmark \
           --label <run_label> [--notes "..."]
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager

import structlog

from fragchain.coverage.benchmark import run_benchmark
from fragchain.coverage.mapper import CoverageMapper
from fragchain.db.session import get_sessionmaker

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def _sessionmaker():
    sm = get_sessionmaker()
    async with sm() as session:
        yield session


async def main_async(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run coverage benchmark")
    parser.add_argument("--label", required=True, help="Run label, e.g. 'phase-a' or 'phase-a-assessment-v1'")
    parser.add_argument("--notes", default=None)
    args = parser.parse_args(argv)

    async with _sessionmaker() as session:
        mapper = CoverageMapper(session)
        result = await run_benchmark(
            session=session, mapper=mapper,
            run_label=args.label, notes=args.notes,
        )
    logger.info(
        "benchmark.completed",
        run_id=str(result.run_id), run_label=result.run_label,
        total=result.total_pairs,
        tp=result.true_positives, fp=result.false_positives,
        tn=result.true_negatives, fn=result.false_negatives,
        precision=result.precision, recall=result.recall, f1=result.f1,
    )


def main() -> None:  # pragma: no cover — entry point
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/scripts/test_run_coverage_benchmark.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/run_coverage_benchmark.py tests/scripts/test_run_coverage_benchmark.py
git commit -m "feat(scripts): CLI runner for coverage benchmark"
```

### Task 3.3: FastAPI router for benchmark runs

**Files:**
- Create: `fragchain/api/routers/coverage_benchmarks.py`
- Modify: `fragchain/api/main.py` (register router)
- Test: `tests/api/test_coverage_benchmarks_router.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/api/test_coverage_benchmarks_router.py
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.asyncio
async def test_post_runs_triggers_benchmark(api_client_factory):
    fake_result = AsyncMock(
        run_id=uuid.uuid4(), run_label="test", total_pairs=2,
        true_positives=1, false_positives=0, true_negatives=1,
        false_negatives=0, precision=1.0, recall=1.0, f1=1.0,
    )
    with patch(
        "fragchain.api.routers.coverage_benchmarks.run_benchmark",
        new=AsyncMock(return_value=fake_result),
    ):
        async with api_client_factory() as client:
            resp = await client.post(
                "/api/v1/coverage/benchmarks/runs",
                json={"run_label": "test"},
            )
    assert resp.status_code == 201
    body = resp.json()
    assert body["run_label"] == "test"
    assert body["precision"] == 1.0


@pytest.mark.asyncio
async def test_get_runs_lists_summary(api_client_factory):
    # ... seed two CoverageBenchmarkRun rows, GET /api/v1/coverage/benchmarks/runs
    # assert both appear with run_label / metrics.
    ...


@pytest.mark.asyncio
async def test_get_run_by_id_returns_detail(api_client_factory):
    # ... seed one row, GET /api/v1/coverage/benchmarks/runs/{id}
    # assert returns the row with per-pair predictions section (initially empty
    # / TODO — the spec says "per-pair predictions for error analysis").
    ...
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/api/test_coverage_benchmarks_router.py -v`
Expected: FAIL (404 — router not registered).

- [ ] **Step 3: Implement the router**

```python
# fragchain/api/routers/coverage_benchmarks.py
"""Coverage benchmark run endpoints (Phase A §3.2)."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.api.deps import get_session  # match the existing dep name
from fragchain.coverage.benchmark import run_benchmark
from fragchain.coverage.mapper import CoverageMapper
from fragchain.db.models import CoverageBenchmarkRun

router = APIRouter(prefix="/api/v1/coverage/benchmarks", tags=["coverage"])


class RunRequest(BaseModel):
    run_label: str
    notes: str | None = None


class RunSummary(BaseModel):
    id: uuid.UUID
    run_label: str
    started_at: str
    completed_at: str | None
    total_pairs: int
    precision: float
    recall: float
    f1: float


class RunDetail(RunSummary):
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    notes: str | None


@router.post("/runs", status_code=status.HTTP_201_CREATED, response_model=RunDetail)
async def create_run(
    body: RunRequest, session: AsyncSession = Depends(get_session),
) -> RunDetail:
    mapper = CoverageMapper(session)
    result = await run_benchmark(
        session=session, mapper=mapper,
        run_label=body.run_label, notes=body.notes,
    )
    row = (
        await session.execute(
            select(CoverageBenchmarkRun).where(
                CoverageBenchmarkRun.id == result.run_id
            )
        )
    ).scalar_one()
    return _to_detail(row)


@router.get("/runs", response_model=list[RunSummary])
async def list_runs(
    session: AsyncSession = Depends(get_session),
) -> list[RunSummary]:
    rows = (
        await session.execute(
            select(CoverageBenchmarkRun)
            .order_by(desc(CoverageBenchmarkRun.started_at))
        )
    ).scalars().all()
    return [_to_summary(r) for r in rows]


@router.get("/runs/{run_id}", response_model=RunDetail)
async def get_run(
    run_id: uuid.UUID, session: AsyncSession = Depends(get_session),
) -> RunDetail:
    row = (
        await session.execute(
            select(CoverageBenchmarkRun).where(
                CoverageBenchmarkRun.id == run_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="benchmark run not found")
    return _to_detail(row)


def _to_summary(row: CoverageBenchmarkRun) -> RunSummary:
    return RunSummary(
        id=row.id, run_label=row.run_label,
        started_at=row.started_at.isoformat(),
        completed_at=row.completed_at.isoformat() if row.completed_at else None,
        total_pairs=row.total_pairs,
        precision=float(row.precision_score or 0),
        recall=float(row.recall_score or 0),
        f1=float(row.f1_score or 0),
    )


def _to_detail(row: CoverageBenchmarkRun) -> RunDetail:
    summary = _to_summary(row)
    return RunDetail(
        **summary.model_dump(),
        true_positives=row.true_positives,
        false_positives=row.false_positives,
        true_negatives=row.true_negatives,
        false_negatives=row.false_negatives,
        notes=row.notes,
    )
```

Register in `fragchain/api/main.py`:

```python
from fragchain.api.routers import coverage_benchmarks  # add to imports
app.include_router(coverage_benchmarks.router)  # add next to existing includes
```

> **Per-pair predictions in `RunDetail`:** Phase A §3.2 says the single-run endpoint should expose "per-pair predictions for error analysis." This requires a new `coverage_benchmark_predictions` table or a JSONB column on `coverage_benchmark_runs` to store the prediction list. **Deferred to a follow-up task** to keep this phase tight — note in the response with a comment that error-analysis detail will land in a follow-up. The runner already throws away the per-pair predictions; capturing them is a one-line change in `run_benchmark` + a schema migration.

- [ ] **Step 4: Run tests to confirm pass**

Run: `pytest tests/api/test_coverage_benchmarks_router.py -v`
Expected: PASS (1+ tests; the listed `...` stubs can be filled out using the existing API test fixture pattern).

- [ ] **Step 5: Commit**

```bash
git add fragchain/api/routers/coverage_benchmarks.py fragchain/api/main.py tests/api/test_coverage_benchmarks_router.py
git commit -m "feat(api): coverage benchmark run endpoints"
```

---

## Phase 4 — Manual Supersede Analyst Action (§3.6)

Goal: Analyst can click "Supersede with existing rule" on a queue item, supply a rationale, and the system records the decision as ground-truth labeling for future benchmark runs.

**Schema status:** migration `0016_coverage_verification` already added `review_queue.supersede_rule_id`, allows `review_queue.status='superseded'`, and created the `rule_evaluations` table. No new migration needed.

### Task 4.1: SupersedeService

**Files:**
- Create: `fragchain/queue/supersede.py`
- Test: `tests/queue/test_supersede.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/queue/test_supersede.py
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.queue.supersede import (
    SupersedeError,
    SupersedeService,
)


def _queue_row(status="pending", chain_id=None, technique_id="T1059"):
    return MagicMock(
        id=uuid.uuid4(), status=status,
        chain_id=chain_id or uuid.uuid4(),
        technique_id=technique_id,
        supersede_rule_id=None,
    )


def _coverage_row(covering=None, partial=None):
    return MagicMock(
        covering_rule_ids=covering or [],
        partial_rule_ids=partial or [],
    )


@pytest.mark.asyncio
async def test_supersede_happy_path_updates_queue_and_coverage_and_writes_eval():
    queue_item = _queue_row()
    existing_rule_id = uuid.uuid4()
    coverage = _coverage_row(covering=[], partial=[existing_rule_id])

    session = AsyncMock()
    queue_fetch = MagicMock(); qs = MagicMock(); qs.scalar_one_or_none.return_value = queue_item; queue_fetch.scalars.return_value = qs
    cov_fetch = MagicMock(); cs = MagicMock(); cs.scalar_one_or_none.return_value = coverage; cov_fetch.scalars.return_value = cs
    rule_fetch = MagicMock(); rs = MagicMock(); rs.scalar_one_or_none.return_value = MagicMock(id=existing_rule_id); rule_fetch.scalars.return_value = rs
    session.execute.side_effect = [queue_fetch, rule_fetch, cov_fetch]

    svc = SupersedeService(session)
    result = await svc.supersede(
        review_id=queue_item.id, supersede_rule_id=existing_rule_id,
        rationale="duplicate of an existing approved rule",
        actor="analyst@example.com",
    )

    assert queue_item.status == "superseded"
    assert queue_item.supersede_rule_id == existing_rule_id
    assert existing_rule_id in coverage.covering_rule_ids
    assert existing_rule_id not in coverage.partial_rule_ids
    # session.add called once for the rule_evaluations row.
    add_calls = session.add.call_args_list
    assert len(add_calls) == 1
    assert result["review_id"] == queue_item.id


@pytest.mark.asyncio
async def test_supersede_rejects_already_superseded_item():
    item = _queue_row(status="superseded")
    session = AsyncMock()
    qf = MagicMock(); qs = MagicMock(); qs.scalar_one_or_none.return_value = item; qf.scalars.return_value = qs
    session.execute.return_value = qf

    svc = SupersedeService(session)
    with pytest.raises(SupersedeError, match="not in pending"):
        await svc.supersede(
            review_id=item.id, supersede_rule_id=uuid.uuid4(),
            rationale="x", actor="a",
        )


@pytest.mark.asyncio
async def test_supersede_rejects_unknown_existing_rule():
    item = _queue_row()
    session = AsyncMock()
    qf = MagicMock(); qs = MagicMock(); qs.scalar_one_or_none.return_value = item; qf.scalars.return_value = qs
    rf = MagicMock(); rs = MagicMock(); rs.scalar_one_or_none.return_value = None; rf.scalars.return_value = rs
    session.execute.side_effect = [qf, rf]

    svc = SupersedeService(session)
    with pytest.raises(SupersedeError, match="not found"):
        await svc.supersede(
            review_id=item.id, supersede_rule_id=uuid.uuid4(),
            rationale="x", actor="a",
        )


@pytest.mark.asyncio
async def test_supersede_rejects_oversized_rationale():
    svc = SupersedeService(AsyncMock())
    with pytest.raises(SupersedeError, match="rationale"):
        await svc.supersede(
            review_id=uuid.uuid4(), supersede_rule_id=uuid.uuid4(),
            rationale="x" * 300,  # > 200 char cap per §3.6
            actor="a",
        )
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/queue/test_supersede.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Implement the service**

```python
# fragchain/queue/supersede.py
"""Manual Supersede analyst action (Phase A §3.6).

Closes a pending review_queue item with status='superseded', records the
chosen existing rule, and writes a rule_evaluations row that doubles as
ground-truth labeling data for future benchmark runs.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.db.models import (
    CoverageMap,
    ReviewQueueItem,
    RuleEvaluation,
    SigmaRule,
)

logger = structlog.get_logger(__name__)


_MAX_RATIONALE_LEN = 200


class SupersedeError(ValueError):
    """Raised when a supersede request cannot be honored."""


class SupersedeService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def supersede(
        self,
        *,
        review_id: uuid.UUID,
        supersede_rule_id: uuid.UUID,
        rationale: str,
        actor: str,
    ) -> dict:
        rationale = (rationale or "").strip()
        if not rationale:
            raise SupersedeError("rationale must be non-empty")
        if len(rationale) > _MAX_RATIONALE_LEN:
            raise SupersedeError(
                f"rationale exceeds {_MAX_RATIONALE_LEN} char cap"
            )

        item = (
            await self._session.execute(
                select(ReviewQueueItem).where(
                    ReviewQueueItem.id == review_id
                )
            )
        ).scalars().scalar_one_or_none()
        if item is None:
            raise SupersedeError(f"review item {review_id} not found")
        if item.status != "pending":
            raise SupersedeError(
                f"review item {review_id} not in pending state "
                f"(status={item.status})"
            )

        existing = (
            await self._session.execute(
                select(SigmaRule).where(SigmaRule.id == supersede_rule_id)
            )
        ).scalars().scalar_one_or_none()
        if existing is None:
            raise SupersedeError(
                f"supersede target rule {supersede_rule_id} not found"
            )

        # Update coverage_map for (chain_id, technique_id).
        coverage = (
            await self._session.execute(
                select(CoverageMap)
                .where(CoverageMap.chain_id == item.chain_id)
                .where(CoverageMap.technique_id == item.technique_id)
            )
        ).scalars().scalar_one_or_none()
        if coverage is not None:
            covering = list(coverage.covering_rule_ids or [])
            partial = list(coverage.partial_rule_ids or [])
            if supersede_rule_id not in covering:
                covering.append(supersede_rule_id)
            partial = [r for r in partial if r != supersede_rule_id]
            coverage.covering_rule_ids = covering
            coverage.partial_rule_ids = partial

        # Close the review item.
        item.status = "superseded"
        item.supersede_rule_id = supersede_rule_id

        # Write a rule_evaluations row — doubles as benchmark labeling data.
        evaluation = RuleEvaluation(
            rule_id=supersede_rule_id,
            chain_id=item.chain_id,
            action="supersede",
            actor=actor,
            rationale=rationale,
            created_at=datetime.now(tz=timezone.utc),
        )
        self._session.add(evaluation)

        logger.info(
            "queue.supersede.applied",
            review_id=str(review_id),
            supersede_rule_id=str(supersede_rule_id),
            actor=actor,
        )
        return {
            "review_id": item.id,
            "status": "superseded",
            "supersede_rule_id": supersede_rule_id,
        }
```

> **Schema note:** `RuleEvaluation` field names (`rule_id`, `chain_id`, `action`, `actor`, `rationale`, `created_at`) are assumed from the §3.6 spec text. Confirm against `fragchain/db/models.py:1249+` and adjust if any field name differs. If the model doesn't yet have `action='supersede'` in any CHECK constraint, no DB change is needed (Python-side enum only).

- [ ] **Step 4: Run test to confirm pass**

Run: `pytest tests/queue/test_supersede.py -v`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add fragchain/queue/supersede.py tests/queue/test_supersede.py
git commit -m "feat(queue): SupersedeService for manual Supersede analyst action"
```

### Task 4.2: API endpoint `POST /api/v1/queue/{review_id}/supersede`

**Files:**
- Modify: `fragchain/api/routers/queue.py`
- Test: `tests/api/test_queue_supersede_endpoint.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/api/test_queue_supersede_endpoint.py
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest

from fragchain.queue.supersede import SupersedeError


@pytest.mark.asyncio
async def test_post_supersede_happy_path(api_client_factory):
    review_id = uuid.uuid4()
    supersede_rule_id = uuid.uuid4()

    with patch(
        "fragchain.api.routers.queue.SupersedeService.supersede",
        new=AsyncMock(return_value={
            "review_id": review_id,
            "status": "superseded",
            "supersede_rule_id": supersede_rule_id,
        }),
    ) as sv:
        async with api_client_factory() as client:
            resp = await client.post(
                f"/api/v1/queue/{review_id}/supersede",
                json={
                    "rule_id": str(supersede_rule_id),
                    "rationale": "duplicate of approved rule abc",
                },
                headers={"X-User-Email": "analyst@example.com"},
            )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "superseded"
    sv.assert_awaited_once()


@pytest.mark.asyncio
async def test_post_supersede_returns_400_on_validation_error(api_client_factory):
    review_id = uuid.uuid4()
    with patch(
        "fragchain.api.routers.queue.SupersedeService.supersede",
        side_effect=SupersedeError("rationale must be non-empty"),
    ):
        async with api_client_factory() as client:
            resp = await client.post(
                f"/api/v1/queue/{review_id}/supersede",
                json={"rule_id": str(uuid.uuid4()), "rationale": ""},
                headers={"X-User-Email": "a@b.c"},
            )
    assert resp.status_code == 400
    assert "rationale" in resp.json()["detail"]
```

- [ ] **Step 2: Run test to confirm failure**

Run: `pytest tests/api/test_queue_supersede_endpoint.py -v`
Expected: 404 (endpoint not registered).

- [ ] **Step 3: Add the endpoint to `fragchain/api/routers/queue.py`**

```python
# Add imports
from pydantic import BaseModel, Field

from fragchain.queue.supersede import SupersedeError, SupersedeService


class SupersedeRequest(BaseModel):
    rule_id: uuid.UUID
    rationale: str = Field(min_length=1, max_length=200)


class SupersedeResponse(BaseModel):
    review_id: uuid.UUID
    status: str
    supersede_rule_id: uuid.UUID


@router.post(
    "/{review_id}/supersede",
    response_model=SupersedeResponse,
)
async def supersede_review_item(
    review_id: uuid.UUID,
    body: SupersedeRequest,
    session: AsyncSession = Depends(get_session),
    actor: str = Depends(get_request_actor),  # match the existing dep
) -> SupersedeResponse:
    svc = SupersedeService(session)
    try:
        result = await svc.supersede(
            review_id=review_id,
            supersede_rule_id=body.rule_id,
            rationale=body.rationale,
            actor=actor,
        )
    except SupersedeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await session.commit()
    return SupersedeResponse(**result)
```

> **Actor resolution:** check the existing `queue.py` router for how it identifies the actor (header, dep, request state). Reuse that pattern instead of inventing a new one. If no actor plumbing exists yet, accept an `X-User-Email` header for v1 and TODO a proper auth integration.

- [ ] **Step 4: Run tests to confirm pass**

Run: `pytest tests/api/test_queue_supersede_endpoint.py -v`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add fragchain/api/routers/queue.py tests/api/test_queue_supersede_endpoint.py
git commit -m "feat(api): POST /queue/{id}/supersede analyst action"
```

---

## Self-Review Checklist

1. **Spec coverage** — every Phase A non-blocker / soft-blocker / hard-blocker item from the audit maps to a phase:
   - §3.1 `structured_complete` → Phase 1 ✓
   - §3.3 mapper Qdrant query → Phase 2 Task 2.2 ✓
   - §3.3 mapper verify prompt → Phase 2 Task 2.1 ✓
   - §3.3 new Phase 1.5 → Phase 2 Task 2.3 ✓
   - §3.2 benchmark runner CLI → Phase 3 Task 3.2 ✓
   - §3.2 benchmark endpoints → Phase 3 Task 3.3 ✓
   - §3.6 manual Supersede action → Phase 4 ✓

2. **Out-of-scope items remain out**: chain generator migration to `structured_complete` (audit §2.9), `content_hash` backfill (audit §2.10), per-pair predictions storage in `coverage_benchmark_runs` (deferred follow-up noted in Task 3.3).

3. **Type consistency:**
   - `structured_complete(*, provider, system, user, model, schema, interaction_type, ...)` signature is identical in Phase 1, Phase 2 mapper, and Plan C Loop 1 / Loop 2.
   - `VerifyVerdict` schema (Phase 2 Task 2.1) is consumed by Phase 1.5 (Task 2.3) and Phase 2's verify call (Task 2.1) — single definition.
   - `SupersedeService.supersede(*, review_id, supersede_rule_id, rationale, actor)` signature is consistent across Task 4.1 + Task 4.2.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-18-phase-a-completion.md`. Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks.
2. **Inline Execution** — execute tasks in this session using `superpowers:executing-plans` with checkpoints.

Which approach?



