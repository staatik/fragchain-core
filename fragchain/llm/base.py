"""LLMProvider Protocol + dataclasses (M5).

The framework half of the LLM access layer. fragchain-core ships exactly one
concrete provider in v1 (`LiteLLMProvider`); future providers (OpenAI direct,
Anthropic direct, Ollama direct — M39/M40/M41) register via the
`fragchain.providers` entry-point group and plug in through this Protocol.

The engine never imports a specific provider. Chain synthesis (M11), rule
generation (M14), and embedding pipelines (M8) all consume `LLMProvider` —
they only know how to call `complete()` and `embed()`. The Protocol therefore
defines the *only* surface the rest of the code is allowed to assume about an
LLM.

Two design rules baked in here, both required by CLAUDE.md §6:

1.  Every call must be observable. `LLMResponse` and `EmbeddingResponse` carry
    an `interaction_id` (UUID) so callers can correlate a chain row → an
    `llm_interactions` row → a MinIO blob. The provider is responsible for
    writing those side effects before returning.

2.  Retry semantics live in the provider, not in callers. The Protocol exposes
    `complete()`/`embed()` as if they always succeed; rate-limit retries (429),
    transient 5xx, and exponential backoff are the provider's job. Callers
    that want to opt out pass `retry=False`.

Reference: CLAUDE.md §6, FragChain_Module_Specifications.md M5.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Enums + dataclasses
# ---------------------------------------------------------------------------


class InteractionType(str, Enum):
    """What kind of LLM call this is — drives the `interaction_type` column.

    Aligned with the four call sites in CLAUDE.md §6 / M5 spec. Anything that
    doesn't fall into one of these should pass `InteractionType.OTHER`.
    """

    CHAIN_GENERATION = "chain_generation"
    RULE_GENERATION = "rule_generation"
    COVERAGE_VERIFY = "coverage_verify"
    EMBEDDING = "embedding"
    HEALTH_CHECK = "health_check"
    OTHER = "other"
    ASSESSMENT_LOOP_1 = "assessment_loop_1"
    ASSESSMENT_LOOP_2 = "assessment_loop_2"
    ASSESSMENT_LOOP_3 = "assessment_loop_3"
    DETECTABILITY_CLASSIFICATION = "detectability_classification"
    MITIGATION_PLAN = "mitigation_plan"
    ANALYST_RESEARCH_TASK = "analyst_research_task"
    TELEMETRY_CONTRACT = "telemetry_contract"


class ProviderHealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ProviderHealth:
    """Result of `LLMProvider.health_check()`.

    `latency_ms` and `message` are diagnostic. The UI surfaces `status` as the
    topbar dot; the provider detail screen (M24) shows the full record.
    """

    status: ProviderHealthStatus
    message: str | None = None
    latency_ms: int | None = None
    checked_at: datetime | None = None
    models_available: list[str] = field(default_factory=list)


@dataclass
class TokenUsage:
    """OpenAI-shaped token counts.

    LiteLLM normalizes every backend's usage payload into this shape, so a
    single dataclass covers every provider we expect to ship. Costs in USD
    when LiteLLM emits them in response headers; otherwise None.
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float | None = None


@dataclass
class LLMResponse:
    """Result of a chat completion.

    `text` is the message content (concatenated tool/assistant deltas if the
    underlying SDK chose to chunk). `raw` is the SDK's response object dumped
    to a dict for debugging — never relied on by callers. `interaction_id` is
    the UUID of the row in `llm_interactions`; callers persist it on the
    artifact they're producing (chain row, rule row, …) so an analyst can
    drill back into the full prompt+response.
    """

    text: str
    model: str
    provider: str
    interaction_id: uuid.UUID
    usage: TokenUsage = field(default_factory=TokenUsage)
    latency_ms: int = 0
    finish_reason: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class EmbeddingResponse:
    """Result of an embedding call.

    `vectors[i]` aligns with the i-th input text. `dimensions` is exposed
    explicitly so callers building a Qdrant collection can sanity-check
    against the deployment's configured dimension (768 in v1 per CLAUDE.md).
    """

    vectors: list[list[float]]
    model: str
    provider: str
    interaction_id: uuid.UUID
    dimensions: int
    usage: TokenUsage = field(default_factory=TokenUsage)
    latency_ms: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


class LLMError(Exception):
    """Base class for provider-side errors that survive retry.

    Providers wrap network/SDK exceptions in subclasses before raising so
    callers can branch on type rather than parsing strings.
    """


class LLMRateLimitError(LLMError):
    """All retries were exhausted on HTTP 429."""


class LLMServerError(LLMError):
    """All retries were exhausted on a 5xx response."""


class LLMAuthError(LLMError):
    """The provider refused credentials. Never retried."""


class LLMInvalidRequestError(LLMError):
    """The request was malformed (4xx other than 429). Never retried."""


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class LLMProvider(Protocol):
    """Pluggable LLM access layer.

    Concrete providers live in separate packages (`fragchain-provider-*`) and
    register via the `fragchain.providers` entry-point group. v1 ships only
    `fragchain-provider-litellm` inside core. The Protocol is closed — adding
    a new method requires bumping every existing provider, so keep it small.

    Lifecycle: a provider is constructed (zero-arg), then `initialize()` is
    called once during app startup. The provider holds long-lived clients
    (e.g. `openai.AsyncOpenAI`) on the instance until `shutdown()`.

    Every call to `complete()` and `embed()` MUST:
      * measure wall-clock latency
      * insert a row into `llm_interactions`
      * store the full I/O JSON to MinIO at `llm-io/{date}/{interaction_id}.json`
      * tolerate the side-effect targets being unavailable (log + degrade,
        never crash the caller)
    """

    name: str
    version: str
    supports_chat: bool
    supports_embeddings: bool
    supports_streaming: bool

    async def initialize(self) -> None: ...

    async def shutdown(self) -> None: ...

    async def health_check(self) -> ProviderHealth: ...

    async def complete(
        self,
        system: str,
        prompt: str,
        model: str,
        *,
        interaction_type: InteractionType = InteractionType.OTHER,
        entity_type: str | None = None,
        entity_id: uuid.UUID | None = None,
        prompt_template_id: uuid.UUID | None = None,
        prompt_version: int | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        retry: bool = True,
        **kwargs: Any,
    ) -> LLMResponse: ...

    async def embed(
        self,
        texts: list[str],
        model: str,
        *,
        interaction_type: InteractionType = InteractionType.EMBEDDING,
        entity_type: str | None = None,
        entity_id: uuid.UUID | None = None,
        retry: bool = True,
        **kwargs: Any,
    ) -> EmbeddingResponse: ...


__all__ = [
    "EmbeddingResponse",
    "InteractionType",
    "LLMAuthError",
    "LLMError",
    "LLMInvalidRequestError",
    "LLMProvider",
    "LLMRateLimitError",
    "LLMResponse",
    "LLMServerError",
    "ProviderHealth",
    "ProviderHealthStatus",
    "TokenUsage",
]
