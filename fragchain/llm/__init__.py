"""LLM provider framework public API (M5).

Importable surface for the rest of the engine. Concrete providers live behind
the `LLMProvider` Protocol — callers should depend on the Protocol and the
registry, never on a specific provider class. The lone exception is the
`LiteLLMProvider` entry-point registration, which references the class by
import path inside `pyproject.toml`.
"""

from fragchain.llm.base import (
    EmbeddingResponse,
    InteractionType,
    LLMAuthError,
    LLMError,
    LLMInvalidRequestError,
    LLMProvider,
    LLMRateLimitError,
    LLMResponse,
    LLMServerError,
    ProviderHealth,
    ProviderHealthStatus,
    TokenUsage,
)
from fragchain.llm.registry import (
    ENTRY_POINT_GROUP,
    ProviderRegistry,
    bootstrap_providers_for_scripts,
    discover_providers,
    get_registry,
    reset_registry,
)
from fragchain.llm.structured import (
    StructuredOutputError,
    StructuredResult,
    structured_complete,
)

__all__ = [
    "ENTRY_POINT_GROUP",
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
    "ProviderRegistry",
    "StructuredOutputError",
    "StructuredResult",
    "TokenUsage",
    "bootstrap_providers_for_scripts",
    "discover_providers",
    "get_registry",
    "reset_registry",
    "structured_complete",
]
