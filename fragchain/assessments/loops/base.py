"""Loop interfaces.

Each loop is a typed coroutine ``run(ctx) -> dict``. The orchestrator
calls them in sequence, persisting outputs to ``assessment_loop_run``.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from fragchain.config import get_settings
from fragchain.llm import get_registry
from fragchain.llm.base import LLMProvider


@dataclass
class LoopContext:
    """Inputs available to any loop."""

    assessment_id: uuid.UUID
    cve_id: uuid.UUID
    cve_textual_id: str
    source_contents: list[str]
    prior_outputs: dict[int, dict[str, Any]] = field(default_factory=dict)


class Loop(Protocol):
    async def run(self, ctx: LoopContext) -> dict[str, Any]: ...


def resolve_chat_model(model_override: str | None, target_model: str | None) -> str:
    """Pick the chat model alias for a loop's LLM call.

    A prompt template's ``target_model`` of ``"*"`` is a *selection* pattern
    ("matches any model"), not a real alias — sending it to the LLM yields a
    model-not-found error. So an explicit override wins, then a concrete
    template target, then the deployment-configured chat model.
    """
    if model_override:
        return model_override
    if target_model and target_model != "*":
        return target_model
    return get_settings().LITELLM_CHAT_MODEL


def resolve_chat_provider(injected: LLMProvider | None) -> LLMProvider:
    """Return the chat provider, preferring an injected one.

    The worker builds loops without a provider, so we pull the
    registry-initialized provider (bootstrapped in the API lifespan /
    ``worker_process_init``) rather than constructing a fresh, uninitialized
    ``LiteLLMProvider`` whose ``complete()`` would raise "not initialized".
    """
    if injected is not None:
        return injected
    provider = get_registry().get_default_chat_provider()
    if provider is None:
        raise RuntimeError(
            "No chat-capable LLM provider registered — "
            "install fragchain-provider-litellm"
        )
    return provider
