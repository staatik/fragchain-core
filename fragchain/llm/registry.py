"""LLM provider plugin discovery + registry (M5).

Discovery walks the `fragchain.providers` entry-point group exactly the way
M4 walks `fragchain.connectors`. Each entry point references a zero-arg
callable (typically a class) that returns an `LLMProvider` instance.

A `ProviderRegistry` singleton holds the loaded instances for the lifetime of
the app. Callers fetch a provider by name, or `get_default_provider()` if
they just want "whichever chat-capable provider the operator installed". In
v1 that's always `litellm`.

Failures must never take the engine down — a broken provider plugin is
isolated, logged, and skipped. This mirrors the `discover_connectors()`
contract from M4.
"""
from __future__ import annotations

import importlib.metadata as md
from typing import Iterable

import structlog

from fragchain.llm.base import LLMProvider

logger = structlog.get_logger(__name__)


ENTRY_POINT_GROUP = "fragchain.providers"


def _iter_entry_points() -> Iterable[md.EntryPoint]:
    """importlib.metadata compatibility shim (matches the M4 connector loader)."""
    eps = md.entry_points()
    select = getattr(eps, "select", None)
    if callable(select):
        return select(group=ENTRY_POINT_GROUP)
    return eps.get(ENTRY_POINT_GROUP, [])  # type: ignore[attr-defined]


def discover_providers() -> list[LLMProvider]:
    """Load every provider registered under `fragchain.providers`.

    Returns the list of instances that loaded successfully. An empty list is
    a valid state — the engine handles "no providers installed" by surfacing
    a degraded health check rather than crashing.
    """
    discovered: list[LLMProvider] = []
    for ep in _iter_entry_points():
        try:
            obj = ep.load()
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "llm.provider.load_failed",
                entry_point=ep.name,
                value=getattr(ep, "value", None),
                error=str(exc),
            )
            continue

        try:
            instance = obj() if isinstance(obj, type) or callable(obj) else obj
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "llm.provider.instantiate_failed",
                entry_point=ep.name,
                error=str(exc),
            )
            continue

        if not isinstance(instance, LLMProvider):
            logger.warning(
                "llm.provider.invalid",
                entry_point=ep.name,
                reason="loaded object does not implement LLMProvider Protocol",
            )
            continue

        logger.info(
            "llm.provider.discovered",
            name=instance.name,
            version=instance.version,
            entry_point=ep.name,
        )
        discovered.append(instance)

    if not discovered:
        logger.info("llm.provider.discovery.empty")

    return discovered


class ProviderRegistry:
    """In-memory holder of every loaded LLM provider.

    There is exactly one of these per process — `get_registry()` returns the
    module-level singleton. Tests reset it with `reset_registry()` between
    runs to avoid cross-test pollution.
    """

    def __init__(self) -> None:
        self._providers: dict[str, LLMProvider] = {}
        self._initialized: set[str] = set()

    def register(self, provider: LLMProvider) -> None:
        """Add a provider to the registry. Idempotent — duplicate name overwrites."""
        if provider.name in self._providers:
            logger.warning("llm.provider.duplicate", name=provider.name)
        self._providers[provider.name] = provider

    def get(self, name: str) -> LLMProvider | None:
        return self._providers.get(name)

    def list_providers(self) -> list[LLMProvider]:
        return list(self._providers.values())

    def names(self) -> list[str]:
        return list(self._providers)

    def get_default_chat_provider(self) -> LLMProvider | None:
        """Pick a chat-capable provider — v1 returns `litellm` if installed.

        Selection logic is intentionally tiny: in v1 the only provider is
        LiteLLM. When direct providers ship (M39-M41) operators will configure
        a preferred-per-task selection via Settings UI (M24); this hook is
        the place to consult that.
        """
        # Prefer litellm when it's installed (v1 default path).
        if "litellm" in self._providers and self._providers["litellm"].supports_chat:
            return self._providers["litellm"]
        for p in self._providers.values():
            if p.supports_chat:
                return p
        return None

    def get_default_embedding_provider(self) -> LLMProvider | None:
        if "litellm" in self._providers and self._providers["litellm"].supports_embeddings:
            return self._providers["litellm"]
        for p in self._providers.values():
            if p.supports_embeddings:
                return p
        return None

    async def initialize_all(self) -> None:
        """Call `initialize()` on every registered provider. Failures isolated."""
        for provider in self._providers.values():
            if provider.name in self._initialized:
                continue
            try:
                await provider.initialize()
                self._initialized.add(provider.name)
                logger.info("llm.provider.initialized", name=provider.name)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "llm.provider.initialize_failed",
                    name=provider.name,
                    error=str(exc),
                )

    async def shutdown_all(self) -> None:
        for provider in self._providers.values():
            try:
                await provider.shutdown()
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "llm.provider.shutdown_failed",
                    name=provider.name,
                    error=str(exc),
                )
        self._initialized.clear()

    def clear(self) -> None:
        """Wipe the registry — test-only."""
        self._providers.clear()
        self._initialized.clear()


_registry: ProviderRegistry | None = None


async def bootstrap_providers_for_scripts() -> None:
    """Discover + initialize every LLM provider for a standalone script.

    The API process runs ``discover_providers()`` and ``initialize_all()`` in
    its FastAPI lifespan, so by the time a request lands the registry is hot.
    Standalone CLI scripts (``scripts/seed_attck_techniques`` and friends)
    start a fresh interpreter without that lifespan, which left
    ``get_default_embedding_provider()`` returning ``None`` and silently
    no-op'd embeddings — every Qdrant upsert in M8's ATT&CK seed failed with
    ``No embedding-capable LLM provider registered`` while the script still
    reported success.

    This helper is the one-call fix: call it once before any code path that
    uses :class:`fragchain.vector.embedder.VectorEmbedder` (or
    ``LLMProvider.complete`` / ``embed`` directly). Idempotent — re-running
    skips already-registered names and already-initialized providers, so the
    helper is safe to drop into every seed script without worrying about
    test wiring.
    """
    registry = get_registry()
    existing_names = set(registry.names())
    discovered = discover_providers()
    newly_registered: list[str] = []
    for provider in discovered:
        if provider.name in existing_names:
            continue
        registry.register(provider)
        newly_registered.append(provider.name)

    if newly_registered:
        logger.info(
            "llm.bootstrap_scripts.registered",
            providers=newly_registered,
            total_registered=len(registry.names()),
        )
    await registry.initialize_all()
    logger.info(
        "llm.bootstrap_scripts.initialized",
        providers=registry.names(),
    )


def get_registry() -> ProviderRegistry:
    """Return the process-wide provider registry, creating it on first use."""
    global _registry
    if _registry is None:
        _registry = ProviderRegistry()
    return _registry


def reset_registry() -> None:
    """Drop the singleton — used by tests and the lifespan shutdown."""
    global _registry
    _registry = None


__all__ = [
    "ENTRY_POINT_GROUP",
    "ProviderRegistry",
    "bootstrap_providers_for_scripts",
    "discover_providers",
    "get_registry",
    "reset_registry",
]
