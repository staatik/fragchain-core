"""F-013 / SAST S-007 + S-026 — webhook receiver hardening helpers.

The connector webhook receiver accepts JSON from external producers.
Without bounds, the receiver is a DoS surface (50 MB nested payload
walks PyJSON + Pydantic) and an amplifier (1000 identical POSTs queue
1000 Celery tasks). This module is the single source of truth for the
three new defenses:

1. ``check_webhook_body_size`` — caps body bytes at the receiver's
   gateway. Default 1 MiB; legitimate connector webhooks are KB-scale.
2. ``check_json_depth`` — caps the recursion depth of the parsed JSON
   payload to a sane bound (default 8). Sigma-shaped + STIX-ish
   payloads top out at 3–4 levels in practice.
3. ``WebhookIdempotencyStore`` — in-process TTL cache keyed on the
   connector's ``Idempotency-Key`` header. When a duplicate arrives,
   the receiver replays the original response without re-enqueueing
   tasks.

Notes:
* All defenses are header-driven and additive — connectors that DON'T
  send an idempotency key get the previous fire-and-forget semantics.
* The cache is **per process**. Multi-worker deployments (post-1.0)
  will swap in a Redis-backed store with the same interface — the
  module exposes a ``get_idempotency_store()`` accessor so swapping
  the implementation is one line.
"""
from __future__ import annotations

import time
from collections import OrderedDict
from typing import Any, Callable


# Default caps. Operators can override per-call (rare); these values
# are correct for the connector-webhook use case.
MAX_WEBHOOK_BODY_BYTES: int = 1_048_576  # 1 MiB
MAX_JSON_DEPTH: int = 8


class WebhookBodyTooLargeError(ValueError):
    """Raised when the webhook body exceeds the byte cap."""


class JsonTooDeepError(ValueError):
    """Raised when the parsed JSON exceeds the depth cap."""


def check_webhook_body_size(
    body: bytes,
    *,
    max_bytes: int = MAX_WEBHOOK_BODY_BYTES,
) -> None:
    """Raise :class:`WebhookBodyTooLargeError` if ``body`` exceeds ``max_bytes``.

    The cap is **inclusive of the cap value** — a body of exactly
    ``max_bytes`` is accepted; a body of ``max_bytes + 1`` is rejected.
    """
    size = len(body)
    if size > max_bytes:
        raise WebhookBodyTooLargeError(
            f"webhook body is {size} bytes which exceeds the "
            f"{max_bytes}-byte cap; refusing to parse"
        )


def check_json_depth(
    value: Any,
    *,
    max_depth: int = MAX_JSON_DEPTH,
) -> None:
    """Raise :class:`JsonTooDeepError` if ``value`` nests beyond ``max_depth``.

    Depth is measured as the deepest container chain (dicts and lists
    count equally). Primitives (str/int/float/bool/None) are depth 0.
    """
    def _walk(v: Any, depth: int) -> None:
        if depth > max_depth:
            raise JsonTooDeepError(
                f"webhook payload nests to depth > {max_depth}; refusing"
            )
        if isinstance(v, dict):
            for child in v.values():
                _walk(child, depth + 1)
        elif isinstance(v, list):
            for child in v:
                _walk(child, depth + 1)
        # primitives: depth contribution is the parent's depth, not a recursion

    _walk(value, 1)


class WebhookIdempotencyStore:
    """In-process TTL cache for connector idempotency keys.

    A connector that supplies an ``Idempotency-Key`` header on every
    retry of the same logical webhook can rely on the receiver to
    replay the original response — no duplicate task enqueues, no
    duplicate downstream side effects.

    Multi-process deployments need a Redis-backed store with the same
    interface. The ``get_idempotency_store()`` module-level accessor
    is the swap point; for now, in-process is enough — the receiver
    has no per-process state-sharing requirement at v1 scale.

    The store enforces both a TTL (``ttl_seconds``, default 24h) and a
    cap on simultaneously-cached entries (``max_entries``, default 1000)
    to prevent unbounded growth. Eviction is LRU-on-insert.
    """

    def __init__(
        self,
        *,
        ttl_seconds: int = 24 * 3600,
        max_entries: int = 1000,
        now: Callable[[], float] | None = None,
    ) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        # OrderedDict so we can do LRU eviction cheaply. Each entry is
        # (result_dict, expires_at_monotonic).
        self._cache: OrderedDict[str, tuple[dict[str, Any], float]] = OrderedDict()
        self._now = now or time.monotonic

    def get(self, key: str) -> dict[str, Any] | None:
        """Return the cached result for ``key`` if it's still live, else None."""
        entry = self._cache.get(key)
        if entry is None:
            return None
        result, expires_at = entry
        if expires_at <= self._now():
            # Expired — evict and treat as a miss.
            self._cache.pop(key, None)
            return None
        # Mark as recently used so cap-driven eviction keeps it longer.
        self._cache.move_to_end(key)
        return result

    def put(self, key: str, result: dict[str, Any]) -> None:
        """Record ``result`` for ``key`` with the configured TTL.

        Opportunistically evicts the oldest entry if the cap is hit
        and prunes expired entries on the way through.
        """
        expires_at = self._now() + self._ttl
        # Evict any expired entries — cheap to do on every put.
        now = self._now()
        expired = [k for k, (_, t) in self._cache.items() if t <= now]
        for k in expired:
            self._cache.pop(k, None)
        # Cap enforcement: evict oldest until we're under the limit.
        while len(self._cache) >= self._max:
            self._cache.popitem(last=False)
        self._cache[key] = (result, expires_at)


_store: WebhookIdempotencyStore | None = None


def get_idempotency_store() -> WebhookIdempotencyStore:
    """Module-level accessor for the singleton store.

    Swap this implementation when a Redis-backed version lands.
    """
    global _store
    if _store is None:
        _store = WebhookIdempotencyStore()
    return _store


def reset_idempotency_store_for_tests() -> None:
    """Wipe the singleton — used by test fixtures so tests don't bleed
    cached results across each other."""
    global _store
    _store = None


__all__ = [
    "MAX_JSON_DEPTH",
    "MAX_WEBHOOK_BODY_BYTES",
    "JsonTooDeepError",
    "WebhookBodyTooLargeError",
    "WebhookIdempotencyStore",
    "check_json_depth",
    "check_webhook_body_size",
    "get_idempotency_store",
    "reset_idempotency_store_for_tests",
]
