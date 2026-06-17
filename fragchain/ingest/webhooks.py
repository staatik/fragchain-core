"""Webhook receiver primitives (M6).

External connectors push new CVEs via ``POST /api/v1/webhooks/connector/{name}``.
Authentication is a shared-secret token compared with :func:`hmac.compare_digest`
to avoid timing-attack leaks. The secret lives in the connector's
``connector_state.config['webhook_secret']`` field — operators set it via
``PATCH /api/v1/connectors/{name}``.

The webhook contract is intentionally lenient: the connector POSTs whatever
shape it wants (typically a CVE record or a list of records); the receiver
just enqueues an ingest task and returns 200 immediately.
"""
from __future__ import annotations

import hmac
import secrets
from typing import Any


def verify_webhook_token(presented: str | None, expected: str | None) -> bool:
    """Constant-time token compare. ``False`` if either value is missing.

    Tokens are compared as UTF-8 bytes via :func:`hmac.compare_digest`.
    Missing/empty configured secrets return ``False`` rather than ``True`` so
    a misconfigured connector never accepts unauthenticated webhooks by
    accident.
    """
    if not presented or not expected:
        return False
    return hmac.compare_digest(str(presented).encode("utf-8"), str(expected).encode("utf-8"))


def extract_token(headers: dict[str, str] | Any, query_token: str | None = None) -> str | None:
    """Pull the webhook token from headers (preferred) or query string.

    Three accepted header names: ``X-FragChain-Token``, ``X-Webhook-Token``,
    and ``Authorization: Bearer <token>``. Falls back to ``query_token``
    for connectors that can't set custom headers (the analyst flow can also
    paste tokens into the URL during local dev).
    """
    if hasattr(headers, "get"):
        for header_name in ("X-FragChain-Token", "X-Webhook-Token", "x-fragchain-token", "x-webhook-token"):
            value = headers.get(header_name)
            if value:
                return str(value).strip()
        auth = headers.get("Authorization") or headers.get("authorization")
        if auth and isinstance(auth, str) and auth.lower().startswith("bearer "):
            return auth.split(" ", 1)[1].strip()
    return query_token


def generate_token() -> str:
    """Mint a 256-bit URL-safe token operators can paste into connector config."""
    return secrets.token_urlsafe(32)


__all__ = ["extract_token", "generate_token", "verify_webhook_token"]
