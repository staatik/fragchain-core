"""TLP enforcement at the HTTP boundary.

Two pieces here:

  1. `TLPRequestContextMiddleware` — decodes the JWT (if present), constructs a
     `RequestUser`, and attaches it to `request.state.user`. Anonymous requests
     get a `None` user. This is the cheap, every-request part.

  2. `apply_tlp_filter()` + `enforce_tlp_access()` — synchronous and async
     helpers that endpoints call to strip over-classified items from a list or
     reject a single-entity response with HTTP 403.

The contract: every endpoint that returns TLP-bearing data MUST apply one of
these filters. CLAUDE.md §19 ("NEVER ignore TLP enforcement in API responses")
is the rule; this module is the mechanism.

The filter never trusts the client — `clearance_level` is read from the DB-backed
JWT claim issued at login, not from the request body.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

import structlog
from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from fragchain.api.security import decode_jwt
from fragchain.security.embargo import effective_tlp
from fragchain.security.tlp import (
    TLP,
    can_user_access,
    is_anonymous,
)

logger = structlog.get_logger(__name__)


@dataclass
class RequestUser:
    """Lightweight user view assembled from JWT claims.

    Matches the `_UserLike` Protocol so TLP helpers accept it without an ORM
    round-trip. Endpoints that need additional user fields should hit the DB
    via `get_db` and look up the row by `id`.
    """

    id: uuid.UUID
    username: str
    tier: str
    clearance_level: str

    @property
    def is_anonymous(self) -> bool:
        return self.tier == "anonymous"


def _user_from_token(authorization: str | None) -> RequestUser | None:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    claims = decode_jwt(token)
    if claims is None:
        return None
    try:
        return RequestUser(
            id=uuid.UUID(claims["sub"]),
            username=str(claims.get("username", "")),
            tier=str(claims.get("tier", "authenticated")),
            clearance_level=str(claims.get("clearance", "tlp:green")),
        )
    except (KeyError, ValueError, TypeError):
        return None


class TLPRequestContextMiddleware(BaseHTTPMiddleware):
    """Populates `request.state.user` from the bearer token, if any.

    Doesn't reject anything on its own — anonymous access is allowed for any
    `tlp:clear` endpoint. Endpoints that require authentication call
    `require_authenticated()` from this module.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        auth = request.headers.get("authorization")
        request.state.user = _user_from_token(auth)
        return await call_next(request)


def get_request_user(request: Request) -> RequestUser | None:
    """Read the user previously attached by the middleware."""
    return getattr(request.state, "user", None)


def require_authenticated(request: Request) -> RequestUser:
    user = get_request_user(request)
    if user is None or user.is_anonymous:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return user


def require_maintainer(request: Request) -> RequestUser:
    """Tier gate for admin actions (embargo release, TLP downgrade, etc.)."""
    user = require_authenticated(request)
    # In v1 only the seeded admin has tier=maintainer-equivalent. We accept
    # 'maintainer' explicitly and fall back to anyone with tlp:red clearance
    # so a fresh deployment isn't locked out before M3 wires tier upgrades.
    if user.tier == "maintainer":
        return user
    if TLP.parse(user.clearance_level) == TLP.RED:
        return user
    # Also allow the seeded admin user (username 'admin' carries tlp:green by
    # default, but is the de-facto maintainer on a fresh install).
    if user.username == "admin":
        return user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Maintainer tier required",
    )


def _read_tlp(item: Any) -> TLP:
    """Pull a TLP value off a dict, Pydantic model, or ORM row.

    Falls back to CLEAR when no `tlp` attribute/key is present — TLP-less
    responses (e.g. `/version`) are unrestricted by design.
    """
    if isinstance(item, dict):
        return TLP.parse(item.get("tlp", TLP.CLEAR))
    value = getattr(item, "tlp", None)
    if value is None:
        return TLP.CLEAR
    return TLP.parse(value)


def _read_embargo(item: Any):
    if isinstance(item, dict):
        return item.get("embargo_until")
    return getattr(item, "embargo_until", None)


def _read_entity_id(item: Any) -> uuid.UUID | None:
    if isinstance(item, dict):
        raw = item.get("id")
    else:
        raw = getattr(item, "id", None)
    if raw is None:
        return None
    if isinstance(raw, uuid.UUID):
        return raw
    try:
        return uuid.UUID(str(raw))
    except (ValueError, TypeError):
        return None


def visible_to_user_sync(
    items: Sequence[Any],
    user: RequestUser | None,
) -> list[Any]:
    """Synchronous filter for the easy cases: CLEAR is always visible, GREEN
    needs an authenticated user. AMBER+ items are excluded — callers needing
    them must use `enforce_tlp_access()` async with DB access.
    """
    out: list[Any] = []
    for item in items:
        declared = _read_tlp(item)
        embargo_until = _read_embargo(item)
        effective = effective_tlp(declared, embargo_until)

        if effective == TLP.CLEAR:
            out.append(item)
            continue
        if is_anonymous(user):
            continue
        if effective == TLP.GREEN:
            assert user is not None
            if TLP.parse(user.clearance_level).restriction_level >= TLP.GREEN.restriction_level:
                out.append(item)
            continue
        # AMBER+ omitted; caller must perform a DB-backed grant check.
    return out


async def apply_tlp_filter(
    session,
    items: Iterable[Any],
    user: RequestUser | None,
) -> list[Any]:
    """Filter an iterable of TLP-bearing rows down to those the user can see.

    Each item must expose a `tlp` attribute/key (defaults to CLEAR if absent),
    an `embargo_until` (optional), and an `id` for grant lookups on amber+.
    """
    visible: list[Any] = []
    for item in items:
        declared = _read_tlp(item)
        embargo_until = _read_embargo(item)
        entity_id = _read_entity_id(item)
        effective = effective_tlp(declared, embargo_until)
        embargoed = effective == TLP.RED and (
            declared != TLP.RED  # i.e. embargo, not a permanently-red entity
        )
        allowed = await can_user_access(
            session,
            user,
            effective,
            entity_id,
            embargoed=embargoed,
        )
        if allowed:
            visible.append(item)
    return visible


async def enforce_tlp_access(
    session,
    item: Any,
    user: RequestUser | None,
) -> None:
    """For single-entity endpoints. Raises HTTP 403 if the user can't read it."""
    declared = _read_tlp(item)
    embargo_until = _read_embargo(item)
    entity_id = _read_entity_id(item)
    effective = effective_tlp(declared, embargo_until)
    embargoed = effective == TLP.RED and declared != TLP.RED
    allowed = await can_user_access(
        session,
        user,
        effective,
        entity_id,
        embargoed=embargoed,
    )
    if not allowed:
        logger.info(
            "tlp.access.denied",
            user_id=str(user.id) if user else None,
            entity_id=str(entity_id) if entity_id else None,
            effective_tlp=str(effective),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="TLP classification forbids access",
        )


__all__ = [
    "RequestUser",
    "TLPRequestContextMiddleware",
    "get_request_user",
    "require_authenticated",
    "require_maintainer",
    "apply_tlp_filter",
    "enforce_tlp_access",
    "visible_to_user_sync",
]
