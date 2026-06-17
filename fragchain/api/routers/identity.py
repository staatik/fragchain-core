"""Identity API — placeholder router.

M3 ships schema (`user_identities`, `trust_attestations`, `contribution_signatures`)
and the protocol/registry interface, but no verification logic. Every mutating
endpoint returns HTTP 501 with the deferred-module body. Real implementations
land post-v1 (M38).

GET `/identity` is the one live endpoint — it reads the current user's tier and
clearance from the JWT-derived RequestUser and reports the registered identity
providers (always empty in v1).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from fragchain.api.middleware import RequestUser, require_authenticated
from fragchain.identity.registry import identity_providers

router = APIRouter()

_DEFERRED_MESSAGE = "Identity module deferred to post-v1 (M38)"
_DEFERRED_BODY: dict[str, str] = {
    "error": "not_implemented",
    "message": _DEFERRED_MESSAGE,
}


def _not_implemented() -> JSONResponse:
    """Standard 501 body for every placeholder endpoint."""
    return JSONResponse(status_code=501, content=_DEFERRED_BODY)


@router.get("/identity")
async def get_identity(
    request: Request,  # noqa: ARG001 — accepted for symmetry with other endpoints
    user: RequestUser = Depends(require_authenticated),
) -> dict[str, object]:
    """Current user's tier + clearance.

    In v1 every authenticated user defaults to `tier='authenticated'`,
    `clearance_level='tlp:green'`. The fields exist on `users` but no
    upgrade workflow ships in v1.
    """
    return {
        "user_id": str(user.id),
        "username": user.username,
        "tier": user.tier,
        "clearance_level": user.clearance_level,
        "verified": False,
        "identity_providers": sorted(identity_providers.keys()),
        "note": _DEFERRED_MESSAGE,
    }


@router.post("/identity/key")
async def register_key() -> JSONResponse:
    return _not_implemented()


@router.delete("/identity/key")
async def revoke_key() -> JSONResponse:
    return _not_implemented()


@router.post("/identity/verify")
async def verify_identity() -> JSONResponse:
    return _not_implemented()


@router.post("/identity/attest")
async def attest_identity() -> JSONResponse:
    return _not_implemented()


@router.post("/identity/revoke")
async def revoke_identity() -> JSONResponse:
    return _not_implemented()
