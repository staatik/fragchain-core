"""F-004 + F-005 — production docs disable + auth-gated health detail.

These are HTTP-level tests against the assembled FastAPI app — same
shape as the rest of the API test suite, but they exercise the
production-mode toggles in ``create_app`` and the maintainer gate on
``/health``.

Each test rebuilds the app inside its own setup so the relevant
``APP_ENV`` / dependency override is in effect; ``get_settings`` is
cached so we clear the lru_cache between cases.
"""
from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI, status
from fastapi.testclient import TestClient

from fragchain.api.middleware.tlp_filter import require_maintainer
from fragchain.api.routers.health import router as health_router
from fragchain.config import get_settings


# ---------------------------------------------------------------------------
# F-005 — /health auth gating
# ---------------------------------------------------------------------------


def _build_health_app(maintainer_user: Any | None) -> FastAPI:
    """Standalone FastAPI app with the health router mounted.

    ``maintainer_user`` controls dependency override:
    * None → don't override; the real maintainer check fires and returns
      401/403 because TestClient is unauthenticated.
    * any object → override with this user so the endpoint succeeds.
    """
    app = FastAPI()
    app.include_router(health_router, prefix="/api/v1")

    if maintainer_user is not None:
        async def _user() -> Any:
            return maintainer_user

        app.dependency_overrides[require_maintainer] = _user
    return app


def test_readyz_is_public() -> None:
    """The coarse liveness probe must work without auth."""
    app = _build_health_app(maintainer_user=None)
    client = TestClient(app)
    resp = client.get("/api/v1/readyz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_health_requires_authentication() -> None:
    """Unauthenticated callers must NOT see per-dependency status."""
    app = _build_health_app(maintainer_user=None)
    client = TestClient(app)
    resp = client.get("/api/v1/health")
    # require_authenticated runs first and returns 401 for anonymous.
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED


def test_health_accessible_to_maintainer() -> None:
    """A maintainer sees the structured payload (services dict).

    External dependency probes will fail in the test environment but the
    response shape must still be present.
    """
    maintainer = MagicMock(
        id=uuid.uuid4(),
        username="ops",
        tier="maintainer",
        clearance_level="tlp:red",
    )
    app = _build_health_app(maintainer_user=maintainer)
    client = TestClient(app)
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert "status" in body
    assert "services" in body
    assert set(body["services"].keys()) == {
        "postgres",
        "redis",
        "minio",
        "qdrant",
        "litellm",
    }


# ---------------------------------------------------------------------------
# F-004 — docs disabled in production
# ---------------------------------------------------------------------------


def _strong_prod_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set strong-secret env so ``Settings`` validates in production
    mode. Used by F-004 tests that need ``create_app`` to think it's
    in production."""
    overrides = {
        "APP_ENV": "production",
        "APP_SECRET_KEY": "x" * 48,
        "JWT_SECRET": "y" * 48,
        "ADMIN_USERNAME": "ops-bootstrap",
        "ADMIN_PASSWORD": "Z9!" + ("a" * 32),
        "POSTGRES_PASSWORD": "p" * 32,
        "REDIS_PASSWORD": "r" * 32,
        "MINIO_ROOT_PASSWORD": "m" * 32,
        "QDRANT_API_KEY": "q" * 32,
        "LITELLM_API_KEY": "l" * 32,
        "LITELLM_BASE_URL": "https://litellm.example.internal:4000",
        "LITELLM_VERIFY_TLS": "true",
        "COMMONS_ALLOW_MOCK_FALLBACK": "false",
        "CORS_ORIGINS": "https://app.example.internal",
    }
    for k, v in overrides.items():
        monkeypatch.setenv(k, v)
    # Clear the cache so create_app picks up the new env.
    get_settings.cache_clear()


def test_settings_picks_up_production_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sanity check that the prod-env fixture itself works."""
    _strong_prod_env(monkeypatch)
    s = get_settings()
    assert s.APP_ENV == "production"
    assert s.is_production is True


def test_production_disables_docs_and_openapi(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """In production mode ``create_app`` returns an app without
    ``docs_url`` or ``openapi_url`` configured.

    We don't spin up the full lifespan (which would require Postgres,
    Redis, etc.) — we inspect the FastAPI object directly.
    """
    _strong_prod_env(monkeypatch)
    from fragchain.api import main as main_mod

    # Reload create_app's view of settings.
    app = main_mod.create_app()
    assert app.docs_url is None
    assert app.openapi_url is None
    assert app.redoc_url is None  # already None before this fix


def test_development_keeps_docs_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Symmetric guard: a dev-mode boot must keep /docs available
    (otherwise contributors lose Swagger).

    We clear env so the default APP_ENV=development takes effect.
    """
    for k in (
        "APP_ENV",
        "APP_SECRET_KEY",
        "JWT_SECRET",
        "ADMIN_PASSWORD",
        "POSTGRES_PASSWORD",
        "REDIS_PASSWORD",
        "MINIO_ROOT_PASSWORD",
        "QDRANT_API_KEY",
        "LITELLM_API_KEY",
        "CORS_ORIGINS",
    ):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("APP_ENV", "development")
    get_settings.cache_clear()

    from fragchain.api import main as main_mod

    app = main_mod.create_app()
    assert app.docs_url == "/api/v1/docs"
    assert app.openapi_url == "/api/v1/openapi.json"
