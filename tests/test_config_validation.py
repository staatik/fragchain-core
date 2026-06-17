"""F-001 — production / staging secret validation.

These tests assert that ``fragchain.config.Settings`` refuses to boot when
critical secrets are placeholder, empty, or too short, and that
development mode keeps the friendly defaults.

Important: ``Settings()`` reads from ``.env``. The fixtures below clear
every relevant env var via monkeypatch and pass values directly so the
checked-in ``.env`` (if any) doesn't influence results.
"""
from __future__ import annotations

import pytest

from fragchain.config import InsecureConfigurationError, Settings


# A minimum-strength set of secrets that should always pass validation in
# any non-development env. Tests mutate one field at a time to assert it
# is the field under test that triggers the rejection.
_GOOD_VALUES: dict[str, str] = {
    "APP_ENV": "production",
    "APP_SECRET_KEY": "x" * 48,
    "ADMIN_USERNAME": "ops-bootstrap",
    "ADMIN_PASSWORD": "Z9!" + ("a" * 32),
    "JWT_SECRET": "y" * 48,
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

# Env keys that production tests should clear out from any inherited env
# so the placeholder defaults don't leak in.
_ALL_KEYS = list(_GOOD_VALUES.keys()) + [
    "ADMIN_EMAIL",
    "POSTGRES_HOST",
    "POSTGRES_DB",
    "POSTGRES_USER",
    "REDIS_HOST",
    "MINIO_HOST",
    "MINIO_ROOT_USER",
    "QDRANT_HOST",
]


def _apply(monkeypatch: pytest.MonkeyPatch, overrides: dict[str, str]) -> None:
    """Clear every relevant key, then set the merged good + override map."""
    for key in _ALL_KEYS:
        monkeypatch.delenv(key, raising=False)
    merged = {**_GOOD_VALUES, **overrides}
    for key, value in merged.items():
        monkeypatch.setenv(key, value)


def test_development_defaults_boot_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    """The shipped placeholder defaults must keep working in development.

    Otherwise every contributor's first `pytest` run fails — that would
    push contributors toward replacing the placeholder defaults with their
    own real secrets in the repo, which is the opposite of safe.
    """
    for key in _ALL_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("APP_ENV", "development")
    Settings(_env_file=None)  # type: ignore[call-arg]


def test_production_rejects_placeholder_app_secret_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _apply(monkeypatch, {"APP_SECRET_KEY": "change-me"})
    with pytest.raises(InsecureConfigurationError) as exc:
        Settings(_env_file=None)  # type: ignore[call-arg]
    assert any("APP_SECRET_KEY" in p for p in exc.value.fields)


def test_production_rejects_placeholder_jwt_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _apply(monkeypatch, {"JWT_SECRET": "replace-with-secret"})
    with pytest.raises(InsecureConfigurationError) as exc:
        Settings(_env_file=None)  # type: ignore[call-arg]
    assert any("JWT_SECRET" in p for p in exc.value.fields)


def test_production_rejects_admin_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    _apply(
        monkeypatch,
        {
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": "admin",
        },
    )
    with pytest.raises(InsecureConfigurationError) as exc:
        Settings(_env_file=None)  # type: ignore[call-arg]
    # Both the placeholder check and the admin/admin combo check should fire.
    assert any("ADMIN_PASSWORD" in p for p in exc.value.fields)


def test_production_rejects_short_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    _apply(monkeypatch, {"APP_SECRET_KEY": "short"})
    with pytest.raises(InsecureConfigurationError) as exc:
        Settings(_env_file=None)  # type: ignore[call-arg]
    assert any(
        "APP_SECRET_KEY" in p and "shorter" in p for p in exc.value.fields
    )


def test_production_rejects_empty_redis_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _apply(monkeypatch, {"REDIS_PASSWORD": ""})
    with pytest.raises(InsecureConfigurationError) as exc:
        Settings(_env_file=None)  # type: ignore[call-arg]
    assert any("REDIS_PASSWORD" in p for p in exc.value.fields)


def test_production_rejects_empty_qdrant_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _apply(monkeypatch, {"QDRANT_API_KEY": ""})
    with pytest.raises(InsecureConfigurationError) as exc:
        Settings(_env_file=None)  # type: ignore[call-arg]
    assert any("QDRANT_API_KEY" in p for p in exc.value.fields)


def test_production_rejects_empty_litellm_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _apply(monkeypatch, {"LITELLM_API_KEY": ""})
    with pytest.raises(InsecureConfigurationError) as exc:
        Settings(_env_file=None)  # type: ignore[call-arg]
    assert any("LITELLM_API_KEY" in p for p in exc.value.fields)


def test_production_rejects_tls_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    _apply(monkeypatch, {"LITELLM_VERIFY_TLS": "false"})
    with pytest.raises(InsecureConfigurationError) as exc:
        Settings(_env_file=None)  # type: ignore[call-arg]
    assert any("LITELLM_VERIFY_TLS" in p for p in exc.value.fields)


def test_production_rejects_commons_mock_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _apply(monkeypatch, {"COMMONS_ALLOW_MOCK_FALLBACK": "true"})
    with pytest.raises(InsecureConfigurationError) as exc:
        Settings(_env_file=None)  # type: ignore[call-arg]
    assert any("COMMONS_ALLOW_MOCK_FALLBACK" in p for p in exc.value.fields)


def test_production_rejects_default_postgres_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _apply(monkeypatch, {"POSTGRES_PASSWORD": "fragchain"})
    with pytest.raises(InsecureConfigurationError) as exc:
        Settings(_env_file=None)  # type: ignore[call-arg]
    assert any("POSTGRES_PASSWORD" in p for p in exc.value.fields)


def test_production_accepts_strong_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sanity check — the canonical 'good' fixture must boot."""
    _apply(monkeypatch, {})
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.APP_ENV == "production"
    assert settings.is_production is True


def test_staging_enforces_same_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    _apply(monkeypatch, {"APP_ENV": "staging", "JWT_SECRET": "change-me"})
    with pytest.raises(InsecureConfigurationError) as exc:
        Settings(_env_file=None)  # type: ignore[call-arg]
    assert any("JWT_SECRET" in p for p in exc.value.fields)


def test_error_message_lists_every_problem(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Operators should see every issue in one boot attempt, not one at a time."""
    _apply(
        monkeypatch,
        {
            "APP_SECRET_KEY": "change-me",
            "JWT_SECRET": "change-me",
            "POSTGRES_PASSWORD": "fragchain",
        },
    )
    with pytest.raises(InsecureConfigurationError) as exc:
        Settings(_env_file=None)  # type: ignore[call-arg]
    flagged_keys = {
        key
        for key in ("APP_SECRET_KEY", "JWT_SECRET", "POSTGRES_PASSWORD")
        if any(key in problem for problem in exc.value.fields)
    }
    assert flagged_keys == {"APP_SECRET_KEY", "JWT_SECRET", "POSTGRES_PASSWORD"}


def test_coverage_redesign_settings_defaults():
    from fragchain.config import Settings
    s = Settings()
    assert s.COVERAGE_LLM_VERIFY_ENABLED is False
    assert s.COVERAGE_VERIFY_MAX_CALLS == 50
    assert s.RULE_SIMILARITY_THRESHOLD == 0.85


def test_llm_timeout_settings_have_defaults() -> None:
    from fragchain.config import Settings

    s = Settings()
    assert s.LLM_STRUCTURED_TIMEOUT_SECONDS == 120.0
    assert s.LITELLM_HTTP_TIMEOUT_SECONDS == 120.0


# ---------------------------------------------------------------------------
# Integration-review F4 — timeout-relationship validation. A Loop 2 pass
# bound tighter than the structured timeout silently pre-empts it (the
# pre-Wave-1a hardcoded 60s did exactly that), so startup must reject
# LOOP2_PASS_TIMEOUT_SECONDS < LLM_STRUCTURED_TIMEOUT_SECONDS.
# ---------------------------------------------------------------------------


def test_loop2_pass_timeout_below_structured_timeout_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pydantic import ValidationError

    for key in _ALL_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("LOOP2_PASS_TIMEOUT_SECONDS", raising=False)
    monkeypatch.delenv("LLM_STRUCTURED_TIMEOUT_SECONDS", raising=False)
    monkeypatch.setenv("APP_ENV", "development")

    with pytest.raises(ValidationError, match="LOOP2_PASS_TIMEOUT_SECONDS"):
        Settings(  # type: ignore[call-arg]
            _env_file=None,
            LOOP2_PASS_TIMEOUT_SECONDS=60.0,
            LLM_STRUCTURED_TIMEOUT_SECONDS=120.0,
        )


def test_loop2_pass_timeout_equal_or_above_structured_timeout_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in _ALL_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("LOOP2_PASS_TIMEOUT_SECONDS", raising=False)
    monkeypatch.delenv("LLM_STRUCTURED_TIMEOUT_SECONDS", raising=False)
    monkeypatch.setenv("APP_ENV", "development")

    # Equal is allowed (the bound still grants the first attempt its full
    # structured timeout); greater is the recommended shape.
    Settings(  # type: ignore[call-arg]
        _env_file=None,
        LOOP2_PASS_TIMEOUT_SECONDS=120.0,
        LLM_STRUCTURED_TIMEOUT_SECONDS=120.0,
    )
    Settings(  # type: ignore[call-arg]
        _env_file=None,
        LOOP2_PASS_TIMEOUT_SECONDS=150.0,
        LLM_STRUCTURED_TIMEOUT_SECONDS=120.0,
    )


def test_headless_min_source_bytes_default():
    from fragchain.config import Settings

    assert Settings().HEADLESS_MIN_SOURCE_BYTES == 500
