from __future__ import annotations

import logging
from functools import lru_cache
from typing import Literal

import structlog
from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# ---------------------------------------------------------------------------
# Secret validation (F-001)
#
# Production / staging deployments MUST fail to boot if any critical secret
# still carries an in-repo placeholder, is empty, or is too short to be a
# real secret. This stops the most common operator footgun (`docker compose
# up` against the shipped `.env.example`) before it lands real traffic.
# ---------------------------------------------------------------------------

# Substrings that, if present in a secret in production, indicate the
# operator forgot to replace the placeholder. Match is case-insensitive
# and substring-based on the SecretStr's revealed value.
_PLACEHOLDER_TOKENS = (
    "change-me",
    "changeme",
    "replace-with",
    "replace-me",
    "your-secret",
    "yoursecret",
    "secret-here",
    "fragchain-dev",
    "dev-password",
    "example",
    "placeholder",
)

# Exact-match values that must NEVER appear in production for any
# password/secret field. "admin" is here specifically so an operator who
# copies .env.example into production gets a clear failure rather than a
# silently usable admin/admin bootstrap.
_FORBIDDEN_EXACT_VALUES = frozenset(
    {
        "",
        "admin",
        "password",
        "fragchain",
        "change-me",
        "changeme",
        "test",
        "dev",
        "development",
    }
)

_MIN_SECRET_LENGTH = 16


class InsecureConfigurationError(RuntimeError):
    """Raised when production/staging boots with placeholder or weak secrets.

    The list of offending fields is exposed on ``.fields`` so callers can
    surface a structured error. The string form lists every problem so the
    operator only has to fix the configuration once.
    """

    def __init__(self, problems: list[str]) -> None:
        self.fields = problems
        joined = "\n  - ".join(problems)
        super().__init__(
            "Insecure configuration detected (refusing to boot):\n  - "
            + joined
            + "\n\nSee .env.example and docs/SECURITY.md for guidance."
        )


def _looks_placeholder(value: str) -> bool:
    """Return True when ``value`` matches a known-bad placeholder pattern.

    Anonymous, low-entropy, or shipped-example values are placeholders.
    The check is intentionally conservative: we only block strings that we
    know are unsafe, not strings that merely look weak. Operators who run
    their own entropy/strength check externally won't be falsely flagged.
    """
    if value is None:
        return True
    lowered = value.strip().lower()
    if lowered in _FORBIDDEN_EXACT_VALUES:
        return True
    return any(tok in lowered for tok in _PLACEHOLDER_TOKENS)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # App
    APP_ENV: Literal["development", "staging", "production"] = "development"
    APP_HOST: str = "0.0.0.0"
    # NOTE: defaults are intentionally placeholder strings so a fresh checkout
    # boots in development mode. The post-init validator below refuses to
    # accept these defaults when APP_ENV is staging or production.
    APP_SECRET_KEY: SecretStr = SecretStr("change-me")
    APP_LOG_LEVEL: str = "INFO"

    # Admin bootstrap
    ADMIN_USERNAME: str = "admin"
    ADMIN_EMAIL: str = "admin@fragchain.local"
    ADMIN_PASSWORD: SecretStr = SecretStr("admin")

    # JWT
    JWT_SECRET: SecretStr = SecretStr("change-me")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_HOURS: int = 12

    # Postgres
    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "fragchain"
    POSTGRES_USER: str = "fragchain"
    POSTGRES_PASSWORD: SecretStr = SecretStr("fragchain")

    # Redis
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: SecretStr = SecretStr("")
    REDIS_DB: int = 0

    # MinIO
    MINIO_HOST: str = "minio"
    MINIO_PORT: int = 9000
    MINIO_ROOT_USER: str = "fragchain"
    MINIO_ROOT_PASSWORD: SecretStr = SecretStr("fragchain")
    MINIO_BUCKET: str = "fragchain"
    MINIO_USE_SSL: bool = False

    # Qdrant
    QDRANT_HOST: str = "qdrant"
    QDRANT_PORT: int = 6333
    QDRANT_API_KEY: SecretStr = SecretStr("")

    # LiteLLM (external, Server 1)
    LITELLM_BASE_URL: str = "http://litellm.internal:4000"
    LITELLM_API_KEY: SecretStr = SecretStr("")
    LITELLM_CHAT_MODEL: str = "claude-opus"
    LITELLM_EMBEDDING_MODEL: str = "nomic-embed-text"
    # TLS trust for the LiteLLM endpoint. If the endpoint is behind a private CA,
    # mount the CA bundle into the container and point LITELLM_CA_BUNDLE at it.
    # Set LITELLM_VERIFY_TLS=false only for dev — never in production.
    LITELLM_VERIFY_TLS: bool = True
    LITELLM_CA_BUNDLE: str = ""

    # CVE pipeline budgets
    MAX_LIVE_CVE_PER_HOUR: int = 10
    MAX_HISTORICAL_CVE_PER_DAY: int = 20
    AUTO_PROCESS_KEV: bool = True

    # W3a-1: pre-spend floor for headless auto-assessment. Below this total
    # source byte count, auto_assess rejects input without creating loop runs.
    HEADLESS_MIN_SOURCE_BYTES: int = 500

    # Coverage mapper — embedding-first. The chat-LLM verify of existing
    # rules is an opt-in precision layer; embeddings + Qdrant carry the
    # coverage signal by default.
    COVERAGE_LLM_VERIFY_ENABLED: bool = False
    COVERAGE_VERIFY_MAX_CALLS: int = 50
    # Generated-rule redundancy: cosine score at/above which a generated rule
    # is considered a near-duplicate of an existing library rule.
    RULE_SIMILARITY_THRESHOLD: float = 0.85
    # pySigma validation is mandatory (CLAUDE.md §19). When pysigma can't be
    # imported, validation fails CLOSED (the rule is marked invalid) by
    # default. Operators running a deliberately minimal/offline build that
    # cannot ship pysigma may set this False to fall back to YAML-only checks
    # — an explicit, recorded choice rather than a silent skip.
    REQUIRE_PYSIGMA: bool = True
    # Assessment detectability gate (CLAUDE.md §12.1): minimum count of
    # non-empty ObservableCategory buckets in Loop 2's output for the
    # deterministic gate to pass (out of 7). Passed by both orchestrator
    # factories to the gate evaluation and to Loop 2's gap-pass threshold.
    GATE_MIN_CATEGORIES: int = 3
    # Artifact router (Phase 2, ADR-0004 §3): below this classifier
    # confidence the routing policy demotes sigma_rule to skipped and
    # recommends an analyst research task instead. Advisory in
    # compatibility mode — the demotion is recorded on the plan, not
    # enforced on generation.
    ROUTER_MIN_CONFIDENCE: float = 0.4
    # Phase 2c gating (ADR-0004): comma-separated detectability classes for which
    # Loop 3 actively SKIPS Sigma generation (vs compatibility-mode recording
    # only). Only ``insufficient_information`` / ``control_only`` are policy-skip
    # classes; listing others has no effect. Default enables both (the
    # precision-1.0 decline classes). Set to "" to restore full compatibility
    # mode without a code change — the per-class kill-switch. See ADR-0004
    # (docs/architecture/adr/ADR-0004-staged-defense-engineering-adoption.md).
    ROUTER_GATING_SKIP_CLASSES: str = "insufficient_information,control_only"
    # LLM call timeouts. The deployment gateway has ~7-8s baseline latency
    # plus ~40 output tok/s, so large structured generations (Loop 1 ≈ 2500
    # tokens) need ~60s. The 120s defaults give headroom above that. The
    # structured timeout is the asyncio.wait_for bound in structured_complete;
    # the httpx timeout bounds the underlying HTTP request and must be >= it.
    LLM_STRUCTURED_TIMEOUT_SECONDS: float = 120.0
    LITELLM_HTTP_TIMEOUT_SECONDS: float = 120.0
    # Loop 2 per-pass wall-clock bound (bulk pass and gap pass each).
    # Must be >= LLM_STRUCTURED_TIMEOUT_SECONDS (startup-validated below):
    # the outer bound guarantees only the FIRST structured attempt its full
    # timeout — repair attempts (up to 3 x LLM_STRUCTURED_TIMEOUT_SECONDS)
    # can exceed it and are cancelled mid-repair BY DESIGN, bounding the
    # wall-clock per pass. A bound below the structured timeout would
    # silently pre-empt even the first attempt (the pre-Wave-1a hardcoded
    # 60s did exactly that and was the live cause of loop timeouts on slow
    # backends), which is why startup rejects that shape.
    LOOP2_PASS_TIMEOUT_SECONDS: float = 150.0
    # Stale in-flight reaper: assessment_loop_run rows 'running' (by
    # started_at) and generated_artifacts rows 'generating' (by created_at)
    # older than this are finalized 'failed' by the beat task
    # assessment.reap_stale_inflight. MUST exceed the worst-case loop
    # wall-clock (Loop 2: two passes x LOOP2_PASS_TIMEOUT_SECONDS plus RAG;
    # Loop 3: serial per-gap-per-profile rule generation) or the reaper
    # kills healthy runs.
    STALE_INFLIGHT_MAX_SECONDS: int = 1800

    # Commons (M7)
    # F-001: This MUST default to False so a misconfigured production
    # deployment fails loudly instead of silently bootstrapping from a stub.
    # Operators flip to True only for offline development.
    COMMONS_ALLOW_MOCK_FALLBACK: bool = False
    COMMONS_SYNC_TIMEOUT_SECONDS: int = 60
    # Optional override for the GitHub API root (used for both reads and
    # contribution PRs). Default is the public github.com — operators on
    # GitHub Enterprise point this at their own host.
    COMMONS_GITHUB_API_BASE: str = "https://api.github.com"

    # Sigma integration (M12)
    # Local clone root for sigma source repos. Each source gets its own
    # subdirectory ``{SIGMA_REPOS_DIR}/{source_id}``. Mount this on a
    # persistent volume so refreshes are incremental fast-forwards rather
    # than full re-clones.
    SIGMA_REPOS_DIR: str = "data/sigma-repos"
    # When False (default), ``git_url`` on sigma_sources / sigma_targets and
    # ``url`` on commons_sources MUST match ``^https?://host/owner/repo``.
    # Flip to True in air-gapped / lab environments where SSH or file://
    # repositories are intentional (E-M4 in the Phase 5 security review).
    SIGMA_ALLOW_NON_HTTPS: bool = False

    # CORS
    CORS_ORIGINS: str = "https://localhost,https://localhost:443"

    # ---- Timeout-relationship validation ---------------------------------
    #
    # Enforced in every APP_ENV (it's a logic misconfiguration, not a
    # secret-strength concern): a Loop 2 pass bound tighter than the
    # structured timeout silently pre-empts the first structured attempt,
    # reintroducing the pre-Wave-1a hardcoded-60s failure mode.
    @model_validator(mode="after")
    def _check_timeout_relationships(self) -> "Settings":
        if self.LOOP2_PASS_TIMEOUT_SECONDS < self.LLM_STRUCTURED_TIMEOUT_SECONDS:
            raise ValueError(
                "LOOP2_PASS_TIMEOUT_SECONDS "
                f"({self.LOOP2_PASS_TIMEOUT_SECONDS}) must be >= "
                "LLM_STRUCTURED_TIMEOUT_SECONDS "
                f"({self.LLM_STRUCTURED_TIMEOUT_SECONDS}); a tighter per-pass "
                "bound silently pre-empts the first structured attempt."
            )
        return self

    # ---- Production / staging secret validation -------------------------
    #
    # This runs after pydantic has loaded every value from env / .env. We
    # only enforce the strict checks when APP_ENV is "staging" or
    # "production"; in "development" the placeholder defaults are fine.
    @model_validator(mode="after")
    def _check_production_secrets(self) -> "Settings":
        if self.APP_ENV not in ("staging", "production"):
            return self
        problems: list[str] = []

        # Critical credential secrets. Empty / placeholder / too-short
        # values are all rejected.
        credential_fields: list[tuple[str, str]] = [
            ("APP_SECRET_KEY", self.APP_SECRET_KEY.get_secret_value()),
            ("JWT_SECRET", self.JWT_SECRET.get_secret_value()),
            ("ADMIN_PASSWORD", self.ADMIN_PASSWORD.get_secret_value()),
            ("POSTGRES_PASSWORD", self.POSTGRES_PASSWORD.get_secret_value()),
            ("MINIO_ROOT_PASSWORD", self.MINIO_ROOT_PASSWORD.get_secret_value()),
        ]
        for name, value in credential_fields:
            if _looks_placeholder(value):
                problems.append(
                    f"{name} is a known placeholder/default; set a strong unique value."
                )
                continue
            if len(value) < _MIN_SECRET_LENGTH:
                problems.append(
                    f"{name} is shorter than {_MIN_SECRET_LENGTH} characters; "
                    "generate at least 32 random bytes."
                )

        # Redis password is optional in dev (some deployments disable AUTH).
        # In production we require it because docker-compose.yml passes it
        # to `redis-server --requirepass`.
        redis_pw = self.REDIS_PASSWORD.get_secret_value()
        if not redis_pw:
            problems.append(
                "REDIS_PASSWORD is empty; redis-server runs with --requirepass "
                "in docker-compose, so an empty value will fail."
            )
        elif _looks_placeholder(redis_pw):
            problems.append("REDIS_PASSWORD is a known placeholder/default.")
        elif len(redis_pw) < _MIN_SECRET_LENGTH:
            problems.append(
                f"REDIS_PASSWORD is shorter than {_MIN_SECRET_LENGTH} characters."
            )

        # Qdrant API key — required because docker-compose enables auth on
        # the Qdrant service. Allow empty only when explicitly opted out of
        # Qdrant auth (not currently supported here, so always required).
        qdrant_key = self.QDRANT_API_KEY.get_secret_value()
        if not qdrant_key:
            problems.append(
                "QDRANT_API_KEY is empty; Qdrant is configured with auth in docker-compose."
            )
        elif _looks_placeholder(qdrant_key):
            problems.append("QDRANT_API_KEY is a known placeholder/default.")

        # LiteLLM is mandatory in v1 (see CLAUDE.md §3). If the operator
        # somehow disabled it the API key check is the only signal; treat
        # it the same as Qdrant.
        litellm_key = self.LITELLM_API_KEY.get_secret_value()
        if not litellm_key:
            problems.append(
                "LITELLM_API_KEY is empty; LiteLLM is mandatory in v1 (CLAUDE.md §3)."
            )
        elif _looks_placeholder(litellm_key):
            problems.append("LITELLM_API_KEY is a known placeholder/default.")

        # Belt-and-braces: admin/admin must never work, even if someone
        # bypasses the placeholder check by setting ADMIN_PASSWORD to a
        # short-but-not-placeholder value that happens to be the username.
        admin_pw = self.ADMIN_PASSWORD.get_secret_value()
        if (
            self.ADMIN_USERNAME.strip().lower() == "admin"
            and admin_pw.strip().lower() == "admin"
        ):
            problems.append(
                "ADMIN_USERNAME=admin combined with ADMIN_PASSWORD=admin is "
                "forbidden; rotate the bootstrap credentials."
            )

        # TLS must not be disabled against LiteLLM in production.
        if not self.LITELLM_VERIFY_TLS:
            problems.append(
                "LITELLM_VERIFY_TLS=false is forbidden in production; mount a "
                "CA bundle via LITELLM_CA_BUNDLE instead."
            )

        # COMMONS mock fallback must stay disabled. Operators who genuinely
        # need an offline bootstrap should run a staging deployment, not
        # production-with-mock-data.
        if self.COMMONS_ALLOW_MOCK_FALLBACK:
            problems.append(
                "COMMONS_ALLOW_MOCK_FALLBACK=true is forbidden in production; "
                "a real commons source is required."
            )

        if problems:
            raise InsecureConfigurationError(problems)
        return self

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def router_gating_skip_classes(self) -> frozenset[str]:
        """Phase 2c skip classes parsed from ``ROUTER_GATING_SKIP_CLASSES``."""
        return frozenset(
            c.strip() for c in self.ROUTER_GATING_SKIP_CLASSES.split(",") if c.strip()
        )

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def database_url(self) -> str:
        pw = self.POSTGRES_PASSWORD.get_secret_value()
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{pw}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def alembic_database_url(self) -> str:
        pw = self.POSTGRES_PASSWORD.get_secret_value()
        return (
            f"postgresql+psycopg2://{self.POSTGRES_USER}:{pw}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def redis_url(self) -> str:
        pw = self.REDIS_PASSWORD.get_secret_value()
        auth = f":{pw}@" if pw else ""
        return f"redis://{auth}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"


@lru_cache
def get_settings() -> Settings:
    return Settings()


def configure_logging(level: str = "INFO") -> None:
    """Configure structlog for JSON output and bridge stdlib logging into it."""
    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, level.upper(), logging.INFO),
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


__all__ = [
    "InsecureConfigurationError",
    "Settings",
    "configure_logging",
    "get_settings",
]
