from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from fragchain import __version__
from fragchain.api.middleware.tlp_filter import TLPRequestContextMiddleware
from fragchain.api.routers import (
    assessments as assessments_router,
    auth,
    chains as chains_router,
    commons as commons_router,
    connectors,
    coverage as coverage_router,
    coverage_benchmarks as coverage_benchmarks_router,
    cves as cves_router,
    embargo,
    evaluations as evaluations_router,
    health,
    identity,
    imports as imports_router,
    llm,
    profiles as profiles_router,
    prompts as prompts_router,
    queue as queue_router,
    rules as rules_router,
    sigma as sigma_router,
    vector as vector_router,
    version,
    webhooks,
    websocket as websocket_router,
)
from fragchain.api.security import hash_password
from fragchain.config import configure_logging, get_settings
from fragchain.connectors import (
    ConnectorConfig,
    discover_connectors,
    get_orchestrator,
    reset_orchestrator,
)
from fragchain.db.models import ConnectorState, User
from fragchain.db.session import dispose_engine, get_sessionmaker
from fragchain.llm import discover_providers, get_registry, reset_registry
from fragchain.vector.collections import ensure_collections

# Side-effect imports: register embargoable tables with the M2 auto-release
# registry (`release_expired` walks every entry every 5 min from beat).
#   * `fragchain.ingest`  → `cves`, `source_documents`
#   * `fragchain.chain`   → `attack_chains` (Phase 4 cleanup C1/D1)
from fragchain import chain as _chain_pkg  # noqa: F401
from fragchain import ingest as _ingest  # noqa: F401

logger = structlog.get_logger(__name__)


async def _seed_admin() -> None:
    """Create the default admin user if no users exist.

    Refuses to seed an ``admin`` / ``admin`` bootstrap credential even in
    development — the Settings validator (F-001) already blocks it in
    production, but a dev operator that copies ``.env.example`` verbatim
    should still fail loudly here rather than ship a usable default
    credential.
    """
    settings = get_settings()
    username = settings.ADMIN_USERNAME.strip()
    password = settings.ADMIN_PASSWORD.get_secret_value()
    if username.lower() == "admin" and password.strip().lower() == "admin":
        logger.error(
            "admin.seed.refused",
            reason="admin/admin bootstrap is forbidden; set ADMIN_PASSWORD",
        )
        return
    sm = get_sessionmaker()
    async with sm() as session:
        result = await session.execute(select(User).limit(1))
        if result.scalar_one_or_none() is not None:
            return
        user = User(
            username=username,
            email=settings.ADMIN_EMAIL,
            hashed_password=hash_password(password),
            tier="authenticated",
            clearance_level="tlp:green",
        )
        session.add(user)
        await session.commit()
        logger.info("admin.seeded", username=username)


async def _bootstrap_connectors() -> None:
    """Discover installed connector plugins and bring up the orchestrator.

    Failures in any one connector never block startup — the orchestrator
    isolates each connector. After registration we initialize every enabled
    one and mirror state to `connector_state` so the Settings UI has rows to
    render even before any operator interaction.
    """
    connectors_loaded = discover_connectors()
    orch = get_orchestrator()
    sm = get_sessionmaker()
    async with sm() as session:
        existing_rows = {
            row.name: row
            for row in (await session.execute(select(ConnectorState))).scalars().all()
        }
        for connector in connectors_loaded:
            db_row = existing_rows.get(connector.name)
            config = ConnectorConfig()
            if db_row is not None:
                config.enabled = bool(db_row.enabled)
                config.config = dict(db_row.config or {})
            orch.register(connector, config=config)
        await orch.initialize_all()
        await orch.sync_state_to_db(session)
    logger.info(
        "connector.bootstrap.complete",
        loaded=len(connectors_loaded),
        names=[c.name for c in connectors_loaded],
    )


async def _bootstrap_commons() -> None:
    """First-run import of every enabled commons source.

    Skipped if any enabled source already has ``last_sync_at`` set — the
    operator can re-run bootstrap explicitly via the API. The Celery beat
    schedule still runs the hourly delta sync regardless.
    """
    from fragchain.commons import CommonsClient, has_been_bootstrapped

    sm = get_sessionmaker()
    async with sm() as session:
        if await has_been_bootstrapped(session):
            logger.info("commons.bootstrap.skipped", reason="already_bootstrapped")
            return
        client = CommonsClient(session)
        result = await client.bootstrap_all()
        logger.info(
            "commons.bootstrap.startup_complete",
            sources=result.total_sources,
            successes=result.successes,
            failures=result.failures,
        )


async def _bootstrap_llm_providers() -> None:
    """Discover installed LLM providers and bring up the registry.

    Mirrors `_bootstrap_connectors`. In v1 exactly one provider ships
    (`litellm`) but the loop handles N providers transparently — when
    M39-M41 add direct providers nothing here changes.
    """
    providers = discover_providers()
    registry = get_registry()
    for provider in providers:
        registry.register(provider)
    await registry.initialize_all()
    logger.info(
        "llm.provider.bootstrap.complete",
        loaded=len(providers),
        names=[p.name for p in providers],
    )


async def _validate_sigma_target_config() -> None:
    """Fail fast if the sigma_targets configuration is inconsistent.

    M12 routing falls back to ``is_default=true`` when no explicit clause
    matches; with two default targets the selection becomes
    target-id-order dependent (which is a random UUID), so the operator
    intent is genuinely ambiguous. Detecting this at startup beats waiting
    for an analyst to approve a rule and notice the routing surprise.

    A deployment with zero default targets is allowed — operators may
    require every approve call to pass an explicit ``target_id`` — but we
    log a WARN so the choice is visible. Two-or-more is the error case.
    """
    from fragchain.db.models import SigmaTarget

    sm = get_sessionmaker()
    async with sm() as session:
        result = await session.execute(
            select(SigmaTarget.name).where(SigmaTarget.is_default.is_(True))
        )
        defaults = [row[0] for row in result.all()]
    if len(defaults) > 1:
        logger.error(
            "sigma.config.multiple_default_targets",
            targets=defaults,
            count=len(defaults),
        )
        raise RuntimeError(
            "Multiple sigma_targets rows have is_default=true "
            f"({defaults}). Set exactly one row to is_default=true, or "
            "none to require explicit target_id on every approval."
        )
    if not defaults:
        logger.warning("sigma.config.no_default_target")


async def _bootstrap_vector_store() -> None:
    """Create the four Qdrant collections (source_chunks, sigma_rules,
    attack_chains, attck_techniques) if absent. Idempotent.

    A Qdrant outage at startup is logged and tolerated — the API still
    serves; the embedding pipeline will surface the issue the next time it
    runs.
    """
    result = await ensure_collections()
    logger.info("qdrant.bootstrap.complete", collections=result)


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    settings = get_settings()
    configure_logging(settings.APP_LOG_LEVEL)
    logger.info(
        "api.startup",
        env=settings.APP_ENV,
        version=__version__,
    )
    try:
        await _seed_admin()
    except Exception as exc:  # noqa: BLE001
        # Don't block boot on a seeding race — log and continue.
        logger.warning("admin.seed.failed", error=str(exc))
    try:
        await _bootstrap_connectors()
    except Exception as exc:  # noqa: BLE001
        # A failure in plugin discovery must not take the API down.
        logger.warning("connector.bootstrap.failed", error=str(exc))
    try:
        await _bootstrap_llm_providers()
    except Exception as exc:  # noqa: BLE001
        logger.warning("llm.provider.bootstrap.failed", error=str(exc))
    # Hard-fail boot on an inconsistent sigma_targets default state — the
    # routing surprise it produces would silently break M16 approvals.
    await _validate_sigma_target_config()
    try:
        await _bootstrap_vector_store()
    except Exception as exc:  # noqa: BLE001
        # Qdrant outage at startup is non-fatal — the API still serves.
        logger.warning("qdrant.bootstrap.failed", error=str(exc))
    # Wave 1a T7: cross-process event bridge — re-emits worker-origin events
    # from Redis into this process's bus so /ws/events subscribers see them.
    # Best-effort: a failure here degrades to local-only events (pre-bridge
    # behavior); the bridge itself retries Redis with backoff.
    bridge_task = None
    try:
        from fragchain.notifications.bridge import start_bridge

        bridge_task = start_bridge(settings.redis_url)
    except Exception as exc:  # noqa: BLE001
        logger.warning("events.bridge.start_failed", error=str(exc))
    try:
        await _bootstrap_commons()
    except Exception as exc:  # noqa: BLE001
        # Hard-fail startup on `CommonsBootstrapError` so an operator who
        # set COMMONS_ALLOW_MOCK_FALLBACK=false notices the unreachable
        # source instead of silently running with a stub (Phase 4 audit
        # Should-fix #5). Other transient errors stay best-effort — the
        # hourly Celery sync will retry.
        from fragchain.commons.bootstrap import CommonsBootstrapError

        if isinstance(exc, CommonsBootstrapError):
            logger.error("commons.bootstrap.fatal", error=str(exc))
            raise
        logger.warning("commons.bootstrap.failed", error=str(exc))
    yield
    if bridge_task is not None:
        try:
            from fragchain.notifications.bridge import stop_bridge

            await stop_bridge(bridge_task)
        except Exception as exc:  # noqa: BLE001
            logger.warning("events.bridge.stop_failed", error=str(exc))
    try:
        await get_orchestrator().shutdown_all()
    except Exception as exc:  # noqa: BLE001
        logger.warning("connector.shutdown.failed", error=str(exc))
    try:
        await get_registry().shutdown_all()
    except Exception as exc:  # noqa: BLE001
        logger.warning("llm.provider.shutdown.failed", error=str(exc))
    reset_orchestrator()
    reset_registry()
    await dispose_engine()
    logger.info("api.shutdown")


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.APP_LOG_LEVEL)

    # F-004: disable interactive docs in production. Swagger UI and the
    # OpenAPI schema both leak the full endpoint surface and parameter
    # shapes, which makes pre-engagement recon trivial. Operators that
    # need the schema in production can still scrape it from a staging
    # deployment or generate it offline from the source.
    docs_url = None if settings.is_production else "/api/v1/docs"
    openapi_url = None if settings.is_production else "/api/v1/openapi.json"

    app = FastAPI(
        title="FragChain Core API",
        version=__version__,
        lifespan=lifespan,
        docs_url=docs_url,
        redoc_url=None,
        openapi_url=openapi_url,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    # Attaches `request.state.user` from the bearer token (None if anonymous).
    # All TLP enforcement downstream relies on this being populated.
    app.add_middleware(TLPRequestContextMiddleware)

    # Root liveness probe (used by container healthcheck — no external deps)
    @app.get("/readyz")
    async def _readyz() -> dict[str, str]:
        return {"status": "ok"}

    api_prefix = "/api/v1"
    app.include_router(health.router, prefix=api_prefix, tags=["system"])
    app.include_router(version.router, prefix=api_prefix, tags=["system"])
    app.include_router(auth.router, prefix=api_prefix, tags=["auth"])
    app.include_router(identity.router, prefix=api_prefix, tags=["identity"])
    app.include_router(embargo.router, prefix=api_prefix, tags=["embargo"])
    app.include_router(connectors.router, prefix=api_prefix, tags=["connectors"])
    app.include_router(llm.router, prefix=api_prefix, tags=["llm"])
    app.include_router(prompts_router.router, prefix=api_prefix, tags=["prompts"])
    app.include_router(vector_router.router, prefix=api_prefix, tags=["vector"])
    app.include_router(commons_router.router, prefix=api_prefix, tags=["commons"])
    app.include_router(cves_router.router, prefix=api_prefix, tags=["cves"])
    app.include_router(chains_router.router, prefix=api_prefix, tags=["chains"])
    app.include_router(imports_router.router, prefix=api_prefix, tags=["imports"])
    app.include_router(webhooks.router, prefix=api_prefix, tags=["webhooks"])
    app.include_router(sigma_router.router, prefix=api_prefix, tags=["sigma"])
    app.include_router(
        profiles_router.router, prefix=api_prefix, tags=["profiles"]
    )
    app.include_router(
        coverage_router.router, prefix=api_prefix, tags=["coverage"]
    )
    app.include_router(
        coverage_benchmarks_router.router, prefix=api_prefix, tags=["coverage"]
    )
    app.include_router(rules_router.router, prefix=api_prefix, tags=["rules"])
    app.include_router(queue_router.router, prefix=api_prefix, tags=["queue"])
    app.include_router(
        evaluations_router.router,
        prefix=api_prefix,
        tags=["evaluations"],
    )
    app.include_router(
        assessments_router.router,
        prefix=api_prefix,
        tags=["assessments"],
    )
    # WebSocket route is mounted at the root (no API prefix) so the URL
    # matches the frontend's `useWebSocket` default of `/ws/events`.
    app.include_router(websocket_router.router, tags=["events"])

    return app


app = create_app()
