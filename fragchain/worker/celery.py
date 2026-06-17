"""Celery application — scaffold only in M1. Real implementations land in later modules."""
from __future__ import annotations

import asyncio

import structlog
from celery import Celery
from celery.exceptions import WorkerShutdown
from celery.schedules import crontab
from celery.signals import worker_process_init, worker_ready

from fragchain.config import get_settings

logger = structlog.get_logger(__name__)

settings = get_settings()

celery_app = Celery(
    "fragchain",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["fragchain.worker.tasks"],
)

celery_app.conf.update(
    task_default_queue="fragchain",
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
    result_expires=3600,
)

# Beat schedule — task stubs only in M1. Cadence is what each task will run at in production;
# the bodies log + return until their owning module fills them in.
celery_app.conf.beat_schedule = {
    "poll_connectors": {
        "task": "fragchain.worker.tasks.poll_connectors",
        "schedule": crontab(minute="*/15"),
    },
    "enforce_budget": {
        "task": "fragchain.worker.tasks.enforce_budget",
        "schedule": crontab(minute="*/5"),
    },
    "release_embargoed_content": {
        "task": "fragchain.worker.tasks.release_embargoed_content",
        "schedule": crontab(minute="*/5"),
    },
    "refresh_matrix_cache": {
        "task": "fragchain.worker.tasks.refresh_matrix_cache",
        "schedule": crontab(minute="0"),
    },
    "sync_commons_source": {
        "task": "fragchain.worker.tasks.sync_commons_source",
        "schedule": crontab(minute="0"),
    },
    "refresh_sigma_sources": {
        "task": "fragchain.worker.tasks.refresh_sigma_sources",
        "schedule": crontab(minute="0", hour="*/6"),
    },
    "prompt_evaluations": {
        "task": "fragchain.worker.tasks.prompt_evaluations",
        "schedule": crontab(minute="0", hour="13"),
    },
    # Wave 1a T6: fail stale 'running'/'generating' rows so a lost broker
    # message cannot 409-block an assessment forever.
    "reap_stale_inflight": {
        "task": "assessment.reap_stale_inflight",
        "schedule": crontab(minute="*/5"),
    },
}


def run_async_task(coro_factory):  # type: ignore[no-untyped-def]
    """Run an async task body and dispose the asyncpg engine afterwards.

    Each Celery prefork worker process handles tasks sequentially. ``asyncio.run``
    spawns a fresh event loop per task, but ``fragchain.db.session`` keeps the
    asyncpg engine + sessionmaker at module scope so the second task on the
    same process reuses a pool whose connections are bound to the *first*
    loop. SQLAlchemy/asyncpg then surface ``Future attached to a different
    loop`` errors (Phase 5 audit Should-fix #8).

    Wrapping each ``asyncio.run`` in this helper disposes the engine in a
    ``finally``: the very next task starts with a fresh engine bound to its
    own loop. ``dispose_engine`` is already idempotent — calling it on an
    already-disposed engine is a no-op.

    Pass a zero-argument callable that returns the coroutine (so the
    coroutine is created inside the new event loop, not at the caller's
    scope where it would be bound to whatever loop was current).
    """
    async def _wrapped() -> object:
        try:
            return await coro_factory()
        finally:
            from fragchain.db.session import dispose_engine

            await dispose_engine()

    return asyncio.run(_wrapped())


# Wave 1a T9: the assessment task surface that MUST be registered for the
# worker to be functional. The Phase 2b registration gap (tasks defined but
# never imported by the worker, so dispatches were silently rejected and DB
# rows stuck in-flight) motivates failing the worker at startup instead.
EXPECTED_TASKS: tuple[str, ...] = (
    "assessment.run_loop",
    "assessment.embed_source",
    "assessment.generate_artifact",
    "assessment.reap_stale_inflight",
)


@worker_ready.connect  # type: ignore[misc]
def _assert_expected_tasks_registered(sender: object = None, **_: object) -> None:
    """Refuse to start a half-registered worker.

    ``worker_ready`` fires exactly once in the main worker process after
    the app's ``include`` imports ran (unlike ``worker_process_init``,
    which fires per prefork child), so the registry is final when we
    check it. A missing task means a broken side-effect import in
    ``fragchain.worker.tasks.__init__`` — log + raise so the deployment
    fails loudly rather than silently dropping dispatches.

    The raise MUST be ``WorkerShutdown`` (a ``SystemExit`` subclass), not
    a plain ``Exception``: Celery's ``Signal.send`` wraps each receiver
    in ``except Exception``, so anything inside the ``Exception``
    hierarchy is logged and swallowed and the half-registered worker
    keeps running (regression-guarded in
    ``tests/worker/test_task_registration.py``).
    """
    app = getattr(sender, "app", None) or celery_app
    registered = app.tasks
    missing = [name for name in EXPECTED_TASKS if name not in registered]
    if missing:
        logger.error(
            "worker.tasks.registration_missing",
            missing=missing,
            expected=list(EXPECTED_TASKS),
        )
        raise WorkerShutdown(
            "Celery worker is missing expected task registrations: "
            f"{missing}. Check the side-effect imports in "
            "fragchain/worker/tasks/__init__.py."
        )
    logger.info(
        "worker.tasks.registration_verified",
        expected=list(EXPECTED_TASKS),
    )


@worker_process_init.connect  # type: ignore[misc]
def _bootstrap_worker_process(**_: object) -> None:
    """Run after each Celery prefork worker process spawns.

    The API process initialises the LLM provider registry in its FastAPI
    lifespan; Celery workers run in their own process and never see that
    lifespan. Without this hook every task that calls
    ``get_default_chat_provider`` / ``get_default_embedding_provider``
    returns ``None`` and fails fast with ``No chat-capable LLM provider
    registered`` (Phase 5 audit L2).

    The signal handler must be synchronous — Celery signals don't await
    coroutines — so we drive the async bootstrap with ``asyncio.run`` in a
    fresh event loop scoped to this hook only.
    """
    from fragchain.llm.registry import bootstrap_providers_for_scripts, get_registry

    try:
        asyncio.run(bootstrap_providers_for_scripts())
    except Exception as exc:  # noqa: BLE001
        # Don't kill the worker — degrade like the API lifespan does. Tasks
        # that need a provider will fail with the clean "no provider"
        # message and the operator can investigate from the structlog event.
        logger.warning("worker.providers.bootstrap_failed", error=str(exc))
        return

    logger.info(
        "worker.providers.bootstrapped",
        providers=get_registry().names(),
    )

    # Mirror the API lifespan's sigma_targets sanity check. With multiple
    # ``is_default=true`` targets the worker's M16 approval path would
    # route in target-id order (random UUID) — refuse to come up rather
    # than letting a default-routing bug surface mid-pipeline.
    #
    # IMPORTANT: this opens a DB session, which lazily creates the
    # asyncpg engine bound to the bootstrap event loop. We MUST dispose
    # the engine before this hook returns — otherwise the first real
    # task on this worker process inherits a sessionmaker whose pooled
    # connections' callbacks are bound to the now-closed bootstrap loop,
    # surfacing as ``Future attached to a different loop`` on every call
    # (Phase 6 follow-up to Phase 5 audit Should-fix #8).
    async def _validate_then_dispose() -> None:
        from fragchain.db.session import dispose_engine

        try:
            await _validate_sigma_target_config_async()
        finally:
            await dispose_engine()

    try:
        asyncio.run(_validate_then_dispose())
    except RuntimeError as exc:
        logger.error("worker.sigma.config.invalid", error=str(exc))
        raise
    except Exception as exc:  # noqa: BLE001
        logger.warning("worker.sigma.config.validate_failed", error=str(exc))


async def _validate_sigma_target_config_async() -> None:
    """Worker-side mirror of the API's ``_validate_sigma_target_config``.

    Lives in this module so the Celery process never imports the API
    package (which would pull in FastAPI + the entire HTTP surface for
    no benefit). The query shape and failure semantics match the API
    lifespan helper.
    """
    from sqlalchemy import select

    from fragchain.db.models import SigmaTarget
    from fragchain.db.session import get_sessionmaker

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
