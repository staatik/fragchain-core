"""The worker imports fragchain.worker.tasks (celery include); every task
must register via side-effect import in that package's __init__ — an
unregistered task is silently rejected by the worker and its DB row is
stuck in-flight forever (Phase 2b review finding C1)."""
from __future__ import annotations

import subprocess
import sys

# Runs in a SUBPROCESS: sibling worker tests import the task submodules
# directly (e.g. ``from fragchain.worker.tasks.generate_artifact import
# _run``), which registers the tasks on the shared in-process celery_app
# and would mask a missing __init__ side-effect import in full-suite runs.
_CHECK = """
import fragchain.worker.tasks  # what the worker's celery include does
from fragchain.worker.celery import celery_app

for name in (
    "assessment.run_loop",
    "assessment.embed_source",
    "assessment.generate_artifact",
    "assessment.reap_stale_inflight",
):
    assert name in celery_app.tasks, f"{name} not registered"
"""


def test_assessment_tasks_registered_with_celery_app() -> None:
    result = subprocess.run(
        [sys.executable, "-c", _CHECK],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"task-registration check failed:\n{result.stderr}"
    )


# ---------------------------------------------------------------------------
# Wave 1a T9 — startup assertion: a half-registered worker refuses to start
# ---------------------------------------------------------------------------


def test_worker_ready_handler_raises_when_expected_task_missing() -> None:
    from unittest.mock import MagicMock

    import pytest
    from celery.exceptions import WorkerShutdown

    from fragchain.worker.celery import (
        EXPECTED_TASKS,
        _assert_expected_tasks_registered,
    )

    incomplete = {name: object() for name in EXPECTED_TASKS[:-1]}
    sender = MagicMock()
    sender.app.tasks = incomplete

    with pytest.raises(WorkerShutdown) as exc_info:
        _assert_expected_tasks_registered(sender=sender)
    assert EXPECTED_TASKS[-1] in str(exc_info.value)


def test_worker_ready_handler_raise_is_not_swallowed_by_signal_dispatch() -> None:
    """Celery's ``Signal.send`` wraps receivers in ``except Exception`` —
    a plain ``Exception`` subclass raised from the ``worker_ready`` handler
    is logged and the half-registered worker keeps running. The handler
    must therefore raise something OUTSIDE the ``Exception`` hierarchy
    (``WorkerShutdown`` derives from ``SystemExit``) so the worker actually
    dies. This test pins that property against future refactors.
    """
    from unittest.mock import MagicMock

    import pytest

    from fragchain.worker.celery import (
        EXPECTED_TASKS,
        _assert_expected_tasks_registered,
    )

    sender = MagicMock()
    sender.app.tasks = {name: object() for name in EXPECTED_TASKS[:-1]}

    with pytest.raises(BaseException) as exc_info:
        _assert_expected_tasks_registered(sender=sender)
    assert not isinstance(exc_info.value, Exception), (
        "the startup assertion must raise a non-Exception (e.g. "
        "celery.exceptions.WorkerShutdown, a SystemExit subclass) — "
        "Celery's Signal.send swallows Exception subclasses and the "
        "worker would keep running half-registered"
    )


def test_worker_ready_handler_passes_with_full_registry() -> None:
    from unittest.mock import MagicMock

    from fragchain.worker.celery import (
        EXPECTED_TASKS,
        _assert_expected_tasks_registered,
    )

    sender = MagicMock()
    # Extra registered tasks beyond the expected set are fine.
    sender.app.tasks = {
        name: object() for name in (*EXPECTED_TASKS, "celery.ping")
    }

    _assert_expected_tasks_registered(sender=sender)  # must not raise


def test_expected_tasks_covers_the_assessment_surface() -> None:
    from fragchain.worker.celery import EXPECTED_TASKS

    assert set(EXPECTED_TASKS) == {
        "assessment.run_loop",
        "assessment.embed_source",
        "assessment.generate_artifact",
        "assessment.reap_stale_inflight",
    }
