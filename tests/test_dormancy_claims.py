"""Mechanical-truth guard #2: executable CLAUDE.md §12.2 dormancy claims.

The §12.2 "Dormant by design" allowlist makes *reachability* claims about
code that is intentionally kept in tree. Those claims rot silently when
wiring changes (the 2026-06-10 platform review found exactly such a drift:
"`ChainGenerator` has no caller in the active flow" while `POST /cves/manual`
— a live UI screen — dispatched it). This module turns each claim into a
grep/import-level assertion so drift fails a test instead.

All assertions are static (file reads / regex) — no DB, no network, no app
startup. Every failure message says how to resolve it: update CLAUDE.md
§12.2 or this test, deliberately.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DRIFT_MSG = "§12.2 claim drifted — update CLAUDE.md §12.2 or this test, deliberately."


def _read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


def _grep_files(pattern: str, root: str = "fragchain") -> set[str]:
    """Repo-relative paths of .py files under *root* whose content matches."""
    rx = re.compile(pattern)
    hits: set[str] = set()
    for path in (REPO_ROOT / root).rglob("*.py"):
        if rx.search(path.read_text(encoding="utf-8")):
            hits.add(str(path.relative_to(REPO_ROOT)))
    return hits


# ---------------------------------------------------------------------------
# ChainGenerator / synthesize_chain — §12.2 rows 1–2
# ---------------------------------------------------------------------------

def test_synthesize_chain_dispatch_sites_are_exactly_the_documented_set() -> None:
    """§12.2 documents three dispatch sites for ``synthesize_chain``:
    POST /cves/manual (routers/cves.py), POST /cves/{id}/resynthesize
    (routers/chains.py), and the enrichment pipeline (ingest/enrichment.py).
    """
    documented = {
        "fragchain/api/routers/cves.py",
        "fragchain/api/routers/chains.py",
        "fragchain/ingest/enrichment.py",
    }
    # Dispatch is always via the fully-qualified task name string passed to
    # celery_app.send_task(...); the defining module declares the same string
    # as name=... and is excluded.
    referencing = _grep_files(r'"fragchain\.worker\.tasks\.synthesize_chain"')
    actual = referencing - {"fragchain/worker/tasks/synthesize.py"}
    assert actual == documented, (
        f"synthesize_chain dispatch sites {sorted(actual)} != documented "
        f"{sorted(documented)}. {DRIFT_MSG}"
    )


def test_synthesize_chain_task_is_still_registered() -> None:
    """The dormant task must keep its Celery registration (revival path)."""
    src = _read("fragchain/worker/tasks/synthesize.py")
    assert 'name="fragchain.worker.tasks.synthesize_chain"' in src, (
        f"synthesize_chain task name declaration missing. {DRIFT_MSG}"
    )
    init = _read("fragchain/worker/tasks/__init__.py")
    assert "synthesize" in init, (
        f"worker/tasks/__init__.py no longer imports the synthesize module — "
        f"the task would not register with the worker. {DRIFT_MSG}"
    )


def test_chain_generator_is_driven_by_the_synthesize_task() -> None:
    """§12.2: synthesize.py 'drives ChainGenerator'."""
    src = _read("fragchain/worker/tasks/synthesize.py")
    assert "ChainGenerator" in src, (
        f"worker/tasks/synthesize.py no longer references ChainGenerator. {DRIFT_MSG}"
    )


# ---------------------------------------------------------------------------
# Webhooks — §12.2 row 3
# ---------------------------------------------------------------------------

def test_webhooks_router_is_included_in_api_main() -> None:
    """§12.2: webhook entry points are wired (router included), traffic-less."""
    main = _read("fragchain/api/main.py")
    assert re.search(r"include_router\(\s*webhooks\.router", main), (
        f"webhooks router not included in api/main.py. {DRIFT_MSG}"
    )


# ---------------------------------------------------------------------------
# Rate limiting — §12.2 row 4
# ---------------------------------------------------------------------------

def test_live_feed_rate_limit_is_still_imported_and_configured() -> None:
    """§12.2: rate_limit.py + MAX_LIVE_CVE_PER_HOUR stay wired."""
    importers = _grep_files(r"fragchain\.ingest\.rate_limit|from fragchain\.ingest import .*rate_limit")
    importers.discard("fragchain/ingest/rate_limit.py")
    assert importers, (
        f"fragchain/ingest/rate_limit.py has no importers left. {DRIFT_MSG}"
    )
    assert "MAX_LIVE_CVE_PER_HOUR" in _read("fragchain/config.py"), (
        f"MAX_LIVE_CVE_PER_HOUR removed from config.py. {DRIFT_MSG}"
    )


# ---------------------------------------------------------------------------
# Import Manager — §12.2 row 5
# ---------------------------------------------------------------------------

def test_imports_router_is_included_and_budget_settings_exist() -> None:
    """§12.2: historical-import router wired; budget settings present."""
    main = _read("fragchain/api/main.py")
    assert re.search(r"include_router\(\s*imports_router\.router", main), (
        f"imports router not included in api/main.py. {DRIFT_MSG}"
    )
    config = _read("fragchain/config.py")
    for setting in ("MAX_HISTORICAL_CVE_PER_DAY", "AUTO_PROCESS_KEV"):
        assert setting in config, (
            f"{setting} removed from config.py. {DRIFT_MSG}"
        )


# ---------------------------------------------------------------------------
# cves.processing_status state machine — §12.2 row 6
# ---------------------------------------------------------------------------

def test_processing_state_machine_is_still_imported_by_active_path() -> None:
    """§12.2: ingest/state.py is imported by prod modules, including the
    active-path coverage task."""
    assert "from fragchain.ingest.state import" in _read(
        "fragchain/worker/tasks/coverage.py"
    ), (
        f"worker/tasks/coverage.py no longer imports fragchain/ingest/state.py. {DRIFT_MSG}"
    )


# ---------------------------------------------------------------------------
# Connector enrichment orchestrator — §12.2 row 7
# ---------------------------------------------------------------------------

def test_poll_connectors_beat_entry_exists() -> None:
    """§12.2: the orchestrator runs from the poll_connectors beat entry."""
    celery_src = _read("fragchain/worker/celery.py")
    assert '"poll_connectors"' in celery_src and (
        "fragchain.worker.tasks.poll_connectors" in celery_src
    ), (
        f"poll_connectors beat schedule entry missing from worker/celery.py. {DRIFT_MSG}"
    )


def test_enrichment_orchestrator_is_still_consumed() -> None:
    """§12.2: connectors/orchestrator.py is consumed by ingest/enrichment.py."""
    enrichment = _read("fragchain/ingest/enrichment.py")
    assert re.search(r"fragchain\.connectors(\.orchestrator)?\b", enrichment), (
        f"ingest/enrichment.py no longer consumes fragchain.connectors. {DRIFT_MSG}"
    )
