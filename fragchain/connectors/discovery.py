"""Connector plugin discovery via Python entry points.

Connectors are separate Python packages that advertise themselves in their
own `pyproject.toml`:

    [project.entry-points."fragchain.connectors"]
    epss = "fragchain_connector_epss:EPSSConnector"

`discover_connectors()` walks the entry-point group and instantiates each
class with no arguments. Connectors keep their construction cheap; expensive
setup belongs in `initialize()` which the orchestrator calls explicitly.

The function never raises on a bad entry point — a broken plugin must not
take the engine down. Failures are logged with the offending entry-point name
and the loader moves on.

Reference: CLAUDE.md §5, FragChain_Ecosystem_Architecture.md §3.2.
"""
from __future__ import annotations

import importlib.metadata as md
from typing import Iterable

import structlog

from fragchain.connectors.base import IntelConnector

logger = structlog.get_logger(__name__)


ENTRY_POINT_GROUP = "fragchain.connectors"


def _iter_entry_points() -> Iterable[md.EntryPoint]:
    """Compatibility shim around importlib.metadata.entry_points().

    Python 3.10+ exposes the `select()` form; falls back to dict-style for
    older interpreters even though we pin 3.12 — keeps unit tests trivial to
    run on a venv that ships an older importlib_metadata shim.
    """
    eps = md.entry_points()
    select = getattr(eps, "select", None)
    if callable(select):
        return select(group=ENTRY_POINT_GROUP)
    return eps.get(ENTRY_POINT_GROUP, [])  # type: ignore[attr-defined]


def discover_connectors() -> list[IntelConnector]:
    """Load every connector registered under `fragchain.connectors`.

    Each entry point should reference a connector *class* (or any zero-arg
    callable that returns an `IntelConnector` instance). The loader logs every
    successful load and every failure. Returns an empty list when no
    connectors are installed.
    """
    discovered: list[IntelConnector] = []
    for ep in _iter_entry_points():
        try:
            obj = ep.load()
        except Exception as exc:  # noqa: BLE001 — broken plugin must not crash startup
            logger.warning(
                "connector.discovery.load_failed",
                entry_point=ep.name,
                value=getattr(ep, "value", None),
                error=str(exc),
            )
            continue

        try:
            instance = obj() if isinstance(obj, type) or callable(obj) else obj
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "connector.discovery.instantiate_failed",
                entry_point=ep.name,
                error=str(exc),
            )
            continue

        if not isinstance(instance, IntelConnector):
            logger.warning(
                "connector.discovery.invalid",
                entry_point=ep.name,
                reason="loaded object does not implement IntelConnector Protocol",
            )
            continue

        logger.info(
            "connector.discovered",
            name=instance.name,
            version=instance.version,
            type=str(instance.type),
            entry_point=ep.name,
        )
        discovered.append(instance)

    if not discovered:
        logger.info("connector.discovery.empty")

    return discovered


__all__ = ["discover_connectors", "ENTRY_POINT_GROUP"]
