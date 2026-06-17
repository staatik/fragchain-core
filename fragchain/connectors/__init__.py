"""Connector framework public API.

Importable surface for the rest of the engine. Specific connectors live in
their own packages and register via the `fragchain.connectors` entry-point
group — they don't import this module, they only need `IntelConnector` and
the dataclasses defined below.
"""

from fragchain.connectors.base import (
    AttackPattern,
    ConnectorConfig,
    ConnectorHealth,
    ConnectorOutput,
    ConnectorType,
    CVERecord,
    EnrichmentResult,
    HealthStatus,
    IntelConnector,
    RateLimit,
)
from fragchain.connectors.discovery import ENTRY_POINT_GROUP, discover_connectors
from fragchain.connectors.orchestrator import (
    ConnectorOrchestrator,
    get_orchestrator,
    reset_orchestrator,
)
from fragchain.connectors.registry_client import (
    RegistryClient,
    RegistryEntry,
    get_registry_client,
    reset_registry_client,
)

__all__ = [
    "AttackPattern",
    "ConnectorConfig",
    "ConnectorHealth",
    "ConnectorOrchestrator",
    "ConnectorOutput",
    "ConnectorType",
    "CVERecord",
    "ENTRY_POINT_GROUP",
    "EnrichmentResult",
    "HealthStatus",
    "IntelConnector",
    "RateLimit",
    "RegistryClient",
    "RegistryEntry",
    "discover_connectors",
    "get_orchestrator",
    "get_registry_client",
    "reset_orchestrator",
    "reset_registry_client",
]
