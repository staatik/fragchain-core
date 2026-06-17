"""Client for the fragchain-registry index.

The registry is a separate Apache 2.0 repo hosted at a configurable URL
(default: a hardcoded JSON URL placeholder until the real registry is up).
It enumerates known third-party connectors so the Settings UI can browse
what's *available* in addition to what's *installed*.

This module fetches and caches the registry JSON. It does NOT install
packages — installation is `pip install fragchain-connector-foo` on the host,
which is admin / DevOps territory. The registry only powers the discover-
and-display half of the UI.

JSON shape (see FragChain_Ecosystem_Architecture.md §2.4):

    {
      "connectors": [
        {
          "name": "opencti",
          "package": "fragchain-connector-opencti",
          "type": "source_stream",
          "official": true,
          "maintainer": "fragchain-core-team",
          "repository": "github.com/fragchain/connector-opencti",
          "version": "1.2.0",
          "health": "active"
        }
      ]
    }
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

logger = structlog.get_logger(__name__)


# Built-in default. Operators override via env (FRAGCHAIN_REGISTRY_URL) or by
# pointing at a `file://` URL for air-gapped deployments. A bundled fallback
# under `scripts/fragchain_registry.json` ships with core so the UI works
# offline on first boot.
DEFAULT_REGISTRY_URL = (
    "https://raw.githubusercontent.com/fragchain/fragchain-registry/main/registry.json"
)

# Path to the bundled offline fallback shipped with fragchain-core. Resolved
# relative to the repo root rather than the package, since the JSON is a
# build artifact maintained alongside docs / scripts.
_BUNDLED_FALLBACK = Path(__file__).resolve().parents[2] / "scripts" / "fragchain_registry.json"


@dataclass(frozen=True)
class RegistryEntry:
    """One connector entry in the registry JSON."""

    name: str
    package: str
    type: str
    official: bool
    version: str
    health: str
    maintainer: str | None = None
    repository: str | None = None
    description: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RegistryEntry":
        return cls(
            name=str(data["name"]),
            package=str(data.get("package", "")),
            type=str(data.get("type", "")),
            official=bool(data.get("official", False)),
            version=str(data.get("version", "")),
            health=str(data.get("health", "unknown")),
            maintainer=data.get("maintainer"),
            repository=data.get("repository"),
            description=data.get("description"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "package": self.package,
            "type": self.type,
            "official": self.official,
            "version": self.version,
            "health": self.health,
            "maintainer": self.maintainer,
            "repository": self.repository,
            "description": self.description,
        }


class RegistryClient:
    """Fetches and caches the fragchain-registry JSON.

    Cache TTL is intentionally short — operators may want to see new
    connectors quickly after they appear in the registry. The cache only
    exists to prevent every UI page-load from hitting the network.
    """

    def __init__(
        self,
        url: str | None = None,
        *,
        cache_ttl_seconds: int = 300,
        timeout_seconds: float = 10.0,
        fallback_path: Path | None = None,
    ) -> None:
        self.url = url or DEFAULT_REGISTRY_URL
        self.cache_ttl = cache_ttl_seconds
        self.timeout = timeout_seconds
        self.fallback_path = fallback_path or _BUNDLED_FALLBACK
        self._cache: tuple[float, list[RegistryEntry]] | None = None

    async def fetch(self, *, force_refresh: bool = False) -> list[RegistryEntry]:
        """Return the current registry contents.

        Order of precedence: live HTTP fetch, then cached value if still
        fresh, then the bundled offline fallback. Network or parse errors
        return the fallback rather than raising — the UI must always render.
        """
        now = time.monotonic()
        if not force_refresh and self._cache is not None:
            cached_at, entries = self._cache
            if now - cached_at < self.cache_ttl:
                return entries

        try:
            data = await self._load_from_url(self.url)
        except Exception as exc:  # noqa: BLE001 — fall back to bundled JSON
            logger.warning(
                "connector.registry.fetch_failed", url=self.url, error=str(exc)
            )
            data = self._load_fallback()

        entries = self._parse(data)
        self._cache = (now, entries)
        return entries

    def invalidate_cache(self) -> None:
        self._cache = None

    # -- internals ---------------------------------------------------------

    async def _load_from_url(self, url: str) -> dict[str, Any]:
        scheme = urlparse(url).scheme.lower()
        if scheme in ("file", ""):
            path = Path(urlparse(url).path) if scheme == "file" else Path(url)
            return json.loads(path.read_text())
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()

    def _load_fallback(self) -> dict[str, Any]:
        if self.fallback_path.exists():
            try:
                return json.loads(self.fallback_path.read_text())
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "connector.registry.fallback_parse_failed",
                    path=str(self.fallback_path),
                    error=str(exc),
                )
        return {"connectors": []}

    @staticmethod
    def _parse(data: dict[str, Any]) -> list[RegistryEntry]:
        items = data.get("connectors", []) if isinstance(data, dict) else []
        out: list[RegistryEntry] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            if "name" not in item:
                continue
            try:
                out.append(RegistryEntry.from_dict(item))
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "connector.registry.entry_invalid",
                    entry=item,
                    error=str(exc),
                )
        return out


_default_client: RegistryClient | None = None


def get_registry_client(url: str | None = None) -> RegistryClient:
    """Lazy process-wide RegistryClient.

    If `url` is provided it always wins (test override). Otherwise the cached
    singleton is reused so the in-memory cache survives across requests.
    """
    global _default_client
    if url is not None:
        return RegistryClient(url=url)
    if _default_client is None:
        _default_client = RegistryClient()
    return _default_client


def reset_registry_client() -> None:
    """Test hook to discard the cached singleton."""
    global _default_client
    _default_client = None


__all__ = [
    "DEFAULT_REGISTRY_URL",
    "RegistryEntry",
    "RegistryClient",
    "get_registry_client",
    "reset_registry_client",
]
