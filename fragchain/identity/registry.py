"""Identity provider registry — empty in v1, populated by post-v1 modules."""
from __future__ import annotations

from fragchain.identity.base import IdentityProvider

identity_providers: dict[str, IdentityProvider] = {}
