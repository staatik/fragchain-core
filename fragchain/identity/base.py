"""IdentityProvider Protocol — interface only, no implementations in v1."""
from __future__ import annotations

import uuid
from typing import Protocol, runtime_checkable


@runtime_checkable
class IdentityProvider(Protocol):
    name: str

    async def verify(self, user_id: uuid.UUID, challenge: str, signature: str) -> bool:
        ...

    async def sign_contribution(self, user_id: uuid.UUID, content_hash: str) -> str:
        ...
