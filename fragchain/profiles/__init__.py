"""Logsource profiles (M13).

Public re-exports for the rest of the codebase. Importers should reach
for these names rather than the submodules so future restructuring
stays painless.
"""
from fragchain.profiles.store import (
    BuiltinProfileImmutableError,
    ProfileNotFoundError,
    ProfileStore,
    ProfileView,
    VALID_PLATFORMS,
)

__all__ = [
    "BuiltinProfileImmutableError",
    "ProfileNotFoundError",
    "ProfileStore",
    "ProfileView",
    "VALID_PLATFORMS",
]
