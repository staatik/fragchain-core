"""Trust + classification primitives. Import from here, not from submodules."""

from fragchain.security.embargo import (
    EmbargoedTable,
    ReleaseResult,
    effective_tlp,
    get_registry,
    is_embargoed,
    list_active,
    register_embargoed_table,
    release_expired,
    release_one,
)
from fragchain.security.tlp import (
    TLP,
    can_user_access,
    filter_tlp_visible,
    has_explicit_grant,
    is_anonymous,
    is_embargo_participant,
    max_tlp,
)

__all__ = [
    "TLP",
    "max_tlp",
    "can_user_access",
    "filter_tlp_visible",
    "has_explicit_grant",
    "is_embargo_participant",
    "is_anonymous",
    "EmbargoedTable",
    "ReleaseResult",
    "register_embargoed_table",
    "get_registry",
    "release_expired",
    "release_one",
    "list_active",
    "effective_tlp",
    "is_embargoed",
]
