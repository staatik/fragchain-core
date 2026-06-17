"""Identity module — placeholder in v1.

Schema exists (per M3) so other modules can reference user_identities et al.,
but no verification logic ships in v1. All endpoints under /api/v1/identity/*
return 501 except GET /api/v1/identity which reports the default tier.

Real identity providers (GPG, SSH, Sigstore) are deferred to post-v1 modules.
"""
from fragchain.identity.base import IdentityProvider
from fragchain.identity.registry import identity_providers

__all__ = ["IdentityProvider", "identity_providers"]
