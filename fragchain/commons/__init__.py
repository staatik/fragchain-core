"""Intelligence commons subsystem (M7).

The public surface for the rest of the engine:

  * :class:`CommonsClient` — async wrapper used by the API router and by M11.
  * :func:`bootstrap_all`, :func:`sync_all`, :func:`contribute_chain` — the
    underlying primitives, importable directly for tests and the Celery worker.
  * Transport classes — :class:`GitHubTransport` (default) and
    :class:`MockTransport` (dev/offline fallback).

Conflict resolution between sources uses ``priority`` (higher wins) with
``trust_level`` as the tiebreaker (``internal`` > ``partner`` > ``community``).
"""

from fragchain.commons.bootstrap import (
    BootstrapResult,
    CommonsBootstrapError,
    SourceImportResult,
    bootstrap_all,
    bootstrap_source,
    has_been_bootstrapped,
)
from fragchain.commons.client import CommonsChainHit, CommonsClient
from fragchain.commons.contribute import (
    ContributeBatchResult,
    ContributeResult,
    contribute_chain,
    contribute_to_source,
)
from fragchain.commons.factory import default_transport_factory
from fragchain.commons.sources import (
    TRUST_LEVEL_RANK,
    VALID_AUTH_TYPES,
    VALID_TRUST_LEVELS,
    list_all_sources,
    list_contribute_sources,
    list_enabled_sources,
    rank_sources,
    select_winning_chain,
    source_priority_key,
    trust_rank,
)
from fragchain.commons.sync import SyncAllResult, SyncResult, sync_all, sync_source
from fragchain.commons.transport import (
    CommonsChainPayload,
    CommonsRelease,
    CommonsTransport,
    ConnectivityResult,
    GitHubTransport,
    MockTransport,
    PullRequestResult,
    parse_github_repo,
)

__all__ = [
    "BootstrapResult",
    "CommonsBootstrapError",
    "CommonsChainHit",
    "CommonsChainPayload",
    "CommonsClient",
    "CommonsRelease",
    "CommonsTransport",
    "ConnectivityResult",
    "ContributeBatchResult",
    "ContributeResult",
    "GitHubTransport",
    "MockTransport",
    "PullRequestResult",
    "SourceImportResult",
    "SyncAllResult",
    "SyncResult",
    "TRUST_LEVEL_RANK",
    "VALID_AUTH_TYPES",
    "VALID_TRUST_LEVELS",
    "bootstrap_all",
    "bootstrap_source",
    "contribute_chain",
    "contribute_to_source",
    "default_transport_factory",
    "has_been_bootstrapped",
    "list_all_sources",
    "list_contribute_sources",
    "list_enabled_sources",
    "parse_github_repo",
    "rank_sources",
    "select_winning_chain",
    "source_priority_key",
    "sync_all",
    "sync_source",
    "trust_rank",
]
