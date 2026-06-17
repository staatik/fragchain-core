"""Sigma integration subsystem (M12).

Public surface:

  * :class:`SigmaSourceClient` — refresh one or many sigma source repos.
  * :class:`SigmaTargetClient` — submit a rule to a target, test connectivity.
  * :class:`RoutingEngine` — pick the right target for an approved rule.
  * Transport classes — :class:`GitHubTransport`, :class:`GitLabTransport`.

CLAUDE.md §13 lays out the multi-source / multi-target architecture this
module implements. Source repos are cloned via gitpython; target writes
go over the REST API of GitHub or GitLab (no working tree required).
"""

from fragchain.sigma.parser import ParsedSigmaRule, parse_sigma_yaml
from fragchain.sigma.sources import (
    RefreshAllResult,
    SigmaSourceClient,
    SourceRefreshResult,
    VALID_AUTH_TYPES as SOURCE_AUTH_TYPES,
)
from fragchain.sigma.targets import (
    ConditionError,
    RoutingDecision,
    RoutingEngine,
    RuleContext,
    SigmaTargetClient,
    SubmitOutcome,
    VALID_AUTH_TYPES as TARGET_AUTH_TYPES,
    compile_condition,
)
from fragchain.sigma.transport import (
    ConnectivityResult,
    GitHubTransport,
    GitLabTransport,
    PullRequestResult,
    SigmaWriteTransport,
    build_transport,
    detect_provider,
    parse_repo,
)

__all__ = [
    "ConditionError",
    "ConnectivityResult",
    "GitHubTransport",
    "GitLabTransport",
    "ParsedSigmaRule",
    "PullRequestResult",
    "RefreshAllResult",
    "RoutingDecision",
    "RoutingEngine",
    "RuleContext",
    "SOURCE_AUTH_TYPES",
    "SigmaSourceClient",
    "SigmaTargetClient",
    "SigmaWriteTransport",
    "SourceRefreshResult",
    "SubmitOutcome",
    "TARGET_AUTH_TYPES",
    "build_transport",
    "compile_condition",
    "detect_provider",
    "parse_repo",
    "parse_sigma_yaml",
]
