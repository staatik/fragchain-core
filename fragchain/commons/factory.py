"""Transport factory — picks the right transport for a commons source row.

Lives in its own module to avoid an import cycle between ``bootstrap.py`` /
``sync.py`` (which need the factory) and ``transport.py`` (which doesn't).

For v1 the URL is the discriminator: anything that parses as a github.com
repo URL uses :class:`GitHubTransport`. Future transports (GitLab, Gitea,
filesystem mirror) plug in here without touching the bootstrap/sync code.
"""
from __future__ import annotations

import structlog

from fragchain.commons.transport import (
    CommonsTransport,
    GitHubTransport,
    MockTransport,
    parse_github_repo,
)
from fragchain.config import get_settings
from fragchain.db.models import CommonsSource

logger = structlog.get_logger(__name__)


def default_transport_factory(source: CommonsSource) -> CommonsTransport:
    """Return a transport bound to ``source``.

    ``auth_credentials_ref`` is treated as the secret value itself for v1
    (operators paste tokens into the field via the Settings UI in M24). The
    full reference-resolution flow (Vault, K8s secrets, etc.) is post-v1.
    """
    settings = get_settings()
    url = source.url.strip()

    if parse_github_repo(url) is not None:
        token = source.auth_credentials_ref if source.auth_type == "token" else None
        return GitHubTransport(
            url=url,
            token=token,
            api_base=settings.COMMONS_GITHUB_API_BASE,
            timeout=float(settings.COMMONS_SYNC_TIMEOUT_SECONDS),
        )

    # Unknown URL scheme — log and return the mock transport so the deployment
    # stays useful for dev. Operators get a structured warning so they know
    # the source isn't actually being talked to.
    logger.warning(
        "commons.transport.unrecognised_url",
        source_id=str(source.id),
        source_name=source.name,
        url=url,
    )
    return MockTransport(connectivity_ok=False)
