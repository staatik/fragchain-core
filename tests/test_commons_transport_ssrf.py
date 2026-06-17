"""F-011 / SAST S-004 — commons transport rejects SSRF / internal hosts.

The GitHub transport (and any HTTP-based commons transport) honours
``browser_download_url`` / ``download_url`` strings returned by the
upstream JSON. A malicious commons source can return URLs targeting
internal services (``http://qdrant:6333/...``) or cloud metadata
(``http://169.254.169.254/...``). With ``follow_redirects=True``, even
the public-host initial URL can 30x to an internal target.

The fix: an httpx ``request`` event hook validates the host of every
outbound request (including redirect hops) and raises
``CommonsSSRFError`` if the destination is internal / loopback /
metadata. The error surfaces as a normal request failure that the
existing ``httpx.RequestError`` handlers swallow.
"""
from __future__ import annotations

import pytest

# Skip the whole module if httpx isn't installed in the test venv.
httpx = pytest.importorskip("httpx")

from fragchain.commons.transport import (  # noqa: E402
    CommonsSSRFError,
    GitHubTransport,
    _assert_safe_request_url,
)


# ---------------------------------------------------------------------------
# Hook unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assert_safe_request_url_allows_public_host() -> None:
    """A public host (github.com) passes the hook."""
    req = httpx.Request("GET", "https://api.github.com/repos/owner/repo")
    # No raise expected.
    await _assert_safe_request_url(req)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/whatever",
        "http://localhost/whatever",
        "http://10.0.0.5/whatever",
        "http://169.254.169.254/latest/meta-data/iam",
        "http://169.254.170.2/v2/credentials",
        "http://172.16.0.1/something",
        "http://192.168.1.50/internal",
        "http://[::1]/loopback",
    ],
)
async def test_assert_safe_request_url_blocks_internal(url: str) -> None:
    req = httpx.Request("GET", url)
    with pytest.raises(CommonsSSRFError):
        await _assert_safe_request_url(req)


# ---------------------------------------------------------------------------
# GitHubTransport integration: malicious browser_download_url is blocked
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_github_transport_blocks_malicious_browser_download_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A commons source that returns a release whose
    ``release_pack.json`` asset points at the AWS metadata endpoint must
    NOT result in any request to that host — the event hook intercepts
    before TCP connect."""
    transport = GitHubTransport(
        url="https://github.com/example/intel",
        api_base="https://api.github.com",
    )

    # Pre-build the client so we can patch its `.get` behaviour.
    # First call returns the release JSON; second call would be the
    # malicious asset URL — that one must fail with CommonsSSRFError
    # via the event hook.
    release_body = {
        "tag_name": "v0.1",
        "name": "v0.1",
        "published_at": "2026-05-01T00:00:00Z",
        "assets": [
            {
                "name": "release_pack.json",
                "browser_download_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            }
        ],
    }

    class _StubTransport(httpx.AsyncBaseTransport):
        """Pretend we got back the release JSON; the asset URL request
        will be intercepted by the real event hook before it reaches us."""

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/releases/latest"):
                import json as _json
                return httpx.Response(
                    200,
                    content=_json.dumps(release_body).encode("utf-8"),
                    headers={"content-type": "application/json"},
                )
            # Should never be reached for the metadata URL; if it is,
            # we'd respond and the test would fail because
            # CommonsSSRFError would not have been raised.
            return httpx.Response(200, content=b"{}")

    transport._client = httpx.AsyncClient(
        transport=_StubTransport(),
        event_hooks={"request": [_assert_safe_request_url]},
        follow_redirects=True,
    )
    transport._owns_client = True

    try:
        # ``fetch_latest_release`` calls ``_materialise_release`` which
        # fetches the manifest asset URL — the hook should raise there.
        # The transport swallows ``httpx.RequestError`` and sets
        # ``manifest = None``, then falls back to ``_scan_chains_dir``
        # which goes back to the public api_base (allowed).
        result = await transport.fetch_latest_release()
        # The release JSON was processed but the manifest fetch was
        # blocked → manifest is None on the result.
        assert result is not None
        assert result.manifest is None
    finally:
        await transport.aclose()


@pytest.mark.asyncio
async def test_github_transport_blocks_redirect_to_internal_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A public URL that 30x's to an internal host is also blocked —
    the event hook fires on every redirect hop."""
    transport = GitHubTransport(
        url="https://github.com/example/intel",
        api_base="https://api.github.com",
    )

    class _RedirectingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            # Initial request returns a 302 to a metadata endpoint.
            return httpx.Response(
                302,
                headers={"location": "http://169.254.169.254/latest/meta-data/"},
            )

    transport._client = httpx.AsyncClient(
        transport=_RedirectingTransport(),
        event_hooks={"request": [_assert_safe_request_url]},
        follow_redirects=True,
    )
    transport._owns_client = True

    try:
        # The initial GET succeeds (public host), but httpx then follows
        # the Location header — that next request hits the hook and is
        # refused. The transport's caller catches httpx.RequestError so
        # the surface error is a "no release" return, not a raise.
        result = await transport.fetch_latest_release()
        assert result is None
    finally:
        await transport.aclose()
