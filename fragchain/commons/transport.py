"""Transport layer for commons sources.

Decouples "how do we talk to a remote commons repo" from "what do we do with
the chains we pull". Two implementations ship in v1:

  * :class:`GitHubTransport` — talks to the GitHub REST API for releases,
    raw file fetches, and PR creation. Handles both public github.com and
    GitHub Enterprise (via the ``api_base`` constructor arg).
  * :class:`MockTransport` — returns an in-memory stub release pack. The
    bootstrap routine falls back to this when the public commons repo isn't
    reachable (offline dev, or the real repo hasn't shipped yet), so M11 has
    something to develop against. Disabled by setting
    ``COMMONS_ALLOW_MOCK_FALLBACK=false``.

Transports never touch the database. The bootstrap/sync routines own
persistence; transports just speak HTTP.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

import httpx
import structlog

from fragchain.security.git_url import is_safe_host

logger = structlog.get_logger(__name__)


class CommonsSSRFError(httpx.RequestError):
    """Raised when the commons transport refuses to fetch an unsafe URL.

    F-011 (SAST S-004): a malicious upstream commons source can return
    ``browser_download_url`` / ``download_url`` strings pointing at
    internal services (``http://qdrant:6333/...``) or cloud metadata
    (``http://169.254.169.254/...``). The httpx event hook catches the
    outgoing request and aborts before any TCP connect happens.

    Subclasses :class:`httpx.RequestError` so existing
    ``except httpx.RequestError`` handlers in the transport (e.g. in
    ``_materialise_release``) treat the SSRF block exactly like a
    network failure — falling back to safe defaults (empty manifest,
    no release, etc.) rather than propagating up to the caller.
    """


async def _assert_safe_request_url(request: httpx.Request) -> None:
    """httpx ``request`` event hook.

    Fires on every outbound request, including auto-followed redirect
    hops. If the destination host is internal / loopback / metadata, we
    raise ``CommonsSSRFError`` and the existing
    ``except httpx.RequestError`` handlers in the transport methods
    swallow it as a request failure (the manifest fetch becomes
    "no manifest", the chain fetch becomes "skip this chain").
    """
    url = request.url
    host = url.host
    if not host or not is_safe_host(host):
        logger.warning(
            "commons.transport.ssrf_blocked",
            url=str(url),
            host=host,
        )
        raise CommonsSSRFError(
            f"commons transport refused to fetch {host!r} "
            f"(internal/loopback/metadata host blocked at request time)",
            request=request,
        )


# ---------------------------------------------------------------------------
# Dataclasses returned by transports
# ---------------------------------------------------------------------------


@dataclass
class CommonsChainPayload:
    """A single chain document pulled from a commons release."""

    cve_id: str
    version: int
    tlp: str
    content_hash: str
    data: dict[str, Any]


@dataclass
class CommonsRelease:
    """The set of chains (and metadata) for a single release tag."""

    version: str
    published_at: datetime | None
    chains: list[CommonsChainPayload] = field(default_factory=list)
    manifest: dict[str, Any] | None = None


@dataclass
class ConnectivityResult:
    ok: bool
    latency_ms: int | None = None
    message: str = ""
    detected_release: str | None = None


@dataclass
class PullRequestResult:
    """Outcome of a contribution PR."""

    created: bool
    url: str | None
    number: int | None
    branch: str | None = None
    message: str = ""


_GITHUB_REPO_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$"
)


def parse_github_repo(url: str) -> tuple[str, str] | None:
    """Extract ``(owner, repo)`` from a github.com URL, or return None."""
    m = _GITHUB_REPO_RE.match(url.strip())
    if not m:
        return None
    return m.group("owner"), m.group("repo")


def _hash_chain(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class CommonsTransport(Protocol):
    """How the engine talks to a remote commons repo.

    Implementations are constructed once per ``commons_sources`` row by the
    transport factory. They hold their own httpx client; ``aclose()`` is
    called when the row is deleted or the app shuts down.
    """

    name: str

    async def test_connectivity(self) -> ConnectivityResult: ...
    async def fetch_latest_release(self) -> CommonsRelease | None: ...
    async def fetch_release(self, version: str) -> CommonsRelease | None: ...
    async def create_chain_pr(
        self,
        *,
        cve_id: str,
        chain_payload: dict[str, Any],
        branch: str,
        title: str,
        body: str,
    ) -> PullRequestResult: ...
    async def aclose(self) -> None: ...


# ---------------------------------------------------------------------------
# GitHub transport
# ---------------------------------------------------------------------------


class GitHubTransport:
    """Talks to the GitHub REST API.

    Bootstrap/sync use ``/repos/{o}/{r}/releases/latest`` and the
    ``intelligence-pack-*.tar.gz`` asset attached to it. For v1, contribution
    uses the simpler "create branch + commit single file + open PR" flow that
    the GitHub REST API supports without needing git CLI installed in the
    container.

    The transport tolerates missing repos / 404s by returning ``None`` from
    :meth:`fetch_latest_release` so the caller can fall back to a mock pack.
    """

    name = "github"

    def __init__(
        self,
        url: str,
        *,
        token: str | None = None,
        api_base: str = "https://api.github.com",
        timeout: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        parsed = parse_github_repo(url)
        if parsed is None:
            raise ValueError(f"Not a recognised github.com repo URL: {url!r}")
        self.owner, self.repo = parsed
        self.api_base = api_base.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._client = client
        self._owns_client = client is None

    def _headers(self) -> dict[str, str]:
        h = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "fragchain-commons/0.1",
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    async def _http(self) -> httpx.AsyncClient:
        """Build (or reuse) the httpx client used for every API call.

        F-011 (SAST S-004): every outbound request (including auto-
        followed redirects) goes through ``_assert_safe_request_url``,
        which refuses loopback / private / metadata hosts. The hook
        fires on every redirect hop too — so a malicious commons source
        that returns a `Location: http://169.254.169.254/...` to a
        legitimate `browser_download_url` is blocked before httpx
        issues the request.
        """
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                event_hooks={"request": [_assert_safe_request_url]},
            )
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    # -- read paths -------------------------------------------------------

    async def test_connectivity(self) -> ConnectivityResult:
        client = await self._http()
        url = f"{self.api_base}/repos/{self.owner}/{self.repo}"
        started = asyncio.get_event_loop().time()
        try:
            resp = await client.get(url, headers=self._headers())
        except httpx.RequestError as exc:
            return ConnectivityResult(ok=False, message=f"network: {exc}")
        latency = int((asyncio.get_event_loop().time() - started) * 1000)
        if resp.status_code == 200:
            return ConnectivityResult(
                ok=True, latency_ms=latency, message="repo reachable"
            )
        if resp.status_code == 404:
            return ConnectivityResult(
                ok=False, latency_ms=latency, message="repo not found (404)"
            )
        if resp.status_code in (401, 403):
            return ConnectivityResult(
                ok=False,
                latency_ms=latency,
                message=f"auth error ({resp.status_code})",
            )
        return ConnectivityResult(
            ok=False, latency_ms=latency, message=f"http {resp.status_code}"
        )

    async def fetch_latest_release(self) -> CommonsRelease | None:
        client = await self._http()
        url = f"{self.api_base}/repos/{self.owner}/{self.repo}/releases/latest"
        try:
            resp = await client.get(url, headers=self._headers())
        except httpx.RequestError as exc:
            logger.warning(
                "commons.github.fetch_release.network",
                owner=self.owner,
                repo=self.repo,
                error=str(exc),
            )
            return None
        if resp.status_code != 200:
            logger.info(
                "commons.github.fetch_release.no_release",
                owner=self.owner,
                repo=self.repo,
                status=resp.status_code,
            )
            return None
        release = resp.json()
        return await self._materialise_release(release)

    async def fetch_release(self, version: str) -> CommonsRelease | None:
        client = await self._http()
        url = (
            f"{self.api_base}/repos/{self.owner}/{self.repo}"
            f"/releases/tags/{version}"
        )
        try:
            resp = await client.get(url, headers=self._headers())
        except httpx.RequestError:
            return None
        if resp.status_code != 200:
            return None
        return await self._materialise_release(resp.json())

    async def _materialise_release(self, release: dict[str, Any]) -> CommonsRelease:
        """Pull chain JSON files out of a release.

        We look for a ``release_pack.json`` asset (the manifest produced by
        the intelligence repo's CI) and download every chain it lists. If no
        manifest is attached, we fall back to scanning the ``chains/`` tree
        at the release tag via the GitHub contents API.
        """
        version = release.get("tag_name") or release.get("name") or "unknown"
        published_at = None
        if release.get("published_at"):
            try:
                published_at = datetime.fromisoformat(
                    release["published_at"].replace("Z", "+00:00")
                )
            except ValueError:
                published_at = None

        assets = release.get("assets") or []
        manifest_asset = next(
            (a for a in assets if a.get("name") == "release_pack.json"), None
        )
        chains: list[CommonsChainPayload] = []
        manifest: dict[str, Any] | None = None

        if manifest_asset is not None and manifest_asset.get("browser_download_url"):
            client = await self._http()
            try:
                mr = await client.get(
                    manifest_asset["browser_download_url"],
                    headers=self._headers(),
                )
                if mr.status_code == 200:
                    manifest = mr.json()
            except httpx.RequestError:
                manifest = None

        if manifest is not None:
            for entry in manifest.get("chains") or []:
                chains.append(_payload_from_chain_dict(entry))
        else:
            # Fall back: enumerate the chains/ directory at the tag. Useful
            # for early commons repos that ship before CI builds the manifest.
            chains.extend(await self._scan_chains_dir(version))

        return CommonsRelease(
            version=str(version),
            published_at=published_at,
            chains=chains,
            manifest=manifest,
        )

    async def _scan_chains_dir(self, ref: str) -> list[CommonsChainPayload]:
        client = await self._http()
        url = (
            f"{self.api_base}/repos/{self.owner}/{self.repo}/contents/chains"
            f"?ref={ref}"
        )
        try:
            resp = await client.get(url, headers=self._headers())
        except httpx.RequestError:
            return []
        if resp.status_code != 200:
            return []
        items = resp.json()
        out: list[CommonsChainPayload] = []
        for item in items if isinstance(items, list) else []:
            if item.get("type") != "file" or not item.get("name", "").endswith(".json"):
                continue
            download_url = item.get("download_url")
            if not download_url:
                continue
            try:
                cr = await client.get(download_url, headers=self._headers())
            except httpx.RequestError:
                continue
            if cr.status_code != 200:
                continue
            try:
                doc = cr.json()
            except json.JSONDecodeError:
                continue
            out.append(_payload_from_chain_dict(doc))
        return out

    # -- write paths ------------------------------------------------------

    async def create_chain_pr(
        self,
        *,
        cve_id: str,
        chain_payload: dict[str, Any],
        branch: str,
        title: str,
        body: str,
    ) -> PullRequestResult:
        """Create a PR with one new chain JSON file.

        Flow (REST-only):
          1. read default branch + head SHA
          2. create a new branch off head
          3. PUT the chain file at ``chains/{year}/{cve_id}.json``
          4. open the PR

        Any step failing returns ``PullRequestResult(created=False, message=...)``;
        we never raise — the caller decides whether to retry or surface the
        error to the operator.
        """
        if not self.token:
            return PullRequestResult(
                created=False, url=None, number=None, branch=branch,
                message="contribute_enabled=True but no auth token configured",
            )
        client = await self._http()
        headers = self._headers()
        repo_url = f"{self.api_base}/repos/{self.owner}/{self.repo}"

        try:
            repo_resp = await client.get(repo_url, headers=headers)
            if repo_resp.status_code != 200:
                return PullRequestResult(
                    created=False, url=None, number=None, branch=branch,
                    message=f"repo lookup failed ({repo_resp.status_code})",
                )
            default_branch = repo_resp.json().get("default_branch", "main")

            ref_resp = await client.get(
                f"{repo_url}/git/ref/heads/{default_branch}", headers=headers
            )
            if ref_resp.status_code != 200:
                return PullRequestResult(
                    created=False, url=None, number=None, branch=branch,
                    message=f"default branch lookup failed ({ref_resp.status_code})",
                )
            head_sha = ref_resp.json()["object"]["sha"]

            create_ref_resp = await client.post(
                f"{repo_url}/git/refs",
                headers=headers,
                json={"ref": f"refs/heads/{branch}", "sha": head_sha},
            )
            if create_ref_resp.status_code not in (200, 201):
                return PullRequestResult(
                    created=False, url=None, number=None, branch=branch,
                    message=(
                        f"branch creation failed "
                        f"({create_ref_resp.status_code}): {create_ref_resp.text[:200]}"
                    ),
                )

            year = cve_id.split("-")[1] if "-" in cve_id else "unknown"
            file_path = f"chains/{year}/{cve_id}.json"
            content_bytes = json.dumps(chain_payload, indent=2).encode("utf-8")
            import base64
            content_b64 = base64.b64encode(content_bytes).decode("ascii")

            put_resp = await client.put(
                f"{repo_url}/contents/{file_path}",
                headers=headers,
                json={
                    "message": title,
                    "content": content_b64,
                    "branch": branch,
                },
            )
            if put_resp.status_code not in (200, 201):
                return PullRequestResult(
                    created=False, url=None, number=None, branch=branch,
                    message=(
                        f"file commit failed "
                        f"({put_resp.status_code}): {put_resp.text[:200]}"
                    ),
                )

            pr_resp = await client.post(
                f"{repo_url}/pulls",
                headers=headers,
                json={
                    "title": title,
                    "head": branch,
                    "base": default_branch,
                    "body": body,
                },
            )
            if pr_resp.status_code not in (200, 201):
                return PullRequestResult(
                    created=False, url=None, number=None, branch=branch,
                    message=(
                        f"PR creation failed "
                        f"({pr_resp.status_code}): {pr_resp.text[:200]}"
                    ),
                )
            pr = pr_resp.json()
            return PullRequestResult(
                created=True,
                url=pr.get("html_url"),
                number=pr.get("number"),
                branch=branch,
                message="ok",
            )
        except httpx.RequestError as exc:
            return PullRequestResult(
                created=False, url=None, number=None, branch=branch,
                message=f"network error: {exc}",
            )


def _payload_from_chain_dict(doc: dict[str, Any]) -> CommonsChainPayload:
    """Normalise a chain JSON document into a payload row."""
    cve_id = str(doc.get("cve_id") or doc.get("cveId") or "UNKNOWN")
    version = int(doc.get("version") or 1)
    tlp = str(doc.get("tlp") or "tlp:clear").lower()
    return CommonsChainPayload(
        cve_id=cve_id,
        version=version,
        tlp=tlp,
        content_hash=_hash_chain(doc),
        data=doc,
    )


# ---------------------------------------------------------------------------
# Mock transport
# ---------------------------------------------------------------------------


_MOCK_DIRTY_FRAG_CHAIN: dict[str, Any] = {
    "cve_id": "CVE-2026-43284",
    "version": 1,
    "tlp": "tlp:clear",
    "overall_confidence": 0.85,
    "predicted_impact": "Local privilege escalation via splice() abuse in esp4",
    "chain": [
        {
            "seq_order": 1,
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "framework": "attck",
            "confidence": 0.9,
            "preconditions": ["unauthenticated network access"],
            "detection_opportunity": "auth_log: failed pre-auth packet patterns",
            "source_refs": [
                {
                    "url": "https://example.invalid/poc",
                    "source_type": "poc",
                    "quality_score": 0.7,
                    "excerpt_summary": "PoC demonstrates remote trigger",
                }
            ],
        },
        {
            "seq_order": 2,
            "tactic": "Privilege Escalation",
            "tactic_id": "TA0004",
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation",
            "framework": "attck",
            "confidence": 0.85,
            "preconditions": ["initial code execution"],
            "detection_opportunity": "auditd: unexpected splice() to kernel pipe",
            "source_refs": [
                {
                    "url": "https://example.invalid/advisory",
                    "source_type": "vendor_advisory",
                    "quality_score": 0.9,
                    "excerpt_summary": "Vendor advisory details kernel abuse",
                }
            ],
        },
    ],
    "sources_used": [],
    "detection_gaps": ["kernel-level splice() telemetry typically not collected"],
    "provenance": {
        "contributed_by": "mock",
        "contributed_at": "2026-05-12T00:00:00+00:00",
        "contribution_source": "fragchain_mock",
        "license": "CC0",
    },
}


class MockTransport:
    """In-memory commons transport for offline dev & tests.

    Returns a single hand-validated Dirty Frag chain so M11 has a known-good
    target. The release version increments per call when ``incrementing=True``
    so a sync loop can observe deltas. Contribution PRs always 'succeed' and
    record the payload in :attr:`prs` for inspection by tests.
    """

    name = "mock"

    def __init__(
        self,
        *,
        chains: list[dict[str, Any]] | None = None,
        version: str = "v0.0.1-mock",
        connectivity_ok: bool = True,
    ) -> None:
        self._chains: list[dict[str, Any]] = (
            chains if chains is not None else [dict(_MOCK_DIRTY_FRAG_CHAIN)]
        )
        self._version = version
        self.connectivity_ok = connectivity_ok
        self.prs: list[dict[str, Any]] = []

    async def test_connectivity(self) -> ConnectivityResult:
        if self.connectivity_ok:
            return ConnectivityResult(
                ok=True, latency_ms=1, message="mock transport ok",
                detected_release=self._version,
            )
        return ConnectivityResult(ok=False, latency_ms=1, message="mock unreachable")

    async def fetch_latest_release(self) -> CommonsRelease | None:
        return CommonsRelease(
            version=self._version,
            published_at=datetime.now(timezone.utc),
            chains=[_payload_from_chain_dict(c) for c in self._chains],
            manifest={"chains": self._chains, "snapshot": "mock"},
        )

    async def fetch_release(self, version: str) -> CommonsRelease | None:
        if version != self._version:
            return None
        return await self.fetch_latest_release()

    async def create_chain_pr(
        self,
        *,
        cve_id: str,
        chain_payload: dict[str, Any],
        branch: str,
        title: str,
        body: str,
    ) -> PullRequestResult:
        record = {
            "cve_id": cve_id,
            "branch": branch,
            "title": title,
            "body": body,
            "payload": chain_payload,
        }
        self.prs.append(record)
        pr_number = len(self.prs)
        return PullRequestResult(
            created=True,
            url=f"mock://commons/pulls/{pr_number}",
            number=pr_number,
            branch=branch,
            message="ok (mock)",
        )

    async def aclose(self) -> None:
        return None
