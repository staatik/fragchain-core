"""HTTP transports for Sigma write targets (PR creation).

The read side uses gitpython (clone + pull) — see ``fragchain.sigma.sources``.
The write side uses a remote git host's REST API to create a branch, commit
one file, and open a PR without needing a working tree.

Two implementations:

  * :class:`GitHubTransport` — github.com + GitHub Enterprise (``api_base``).
  * :class:`GitLabTransport` — gitlab.com + self-hosted GitLab (``api_base``).

Both are picked automatically based on the target ``git_url``. They share
the dataclasses below.
"""
from __future__ import annotations

import asyncio
import base64
import re
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable
from urllib.parse import quote

import httpx
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ConnectivityResult:
    ok: bool
    latency_ms: int | None = None
    message: str = ""
    default_branch: str | None = None


@dataclass
class PullRequestResult:
    """Outcome of a PR/MR creation attempt."""

    created: bool
    url: str | None
    number: int | None
    branch: str | None = None
    commit_sha: str | None = None
    message: str = ""


_GITHUB_REPO_RE = re.compile(
    r"^https?://(?:www\.)?(?P<host>[^/]+)/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$"
)


def parse_repo(url: str) -> tuple[str, str, str] | None:
    """Extract ``(host, owner, repo)`` from a git URL."""
    m = _GITHUB_REPO_RE.match(url.strip())
    if not m:
        return None
    return m.group("host"), m.group("owner"), m.group("repo")


def detect_provider(url: str) -> str:
    """Return ``'github'`` or ``'gitlab'`` based on the host."""
    parsed = parse_repo(url)
    if parsed is None:
        return "github"
    host = parsed[0].lower()
    if "gitlab" in host:
        return "gitlab"
    return "github"


@runtime_checkable
class SigmaWriteTransport(Protocol):
    name: str

    async def test_connectivity(self) -> ConnectivityResult: ...
    async def create_rule_pr(
        self,
        *,
        rule_path: str,
        rule_yaml: str,
        branch: str,
        commit_message: str,
        pr_title: str,
        pr_body: str,
        base_branch: str | None = None,
    ) -> PullRequestResult: ...
    async def aclose(self) -> None: ...


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------


class GitHubTransport:
    """Talks to the GitHub REST API for PR creation.

    Token-only auth (PAT or GitHub App installation token). No git CLI
    required in the container — every step is an HTTP call.
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
        parsed = parse_repo(url)
        if parsed is None:
            raise ValueError(f"Not a recognised git repo URL: {url!r}")
        _, self.owner, self.repo = parsed
        self.api_base = api_base.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._client = client
        self._owns_client = client is None

    def _headers(self) -> dict[str, str]:
        h = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "fragchain-sigma/0.1",
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True
            )
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

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
            data = resp.json()
            return ConnectivityResult(
                ok=True,
                latency_ms=latency,
                message="repo reachable",
                default_branch=data.get("default_branch"),
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

    async def create_rule_pr(
        self,
        *,
        rule_path: str,
        rule_yaml: str,
        branch: str,
        commit_message: str,
        pr_title: str,
        pr_body: str,
        base_branch: str | None = None,
    ) -> PullRequestResult:
        if not self.token:
            return PullRequestResult(
                created=False, url=None, number=None, branch=branch,
                message="auto_pr requires a token; configure auth_credentials_ref",
            )
        client = await self._http()
        headers = self._headers()
        repo_url = f"{self.api_base}/repos/{self.owner}/{self.repo}"

        base = base_branch
        if base is None:
            try:
                meta = await client.get(repo_url, headers=headers)
            except httpx.RequestError as exc:
                return PullRequestResult(
                    False, None, None, branch=branch, message=f"network: {exc}"
                )
            if meta.status_code != 200:
                return PullRequestResult(
                    False, None, None, branch=branch,
                    message=f"repo lookup http {meta.status_code}",
                )
            base = meta.json().get("default_branch") or "main"

        # Get head SHA of base
        try:
            ref_resp = await client.get(
                f"{repo_url}/git/refs/heads/{base}", headers=headers
            )
        except httpx.RequestError as exc:
            return PullRequestResult(
                False, None, None, branch=branch, message=f"network: {exc}"
            )
        if ref_resp.status_code != 200:
            return PullRequestResult(
                False, None, None, branch=branch,
                message=f"base ref lookup http {ref_resp.status_code}",
            )
        head_sha = ref_resp.json().get("object", {}).get("sha")
        if not head_sha:
            return PullRequestResult(
                False, None, None, branch=branch, message="no base sha"
            )

        # Create branch
        try:
            br_resp = await client.post(
                f"{repo_url}/git/refs",
                headers=headers,
                json={"ref": f"refs/heads/{branch}", "sha": head_sha},
            )
        except httpx.RequestError as exc:
            return PullRequestResult(
                False, None, None, branch=branch, message=f"network: {exc}"
            )
        if br_resp.status_code not in (200, 201, 422):
            return PullRequestResult(
                False, None, None, branch=branch,
                message=f"branch create http {br_resp.status_code}",
            )

        # Check if file exists to capture its SHA (PUT contents needs SHA on update)
        existing_sha = None
        try:
            ex = await client.get(
                f"{repo_url}/contents/{rule_path}",
                headers=headers,
                params={"ref": branch},
            )
            if ex.status_code == 200:
                existing_sha = ex.json().get("sha")
        except httpx.RequestError:
            existing_sha = None

        encoded = base64.b64encode(rule_yaml.encode("utf-8")).decode("ascii")
        put_body: dict[str, Any] = {
            "message": commit_message,
            "content": encoded,
            "branch": branch,
        }
        if existing_sha is not None:
            put_body["sha"] = existing_sha

        try:
            put_resp = await client.put(
                f"{repo_url}/contents/{rule_path}",
                headers=headers,
                json=put_body,
            )
        except httpx.RequestError as exc:
            return PullRequestResult(
                False, None, None, branch=branch, message=f"network: {exc}"
            )
        if put_resp.status_code not in (200, 201):
            return PullRequestResult(
                False, None, None, branch=branch,
                message=f"file commit http {put_resp.status_code}: {put_resp.text[:200]}",
            )
        commit_sha = put_resp.json().get("commit", {}).get("sha")

        # Open PR
        try:
            pr_resp = await client.post(
                f"{repo_url}/pulls",
                headers=headers,
                json={
                    "title": pr_title,
                    "head": branch,
                    "base": base,
                    "body": pr_body,
                },
            )
        except httpx.RequestError as exc:
            return PullRequestResult(
                False, None, None, branch=branch,
                commit_sha=commit_sha, message=f"network: {exc}",
            )
        if pr_resp.status_code not in (200, 201):
            return PullRequestResult(
                False, None, None, branch=branch,
                commit_sha=commit_sha,
                message=f"pr create http {pr_resp.status_code}: {pr_resp.text[:200]}",
            )
        pr_json = pr_resp.json()
        return PullRequestResult(
            created=True,
            url=pr_json.get("html_url"),
            number=pr_json.get("number"),
            branch=branch,
            commit_sha=commit_sha,
            message="ok",
        )


# ---------------------------------------------------------------------------
# GitLab
# ---------------------------------------------------------------------------


class GitLabTransport:
    """Talks to the GitLab REST API v4 for MR creation."""

    name = "gitlab"

    def __init__(
        self,
        url: str,
        *,
        token: str | None = None,
        api_base: str | None = None,
        timeout: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        parsed = parse_repo(url)
        if parsed is None:
            raise ValueError(f"Not a recognised git repo URL: {url!r}")
        host, self.owner, self.repo = parsed
        self.api_base = (api_base or f"https://{host}/api/v4").rstrip("/")
        self.token = token
        self.timeout = timeout
        self._client = client
        self._owns_client = client is None
        self.project_id = quote(f"{self.owner}/{self.repo}", safe="")

    def _headers(self) -> dict[str, str]:
        h = {
            "User-Agent": "fragchain-sigma/0.1",
            "Content-Type": "application/json",
        }
        if self.token:
            h["PRIVATE-TOKEN"] = self.token
        return h

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True
            )
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def test_connectivity(self) -> ConnectivityResult:
        client = await self._http()
        url = f"{self.api_base}/projects/{self.project_id}"
        started = asyncio.get_event_loop().time()
        try:
            resp = await client.get(url, headers=self._headers())
        except httpx.RequestError as exc:
            return ConnectivityResult(ok=False, message=f"network: {exc}")
        latency = int((asyncio.get_event_loop().time() - started) * 1000)
        if resp.status_code == 200:
            data = resp.json()
            return ConnectivityResult(
                ok=True,
                latency_ms=latency,
                message="project reachable",
                default_branch=data.get("default_branch"),
            )
        if resp.status_code == 404:
            return ConnectivityResult(
                ok=False, latency_ms=latency, message="project not found (404)"
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

    async def create_rule_pr(
        self,
        *,
        rule_path: str,
        rule_yaml: str,
        branch: str,
        commit_message: str,
        pr_title: str,
        pr_body: str,
        base_branch: str | None = None,
    ) -> PullRequestResult:
        if not self.token:
            return PullRequestResult(
                created=False, url=None, number=None, branch=branch,
                message="auto_pr requires a token; configure auth_credentials_ref",
            )
        client = await self._http()
        headers = self._headers()
        project = f"{self.api_base}/projects/{self.project_id}"

        base = base_branch
        if base is None:
            try:
                meta = await client.get(project, headers=headers)
            except httpx.RequestError as exc:
                return PullRequestResult(
                    False, None, None, branch=branch, message=f"network: {exc}"
                )
            if meta.status_code != 200:
                return PullRequestResult(
                    False, None, None, branch=branch,
                    message=f"project lookup http {meta.status_code}",
                )
            base = meta.json().get("default_branch") or "main"

        # Single commit-action call creates branch + file in one request.
        # action=create if new, action=update otherwise.
        action = "create"
        try:
            head = await client.get(
                f"{project}/repository/files/{quote(rule_path, safe='')}",
                headers=headers,
                params={"ref": base},
            )
            if head.status_code == 200:
                action = "update"
        except httpx.RequestError:
            action = "create"

        commit_body = {
            "branch": branch,
            "start_branch": base,
            "commit_message": commit_message,
            "actions": [
                {
                    "action": action,
                    "file_path": rule_path,
                    "content": rule_yaml,
                }
            ],
        }
        try:
            cm = await client.post(
                f"{project}/repository/commits",
                headers=headers,
                json=commit_body,
            )
        except httpx.RequestError as exc:
            return PullRequestResult(
                False, None, None, branch=branch, message=f"network: {exc}"
            )
        if cm.status_code not in (200, 201):
            return PullRequestResult(
                False, None, None, branch=branch,
                message=f"commit http {cm.status_code}: {cm.text[:200]}",
            )
        commit_sha = cm.json().get("id")

        # Open MR
        try:
            mr = await client.post(
                f"{project}/merge_requests",
                headers=headers,
                json={
                    "source_branch": branch,
                    "target_branch": base,
                    "title": pr_title,
                    "description": pr_body,
                    "remove_source_branch": True,
                },
            )
        except httpx.RequestError as exc:
            return PullRequestResult(
                False, None, None, branch=branch,
                commit_sha=commit_sha, message=f"network: {exc}",
            )
        if mr.status_code not in (200, 201):
            return PullRequestResult(
                False, None, None, branch=branch,
                commit_sha=commit_sha,
                message=f"mr create http {mr.status_code}: {mr.text[:200]}",
            )
        body = mr.json()
        return PullRequestResult(
            created=True,
            url=body.get("web_url"),
            number=body.get("iid"),
            branch=branch,
            commit_sha=commit_sha,
            message="ok",
        )


def build_transport(
    git_url: str,
    *,
    token: str | None = None,
    api_base: str | None = None,
) -> SigmaWriteTransport:
    """Construct a transport based on the target's ``git_url`` host."""
    provider = detect_provider(git_url)
    if provider == "gitlab":
        return GitLabTransport(git_url, token=token, api_base=api_base)
    base = api_base or "https://api.github.com"
    return GitHubTransport(git_url, token=token, api_base=base)


__all__ = [
    "ConnectivityResult",
    "GitHubTransport",
    "GitLabTransport",
    "PullRequestResult",
    "SigmaWriteTransport",
    "build_transport",
    "detect_provider",
    "parse_repo",
]
