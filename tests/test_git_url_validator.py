"""F-011 / SAST S-004 + S-009 + S-010 + S-019 — git URL/branch/path validators.

The previous regex (`^https?://[^/\s]+/[^/\s]+/[^/\s]+(?:\.git)?/?$`)
accepted:

* URLs with embedded credentials (``https://token@host/...``,
  ``https://user:pass@host/...``) — token leakage via persisted URL,
  error strings, and UI display (S-009).
* SSRF candidate hosts (``localhost``, ``127.0.0.1``, ``[::1]``,
  ``169.254.169.254``, ``metadata.google.internal``) — `git clone` from
  inside the Docker network reaches cloud-metadata endpoints (S-010).

Branch + path_filter passed straight through to gitpython without
validation (S-019).

This file covers the new validator module
``fragchain.security.git_url``.
"""
from __future__ import annotations

import pytest

from fragchain.security.git_url import (
    GitUrlValidationError,
    is_safe_host,
    validate_git_branch,
    validate_git_path_filter,
    validate_git_url,
)


# ---------------------------------------------------------------------------
# validate_git_url — accept
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/SigmaHQ/sigma",
        "https://github.com/SigmaHQ/sigma.git",
        "https://github.com/SigmaHQ/sigma/",
        "http://gitea.example.com/team/repo",
        "https://gitlab.com/owner/project.git",
    ],
)
def test_validate_git_url_accepts_canonical_forms(url: str) -> None:
    assert validate_git_url(url) == url


# ---------------------------------------------------------------------------
# validate_git_url — reject (S-009): embedded credentials
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://token@github.com/owner/repo",
        "https://user:pass@github.com/owner/repo",
        "https://oauth2:gho_xxx@github.com/owner/repo",
        "https://x-access-token:abc@gitlab.example/owner/repo",
    ],
)
def test_validate_git_url_rejects_embedded_credentials(url: str) -> None:
    with pytest.raises(GitUrlValidationError, match="credentials"):
        validate_git_url(url)


# ---------------------------------------------------------------------------
# validate_git_url — reject (S-010): SSRF candidate hosts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        # Loopback (literal IPv4)
        "https://127.0.0.1/owner/repo",
        "https://127.5.5.5/owner/repo",
        # IPv6 loopback
        "https://[::1]/owner/repo",
        # localhost name
        "https://localhost/owner/repo",
        "http://localhost:8080/owner/repo",
        # AWS cloud metadata
        "https://169.254.169.254/owner/repo",
        # AWS ECS task metadata
        "https://169.254.170.2/owner/repo",
        # GCP metadata service hostname
        "https://metadata.google.internal/owner/repo",
        # RFC1918 private ranges
        "https://10.0.0.5/owner/repo",
        "https://10.255.255.255/owner/repo",
        "https://172.16.0.1/owner/repo",
        "https://172.31.255.254/owner/repo",
        "https://192.168.1.1/owner/repo",
    ],
)
def test_validate_git_url_rejects_ssrf_candidate_hosts(url: str) -> None:
    with pytest.raises(GitUrlValidationError, match=r"(?:private|loopback|link-local|metadata)"):
        validate_git_url(url)


# ---------------------------------------------------------------------------
# validate_git_url — reject (existing F-007-ish): non-http schemes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ssh://git@github.com/owner/repo",
        "git://github.com/owner/repo",
        "javascript:alert(1)",
        "gopher://example.com/",
        "ftp://example.com/repo",
    ],
)
def test_validate_git_url_rejects_non_http_schemes(url: str) -> None:
    with pytest.raises(GitUrlValidationError):
        validate_git_url(url)


def test_validate_git_url_accepts_non_http_when_explicit_opt_in() -> None:
    """``allow_non_https=True`` opts into the air-gapped / lab path
    (CLAUDE.md §13's SIGMA_ALLOW_NON_HTTPS escape hatch). Even so, the
    credentials + SSRF gates still apply.
    """
    assert (
        validate_git_url("ssh://git@github.example.com/owner/repo", allow_non_https=True)
        == "ssh://git@github.example.com/owner/repo"
    )


def test_validate_git_url_with_opt_in_still_rejects_loopback_and_creds() -> None:
    """SIGMA_ALLOW_NON_HTTPS opens schemes, NOT SSRF + credential paths."""
    with pytest.raises(GitUrlValidationError, match="(?:loopback|private)"):
        validate_git_url("ssh://127.0.0.1/owner/repo", allow_non_https=True)
    # ssh:// canonical-form lets us put credentials only as user@; we
    # accept that form under opt-in (it's the legitimate ssh-key path).
    # The check is HTTPS-scheme-credential injection — covered above.


# ---------------------------------------------------------------------------
# validate_git_url — malformed / empty
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "not-a-url",
        "https://",
        "https://host",
        "https://host/onlyone",
    ],
)
def test_validate_git_url_rejects_malformed(url: str) -> None:
    with pytest.raises(GitUrlValidationError):
        validate_git_url(url)


# ---------------------------------------------------------------------------
# is_safe_host — the SSRF blocklist primitive
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "github.com",
        "gitlab.com",
        "gitea.example.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
    ],
)
def test_is_safe_host_public(host: str) -> None:
    assert is_safe_host(host) is True


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "127.0.0.1",
        "[::1]",
        "::1",
        "169.254.169.254",
        "169.254.170.2",
        "metadata.google.internal",
        "10.0.0.1",
        "192.168.0.1",
        "172.16.0.1",
        "0.0.0.0",
    ],
)
def test_is_safe_host_blocks_internal(host: str) -> None:
    assert is_safe_host(host) is False


# ---------------------------------------------------------------------------
# validate_git_branch — S-019
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "branch",
    ["main", "master", "release/v1.0", "feature/F-011", "fix-123", "v2.0.1"],
)
def test_validate_git_branch_accepts_canonical_forms(branch: str) -> None:
    assert validate_git_branch(branch) == branch


@pytest.mark.parametrize(
    "branch",
    [
        # Shell metacharacters
        "main; rm -rf /",
        "main$(cat /etc/passwd)",
        "main`whoami`",
        "main && echo pwned",
        "main | sh",
        # Leading dash — git option injection surface
        "--upload-pack=evil.sh",
        "-q",
        # Whitespace / newlines
        "main\nsecond",
        "main with spaces",
        "main\t",
        # Empty / whitespace
        "",
        " ",
        # NUL byte
        "main\x00",
    ],
)
def test_validate_git_branch_rejects_unsafe(branch: str) -> None:
    with pytest.raises(GitUrlValidationError):
        validate_git_branch(branch)


# ---------------------------------------------------------------------------
# validate_git_path_filter
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        None,  # absent path_filter is fine
        "rules",
        "rules/linux",
        "rules-windows-sysmon",
        "rules/windows/sysmon",
    ],
)
def test_validate_git_path_filter_accepts_canonical_forms(path: str | None) -> None:
    assert validate_git_path_filter(path) == path


@pytest.mark.parametrize(
    "path",
    [
        "../etc/passwd",
        "../../",
        "/absolute",
        "rules/../../",
        "rules$(cat /etc/passwd)",
        "rules;rm -rf /",
        "rules\nsecond",
        "rules\x00",
    ],
)
def test_validate_git_path_filter_rejects_unsafe(path: str) -> None:
    with pytest.raises(GitUrlValidationError):
        validate_git_path_filter(path)
