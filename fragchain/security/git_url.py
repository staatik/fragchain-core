"""F-011 — git URL / branch / path validators (SAST S-009 + S-010 + S-019).

The original regex
``^https?://[^/\\s]+/[^/\\s]+/[^/\\s]+(?:\\.git)?/?$``
shipped in ``fragchain.api.routers.sigma`` and ``commons`` accepted:

* URLs with embedded credentials (``https://token@host/...``,
  ``https://user:pass@host/...``) — leaked tokens persisted in the DB,
  error strings, and UI display (S-009).
* SSRF candidate hosts (``localhost``, ``127.0.0.1``, RFC1918,
  link-local including AWS/GCP metadata at ``169.254.169.254``) — git
  clone from inside the Docker network reached internal services and
  cloud-metadata endpoints (S-010).

``branch`` and ``path_filter`` columns also went unvalidated past write
time — gitpython routes them through keyword API, so the practical
attack surface is narrower than the URL but the values still ended up
in subprocess argv and were the kind of input class a future gitpython
regression could turn into an option-injection (S-019).

This module is the single source of truth for all three validations.
Callers (router write paths, ``sigma/sources.py``, ``commons/sync.py``)
import the three ``validate_*`` helpers and raise
:class:`GitUrlValidationError` to refuse bad input.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


class GitUrlValidationError(ValueError):
    """Raised when a git URL, branch, or path_filter fails validation.

    Subclasses :class:`ValueError` so router validators that already
    catch ``ValueError`` produce 422s out of the box.
    """


# Hostname blocklist for SSRF prevention. Anything resolving to one of
# these names is refused — DNS resolution is intentionally NOT performed
# at validation time (a hostname that returns a public IP today might
# return a metadata IP tomorrow via DNS rebinding, but that's covered by
# the operator's network egress policy, not by this validator).
_BLOCKED_HOSTNAMES: frozenset[str] = frozenset(
    {
        "localhost",
        # AWS / GCP / Azure cloud metadata hostnames
        "metadata.google.internal",
        "metadata",
        "metadata.goog",
    }
)


# IP literals that are technically link-local (so caught by
# ``ip.is_link_local``) but listed explicitly because operator
# diagnostics benefit from a clearer error message.
_BLOCKED_METADATA_IPS: frozenset[str] = frozenset(
    {
        "169.254.169.254",  # AWS / GCP / Azure / DigitalOcean instance metadata
        "169.254.170.2",    # AWS ECS task metadata
    }
)


# Branch and path_filter shape: alphanumeric start, then allow
# dot, dash, underscore, slash. Capped at 255 chars to bound any
# downstream buffer. The leading-non-dash rule prevents git option
# injection (``git clone --branch=-u-payload.sh ...``).
_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
_PATH_FILTER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")


def _strip_host(host: str) -> str:
    """Normalize a host string by stripping brackets, port, and casing."""
    h = host.strip().lower()
    # IPv6 in brackets, with or without port
    if h.startswith("[") and "]" in h:
        h = h[1:].split("]")[0]
    elif h.count(":") == 1:
        # IPv4 with port (1.2.3.4:80) OR hostname with port (host:80) —
        # NOT bare IPv6 (which has multiple colons).
        h = h.split(":", 1)[0]
    return h


def is_safe_host(host: str) -> bool:
    """True iff ``host`` is a "public" host — not loopback / private /
    link-local / multicast / reserved / cloud-metadata.

    Hostnames that aren't IP literals get a literal-string blocklist
    check (covers ``localhost``, ``metadata.google.internal``) and
    otherwise pass — DNS-resolution is left to the egress firewall.
    """
    if not host:
        return False

    h = _strip_host(host)

    if h in _BLOCKED_HOSTNAMES:
        return False

    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        # Not an IP literal — trust the hostname (caller's egress policy
        # handles DNS rebinding).
        return True

    if str(ip) in _BLOCKED_METADATA_IPS:
        return False
    if (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False
    return True


def _classify_blocked_host(host: str) -> str:
    """Return a one-word reason explaining why ``host`` is blocked.

    Used to build operator-friendly error messages. ``is_safe_host``
    returning ``False`` doesn't tell the caller *why* — this fills in
    the gap without duplicating the classification.
    """
    h = _strip_host(host)
    if h in _BLOCKED_HOSTNAMES:
        return "metadata-or-localhost"
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return "blocked"
    if str(ip) in _BLOCKED_METADATA_IPS:
        return "metadata"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "private"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    return "blocked"


def validate_git_url(url: str, *, allow_non_https: bool = False) -> str:
    """Validate a git remote URL for use as sigma_sources.git_url,
    sigma_targets.git_url, or commons_sources.url.

    Raises :class:`GitUrlValidationError` on:

    * Embedded credentials (``https://token@host/...``) — SAST S-009.
      Only checked for http(s) schemes; ``ssh://git@host/...`` is the
      conventional SSH form and is allowed under ``allow_non_https``.
    * SSRF-candidate hosts (loopback, private, link-local, metadata) —
      SAST S-010.
    * Non-http(s) schemes — unless ``allow_non_https=True`` is set, in
      which case the caller has opted into CLAUDE.md §13's air-gapped /
      lab escape hatch (``SIGMA_ALLOW_NON_HTTPS=true``).
    * Malformed URLs (no host, no /owner/repo path shape) — under
      ``allow_non_https`` the path shape constraint is relaxed because
      git providers behind a private mirror can have unusual paths.

    Returns the validated URL unchanged so the helper can be used as a
    pydantic ``field_validator`` body.
    """
    if not isinstance(url, str) or not url.strip():
        raise GitUrlValidationError("url is required")

    parsed = urlparse(url)

    # Scheme: only http(s) by default; other schemes require operator opt-in.
    if parsed.scheme not in ("http", "https"):
        if not allow_non_https:
            raise GitUrlValidationError(
                f"url must use http:// or https:// (got scheme {parsed.scheme!r}); "
                f"set SIGMA_ALLOW_NON_HTTPS=true to allow ssh/file/git schemes"
            )

    # Embedded credentials check — only for http(s). ``ssh://git@host``
    # is conventional and the credential is the SSH key, not the URL.
    if parsed.scheme in ("http", "https"):
        if parsed.username is not None or parsed.password is not None:
            raise GitUrlValidationError(
                "url must not contain embedded credentials "
                "(user@ or user:pass@); store credentials in "
                "auth_credentials_ref instead"
            )

    host = parsed.hostname
    if not host:
        raise GitUrlValidationError("url must include a host")

    # /owner/repo shape (strict under default; relaxed under opt-in).
    if not allow_non_https:
        path = (parsed.path or "").strip("/")
        parts = [p for p in path.split("/") if p]
        if len(parts) != 2:
            raise GitUrlValidationError(
                f"url path must be of the form '/owner/repo' "
                f"(got {parsed.path!r})"
            )

    # SSRF check.
    if not is_safe_host(host):
        reason = _classify_blocked_host(host)
        raise GitUrlValidationError(
            f"url host {host!r} is not allowed ({reason}); "
            f"FragChain refuses internal / loopback / metadata hosts to prevent SSRF"
        )

    return url


def validate_git_branch(branch: str) -> str:
    """Validate a git branch name (passed to ``git clone --branch=``).

    Rejects shell metacharacters, leading dashes (git option injection),
    whitespace, newlines, and NUL bytes. Accepts canonical branch names
    like ``main``, ``master``, ``release/v1.0``, ``feature/F-011``.

    SAST S-019. Defense-in-depth: even with gitpython routing ``branch=``
    through its keyword API rather than positional argv, the value still
    reaches subprocess; an option-injection-shaped string is an
    unnecessary risk.
    """
    if not isinstance(branch, str) or not branch.strip():
        raise GitUrlValidationError("branch is required")

    if branch != branch.strip():
        raise GitUrlValidationError(
            "branch must not have leading or trailing whitespace"
        )

    if not _BRANCH_RE.match(branch):
        raise GitUrlValidationError(
            f"branch contains invalid characters or has unsafe form: {branch!r}; "
            f"allowed: alphanumeric, dot, dash, underscore, slash; "
            f"must not start with a dash or contain shell metacharacters"
        )

    return branch


def validate_git_path_filter(path: str | None) -> str | None:
    """Validate a path_filter (subpath inside a cloned repo).

    ``None`` / empty string is allowed (filter is optional and means
    "walk the entire repo"). When provided, the path must look like a
    relative subpath (``rules``, ``rules/linux``). Path traversal,
    absolute paths, shell metacharacters, and NUL bytes are rejected.
    """
    if path is None or path == "":
        return path

    if not isinstance(path, str):
        raise GitUrlValidationError("path_filter must be a string")

    if path != path.strip():
        raise GitUrlValidationError(
            "path_filter must not have leading or trailing whitespace"
        )

    if not _PATH_FILTER_RE.match(path):
        raise GitUrlValidationError(
            f"path_filter has unsafe form: {path!r}; "
            f"must be a relative subpath (e.g. 'rules' or 'rules/linux'); "
            f"absolute paths, '..' traversal, and shell metacharacters are forbidden"
        )

    # Reject '..' segments — the regex permits dots (for filenames like
    # ``.gitkeep``), so explicit segment-shape enforcement is needed to
    # block ``rules/../../etc/passwd``.
    segments = path.split("/")
    if any(seg == ".." or seg == "." for seg in segments):
        raise GitUrlValidationError(
            f"path_filter must not contain '..' or '.' segments: {path!r}"
        )

    return path


__all__ = [
    "GitUrlValidationError",
    "is_safe_host",
    "validate_git_branch",
    "validate_git_path_filter",
    "validate_git_url",
]
