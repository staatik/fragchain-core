"""F-012 / SAST S-005 — neutralize repo-supplied hooks on `git clone`.

`clone` itself does not execute repo hooks (hooks ship un-executable
until a `checkout` / `fetch` runs them), but `_sync_repo` issues a
subsequent fetch / checkout that can trigger `post-checkout` /
`post-merge` hooks shipped under `.githooks/` if the cloned repo has
`core.hooksPath = .githooks` in its config.

The fix: pass ``multi_options=["-c", "core.hooksPath=/dev/null", "-c",
"protocol.allow=user"]`` to every ``git.Repo.clone_from()`` so the
cloned working copy's git config has hooks pinned to nowhere and the
transport-allow list pinned to `user`.

Source-grep test, matching the same shape used for SAST S-020
(`tests/test_sigma_git_safe_flags.py`). The PR-C counter test already
ensures both safe-flag kwargs are present; this file extends the
contract to also require the `multi_options` line.
"""
from __future__ import annotations

from pathlib import Path


SOURCES_PATH = (
    Path(__file__).resolve().parent.parent / "fragchain" / "sigma" / "sources.py"
)


def test_every_clone_from_call_pins_hooks_path() -> None:
    """For every ``git.Repo.clone_from(...)`` call in
    ``fragchain/sigma/sources.py`` the source must explicitly include
    ``core.hooksPath=/dev/null`` in a ``multi_options=[...]`` slot.

    This is the F-012 / SAST S-005 regression guard. The counter-based
    structure mirrors ``test_sigma_git_safe_flags.py`` so a future
    clone site added without hook-neutralization fails noisily.
    """
    text = SOURCES_PATH.read_text()
    clone_calls = text.count("git.Repo.clone_from(")
    hook_pins = text.count("core.hooksPath=/dev/null")

    assert clone_calls > 0, (
        f"Expected at least one git.Repo.clone_from() in {SOURCES_PATH}; "
        f"got 0 (F-012 regression test can't find its target)"
    )
    assert hook_pins >= clone_calls, (
        f"Found {clone_calls} clone_from() calls but only {hook_pins} "
        f"include `core.hooksPath=/dev/null` in their multi_options. "
        f"Every clone site must neutralize repo-supplied hooks per "
        f"F-012 / SAST S-005."
    )


def test_every_clone_from_call_pins_protocol_allow() -> None:
    """Belt-and-suspenders alongside ``allow_unsafe_protocols=False``
    (which F-011 already pinned at every site): include
    ``-c protocol.allow=user`` in multi_options so the cloned working
    copy can't fall back to an unsafe transport via its own config.
    """
    text = SOURCES_PATH.read_text()
    clone_calls = text.count("git.Repo.clone_from(")
    protocol_pins = text.count("protocol.allow=user")

    assert protocol_pins >= clone_calls, (
        f"Found {clone_calls} clone_from() calls but only {protocol_pins} "
        f"include `protocol.allow=user` in their multi_options. "
        f"Every clone site must restrict allowed transports per "
        f"F-012 / SAST S-005."
    )
