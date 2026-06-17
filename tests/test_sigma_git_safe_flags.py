"""F-011 / SAST S-020 — gitpython clone calls pin safe defaults.

Recent gitpython defaults ``allow_unsafe_options=False`` (since 3.1.31)
and ``allow_unsafe_protocols=False`` (since 3.1.42). The project doesn't
pin gitpython explicitly (CLAUDE.md POC review D1.4-F2 "deps use `>=`,
not pinned"), so a future drift could re-enable
``--upload-pack=<script>`` / ``ext::<cmd>``. F-011 makes the safe flags
explicit at every call site.

This file verifies the kwargs are passed by reading the source — the
clone path is not exercised by the real gitpython at test time because
the local venv doesn't have all the build deps (and the real call
would require a live remote). Source-grep is the appropriate test
here: the only way it can regress is by deleting the explicit kwargs,
which the grep catches.
"""
from __future__ import annotations

from pathlib import Path

# Path to the sources module under test, relative to repo root.
SOURCES_PATH = (
    Path(__file__).resolve().parent.parent / "fragchain" / "sigma" / "sources.py"
)


def _count_clone_from_calls() -> int:
    """How many ``git.Repo.clone_from`` invocations live in sources.py.

    Tracked separately so a future PR adding a third clone site sees the
    test failure rather than silently inheriting whatever defaults the
    installed gitpython version provides.
    """
    text = SOURCES_PATH.read_text()
    return text.count("git.Repo.clone_from(")


def test_every_clone_from_call_pins_safe_flags() -> None:
    """For every ``git.Repo.clone_from(...)`` call in
    ``fragchain/sigma/sources.py`` the source must explicitly pass both
    ``allow_unsafe_options=False`` and ``allow_unsafe_protocols=False``.

    Counting strategy: count call sites, count flag passes, compare. A
    future call site that forgets the flags will trip the count
    mismatch.
    """
    text = SOURCES_PATH.read_text()
    clone_calls = text.count("git.Repo.clone_from(")
    options_pins = text.count("allow_unsafe_options=False")
    protocols_pins = text.count("allow_unsafe_protocols=False")

    assert clone_calls > 0, (
        "Expected at least one git.Repo.clone_from() call in "
        f"{SOURCES_PATH}; got 0 (the SAST S-020 regression test is "
        "looking for the real call site)"
    )
    assert options_pins == clone_calls, (
        f"Found {clone_calls} clone_from() calls but only {options_pins} "
        f"pass allow_unsafe_options=False — every call site must pin "
        f"the safe flag explicitly per F-011 / SAST S-020"
    )
    assert protocols_pins == clone_calls, (
        f"Found {clone_calls} clone_from() calls but only {protocols_pins} "
        f"pass allow_unsafe_protocols=False — every call site must pin "
        f"the safe flag explicitly per F-011 / SAST S-020"
    )


def test_sources_count_matches_known_layout() -> None:
    """Sanity guard: if the file structure changes (a new clone site
    added, an old one removed), the test above's coverage assumption
    needs updating too. Bump this number deliberately when you change
    the layout — a hidden change is the regression we're guarding
    against.
    """
    expected = 2  # primary + fallback (no-branch) in sigma/sources.py
    actual = _count_clone_from_calls()
    assert actual == expected, (
        f"sigma/sources.py has {actual} clone_from() call(s); the F-011 "
        f"safety test was written assuming {expected}. If you intentionally "
        f"added or removed a clone path, update this counter."
    )
