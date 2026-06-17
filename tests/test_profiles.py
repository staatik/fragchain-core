"""M13 — Logsource profiles tests.

Covers:

* ``ProfileStore.build_prompt_context`` shape — confirms the dict
  contract M15 will consume.
* Platform validation in ``create_custom`` / ``update_custom``.
* All seven built-in profile specs in ``scripts/seed_profiles.py``:
  default-enabled set, required field shapes, at least two example
  rules per profile, valid platform.
* Built-in-immutable rejection in ``update_custom`` / ``delete_custom``.
* Idempotent ``upsert_builtin`` behavior — created / unchanged /
  updated paths, and the operator-preference invariant (re-seeding
  never flips ``enabled``).

Pure-Python: no real Postgres. ``ProfileStore`` is exercised against a
minimal in-memory async fake session that handles only the operations
the store actually issues (``select`` filtered by name, ``get`` by PK,
``add`` / ``flush`` / ``delete``). JSONB / ARRAY / UUID-aware
integration tests live outside the unit layer.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from fragchain.profiles import (
    BuiltinProfileImmutableError,
    ProfileNotFoundError,
    ProfileStore,
    ProfileView,
    VALID_PLATFORMS,
)
from scripts.seed_profiles import BUILTIN_PROFILES


# ---------------------------------------------------------------------------
# Fake row + session
# ---------------------------------------------------------------------------


class FakeProfileRow:
    """Stand-in for a LogsourceProfile ORM row.

    Mutates the same attributes the store reads/writes; nothing else is
    exercised through the fake.
    """

    def __init__(
        self,
        *,
        name: str,
        display_name: str,
        platform: str,
        description: str | None = None,
        sigma_product: str | None = None,
        sigma_service: str | None = None,
        field_conventions: dict[str, Any] | None = None,
        example_rules: list[Any] | None = None,
        enabled: bool = True,
        is_builtin: bool = False,
        id: uuid.UUID | None = None,
    ) -> None:
        self.id = id or uuid.uuid4()
        self.name = name
        self.display_name = display_name
        self.platform = platform
        self.description = description
        self.sigma_product = sigma_product
        self.sigma_service = sigma_service
        self.field_conventions = dict(field_conventions or {})
        self.example_rules = list(example_rules or [])
        self.enabled = enabled
        self.is_builtin = is_builtin
        self.created_at = datetime.now(tz=timezone.utc)
        self.updated_at = self.created_at


class FakeResult:
    def __init__(self, rows: list[Any]):
        self._rows = rows

    def scalar_one_or_none(self) -> Any:
        return self._rows[0] if self._rows else None

    def scalars(self) -> "FakeResult":
        return self

    def all(self) -> list[Any]:
        return list(self._rows)


class FakeProfileSession:
    """In-memory async session sufficient for ProfileStore unit tests.

    The store issues three kinds of queries:

      1. ``session.get(LogsourceProfile, uuid)`` — primary-key lookup.
      2. ``select(LogsourceProfile).where(name == ...)`` — by-name lookup.
      3. ``select(LogsourceProfile).where(enabled.is_(True)).order_by(...)``
         and ``select(LogsourceProfile).order_by(...)`` — list queries.

    We pattern-match on the where-clause text and ignore ORDER BY so
    the fake stays small.
    """

    def __init__(self) -> None:
        from fragchain.db.models import LogsourceProfile

        self._model_cls = LogsourceProfile
        self.rows: list[FakeProfileRow] = []
        self.flushes = 0
        self.deletes = 0

    def add(self, obj: Any) -> None:
        if isinstance(obj, self._model_cls):
            # Real ORM instance — coerce to FakeProfileRow.
            self.rows.append(
                FakeProfileRow(
                    name=obj.name,
                    display_name=obj.display_name,
                    platform=obj.platform,
                    description=obj.description,
                    sigma_product=obj.sigma_product,
                    sigma_service=obj.sigma_service,
                    field_conventions=obj.field_conventions,
                    example_rules=obj.example_rules,
                    enabled=obj.enabled,
                    is_builtin=obj.is_builtin,
                )
            )
        elif isinstance(obj, FakeProfileRow):
            self.rows.append(obj)

    async def flush(self) -> None:
        self.flushes += 1

    async def refresh(self, obj: Any) -> None:
        # No-op: our fake rows are already coherent post-add.
        return

    async def commit(self) -> None:
        return

    async def rollback(self) -> None:
        return

    async def delete(self, obj: Any) -> None:
        self.rows = [r for r in self.rows if r.id != obj.id]
        self.deletes += 1

    async def get(self, model: Any, ident: Any) -> Any:
        if model is self._model_cls:
            for row in self.rows:
                if row.id == ident:
                    return row
        return None

    async def execute(self, stmt: Any) -> FakeResult:
        from sqlalchemy.sql import Select

        if not isinstance(stmt, Select):
            return FakeResult([])

        rows = list(self.rows)

        where = stmt.whereclause
        if where is not None:
            text = str(where)
            # name == 'foo'
            if "logsource_profiles.name" in text:
                literal = _extract_literal(where, attr_name="name")
                if literal is not None:
                    rows = [r for r in rows if r.name == literal]
            # enabled IS true
            if "logsource_profiles.enabled" in text and "IS true" in text:
                rows = [r for r in rows if r.enabled is True]
        return FakeResult(rows)


def _extract_literal(clause: Any, *, attr_name: str) -> Any:
    """Best-effort pull of the right-hand bind value from a comparison clause."""
    cls = clause.__class__.__name__
    if cls == "BooleanClauseList":
        for child in clause.clauses:
            value = _extract_literal(child, attr_name=attr_name)
            if value is not None:
                return value
        return None
    if cls == "BinaryExpression":
        left_key = getattr(clause.left, "key", None) or getattr(
            clause.left, "name", None
        )
        if left_key != attr_name:
            return None
        right = clause.right
        return getattr(right, "value", None)
    return None


# ---------------------------------------------------------------------------
# build_prompt_context shape
# ---------------------------------------------------------------------------


def test_build_prompt_context_returns_stable_shape():
    view = ProfileView(
        id=uuid.uuid4(),
        name="linux-auditd",
        display_name="Linux auditd",
        description="kernel audit",
        platform="linux",
        sigma_product="linux",
        sigma_service="auditd",
        field_conventions={"exe": "binary path", "uid": "user id"},
        example_rules=[
            {"title": "ex1", "yaml": "...", "explanation": "..."},
        ],
        enabled=True,
        is_builtin=True,
    )
    ctx = ProfileStore.build_prompt_context(view)
    assert ctx["name"] == "linux-auditd"
    assert ctx["display_name"] == "Linux auditd"
    assert ctx["platform"] == "linux"
    assert ctx["logsource"] == {"product": "linux", "service": "auditd"}
    assert ctx["field_conventions"] == {"exe": "binary path", "uid": "user id"}
    assert isinstance(ctx["example_rules"], list)
    assert len(ctx["example_rules"]) == 1


def test_build_prompt_context_handles_null_product_service():
    view = ProfileView(
        id=uuid.uuid4(),
        name="custom",
        display_name="Custom",
        description=None,
        platform="cloud",
        sigma_product=None,
        sigma_service=None,
    )
    ctx = ProfileStore.build_prompt_context(view)
    assert ctx["logsource"] == {"product": None, "service": None}
    assert ctx["field_conventions"] == {}
    assert ctx["example_rules"] == []


def test_build_prompt_context_returns_independent_copies():
    """The prompt builder shouldn't be able to mutate the source view's data."""
    view = ProfileView(
        id=uuid.uuid4(),
        name="x",
        display_name="X",
        description=None,
        platform="linux",
        sigma_product="linux",
        sigma_service="auditd",
        field_conventions={"a": "1"},
        example_rules=[{"title": "t"}],
    )
    ctx = ProfileStore.build_prompt_context(view)
    ctx["field_conventions"]["b"] = "2"
    ctx["example_rules"].append({"title": "u"})
    assert "b" not in view.field_conventions
    assert len(view.example_rules) == 1


# ---------------------------------------------------------------------------
# Built-in profile data validation
# ---------------------------------------------------------------------------


def test_seven_builtin_profiles_present():
    names = {p["name"] for p in BUILTIN_PROFILES}
    assert names == {
        "linux-auditd",
        "linux-sysmon",
        "linux-falco",
        "windows-security",
        "windows-sysmon",
        "network-zeek",
        "network-suricata",
    }


def test_default_enabled_set_is_linux_auditd_and_windows_security():
    enabled_names = {
        p["name"] for p in BUILTIN_PROFILES if p.get("default_enabled")
    }
    assert enabled_names == {"linux-auditd", "windows-security"}


def test_every_builtin_has_valid_platform():
    for p in BUILTIN_PROFILES:
        assert p["platform"] in VALID_PLATFORMS, p["name"]


def test_every_builtin_has_at_least_two_example_rules():
    for p in BUILTIN_PROFILES:
        examples = p["example_rules"]
        assert len(examples) >= 2, p["name"]
        for ex in examples:
            assert "title" in ex
            assert "yaml" in ex
            assert "explanation" in ex
            assert "logsource:" in ex["yaml"], p["name"]


def test_every_builtin_has_field_conventions():
    for p in BUILTIN_PROFILES:
        fc = p["field_conventions"]
        assert isinstance(fc, dict)
        assert fc, p["name"]  # non-empty
        for key, val in fc.items():
            assert isinstance(key, str)
            assert isinstance(val, str)


def test_every_builtin_has_unique_name():
    names = [p["name"] for p in BUILTIN_PROFILES]
    assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# ProfileStore — async unit tests against the fake session
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_custom_persists_row_with_is_builtin_false():
    session = FakeProfileSession()
    store = ProfileStore(session)
    view = await store.create_custom(
        name="my-profile",
        display_name="My Profile",
        platform="linux",
        sigma_product="linux",
        sigma_service="custom",
        field_conventions={"a": "b"},
        example_rules=[{"title": "t", "yaml": "logsource:\n", "explanation": "x"}],
    )
    assert view.is_builtin is False
    assert view.name == "my-profile"
    assert view.platform == "linux"
    assert len(session.rows) == 1
    assert session.rows[0].is_builtin is False


@pytest.mark.asyncio
async def test_create_custom_rejects_bad_platform():
    session = FakeProfileSession()
    store = ProfileStore(session)
    with pytest.raises(ValueError):
        await store.create_custom(
            name="bad",
            display_name="Bad",
            platform="mainframe",
        )


@pytest.mark.asyncio
async def test_update_custom_modifies_fields():
    session = FakeProfileSession()
    seed = FakeProfileRow(
        name="my-profile",
        display_name="Old",
        platform="linux",
        sigma_product="linux",
        sigma_service="auditd",
    )
    session.rows.append(seed)
    store = ProfileStore(session)
    view = await store.update_custom(
        "my-profile",
        display_name="New",
        sigma_service="auditd-v2",
    )
    assert view.display_name == "New"
    assert view.sigma_service == "auditd-v2"


@pytest.mark.asyncio
async def test_update_custom_rejects_builtin_with_immutable_error():
    session = FakeProfileSession()
    seed = FakeProfileRow(
        name="linux-auditd",
        display_name="Linux auditd",
        platform="linux",
        is_builtin=True,
    )
    session.rows.append(seed)
    store = ProfileStore(session)
    with pytest.raises(BuiltinProfileImmutableError):
        await store.update_custom("linux-auditd", display_name="hacked")


@pytest.mark.asyncio
async def test_update_custom_raises_not_found():
    session = FakeProfileSession()
    store = ProfileStore(session)
    with pytest.raises(ProfileNotFoundError):
        await store.update_custom("ghost", display_name="x")


@pytest.mark.asyncio
async def test_set_enabled_flips_builtin_flag():
    """Operators can disable a built-in via set_enabled (the only allowed mutation)."""
    session = FakeProfileSession()
    seed = FakeProfileRow(
        name="windows-security",
        display_name="Windows Security",
        platform="windows",
        is_builtin=True,
        enabled=True,
    )
    session.rows.append(seed)
    store = ProfileStore(session)
    view = await store.set_enabled("windows-security", enabled=False)
    assert view.enabled is False
    assert view.is_builtin is True  # unchanged


@pytest.mark.asyncio
async def test_set_enabled_no_op_when_already_at_target_state():
    session = FakeProfileSession()
    seed = FakeProfileRow(
        name="x",
        display_name="X",
        platform="linux",
        enabled=True,
    )
    session.rows.append(seed)
    store = ProfileStore(session)
    before_flushes = session.flushes
    view = await store.set_enabled("x", enabled=True)
    assert view.enabled is True
    assert session.flushes == before_flushes


@pytest.mark.asyncio
async def test_delete_custom_rejects_builtin():
    session = FakeProfileSession()
    seed = FakeProfileRow(
        name="linux-auditd",
        display_name="Linux auditd",
        platform="linux",
        is_builtin=True,
    )
    session.rows.append(seed)
    store = ProfileStore(session)
    with pytest.raises(BuiltinProfileImmutableError):
        await store.delete_custom("linux-auditd")
    assert len(session.rows) == 1


@pytest.mark.asyncio
async def test_delete_custom_removes_non_builtin():
    session = FakeProfileSession()
    seed = FakeProfileRow(
        name="my-profile",
        display_name="My Profile",
        platform="linux",
        is_builtin=False,
    )
    session.rows.append(seed)
    store = ProfileStore(session)
    await store.delete_custom("my-profile")
    assert session.rows == []
    assert session.deletes == 1


@pytest.mark.asyncio
async def test_get_enabled_returns_only_enabled():
    session = FakeProfileSession()
    session.rows.extend(
        [
            FakeProfileRow(
                name="a",
                display_name="A",
                platform="linux",
                enabled=True,
            ),
            FakeProfileRow(
                name="b",
                display_name="B",
                platform="windows",
                enabled=False,
            ),
            FakeProfileRow(
                name="c",
                display_name="C",
                platform="network",
                enabled=True,
            ),
        ]
    )
    store = ProfileStore(session)
    enabled = await store.get_enabled()
    names = {v.name for v in enabled}
    assert names == {"a", "c"}


@pytest.mark.asyncio
async def test_get_by_name_returns_view():
    session = FakeProfileSession()
    seed = FakeProfileRow(
        name="linux-auditd",
        display_name="Linux auditd",
        platform="linux",
        is_builtin=True,
    )
    session.rows.append(seed)
    store = ProfileStore(session)
    view = await store.get("linux-auditd")
    assert view.name == "linux-auditd"
    assert view.is_builtin is True


# ---------------------------------------------------------------------------
# upsert_builtin idempotency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upsert_builtin_creates_when_absent():
    session = FakeProfileSession()
    store = ProfileStore(session)
    state, view = await store.upsert_builtin(
        name="linux-auditd",
        display_name="Linux auditd",
        platform="linux",
        description="kernel audit",
        sigma_product="linux",
        sigma_service="auditd",
        field_conventions={"exe": "path"},
        example_rules=[{"title": "t", "yaml": "logsource:\n", "explanation": "x"}],
        default_enabled=True,
    )
    assert state == "created"
    assert view.is_builtin is True
    assert view.enabled is True


@pytest.mark.asyncio
async def test_upsert_builtin_reports_unchanged_on_re_run():
    session = FakeProfileSession()
    store = ProfileStore(session)
    kwargs: dict[str, Any] = dict(
        name="linux-auditd",
        display_name="Linux auditd",
        platform="linux",
        description="kernel audit",
        sigma_product="linux",
        sigma_service="auditd",
        field_conventions={"exe": "path"},
        example_rules=[{"title": "t", "yaml": "logsource:\n", "explanation": "x"}],
        default_enabled=True,
    )
    await store.upsert_builtin(**kwargs)
    state, _ = await store.upsert_builtin(**kwargs)
    assert state == "unchanged"


@pytest.mark.asyncio
async def test_upsert_builtin_reports_updated_when_body_changes():
    session = FakeProfileSession()
    store = ProfileStore(session)
    kwargs: dict[str, Any] = dict(
        name="linux-auditd",
        display_name="Linux auditd",
        platform="linux",
        description="kernel audit",
        sigma_product="linux",
        sigma_service="auditd",
        field_conventions={"exe": "path"},
        example_rules=[{"title": "t", "yaml": "logsource:\n", "explanation": "x"}],
        default_enabled=True,
    )
    await store.upsert_builtin(**kwargs)
    kwargs2 = dict(kwargs)
    kwargs2["description"] = "kernel audit subsystem"
    state, _ = await store.upsert_builtin(**kwargs2)
    assert state == "updated"


@pytest.mark.asyncio
async def test_upsert_builtin_never_flips_existing_enabled_flag():
    """Operator preference wins over default_enabled on re-seed."""
    session = FakeProfileSession()
    seed = FakeProfileRow(
        name="windows-security",
        display_name="Windows Security",
        platform="windows",
        sigma_product="windows",
        sigma_service="security",
        description="native",
        field_conventions={"EventID": "..."},
        example_rules=[{"title": "t", "yaml": "logsource:\n", "explanation": "x"}],
        enabled=False,  # operator turned it off
        is_builtin=True,
    )
    session.rows.append(seed)
    store = ProfileStore(session)
    state, view = await store.upsert_builtin(
        name="windows-security",
        display_name="Windows Security",
        platform="windows",
        description="native",
        sigma_product="windows",
        sigma_service="security",
        field_conventions={"EventID": "..."},
        example_rules=[{"title": "t", "yaml": "logsource:\n", "explanation": "x"}],
        default_enabled=True,  # built-in defaults to enabled, but operator preference wins
    )
    assert state == "unchanged"
    assert view.enabled is False
