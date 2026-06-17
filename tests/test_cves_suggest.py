"""Tests for the M23 catch-up ``GET /api/v1/cves/suggest`` endpoint.

Exercises the route handler directly with a fake AsyncSession. The
actual JSONB SQL is opaque to these tests (Postgres-only); the
contract under test is parameter validation, response shape, and
graceful degradation when the cache is unavailable or the DB
errors out.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from fragchain.api.routers import cves as cves_router
from fragchain.api.routers.cves import SuggestResponse, suggest_cves


class _FakeResult:
    def __init__(self, rows: list[tuple]) -> None:
        self._rows = rows

    def all(self) -> list[tuple]:
        return list(self._rows)


class _FakeSession:
    def __init__(
        self,
        rows: list[tuple] | None = None,
        *,
        raise_on_execute: bool = False,
    ) -> None:
        self.rows = rows or []
        self.raise_on_execute = raise_on_execute

    async def execute(self, _sql):  # noqa: ANN001 — opaque SQL clause
        if self.raise_on_execute:
            raise RuntimeError("synthetic db error")
        return _FakeResult(self.rows)


@pytest.fixture(autouse=True)
def _disable_redis(monkeypatch):
    """The autocomplete cache is Redis-backed. Tests run without Redis."""

    async def _none(_key):
        return None

    async def _noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(cves_router, "_suggest_cache_get", _none)
    monkeypatch.setattr(cves_router, "_suggest_cache_set", _noop)


@pytest.mark.asyncio
async def test_suggest_invalid_field_returns_422():
    db = _FakeSession()
    with pytest.raises(HTTPException) as info:
        await suggest_cves(field="company", q="acme", limit=10, db=db, _user=None)
    assert info.value.status_code == 422
    assert "vendor" in info.value.detail.lower()


@pytest.mark.asyncio
async def test_suggest_happy_path_returns_ordered_suggestions():
    # The SQL is opaque to the fake session; we hand it the rows it would
    # return for q="mic" in the canonical case and assert the route
    # preserves order (most-common first).
    db = _FakeSession(rows=[("microsoft", 12), ("micro_focus", 3)])
    resp = await suggest_cves(field="vendor", q="mic", limit=10, db=db, _user=None)
    assert isinstance(resp, SuggestResponse)
    assert resp.suggestions == ["microsoft", "micro_focus"]


@pytest.mark.asyncio
async def test_suggest_empty_result_returns_empty_list():
    db = _FakeSession(rows=[])
    resp = await suggest_cves(field="product", q="nothing", limit=5, db=db, _user=None)
    assert resp.suggestions == []


@pytest.mark.asyncio
async def test_suggest_db_failure_degrades_gracefully():
    db = _FakeSession(raise_on_execute=True)
    resp = await suggest_cves(field="vendor", q="x", limit=10, db=db, _user=None)
    assert resp.suggestions == []


@pytest.mark.asyncio
async def test_suggest_drops_null_rows():
    db = _FakeSession(rows=[("kernel", 5), (None, 1), ("kerberos", 2)])
    resp = await suggest_cves(field="product", q="ke", limit=10, db=db, _user=None)
    assert resp.suggestions == ["kernel", "kerberos"]
