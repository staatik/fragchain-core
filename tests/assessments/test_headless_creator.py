"""Creator-resolution + guard for the headless trigger (W3a-1 bug fix).

The headless CLI used to default ``creator_id`` to ``uuid.uuid4()`` — a
phantom id with no ``users`` row. ``coverage_assessment.creator_id`` is not a
FK, so creation succeeded, but the first ``audit_log.actor`` write during loop
execution hit the FK to ``users`` and failed the run deep in the worker.

The fix: ``auto_assess`` guards an unknown creator up front (no work, clear
``rejected_unknown_creator``), and ``resolve_default_operator_id`` lets the CLI
default to a real operator (the configured admin, else any user) instead of a
random uuid.
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from fragchain.assessments.headless import (
    HeadlessSource,
    auto_assess,
    resolve_default_operator_id,
)
from fragchain.config import get_settings
from fragchain.db.models import Base, User


def _src(content="x" * 1000, title="t"):
    return HeadlessSource(title=title, content=content)


@pytest.fixture
async def user_session():
    """In-memory SQLite session with only the ``users`` table."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(
            lambda c: Base.metadata.create_all(c, tables=[User.__table__])
        )
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        yield s
    await engine.dispose()


async def _seed_user(session, username: str) -> uuid.UUID:
    u = User(
        username=username,
        email=f"{username}@example.test",
        hashed_password="x",
        tier="authenticated",
        clearance_level="tlp:green",
    )
    session.add(u)
    await session.commit()
    await session.refresh(u)
    return u.id


def _mock_services():
    asmt = MagicMock()
    asmt.id = uuid.uuid4()
    svc = MagicMock()
    svc.create = AsyncMock(return_value=asmt)
    svc.set_auto_advance = AsyncMock()
    src_svc = MagicMock()
    src_svc.create = AsyncMock()
    run = MagicMock()
    run.id = uuid.uuid4()
    orch = MagicMock()
    orch.begin_run = AsyncMock(return_value=run)
    return asmt, svc, src_svc, orch


@pytest.mark.asyncio
async def test_auto_assess_rejects_unknown_creator(user_session):
    """A creator_id with no users row stops before any write."""
    await _seed_user(user_session, "realop")
    _, svc, src_svc, orch = _mock_services()
    with patch("fragchain.assessments.headless.AssessmentService", return_value=svc), \
         patch("fragchain.assessments.headless.SourceService", return_value=src_svc), \
         patch("fragchain.assessments.headless.build_orchestrator", return_value=orch):
        result = await auto_assess(
            user_session,
            cve_id=uuid.uuid4(),
            cve_textual_id="CVE-2024-0001",
            sources=[_src()],
            creator_id=uuid.uuid4(),  # phantom — not the seeded user
            dispatch=lambda rid: None,
        )
    assert result.status == "rejected_unknown_creator"
    assert result.assessment_id is None
    svc.create.assert_not_awaited()
    orch.begin_run.assert_not_awaited()


@pytest.mark.asyncio
async def test_auto_assess_proceeds_for_known_creator(user_session):
    """A real users row passes the guard and dispatches Loop 1."""
    creator = await _seed_user(user_session, "realop")
    asmt, svc, src_svc, orch = _mock_services()
    dispatched = {}
    with patch("fragchain.assessments.headless.AssessmentService", return_value=svc), \
         patch("fragchain.assessments.headless.SourceService", return_value=src_svc), \
         patch("fragchain.assessments.headless.build_orchestrator", return_value=orch):
        result = await auto_assess(
            user_session,
            cve_id=uuid.uuid4(),
            cve_textual_id="CVE-2024-0001",
            sources=[_src()],
            creator_id=creator,
            dispatch=lambda rid: dispatched.setdefault("rid", rid),
        )
    assert result.status == "started"
    svc.create.assert_awaited_once()
    assert dispatched["rid"] == str(orch.begin_run.return_value.id)


@pytest.mark.asyncio
async def test_resolve_default_operator_prefers_admin(user_session):
    admin_username = get_settings().ADMIN_USERNAME.strip()
    await _seed_user(user_session, "someone-else")
    admin_id = await _seed_user(user_session, admin_username)
    resolved = await resolve_default_operator_id(user_session)
    assert resolved == admin_id


@pytest.mark.asyncio
async def test_resolve_default_operator_falls_back_to_any_user(user_session):
    # No user matching ADMIN_USERNAME → fall back to the only existing user.
    settings = get_settings()
    other = "not-" + settings.ADMIN_USERNAME.strip()
    only_id = await _seed_user(user_session, other)
    resolved = await resolve_default_operator_id(user_session)
    assert resolved == only_id


@pytest.mark.asyncio
async def test_resolve_default_operator_none_when_no_users(user_session):
    resolved = await resolve_default_operator_id(user_session)
    assert resolved is None
