from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from fragchain.assessments.rule_supersession import RuleSuperseder


def _queue_row(*, sigma_rule_id, status="pending",
               superseded_by_assessment_id=None):
    return MagicMock(
        id=uuid.uuid4(),
        sigma_rule_id=sigma_rule_id,
        status=status,
        superseded_by_assessment_id=superseded_by_assessment_id,
    )


def _sigma_row(*, id=None,
               deprecated_by_rule_id=None, deprecated_at=None,
               deprecated_by_assessment_id=None, status="approved"):
    return MagicMock(
        id=id or uuid.uuid4(),
        status=status,
        deprecated_by_rule_id=deprecated_by_rule_id,
        deprecated_at=deprecated_at,
        deprecated_by_assessment_id=deprecated_by_assessment_id,
    )


@pytest.mark.asyncio
async def test_supersede_pending_queue_row_for_same_triple():
    cve_id = uuid.uuid4()
    asmt_id = uuid.uuid4()
    new_rule_id = uuid.uuid4()

    prior_queue = _queue_row(sigma_rule_id=uuid.uuid4(), status="pending")

    session = AsyncMock()
    # First execute() → pending queue rows. Second execute() → no approved sigma rows.
    queue_fetch = MagicMock()
    queue_scalars = MagicMock()
    queue_scalars.all.return_value = [prior_queue]
    queue_fetch.scalars.return_value = queue_scalars

    sigma_fetch = MagicMock()
    sigma_scalars = MagicMock()
    sigma_scalars.all.return_value = []
    sigma_fetch.scalars.return_value = sigma_scalars

    session.execute.side_effect = [queue_fetch, sigma_fetch]

    sup = RuleSuperseder(session)
    summary = await sup.supersede_prior_for_triple(
        cve_id=cve_id,
        technique_id="T1059",
        profile_name="linux-auditd",
        new_rule_id=new_rule_id,
        assessment_id=asmt_id,
    )

    assert prior_queue.superseded_by_assessment_id == asmt_id
    assert prior_queue.status == "superseded"
    assert summary["pending_superseded"] == 1
    assert summary["approved_deprecated"] == 0


@pytest.mark.asyncio
async def test_deprecate_approved_sigma_rule_for_same_triple():
    cve_id = uuid.uuid4()
    asmt_id = uuid.uuid4()
    new_rule_id = uuid.uuid4()

    prior_sigma = _sigma_row()

    session = AsyncMock()
    queue_fetch = MagicMock()
    queue_scalars = MagicMock()
    queue_scalars.all.return_value = []
    queue_fetch.scalars.return_value = queue_scalars

    sigma_fetch = MagicMock()
    sigma_scalars = MagicMock()
    sigma_scalars.all.return_value = [prior_sigma]
    sigma_fetch.scalars.return_value = sigma_scalars

    session.execute.side_effect = [queue_fetch, sigma_fetch]

    sup = RuleSuperseder(session)
    summary = await sup.supersede_prior_for_triple(
        cve_id=cve_id,
        technique_id="T1059",
        profile_name="windows-sysmon",
        new_rule_id=new_rule_id,
        assessment_id=asmt_id,
    )

    assert prior_sigma.deprecated_by_rule_id == new_rule_id
    assert prior_sigma.deprecated_by_assessment_id == asmt_id
    assert prior_sigma.deprecated_at is not None
    assert summary["approved_deprecated"] == 1
    assert summary["pending_superseded"] == 0


@pytest.mark.asyncio
async def test_matches_technique_exactly_not_by_containment():
    # D-4 regression: the superseder must match technique_ids EXACTLY
    # (== [technique_id]) so a broader, still-valid multi-technique rule isn't
    # clobbered by a narrower single-technique one. Verify at the SQL level —
    # array equality compiles to '=', containment to PostgreSQL's '@>'.
    session = AsyncMock()
    empty = MagicMock()
    empty_scalars = MagicMock()
    empty_scalars.all.return_value = []
    empty.scalars.return_value = empty_scalars
    session.execute.side_effect = [empty, empty]

    sup = RuleSuperseder(session)
    await sup.supersede_prior_for_triple(
        cve_id=uuid.uuid4(), technique_id="T1059",
        profile_name="linux-auditd",
        new_rule_id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
    )

    for call in session.execute.call_args_list:
        compiled = str(
            call.args[0].compile(compile_kwargs={"literal_binds": True})
        )
        assert "@>" not in compiled, "must not use array containment"
        assert "technique_ids = " in compiled.lower()


@pytest.mark.asyncio
async def test_no_op_when_no_prior_rule_exists():
    session = AsyncMock()
    empty = MagicMock()
    empty_scalars = MagicMock()
    empty_scalars.all.return_value = []
    empty.scalars.return_value = empty_scalars
    session.execute.side_effect = [empty, empty]

    sup = RuleSuperseder(session)
    summary = await sup.supersede_prior_for_triple(
        cve_id=uuid.uuid4(), technique_id="T1059",
        profile_name="linux-auditd",
        new_rule_id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
    )
    assert summary == {"pending_superseded": 0, "approved_deprecated": 0}
