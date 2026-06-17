"""ABTestRouter — pick variant A or B based on traffic split (M9).

When an A/B test row in ``prompt_ab_tests`` is ``status='active'`` for a
given ``task_type``, the engine routes a fraction of requests
(``traffic_split``) to variant A and the rest to variant B. The router
returns a ``PromptTemplateView`` that callers feed straight into
``LLMProvider.complete()`` so the variant is observable on the resulting
``llm_interactions`` row.

A request-level deterministic key (``request_id`` / ``cve_id`` / random) is
used so the same logical request always lands on the same variant across
retries — that lets the operator compare apples-to-apples without
stochastic re-routing during a retry storm.

The router falls back to ``PromptStore.get_active()`` when:

  * no active A/B test exists for the task,
  * the test's variant rows can't be loaded (defensive),
  * or the caller explicitly opts out via ``use_ab=False``.

A/B test conclusion logic lives outside the router — the API endpoint
flips ``status='concluded'`` and records the winner.
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fragchain.db.models import PromptABTest, PromptTemplate
from fragchain.prompts.store import PromptStore, PromptTemplateView

logger = structlog.get_logger(__name__)


@dataclass
class ABSelection:
    """Result of an A/B route decision.

    ``variant`` is ``'A'`` or ``'B'`` when a test fired, ``None`` when the
    router fell back to the regular active prompt (no test for this task).
    Callers persist ``ab_test_id`` + ``variant`` on the artifact so post-hoc
    analysis can attribute outcomes.
    """

    template: PromptTemplateView
    variant: str | None  # 'A' | 'B' | None
    ab_test_id: uuid.UUID | None = None


class ABTestRouter:
    """Resolver that consults active A/B tests before falling back to PromptStore."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._store = PromptStore(session)

    async def select_variant(
        self,
        task_type: str,
        target_model: str,
        target_provider: str = "litellm",
        *,
        routing_key: str | None = None,
        use_ab: bool = True,
    ) -> ABSelection | None:
        """Return the prompt the engine should use for this request.

        ``routing_key`` is the deterministic seed (e.g. the CVE id) — same
        key always lands on the same variant. If omitted, a random UUID is
        used (effectively per-request randomization).
        """
        if use_ab:
            test = await self._active_test_for(task_type)
            if test is not None:
                variant_row, variant_label = await self._pick_variant(
                    test, routing_key or str(uuid.uuid4())
                )
                if variant_row is not None:
                    logger.info(
                        "prompt.ab.routed",
                        ab_test_id=str(test.id),
                        task_type=task_type,
                        variant=variant_label,
                        template_id=str(variant_row.id),
                    )
                    return ABSelection(
                        template=PromptTemplateView.from_row(variant_row),
                        variant=variant_label,
                        ab_test_id=test.id,
                    )

        fallback = await self._store.get_active(
            task_type, target_model, target_provider
        )
        if fallback is None:
            return None
        return ABSelection(template=fallback, variant=None, ab_test_id=None)

    async def list_active_tests(self) -> list[PromptABTest]:
        stmt = (
            select(PromptABTest)
            .where(PromptABTest.status == "active")
            .order_by(PromptABTest.started_at.desc())
        )
        return list((await self._session.execute(stmt)).scalars().all())

    async def list_tests(
        self, *, status: str | None = None
    ) -> list[PromptABTest]:
        stmt = select(PromptABTest)
        if status is not None:
            stmt = stmt.where(PromptABTest.status == status)
        stmt = stmt.order_by(PromptABTest.started_at.desc())
        return list((await self._session.execute(stmt)).scalars().all())

    async def get_test(self, ab_test_id: uuid.UUID) -> PromptABTest | None:
        return await self._session.get(PromptABTest, ab_test_id)

    async def create_test(
        self,
        *,
        name: str,
        task_type: str,
        variant_a_id: uuid.UUID,
        variant_b_id: uuid.UUID,
        traffic_split: float = 0.50,
    ) -> PromptABTest:
        """Persist a new A/B test row.

        Both variant templates must exist and share the same ``task_type``
        as the test — mismatches would silently route the wrong prompt to
        the wrong call site.
        """
        if not 0.0 <= traffic_split <= 1.0:
            raise ValueError("traffic_split must be in [0.0, 1.0]")

        a = await self._session.get(PromptTemplate, variant_a_id)
        b = await self._session.get(PromptTemplate, variant_b_id)
        if a is None or b is None:
            missing = variant_a_id if a is None else variant_b_id
            raise ValueError(f"prompt template {missing} not found")
        if a.task_type != task_type or b.task_type != task_type:
            raise ValueError(
                f"variant task_type mismatch: A={a.task_type!r} B={b.task_type!r} "
                f"requested={task_type!r}"
            )

        from decimal import Decimal

        test = PromptABTest(
            name=name,
            task_type=task_type,
            variant_a_template_id=variant_a_id,
            variant_b_template_id=variant_b_id,
            traffic_split=Decimal(format(traffic_split, ".2f")),
            status="active",
        )
        self._session.add(test)
        await self._session.commit()
        logger.info(
            "prompt.ab.created",
            id=str(test.id),
            name=name,
            task_type=task_type,
            traffic_split=traffic_split,
        )
        return test

    async def conclude(
        self, ab_test_id: uuid.UUID, *, winner: str | None = None
    ) -> PromptABTest:
        """Flip the test to ``concluded`` and stamp a winner.

        ``winner`` may be ``'A'``, ``'B'``, or ``None`` (no winner picked).
        """
        from datetime import datetime, timezone

        test = await self._session.get(PromptABTest, ab_test_id)
        if test is None:
            raise ValueError(f"A/B test {ab_test_id} not found")
        if winner is not None and winner not in ("A", "B"):
            raise ValueError("winner must be 'A' or 'B' or None")
        test.status = "concluded"
        test.winner = winner
        test.concluded_at = datetime.now(tz=timezone.utc)
        await self._session.commit()
        logger.info(
            "prompt.ab.concluded",
            id=str(test.id),
            winner=winner,
        )
        return test

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    async def _active_test_for(self, task_type: str) -> PromptABTest | None:
        # Most recent active test wins if multiple exist for a task.
        stmt = (
            select(PromptABTest)
            .where(
                PromptABTest.task_type == task_type,
                PromptABTest.status == "active",
            )
            .order_by(PromptABTest.started_at.desc())
            .limit(1)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def _pick_variant(
        self, test: PromptABTest, routing_key: str
    ) -> tuple[PromptTemplate | None, str]:
        """Decide A vs B for ``routing_key`` using the configured split."""
        roll = _deterministic_roll(routing_key, str(test.id))
        split = float(test.traffic_split or 0.0)
        if roll < split:
            label = "A"
            template_id = test.variant_a_template_id
        else:
            label = "B"
            template_id = test.variant_b_template_id
        row = await self._session.get(PromptTemplate, template_id)
        return row, label


def _deterministic_roll(routing_key: str, salt: str) -> float:
    """Map ``(routing_key, salt)`` to a stable float in ``[0, 1)``.

    SHA-256 of the joined string, take the first 8 bytes as a uint64, and
    normalize. Stable across processes so retries always pick the same
    variant for the same key.
    """
    digest = hashlib.sha256(f"{routing_key}|{salt}".encode("utf-8")).digest()
    n = int.from_bytes(digest[:8], byteorder="big", signed=False)
    return (n % 10_000_000) / 10_000_000.0


__all__ = ["ABSelection", "ABTestRouter"]
