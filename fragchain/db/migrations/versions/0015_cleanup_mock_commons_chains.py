"""cleanup_mock_commons_chains (Phase 5 cleanup #5 — one-off scrub)

Revision ID: 0015_cleanup_mock_commons_chains
Revises: 0014_rule_evaluations
Create Date: 2026-05-13

Phase 5 audit L3 / Phase 4 audit D5: deployments that ran before Phase 4
flipped ``COMMONS_ALLOW_MOCK_FALLBACK`` to ``false`` may have a synthetic
``fragchain_mock`` commons chain in ``commons_chains`` and a matching
``v0.0.1-mock*`` row in ``commons_sources``. That mock payload carries a
``provenance`` field that Pydantic's ``extra='forbid'`` rejects on
projection, which used to recurse indefinitely through the LLM fallback
(L3). Phase 5 fixes the recursion + adds an unknown-key strip to the
projector; this migration removes the polluted rows so existing
deployments don't carry the legacy mock chain forever.

The migration is a one-off scrub. ``down_revision`` is a no-op — once the
mock rows are gone they cannot be reconstructed.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0015_cleanup_mock_commons_chains"
down_revision: Union[str, Sequence[str], None] = "0014_rule_evaluations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Drop any commons_chains row whose payload was minted by the
    # MockTransport fallback. The data column is JSONB.
    op.execute(
        """
        DELETE FROM commons_chains
        WHERE data->'provenance'->>'contribution_source' = 'fragchain_mock'
        """
    )
    # And drop any commons_sources row that bootstrapped against the mock
    # release tag. The version column carries the release tag string.
    op.execute(
        """
        DELETE FROM commons_sources
        WHERE last_release_version LIKE 'v0.0.1-mock%'
        """
    )


def downgrade() -> None:
    # No-op — deleted rows cannot be reconstructed.
    pass
