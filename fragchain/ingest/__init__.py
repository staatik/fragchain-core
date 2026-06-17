"""Intel ingestion subsystem (M6).

Owns the CVE state machine, live + historical import workflows, novelty
filters, and the saved-filter presets that drive the Import Manager UI.

Public surface:

  * :class:`ImportFilters` — Pydantic model for the basic + novelty filter set.
  * :class:`PreviewResult` — preview-endpoint response shape.
  * :class:`FilterPreset` — saved-filter Pydantic model.
  * :func:`compute_effective_date_from` — translates ``published_within_days`` → ``date_from``.
  * :func:`apply_basic_filters` / :func:`apply_novelty_filters` — pure helpers
    reused by the preview endpoint, the staging worker, and the tests.
"""

from fragchain.security.embargo import EmbargoedTable, register_embargoed_table

# Register the M6 tables for embargo auto-release. M2's `release_embargoed_content`
# Celery task walks this registry every 5 min, so this side-effect import is the
# whole wiring — no additional config needed.
register_embargoed_table(EmbargoedTable(table="cves", entity_type="cve"))
register_embargoed_table(
    EmbargoedTable(table="source_documents", entity_type="source_document")
)

from fragchain.ingest.filters import (
    BUILTIN_PRESETS,
    FilterPreset,
    FilterPresetCreate,
    FilterPresetUpdate,
    ImportFilters,
    PreviewResult,
    PreviewSample,
    apply_basic_filters,
    apply_novelty_filters,
    compute_effective_date_from,
    has_novelty_filters,
)
from fragchain.ingest.rate_limit import (
    LiveRateCheck,
    check_live_rate,
    check_daily_budget,
)
from fragchain.ingest.state import (
    audit_state_change,
    set_processing_failed,
    set_processing_stage,
)
from fragchain.ingest.webhooks import verify_webhook_token

__all__ = [
    "BUILTIN_PRESETS",
    "FilterPreset",
    "FilterPresetCreate",
    "FilterPresetUpdate",
    "ImportFilters",
    "LiveRateCheck",
    "PreviewResult",
    "PreviewSample",
    "apply_basic_filters",
    "apply_novelty_filters",
    "audit_state_change",
    "check_daily_budget",
    "check_live_rate",
    "compute_effective_date_from",
    "has_novelty_filters",
    "set_processing_failed",
    "set_processing_stage",
    "verify_webhook_token",
]
