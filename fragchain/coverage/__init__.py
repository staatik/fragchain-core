"""Coverage mapping + matrix data (M14).

Public surface re-exported from this package:

  * :class:`CoverageMapper` — runs the two-phase mapping for one chain.
  * :class:`CoverageReport`, :class:`CoverageStatus` — return shapes.
  * :class:`MatrixCache`, :class:`MatrixData`, :class:`MatrixFilters` —
    Redis-cached matrix data for the ATT&CK Matrix UI.

The Celery tasks (:func:`fragchain.worker.tasks.map_coverage`,
:func:`fragchain.worker.tasks.refresh_matrix_cache`) live alongside the
rest of the worker tasks, not here.
"""

from fragchain.coverage.mapper import (
    CoverageMapper,
    CoverageMappingError,
    CoverageReport,
    CoverageStatus,
    LLM_VERIFY_PARALLELISM,
    SEMANTIC_RESULT_LIMIT,
    SEMANTIC_SCORE_THRESHOLD,
)
from fragchain.coverage.matrix import (
    CACHE_TTL_SECONDS,
    DEFAULT_FRAMEWORK,
    ENTERPRISE_TACTIC_ORDER,
    MatrixCache,
    MatrixCell,
    MatrixData,
    MatrixFilters,
    MatrixSummary,
    MatrixTactic,
)

__all__ = [
    "CACHE_TTL_SECONDS",
    "CoverageMapper",
    "CoverageMappingError",
    "CoverageReport",
    "CoverageStatus",
    "DEFAULT_FRAMEWORK",
    "ENTERPRISE_TACTIC_ORDER",
    "LLM_VERIFY_PARALLELISM",
    "MatrixCache",
    "MatrixCell",
    "MatrixData",
    "MatrixFilters",
    "MatrixSummary",
    "MatrixTactic",
    "SEMANTIC_RESULT_LIMIT",
    "SEMANTIC_SCORE_THRESHOLD",
]
