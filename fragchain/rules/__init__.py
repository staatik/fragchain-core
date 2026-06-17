"""Rule generation package (M15).

Public surface used by the engine + tests:

  * :class:`RuleGenerator` — multi-profile Sigma rule synthesizer.
  * :func:`validate_yaml` — pySigma wrapper that never raises.
  * :class:`ValidationResult` — outcome dataclass for the validator.
  * :class:`GenerationReport` — result of one ``generate_all_gaps`` run.

Every gap × enabled-profile pair produces one ``sigma_rules`` row
(``status='generated'``) and one ``review_queue`` entry. The Celery task
``fragchain.worker.tasks.generate_rules`` wraps the generator with the
state-machine guard (``generating → complete``).

See CLAUDE.md §12 (pipeline) and §14 (mandatory tags).
"""
from __future__ import annotations

from fragchain.rules.generator import (
    GeneratedRule,
    GenerationReport,
    MAX_VALIDATION_RETRIES,
    RuleGenerationError,
    RuleGenerator,
)
from fragchain.rules.validator import ValidationResult, validate_yaml

__all__ = [
    "GeneratedRule",
    "GenerationReport",
    "MAX_VALIDATION_RETRIES",
    "RuleGenerationError",
    "RuleGenerator",
    "ValidationResult",
    "validate_yaml",
]
