"""Pure scoring for the detectability-classifier benchmark.

No LLM, no DB. Given per-case (expected, predicted, confidence) it computes
accuracy, per-class precision/recall/F1, a 5x5 confusion matrix, and a
confidence-calibration summary. Used by scripts/run_detectability_benchmark.py.
"""
from __future__ import annotations

from dataclasses import dataclass

from fragchain.assessments.detectability import DetectabilityClass

CLASS_ORDER: list[str] = [c.value for c in DetectabilityClass]


@dataclass
class CaseOutcome:
    case_id: str
    expected: str
    predicted: str
    confidence: float

    @property
    def correct(self) -> bool:
        return self.expected == self.predicted


def _round(x: float | None) -> float | None:
    return None if x is None else round(x, 4)


def compute_metrics(results: list[CaseOutcome]) -> dict:
    n = len(results)
    if n == 0:
        return {
            "n": 0,
            "accuracy": None,
            "macro_f1": None,
            "per_class": {c: {"precision": None, "recall": None, "f1": None, "support": 0} for c in CLASS_ORDER},
            "confusion_matrix": {"classes": CLASS_ORDER, "matrix": [[0] * len(CLASS_ORDER) for _ in CLASS_ORDER]},
            "calibration": {"mean_confidence": None, "mean_confidence_correct": None, "mean_confidence_incorrect": None},
        }

    correct = sum(1 for r in results if r.correct)
    accuracy = correct / n

    idx = {c: i for i, c in enumerate(CLASS_ORDER)}
    matrix = [[0] * len(CLASS_ORDER) for _ in CLASS_ORDER]
    for r in results:
        # Unknown labels (shouldn't happen post-fixture-validation) are skipped
        # from the matrix but still counted in n/accuracy.
        if r.expected in idx and r.predicted in idx:
            matrix[idx[r.expected]][idx[r.predicted]] += 1

    per_class: dict[str, dict] = {}
    f1s: list[float] = []
    for c in CLASS_ORDER:
        tp = sum(1 for r in results if r.expected == c and r.predicted == c)
        fp = sum(1 for r in results if r.expected != c and r.predicted == c)
        fn = sum(1 for r in results if r.expected == c and r.predicted != c)
        support = sum(1 for r in results if r.expected == c)
        precision = tp / (tp + fp) if (tp + fp) > 0 else None
        recall = tp / (tp + fn) if (tp + fn) > 0 else None
        if precision is not None and recall is not None and (precision + recall) > 0:
            f1: float | None = 2 * precision * recall / (precision + recall)
        elif (tp + fp) == 0 and (tp + fn) == 0:
            f1 = None  # class absent from both expected and predicted
        else:
            f1 = 0.0
        if f1 is not None:
            f1s.append(f1)
        per_class[c] = {
            "precision": _round(precision),
            "recall": _round(recall),
            "f1": _round(f1),
            "support": support,
        }

    macro_f1 = _round(sum(f1s) / len(f1s)) if f1s else None

    confs = [r.confidence for r in results]
    correct_confs = [r.confidence for r in results if r.correct]
    incorrect_confs = [r.confidence for r in results if not r.correct]
    calibration = {
        "mean_confidence": _round(sum(confs) / len(confs)) if confs else None,
        "mean_confidence_correct": _round(sum(correct_confs) / len(correct_confs)) if correct_confs else None,
        "mean_confidence_incorrect": _round(sum(incorrect_confs) / len(incorrect_confs)) if incorrect_confs else None,
    }

    return {
        "n": n,
        "accuracy": _round(accuracy),
        "macro_f1": macro_f1,
        "per_class": per_class,
        "confusion_matrix": {"classes": CLASS_ORDER, "matrix": matrix},
        "calibration": calibration,
    }
