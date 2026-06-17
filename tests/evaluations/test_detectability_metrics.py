"""Tests for the pure detectability-classification metrics."""
from __future__ import annotations

from fragchain.evaluations.detectability_metrics import CaseOutcome, compute_metrics


def _o(cid, exp, pred, conf):
    return CaseOutcome(case_id=cid, expected=exp, predicted=pred, confidence=conf)


def test_accuracy_and_n():
    res = compute_metrics([
        _o("a", "directly_detectable", "directly_detectable", 0.9),
        _o("b", "control_only", "control_only", 0.8),
        _o("c", "control_only", "directly_detectable", 0.7),
    ])
    assert res["n"] == 3
    assert res["accuracy"] == round(2 / 3, 4)


def test_per_class_precision_recall_f1():
    res = compute_metrics([
        _o("a", "directly_detectable", "directly_detectable", 0.9),
        _o("c", "control_only", "directly_detectable", 0.7),
    ])
    dd = res["per_class"]["directly_detectable"]
    assert dd["precision"] == 0.5
    assert dd["recall"] == 1.0
    co = res["per_class"]["control_only"]
    assert co["recall"] == 0.0
    assert co["precision"] is None


def test_confusion_matrix_shape_and_counts():
    res = compute_metrics([
        _o("a", "directly_detectable", "directly_detectable", 0.9),
        _o("c", "control_only", "directly_detectable", 0.7),
    ])
    classes = res["confusion_matrix"]["classes"]
    assert len(classes) == 5
    m = res["confusion_matrix"]["matrix"]
    di = classes.index("directly_detectable")
    ci = classes.index("control_only")
    assert m[di][di] == 1
    assert m[ci][di] == 1
    assert all(len(row) == 5 for row in m)
    assert sum(sum(row) for row in m) == 2


def test_calibration_correct_vs_incorrect():
    res = compute_metrics([
        _o("a", "directly_detectable", "directly_detectable", 0.9),
        _o("c", "control_only", "directly_detectable", 0.7),
    ])
    cal = res["calibration"]
    assert cal["mean_confidence"] == 0.8
    assert cal["mean_confidence_correct"] == 0.9
    assert cal["mean_confidence_incorrect"] == 0.7


def test_empty_input_is_safe():
    res = compute_metrics([])
    assert res["n"] == 0
    assert res["accuracy"] is None
