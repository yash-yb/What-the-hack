"""Validation-only threshold selection for operational forecasting alerts."""

from __future__ import annotations

import numpy as np


def calibrate_threshold(y_true: np.ndarray, y_score: np.ndarray, max_false_positive_rate: float = 0.05) -> dict:
    """Choose the highest-recall threshold that respects a held-out FPR budget.

    This is a validation-only operational policy, not probability calibration. It refuses
    single-class data because an FPR target without benign windows is meaningless.
    """
    if not 0.0 <= max_false_positive_rate <= 1.0:
        raise ValueError("max_false_positive_rate must be between 0 and 1")
    y_true, y_score = np.asarray(y_true), np.asarray(y_score)
    if set(np.unique(y_true)) != {0, 1}:
        raise ValueError("Threshold calibration requires benign and attack windows in the held-out partition.")
    candidates = np.unique(np.r_[0.0, y_score, 1.0])
    feasible: list[tuple[float, float, float]] = []
    for threshold in candidates:
        predicted = y_score >= threshold
        benign, attacks = y_true == 0, y_true == 1
        fpr = float(predicted[benign].mean())
        recall = float(predicted[attacks].mean())
        if fpr <= max_false_positive_rate:
            feasible.append((recall, threshold, fpr))
    if not feasible:
        return {"threshold": 1.0, "recall": 0.0, "false_positive_rate": 0.0, "max_false_positive_rate": max_false_positive_rate}
    recall, threshold, fpr = max(feasible, key=lambda item: (item[0], item[1]))
    return {"threshold": round(float(threshold), 4), "recall": round(recall, 4), "false_positive_rate": round(fpr, 4), "max_false_positive_rate": max_false_positive_rate}
