import numpy as np
import pytest

from ai.evaluation.calibration import calibrate_threshold


def test_calibration_selects_the_best_recall_under_fpr_budget():
    # threshold .70 catches both attacks and no benign score; .60 would create one false alarm.
    result = calibrate_threshold(np.array([0, 0, 1, 1]), np.array([0.1, 0.6, 0.7, 0.9]), 0.0)
    assert result == {"threshold": 0.7, "recall": 1.0, "false_positive_rate": 0.0, "max_false_positive_rate": 0.0}


def test_calibration_refuses_a_single_class_validation_set():
    with pytest.raises(ValueError, match="benign and attack"):
        calibrate_threshold(np.array([1, 1]), np.array([0.2, 0.9]))
