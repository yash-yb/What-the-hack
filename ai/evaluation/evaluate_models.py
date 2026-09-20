"""
Evaluate the world model against a logistic-regression baseline, honestly.

Both models are scored on the same chronological held-out partition, and the world model
must have been trained with the same ``--test-fraction`` so its training data ends before
the test window begins. Pass the checkpoint written by ai.training.train_world_model; this
script refuses one whose recorded split does not match.

Beyond the usual classification metrics it reports the two numbers that actually describe
an early-warning system:

* **Mean lead time**: how long before an attack window the model first crosses the alert
  threshold. This is the project's entire claim, so it is measured rather than asserted.
* **False warnings per hour**: how much noise an analyst absorbs to get that lead time.
"""

from __future__ import annotations

import argparse
import json

import numpy as np
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

from ai.evaluation.lead_time import WINDOW_SECONDS, lead_time_metrics
from ai.feature_engineering.labeled_windows import build_labeled_windows
from ai.inference.forecast_engine import load_model
from ai.training.train_world_model import SEQ_LEN, purge_size, require_evaluable_split, split_index

DEFAULT_THRESHOLD = 0.5


def classification_metrics(y_true: np.ndarray, y_score: np.ndarray, threshold: float) -> dict[str, float]:
    y_pred = (y_score >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    both_classes = len(np.unique(y_true)) > 1
    return {
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, y_score)), 4) if both_classes else None,
        "pr_auc": round(float(average_precision_score(y_true, y_score)), 4) if both_classes else None,
        "false_positive_rate": round(float(fp / (fp + tn)) if fp + tn else 0.0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "support": int(len(y_true)),
        "positive_support": int(y_true.sum()),
    }


def main(csv_path: str, checkpoint_path: str, test_fraction: float, threshold: float) -> None:
    data = build_labeled_windows(csv_path)
    total = len(data.features)
    boundary = split_index(total, test_fraction)
    train_end = max(boundary - purge_size(), 0)
    require_evaluable_split(data.risk_labels, train_end, boundary)

    model, checkpoint = load_model(checkpoint_path)
    trained = checkpoint.get("training")
    if trained is None:
        print("WARNING: this checkpoint records no training split. It may have been trained on the test data, which would make the world-model numbers meaningless.")
    elif abs(trained.get("test_fraction", -1) - test_fraction) > 1e-9:
        raise SystemExit(
            f"Checkpoint was trained with --test-fraction {trained.get('test_fraction')}, "
            f"but this run uses {test_fraction}. Re-run with the matching value."
        )

    # Normalise with training-partition statistics only, matching how the model was fitted.
    mean, std = data.features[:train_end].mean(0), data.features[:train_end].std(0)
    x = (data.features - mean) / np.where(std < 1e-6, 1, std)

    baseline = LogisticRegression(max_iter=1000, class_weight="balanced").fit(x[:train_end], data.risk_labels[:train_end])
    baseline_scores = baseline.predict_proba(x[boundary:])[:, 1]

    seq = checkpoint["seq_len"]
    start = max(boundary, seq)
    world_scores, targets = [], []
    with torch.no_grad():
        for index in range(start, total):
            history = torch.tensor(x[index - seq:index], dtype=torch.float32).unsqueeze(0)
            world_scores.append(model.forecast(history, 1)["risk_timeline"][0, 0].item())
            targets.append(data.risk_labels[index])
    world_scores, targets = np.asarray(world_scores), np.asarray(targets)
    baseline_aligned = baseline_scores[start - boundary:]

    report = {
        "dataset": csv_path,
        "checkpoint": checkpoint_path,
        "split": {
            "type": "chronological with purge embargo",
            "test_fraction": test_fraction,
            "total_windows": total,
            "train_windows": train_end,
            "purged_windows": boundary - train_end,
            "test_windows": len(targets),
            "test_positive_rate": round(float(targets.mean()), 4) if len(targets) else None,
        },
        "threshold": threshold,
        "logistic_regression": classification_metrics(targets, baseline_aligned, threshold),
        "world_model": classification_metrics(targets, world_scores, threshold),
        "world_model_early_warning": lead_time_metrics(targets, world_scores, threshold),
        "logistic_regression_early_warning": lead_time_metrics(targets, baseline_aligned, threshold),
    }
    if len(np.unique(targets)) < 2:
        report["caveat"] = "The test partition contains a single class, so ROC-AUC and PR-AUC are undefined and the other metrics are not meaningful. Use a capture where both benign and attack windows fall after the split."
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path")
    parser.add_argument("checkpoint_path")
    parser.add_argument("--test-fraction", type=float, default=0.2, help="Must match the value used for training.")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    args = parser.parse_args()
    main(args.csv_path, args.checkpoint_path, args.test_fraction, args.threshold)
