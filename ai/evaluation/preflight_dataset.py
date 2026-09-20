"""Fail-fast quality gate for a labeled forecasting dataset before model training."""

from __future__ import annotations

import argparse
import json

from ai.feature_engineering.labeled_windows import build_labeled_windows
from ai.training.train_world_model import purge_size, require_evaluable_split, split_index


def inspect(csv_path: str, test_fraction: float) -> dict:
    windows = build_labeled_windows(csv_path)
    total = len(windows.risk_labels)
    boundary = split_index(total, test_fraction)
    train_end = max(boundary - purge_size(), 0)
    result = {
        "windows": total,
        "attack_windows": int(windows.risk_labels.sum()),
        "benign_windows": int(total - windows.risk_labels.sum()),
        "test_fraction": test_fraction,
        "train_windows_after_embargo": train_end,
        "purged_windows": boundary - train_end,
        "held_out_windows": total - boundary,
    }
    try:
        require_evaluable_split(windows.risk_labels, train_end, boundary)
        result["ready"] = True
        result["message"] = "Split contains benign and attack windows in both partitions. Train, then evaluate the same split."
    except ValueError as exc:
        result["ready"] = False
        result["message"] = str(exc)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path")
    parser.add_argument("--test-fraction", type=float, default=0.2)
    args = parser.parse_args()
    result = inspect(args.csv_path, args.test_fraction)
    print(json.dumps(result, indent=2))
    if not result["ready"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
