"""
Train the world model from normalized upload CSVs or raw CICIDS2017 labeled-flow CSVs.

Two properties make the reported numbers defensible:

1. **Chronological split.** Windows are ordered in time, so the test partition is always
   the future relative to training. A shuffled split would let the model interpolate
   between windows either side of an attack and look far better than it is.
2. **Purge embargo.** The windows spanning the boundary are dropped entirely. A training
   sample's history reaches back ``seq_len`` windows, so without a gap the last training
   samples would overlap the first test windows. The contract states the rule as
   ``purge >= window_size + horizon``.

The evaluation script consumes the same split, so `--test-fraction` must match there.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset

from ai.feature_engineering.labeled_windows import build_labeled_windows
from ai.inference.contract import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from ai.models.world_model import WorldModel

SEQ_LEN, BATCH_SIZE, LR = 10, 64, 1e-3
# The bundled replay's last 20% is attack-only.  Half keeps both classes in its
# held-out segment; real data still has to pass the explicit split checks below.
DEFAULT_TEST_FRACTION = 0.5


def split_index(total: int, test_fraction: float) -> int:
    """First index belonging to the test partition."""
    return int(total * (1 - test_fraction))


def purge_size(seq_len: int = SEQ_LEN) -> int:
    """
    Windows dropped at the boundary so no training sample can see test data.

    A sample at index i reads windows [i, i + seq_len) and is labelled at i + seq_len, so
    dropping seq_len windows before the split removes every overlapping sample.
    """
    return seq_len


def require_evaluable_split(risk_labels: np.ndarray, train_end: int, boundary: int) -> None:
    """Refuse a split that cannot support a binary forecasting claim.

    AUC/F1 from a single-class train or test partition is not merely weak—it is
    undefined or misleading.  Users must provide a longer/more varied capture or choose
    a chronological split that contains benign and attack windows on both sides.
    """
    partitions = {"training": risk_labels[:train_end], "held-out": risk_labels[boundary:]}
    for name, values in partitions.items():
        present = {int(value) for value in values.tolist()}
        if present != {0, 1}:
            raise ValueError(
                f"The {name} partition has classes {sorted(present)}, not both benign (0) and attack (1). "
                "Do not train or report metrics on this split; use a longer, chronologically varied capture."
            )


class WindowSequenceDataset(Dataset):
    """Teacher-forced input history and the immediately following labelled window."""

    def __init__(self, features, risk_labels, stage_labels, seq_len: int = SEQ_LEN):
        self.features = torch.as_tensor(features, dtype=torch.float32)
        self.risk_labels = torch.as_tensor(risk_labels, dtype=torch.float32)
        self.stage_labels = torch.as_tensor(stage_labels, dtype=torch.long)
        self.seq_len = seq_len
        if len(self.features) <= seq_len:
            raise ValueError(f"Need more than {seq_len} traffic windows, got {len(self.features)}.")

    def __len__(self):
        return len(self.features) - self.seq_len

    def __getitem__(self, index):
        target = index + self.seq_len
        return self.features[index:target], self.features[target], self.risk_labels[target], self.stage_labels[target]


def _fit(model, loader, loss_for, epochs: int, name: str) -> float:
    optimizer = torch.optim.Adam(model.parameters(), lr=LR)
    model.train()
    last = 0.0
    for epoch in range(epochs):
        total = 0.0
        for batch in loader:
            optimizer.zero_grad()
            loss = loss_for(batch)
            loss.backward()
            optimizer.step()
            total += loss.item()
        last = total / max(len(loader), 1)
        print(f"[{name}] epoch {epoch + 1}/{epochs} loss={last:.4f}")
    return last


def main(
    csv_path: str,
    out_path: str = "ai/models/world_model.pt",
    epochs: int = 15,
    test_fraction: float = DEFAULT_TEST_FRACTION,
) -> None:
    windows = build_labeled_windows(csv_path)
    total = len(windows.features)
    boundary = split_index(total, test_fraction)
    purge = purge_size()
    train_end = max(boundary - purge, 0)
    if train_end <= SEQ_LEN:
        raise ValueError(
            f"Not enough training windows after the purge embargo: {train_end} usable of {total}. "
            f"Use a longer capture or a smaller --test-fraction."
        )
    require_evaluable_split(windows.risk_labels, train_end, boundary)

    print(
        f"windows={total} train=[0,{train_end}) purged=[{train_end},{boundary}) test=[{boundary},{total}) "
        f"positives_in_train={float(windows.risk_labels[:train_end].mean()):.3f}"
    )

    # Normalisation statistics come from the training partition only. Fitting them on the
    # whole file would leak the test distribution into the model's inputs.
    train_features = windows.features[:train_end]
    mean, std = train_features.mean(axis=0), train_features.std(axis=0)
    normalised = (windows.features - mean) / np.where(std < 1e-6, 1.0, std)

    loader = DataLoader(
        WindowSequenceDataset(normalised[:train_end], windows.risk_labels[:train_end], windows.stage_labels[:train_end]),
        batch_size=BATCH_SIZE,
        shuffle=True,
    )
    model = WorldModel()
    dynamics_loss = _fit(
        model.dynamics, loader,
        lambda batch: nn.functional.mse_loss(model.dynamics(batch[0])[0], batch[1]),
        epochs, "dynamics",
    )

    # Class weighting: precursor windows are the minority, and an unweighted loss collapses
    # to predicting benign for everything.
    positives = float(windows.risk_labels[:train_end].sum())
    negatives = float(train_end - positives)
    pos_weight = torch.tensor(max(negatives / positives, 1.0) if positives else 1.0)
    bce = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    cross_entropy = nn.CrossEntropyLoss()

    def risk_stage_loss(batch):
        probability, logits = model.risk_stage(batch[1])
        # The head returns a sigmoid probability; recover the logit for the weighted loss.
        risk_logit = torch.logit(probability.clamp(1e-6, 1 - 1e-6))
        return bce(risk_logit, batch[2]) + cross_entropy(logits, batch[3])

    stage_loss = _fit(model.risk_stage, loader, risk_stage_loss, epochs, "risk/stage")

    destination = Path(out_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "state_dict": model.state_dict(),
            "feature_names": list(FEATURE_NAMES),
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "seq_len": SEQ_LEN,
            "normalisation": {"mean": mean.tolist(), "std": std.tolist()},
            "training": {
                "source_csv": str(csv_path),
                "epochs": epochs,
                "test_fraction": test_fraction,
                "total_windows": total,
                "train_windows": train_end,
                "purged_windows": purge,
                "positive_rate_train": float(windows.risk_labels[:train_end].mean()),
                "positive_rate_held_out": float(windows.risk_labels[boundary:].mean()),
                "pos_weight": float(pos_weight),
                "final_dynamics_loss": dynamics_loss,
                "final_risk_stage_loss": stage_loss,
            },
        },
        destination,
    )
    print(f"saved checkpoint to {destination}")
    print(json.dumps({"train_windows": train_end, "held_out_windows": total - boundary}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path")
    parser.add_argument("--out", default="ai/models/world_model.pt")
    parser.add_argument("--epochs", type=int, default=15)
    parser.add_argument(
        "--test-fraction", type=float, default=DEFAULT_TEST_FRACTION,
        help="Chronological fraction held out for evaluation. Must match evaluate_models.py.",
    )
    arguments = parser.parse_args()
    main(arguments.csv_path, arguments.out, arguments.epochs, arguments.test_fraction)
