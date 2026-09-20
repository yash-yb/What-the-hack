"""World-model inference using the repository's 37-feature contract."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

import torch

from ai.inference.contract import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    OOD_MIN_FEATURES,
    OOD_ZSCORE_THRESHOLD,
    attack_type_for_stage,
    risk_level_for,
    validate_features,
)
from ai.inference.mitre_stage_map import MITRE_STAGES, candidates_for_stage
from ai.models.world_model import WorldModel


def load_model(checkpoint_path: str | Path) -> tuple[WorldModel, dict[str, Any]]:
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    if checkpoint.get("feature_names") != list(FEATURE_NAMES) or checkpoint.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
        raise ValueError("Model artifact does not match the active feature schema.")
    model = WorldModel(); model.load_state_dict(checkpoint["state_dict"]); model.eval()
    return model, checkpoint


def forecast(model: WorldModel, checkpoint: dict[str, Any], history: Sequence[dict[str, float]], k_steps: int = 5) -> dict[str, Any]:
    """Forecast a sequence of validated production feature dictionaries."""
    if len(history) != checkpoint["seq_len"]: raise ValueError(f"Expected exactly {checkpoint['seq_len']} history windows.")
    rows = [[validate_features(window)[name] for name in FEATURE_NAMES] for window in history]
    mean, std = checkpoint["normalisation"]["mean"], checkpoint["normalisation"]["std"]
    observed = torch.tensor([[[(value - mean[index]) / (std[index] if std[index] >= 1e-6 else 1.0) for index, value in enumerate(row)] for row in rows]], dtype=torch.float32)
    with torch.no_grad(): output = model.forecast(observed, k_steps)
    risks = output["risk_timeline"][0].tolist()
    stage_probabilities = torch.softmax(output["stage_logits"][0], dim=-1)
    stage_ids = stage_probabilities.argmax(dim=-1).tolist()
    stages = [MITRE_STAGES[index] for index in stage_ids]
    peak = max(range(len(risks)), key=risks.__getitem__)

    # Confidence is the model's own certainty about the stage it named at the peak step,
    # tempered by how decisive the risk value is. A risk near 0.5 is the least informative
    # output the risk head can produce, so it should not read as confident.
    stage_confidence = float(stage_probabilities[peak].max())
    risk_decisiveness = abs(2.0 * float(risks[peak]) - 1.0)
    confidence = round(0.5 * stage_confidence + 0.5 * risk_decisiveness, 3)

    out_of_distribution = ood_report(checkpoint, history[-1])
    return {
        "risk_timeline": [
            {
                "step": index + 1,
                "risk_score": float(risk),
                "stage": stages[index],
                "stage_confidence": round(float(stage_probabilities[index].max()), 3),
            }
            for index, risk in enumerate(risks)
        ],
        "peak_risk_level": risk_level_for(float(risks[peak]) * 100),
        "peak_risk_window": peak + 1,
        "peak_risk_stage": stages[peak],
        "predicted_attack_type": attack_type_for_stage(stages[peak]),
        # The model has a six-class stage head, not a per-attack classifier.  Expose the
        # individual training labels compatible with its stage instead of pretending that
        # the first broad family is a confirmed exact attack.
        "attack_candidates": candidates_for_stage(stages[peak]),
        "confidence_score": confidence,
        "is_uncertain": confidence < 0.55,
        "is_ood": len(out_of_distribution) >= OOD_MIN_FEATURES,
        "ood_features": out_of_distribution,
        "top_feature_contributors": explain_step(model, observed, peak, k_steps),
    }


def ood_report(checkpoint: dict[str, Any], window: dict[str, float]) -> list[dict[str, float]]:
    """
    Features of the latest observed window that sit far outside the training distribution.

    The contract calls a window out-of-distribution when at least OOD_MIN_FEATURES features
    exceed OOD_ZSCORE_THRESHOLD standard deviations from the training mean. The mean and
    standard deviation are the ones stored in the checkpoint at training time.
    """
    mean, std = checkpoint["normalisation"]["mean"], checkpoint["normalisation"]["std"]
    validated = validate_features(window)
    flagged = []
    for index, name in enumerate(FEATURE_NAMES):
        spread = std[index] if std[index] >= 1e-6 else 1.0
        z_score = (validated[name] - mean[index]) / spread
        if abs(z_score) > OOD_ZSCORE_THRESHOLD:
            flagged.append({"feature": name, "z_score": round(float(z_score), 2)})
    return sorted(flagged, key=lambda item: abs(item["z_score"]), reverse=True)


def explain_step(model: WorldModel, history: torch.Tensor, step_idx: int, k_steps: int, top_n: int = 5):
    observed = history.detach().clone().requires_grad_(True); model.zero_grad(set_to_none=True)
    model.forecast(observed, k_steps)["risk_timeline"][0, step_idx].backward()
    scores = (observed.grad[0] * observed[0]).abs().sum(dim=0)
    total = float(scores.sum().detach()) or 1.0
    return [{"feature": FEATURE_NAMES[index], "contribution": float(scores[index].detach()) / total} for index in torch.argsort(scores, descending=True)[:top_n].tolist()]
