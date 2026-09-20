"""Fixed mapping shared by world-model labels, inference, and documentation."""

from __future__ import annotations

from ai.inference.contract import LABEL_TO_FAMILY, MITRE_STAGES
from ai.inference.mitre_attack_map import candidates_for_stage

__all__ = ["MITRE_STAGES", "stage_for_label", "risk_for_label", "candidates_for_stage"]

_FAMILY_TO_STAGE = {
    "Reconnaissance": 1, "BruteForce": 2, "WebAttack": 2,
    "Infiltration": 3, "Botnet_C2": 4, "DoS": 5, "DDoS": 5,
}


def stage_for_label(label: object) -> int:
    """Map CICIDS canonical labels to one of the demo's six coarse stages."""
    value = str(label).strip()
    if value.upper() == "BENIGN":
        return 0
    family = LABEL_TO_FAMILY.get(value)
    if family is not None:
        return _FAMILY_TO_STAGE[family]
    # Accept common raw CICIDS spellings before its download normaliser runs.
    lowered = value.lower().replace(" ", "_").replace("-", "_")
    if "portscan" in lowered: return 1
    if any(token in lowered for token in ("patator", "web_", "heartbleed")): return 2
    if "infiltration" in lowered: return 3
    if "bot" in lowered: return 4
    if "dos" in lowered: return 5
    return 0


def risk_for_label(label: object) -> float:
    return float(stage_for_label(label) != 0)
