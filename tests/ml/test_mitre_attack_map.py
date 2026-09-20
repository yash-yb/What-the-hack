from ai.inference.contract import CANONICAL_ATTACK_LABELS
from ai.inference.mitre_attack_map import BY_LABEL, candidates_for_stage


def test_every_canonical_attack_has_a_conservative_mitre_reference() -> None:
    assert set(CANONICAL_ATTACK_LABELS) == set(BY_LABEL)
    assert all(item.technique_id.startswith("T") for item in BY_LABEL.values())


def test_impact_candidates_include_every_dos_label_without_claiming_exfiltration() -> None:
    labels = {item["label"] for item in candidates_for_stage("Impact")}
    assert {"DDoS_LOIC", "DoS_Hulk", "DoS_GoldenEye", "DoS_Slowloris", "DoS_Slowhttptest"} <= labels
    assert candidates_for_stage("Exfiltration / Impact") == []
