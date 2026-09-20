"""Conservative ATT&CK reference for every supported training label.

This table is a *label-to-reference* aid, not a claim that a flow-only forecast has
verified an ATT&CK technique.  The model predicts a broad campaign stage; callers use
``candidates_for_stage`` to show the individual labels compatible with that stage.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackAlignment:
    label: str
    family: str
    tactic: str
    technique_id: str
    technique: str
    caveat: str


ATTACK_ALIGNMENTS: tuple[AttackAlignment, ...] = (
    AttackAlignment("PortScan", "Reconnaissance", "Discovery", "T1046", "Network Service Scanning", "Flow diversity can suggest scanning; validate targets and scanner ownership."),
    AttackAlignment("FTP_Patator", "BruteForce", "Credential Access", "T1110", "Brute Force", "Authentication logs are required to confirm credential guessing."),
    AttackAlignment("SSH_Patator", "BruteForce", "Credential Access", "T1110", "Brute Force", "Authentication logs are required to confirm credential guessing."),
    AttackAlignment("Web_BruteForce", "WebAttack", "Credential Access", "T1110", "Brute Force", "Web access and authentication logs are required to confirm this."),
    AttackAlignment("Web_XSS", "WebAttack", "Initial Access", "T1190", "Exploit Public-Facing Application", "A flow record cannot establish payload content or exploitation."),
    AttackAlignment("Web_SqlInjection", "WebAttack", "Initial Access", "T1190", "Exploit Public-Facing Application", "A flow record cannot establish payload content or exploitation."),
    AttackAlignment("Heartbleed", "DoS", "Initial Access", "T1190", "Exploit Public-Facing Application", "The dataset label is only a proxy; inspect the TLS service and packet evidence."),
    AttackAlignment("Infiltration", "Infiltration", "Lateral Movement", "T1021", "Remote Services", "CICIDS' broad Infiltration label does not identify a specific remote-service technique."),
    AttackAlignment("Botnet", "Botnet_C2", "Command and Control", "T1071", "Application Layer Protocol", "Beaconing and process/DNS evidence are required to establish C2."),
    AttackAlignment("DoS_Hulk", "DoS", "Impact", "T1499", "Endpoint Denial of Service", "Volume alone does not prove a denial-of-service attack."),
    AttackAlignment("DoS_GoldenEye", "DoS", "Impact", "T1499", "Endpoint Denial of Service", "Volume alone does not prove a denial-of-service attack."),
    AttackAlignment("DoS_Slowloris", "DoS", "Impact", "T1499", "Endpoint Denial of Service", "Volume alone does not prove a denial-of-service attack."),
    AttackAlignment("DoS_Slowhttptest", "DoS", "Impact", "T1499", "Endpoint Denial of Service", "Volume alone does not prove a denial-of-service attack."),
    AttackAlignment("DDoS_LOIC", "DDoS", "Impact", "T1498", "Network Denial of Service", "Validate source distribution and upstream telemetry before escalation."),
)

BY_LABEL = {item.label: item for item in ATTACK_ALIGNMENTS}

_STAGE_FAMILIES = {
    "Reconnaissance": {"Reconnaissance"},
    "Initial Access": {"BruteForce", "WebAttack", "DoS"},
    "Lateral Movement": {"Infiltration"},
    "Command & Control": {"Botnet_C2"},
    "Impact": {"DoS", "DDoS"},
}


def candidates_for_stage(stage: str | None) -> list[dict[str, str]]:
    """Return transparent label candidates for a coarse model stage."""
    families = _STAGE_FAMILIES.get(stage or "", set())
    return [
        {"label": item.label, "family": item.family, "tactic": item.tactic,
         "technique_id": item.technique_id, "technique": item.technique}
        for item in ATTACK_ALIGNMENTS if item.family in families
    ]
