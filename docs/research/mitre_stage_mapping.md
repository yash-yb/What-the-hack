# World-model MITRE stage and attack-label reference

`ai/inference/mitre_stage_map.py` owns the coarse six-class stage mapping and
`ai/inference/mitre_attack_map.py` owns the per-label ATT&CK reference. This prevents the
training pipeline and dashboard from silently drifting apart.

| CICIDS2017 label/family | World-model stage |
| --- | --- |
| `BENIGN` | Benign |
| `PortScan` / Reconnaissance | Reconnaissance |
| FTP/SSH Patator, web attacks, Heartbleed | Initial Access |
| Infiltration | Lateral Movement |
| Botnet | Command & Control |
| DoS / DDoS | Impact |

The final bucket is **Impact**. It intentionally groups disruptive outcomes for this demo;
it is never a claim that DoS is data exfiltration.

## Individual supported attack labels

The LSTM currently forecasts a **coarse stage**, not an exact attack label. The table below
is therefore a transparent reference for the labels compatible with a stage, not proof that
the forecast observed the named technique. Confirm every alert with endpoint, identity, and
where appropriate packet/application telemetry.

| Training label | ATT&CK tactic | Candidate technique | Why confirmation is required |
| --- | --- | --- | --- |
| `PortScan` | Discovery | T1046 Network Service Scanning | Flow diversity can resemble authorized inventory scans. |
| `FTP_Patator`, `SSH_Patator`, `Web_BruteForce` | Credential Access | T1110 Brute Force | Authentication logs establish whether credentials were actually guessed. |
| `Web_XSS`, `Web_SqlInjection`, `Heartbleed` | Initial Access | T1190 Exploit Public-Facing Application | A flow record contains no payload or exploit result. |
| `Infiltration` | Lateral Movement | T1021 Remote Services | CICIDS' broad label does not identify a remote-service technique. |
| `Botnet` | Command and Control | T1071 Application Layer Protocol | DNS, process, and timing evidence is needed to establish C2. |
| `DoS_Hulk`, `DoS_GoldenEye`, `DoS_Slowloris`, `DoS_Slowhttptest` | Impact | T1499 Endpoint Denial of Service | High volume alone can be legitimate. |
| `DDoS_LOIC` | Impact | T1498 Network Denial of Service | Confirm source distribution and upstream telemetry. |

## Training input

`python -m ai.training.train_world_model <csv>` accepts either the repository's
normalized upload CSV (`timestamp`, `src_ip`, …, `label`) or a raw CICIDS2017 CSV.
Raw CICIDS files are first passed through the existing dataset normalizer, then grouped
into the contract's 60-second windows. A real training dataset must contain more than
ten windows; the tiny demo replay is suitable for feature verification, not training.
