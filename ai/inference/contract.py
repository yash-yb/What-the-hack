"""
Single source of truth for the ML <-> backend contract (feature schema v1).

Everything in docs/api/feature_schema_contract.json that describes features, enums,
bands, and thresholds is generated from this module by
ai/feature_engineering/build_feature_schema_contract.py. Change it here, regenerate,
and bump CONTRACT_VERSION.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

CONTRACT_VERSION = "1.0.0"
FEATURE_SCHEMA_VERSION = "v1"

# --- Forecast horizon -------------------------------------------------------------
ALLOWED_HORIZONS_SEC = (60, 120, 300)
DEFAULT_HORIZON_SEC = 300

# --- Risk bands (research doc section 8, stage 6) -------------------------------
RISK_LEVELS = ("low", "medium", "high", "critical")
RISK_LEVEL_BANDS = {
    "low": (0.0, 20.0),
    "medium": (20.0, 50.0),
    "high": (50.0, 75.0),
    "critical": (75.0, 100.0),
}
DEFAULT_ALERT_THRESHOLD = 50.0

STAGES = (
    "S0_BENIGN_BASELINE",
    "S1_RECON_PRECURSOR",
    "S2_WEAPONIZATION_ESCALATION",
    "S3_ACTIVE_PEAK",
)

# --- Confidence / OOD ---------------------------------------------------------------
LOW_CONFIDENCE_THRESHOLD = 0.55   # confidence_score below this => is_uncertain
OOD_ZSCORE_THRESHOLD = 6.0        # |z| above this on >= OOD_MIN_FEATURES features => is_ood
OOD_MIN_FEATURES = 3
INFERENCE_TIMEOUT_SEC = 2.0       # backend deadline before switching to the fallback

# --- Attack-type taxonomy -------------------------------------------------------------
# Canonical CICIDS2017 labels (ai/datasets/download_cicids2017.py LABEL_MAPPING values).
CANONICAL_ATTACK_LABELS = (
    "PortScan",
    "DoS_Hulk",
    "DoS_GoldenEye",
    "DoS_Slowloris",
    "DoS_Slowhttptest",
    "Heartbleed",
    "DDoS_LOIC",
    "FTP_Patator",
    "SSH_Patator",
    "Botnet",
    "Web_BruteForce",
    "Web_XSS",
    "Web_SqlInjection",
    "Infiltration",
)
# Coarse families a model (or the fallback) may return when it cannot be more specific.
ATTACK_FAMILIES = ("Reconnaissance", "BruteForce", "DoS", "DDoS", "WebAttack", "Botnet_C2", "Infiltration")
ATTACK_TYPES = ("BENIGN",) + CANONICAL_ATTACK_LABELS + ATTACK_FAMILIES + ("UNKNOWN",)

LABEL_TO_FAMILY = {
    "PortScan": "Reconnaissance",
    "DoS_Hulk": "DoS",
    "DoS_GoldenEye": "DoS",
    "DoS_Slowloris": "DoS",
    "DoS_Slowhttptest": "DoS",
    "Heartbleed": "DoS",
    "DDoS_LOIC": "DDoS",
    "FTP_Patator": "BruteForce",
    "SSH_Patator": "BruteForce",
    "Botnet": "Botnet_C2",
    "Web_BruteForce": "WebAttack",
    "Web_XSS": "WebAttack",
    "Web_SqlInjection": "WebAttack",
    "Infiltration": "Infiltration",
}

# --- Feature specification -------------------------------------------------------------
# missing rule vocabulary:
#   no_flows_reject            window with zero flows is rejected before inference
#   zero_if_denominator_zero   ratio evaluates to 0.0 when its denominator is 0
#   zero_if_no_previous_window delta features are 0.0 for the first window of a source
#   one_if_no_history          burst scores are 1.0 (neutral) until 3 prior windows exist
#   always_defined             count/sum that is always computable for a non-empty window
# Any NaN/inf/missing value after these rules => request rejected (INVALID_FEATURES).


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    type: str            # "integer" | "number"
    unit: str
    minimum: float | None
    maximum: float | None
    missing_rule: str
    description: str


FEATURE_SPECS: tuple[FeatureSpec, ...] = (
    # Volume
    FeatureSpec("flow_count", "integer", "flows", 0, None, "no_flows_reject", "Distinct 5-tuples in the window."),
    FeatureSpec("packet_count", "integer", "packets", 0, None, "always_defined", "Sum of packets over all flows."),
    FeatureSpec("byte_count", "integer", "bytes", 0, None, "always_defined", "Sum of bytes over all flows."),
    FeatureSpec("avg_packets_per_flow", "number", "packets/flow", 0, None, "zero_if_denominator_zero", "packet_count / flow_count."),
    FeatureSpec("avg_bytes_per_flow", "number", "bytes/flow", 0, None, "zero_if_denominator_zero", "byte_count / flow_count."),
    FeatureSpec("avg_duration_ms", "number", "milliseconds", 0, None, "zero_if_denominator_zero", "Mean flow duration."),
    FeatureSpec("packet_length_mean", "number", "bytes", 0, None, "zero_if_denominator_zero", "Mean packet size, byte_count / packet_count."),
    FeatureSpec("packet_length_std", "number", "bytes", 0, None, "zero_if_denominator_zero", "Std. dev. of per-flow mean packet size."),
    # Diversity
    FeatureSpec("unique_src_ips", "integer", "hosts", 0, None, "always_defined", "Distinct source IPs."),
    FeatureSpec("unique_dst_ips", "integer", "hosts", 0, None, "always_defined", "Distinct destination IPs."),
    FeatureSpec("unique_src_ports", "integer", "ports", 0, 65536, "always_defined", "Distinct source ports."),
    FeatureSpec("unique_dst_ports", "integer", "ports", 0, 65536, "always_defined", "Distinct destination ports."),
    FeatureSpec("src_ip_entropy", "number", "bits", 0, 32, "zero_if_denominator_zero", "Shannon entropy of source IP distribution over flows."),
    FeatureSpec("dst_port_entropy", "number", "bits", 0, 16, "zero_if_denominator_zero", "Shannon entropy of destination port distribution over flows."),
    # Protocol mix
    FeatureSpec("protocol_tcp_ratio", "number", "ratio", 0, 1, "zero_if_denominator_zero", "TCP flows / flow_count."),
    FeatureSpec("protocol_udp_ratio", "number", "ratio", 0, 1, "zero_if_denominator_zero", "UDP flows / flow_count."),
    FeatureSpec("protocol_icmp_ratio", "number", "ratio", 0, 1, "zero_if_denominator_zero", "ICMP flows / flow_count."),
    # TCP handshake health (flags parsed from RawFlow.flags; non-TCP flows count as no flags)
    FeatureSpec("syn_ratio", "number", "ratio", 0, 1, "zero_if_denominator_zero", "Flows carrying SYN / flow_count."),
    FeatureSpec("ack_ratio", "number", "ratio", 0, 1, "zero_if_denominator_zero", "Flows carrying ACK / flow_count."),
    FeatureSpec("fin_ratio", "number", "ratio", 0, 1, "zero_if_denominator_zero", "Flows carrying FIN / flow_count."),
    FeatureSpec("rst_ratio", "number", "ratio", 0, 1, "zero_if_denominator_zero", "Flows carrying RST / flow_count."),
    FeatureSpec("syn_ack_ratio", "number", "ratio", 0, None, "always_defined", "SYN flows / (ACK flows + 1). Handshake asymmetry; ~1.0 is healthy."),
    FeatureSpec("failed_conn_ratio", "number", "ratio", 0, 1, "zero_if_denominator_zero", "Flows with failed_conn_info in {SYN_NO_ACK, RST_ABORT, ZERO_WIN} / flow_count."),
    FeatureSpec("short_flow_ratio", "number", "ratio", 0, 1, "zero_if_denominator_zero", "Flows with duration_ms < 100 / flow_count."),
    FeatureSpec("inbound_outbound_ratio", "number", "ratio", 0, None, "zero_if_denominator_zero", "Flows into the monitored subnet / (flows out + 1)."),
    FeatureSpec("retry_rate", "number", "ratio", 0, 1, "zero_if_denominator_zero", "Flows repeating an earlier (src_ip, dst_ip, dst_port) in the window / flow_count."),
    # Rates
    FeatureSpec("packet_rate_per_sec", "number", "packets/s", 0, None, "always_defined", "packet_count / window_size_sec."),
    FeatureSpec("byte_rate_per_sec", "number", "bytes/s", 0, None, "always_defined", "byte_count / window_size_sec."),
    FeatureSpec("flow_rate_per_sec", "number", "flows/s", 0, None, "always_defined", "flow_count / window_size_sec."),
    # Momentum (lookback = 3 previous windows)
    FeatureSpec("packet_burst_score", "number", "multiplier", 0, None, "one_if_no_history", "packet_count / (mean packet_count of previous 3 windows + 1)."),
    FeatureSpec("syn_burst_score", "number", "multiplier", 0, None, "one_if_no_history", "SYN flows / (mean SYN flows of previous 3 windows + 1)."),
    # Deltas vs previous window
    FeatureSpec("delta_packet_rate", "number", "packets/s", None, None, "zero_if_no_previous_window", "packet_rate_per_sec minus previous window."),
    FeatureSpec("delta_byte_rate", "number", "bytes/s", None, None, "zero_if_no_previous_window", "byte_rate_per_sec minus previous window."),
    FeatureSpec("delta_syn_ratio", "number", "ratio", -1, 1, "zero_if_no_previous_window", "syn_ratio minus previous window."),
    FeatureSpec("delta_failed_conn_ratio", "number", "ratio", -1, 1, "zero_if_no_previous_window", "failed_conn_ratio minus previous window."),
    FeatureSpec("delta_unique_dst_ports", "integer", "ports", -65536, 65536, "zero_if_no_previous_window", "unique_dst_ports minus previous window."),
    FeatureSpec("delta_packet_burst_score", "number", "multiplier", None, None, "zero_if_no_previous_window", "packet_burst_score minus previous window."),
)

FEATURE_NAMES: tuple[str, ...] = tuple(spec.name for spec in FEATURE_SPECS)
FEATURE_BY_NAME = {spec.name: spec for spec in FEATURE_SPECS}
assert len(FEATURE_NAMES) == 37

# Typical benign (S0) values used as baselines in explanations.
BASELINE_VALUES = {
    "syn_ack_ratio": 1.0,
    "failed_conn_ratio": 0.03,
    "dst_port_entropy": 1.5,
    "src_ip_entropy": 2.0,
    "short_flow_ratio": 0.10,
    "syn_ratio": 0.30,
    "rst_ratio": 0.02,
    "retry_rate": 0.02,
    "packet_burst_score": 1.0,
    "syn_burst_score": 1.0,
    "delta_failed_conn_ratio": 0.0,
    "delta_unique_dst_ports": 0,
    "delta_packet_rate": 0.0,
}


class InferenceError(Exception):
    """Raised for requests the model must refuse. ``code`` is one of ERROR_CODES."""

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {"error_code": self.code, "message": self.message, "details": self.details}


ERROR_CODES = {
    "FEATURE_SCHEMA_MISMATCH": "feature_schema_version differs from the version the model was trained on; fail closed, audit, no fallback.",
    "INVALID_FEATURES": "A feature is missing, non-numeric, NaN/inf, or outside its contract bounds; fail closed, no fallback.",
    "MODEL_UNAVAILABLE": "No active model artifact could be loaded; the backend uses the rule-based fallback.",
    "INFERENCE_TIMEOUT": "The model did not answer within INFERENCE_TIMEOUT_SEC; the backend uses the rule-based fallback.",
    "INTERNAL_ERROR": "Unexpected exception inside the model; the backend uses the rule-based fallback and logs the trace.",
}


def risk_level_for(risk_score: float) -> str:
    if risk_score < 20.0:
        return "low"
    if risk_score < 50.0:
        return "medium"
    if risk_score < 75.0:
        return "high"
    return "critical"


def stage_for(risk_score: float) -> str:
    return STAGES[RISK_LEVELS.index(risk_level_for(risk_score))]


def validate_features(features: Any, schema_version: str = FEATURE_SCHEMA_VERSION) -> dict[str, float]:
    """
    Enforce the v1 feature contract. Returns a clean dict of floats/ints in FEATURE_NAMES order.
    Raises InferenceError(FEATURE_SCHEMA_MISMATCH | INVALID_FEATURES).
    """
    if schema_version != FEATURE_SCHEMA_VERSION:
        raise InferenceError(
            "FEATURE_SCHEMA_MISMATCH",
            f"Expected feature_schema_version {FEATURE_SCHEMA_VERSION!r}, got {schema_version!r}",
            {"expected": FEATURE_SCHEMA_VERSION, "received": schema_version},
        )
    if not isinstance(features, dict):
        raise InferenceError("INVALID_FEATURES", "features must be an object")

    missing = [name for name in FEATURE_NAMES if name not in features]
    extra = sorted(set(features) - set(FEATURE_NAMES))
    if missing or extra:
        raise InferenceError(
            "INVALID_FEATURES",
            "Feature set does not match schema v1",
            {"missing": missing, "unexpected": extra},
        )

    problems: dict[str, str] = {}
    clean: dict[str, float] = {}
    for spec in FEATURE_SPECS:
        value = features[spec.name]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            problems[spec.name] = "not numeric"
            continue
        if math.isnan(value) or math.isinf(value):
            problems[spec.name] = "NaN or inf"
            continue
        if spec.type == "integer" and float(value) != int(value):
            problems[spec.name] = "must be an integer"
            continue
        if spec.minimum is not None and value < spec.minimum:
            problems[spec.name] = f"below minimum {spec.minimum}"
            continue
        if spec.maximum is not None and value > spec.maximum:
            problems[spec.name] = f"above maximum {spec.maximum}"
            continue
        clean[spec.name] = int(value) if spec.type == "integer" else float(value)

    if problems:
        raise InferenceError("INVALID_FEATURES", "One or more features violate the contract", {"violations": problems})
    if clean["flow_count"] == 0:
        raise InferenceError("INVALID_FEATURES", "Window has zero flows; nothing to forecast", {"violations": {"flow_count": "must be >= 1"}})
    return clean
