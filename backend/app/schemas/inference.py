"""
Pydantic mirror of docs/api/feature_schema_contract.json (feature schema v1).

These models are the backend's validation boundary for the ML inference call. They must
stay in sync with ai/inference/contract.py; backend/tests/test_inference_schemas.py
checks the field list against the committed JSON contract.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

FEATURE_SCHEMA_VERSION = "v1"
ALLOWED_HORIZONS = (60, 120, 300)
DEFAULT_HORIZON_SEC = 300
DEFAULT_ALERT_THRESHOLD = 50.0
LOW_CONFIDENCE_THRESHOLD = 0.55

RiskLevel = Literal["low", "medium", "high", "critical"]
Horizon = Literal[60, 120, 300]
Stage = Literal["S0_BENIGN_BASELINE", "S1_RECON_PRECURSOR", "S2_WEAPONIZATION_ESCALATION", "S3_ACTIVE_PEAK"]
AttackType = Literal[
    "BENIGN",
    "PortScan", "DoS_Hulk", "DoS_GoldenEye", "DoS_Slowloris", "DoS_Slowhttptest", "Heartbleed", "DDoS_LOIC",
    "FTP_Patator", "SSH_Patator", "Botnet", "Web_BruteForce", "Web_XSS", "Web_SqlInjection", "Infiltration",
    "Reconnaissance", "BruteForce", "DoS", "DDoS", "WebAttack", "Botnet_C2",
    "UNKNOWN",
]
ErrorCode = Literal["FEATURE_SCHEMA_MISMATCH", "INVALID_FEATURES", "MODEL_UNAVAILABLE", "INFERENCE_TIMEOUT", "INTERNAL_ERROR"]
ExplanationMethod = Literal["treeshap", "feature_importance", "rule_based"]


class WindowFeaturesV1(BaseModel):
    """The 37-feature vector x_t. All fields required; extra fields rejected."""

    model_config = ConfigDict(extra="forbid")

    # Volume
    flow_count: int = Field(ge=0)
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)
    avg_packets_per_flow: float = Field(ge=0)
    avg_bytes_per_flow: float = Field(ge=0)
    avg_duration_ms: float = Field(ge=0)
    packet_length_mean: float = Field(ge=0)
    packet_length_std: float = Field(ge=0)
    # Diversity
    unique_src_ips: int = Field(ge=0)
    unique_dst_ips: int = Field(ge=0)
    unique_src_ports: int = Field(ge=0, le=65536)
    unique_dst_ports: int = Field(ge=0, le=65536)
    src_ip_entropy: float = Field(ge=0, le=32)
    dst_port_entropy: float = Field(ge=0, le=16)
    # Protocol mix
    protocol_tcp_ratio: float = Field(ge=0, le=1)
    protocol_udp_ratio: float = Field(ge=0, le=1)
    protocol_icmp_ratio: float = Field(ge=0, le=1)
    # TCP handshake health
    syn_ratio: float = Field(ge=0, le=1)
    ack_ratio: float = Field(ge=0, le=1)
    fin_ratio: float = Field(ge=0, le=1)
    rst_ratio: float = Field(ge=0, le=1)
    syn_ack_ratio: float = Field(ge=0)
    failed_conn_ratio: float = Field(ge=0, le=1)
    short_flow_ratio: float = Field(ge=0, le=1)
    inbound_outbound_ratio: float = Field(ge=0)
    retry_rate: float = Field(ge=0, le=1)
    # Rates
    packet_rate_per_sec: float = Field(ge=0)
    byte_rate_per_sec: float = Field(ge=0)
    flow_rate_per_sec: float = Field(ge=0)
    # Momentum
    packet_burst_score: float = Field(ge=0)
    syn_burst_score: float = Field(ge=0)
    # Deltas
    delta_packet_rate: float
    delta_byte_rate: float
    delta_syn_ratio: float = Field(ge=-1, le=1)
    delta_failed_conn_ratio: float = Field(ge=-1, le=1)
    delta_unique_dst_ports: int = Field(ge=-65536, le=65536)
    delta_packet_burst_score: float


class InferenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
    timestamp: str
    features: WindowFeaturesV1
    requested_horizon_sec: Horizon = DEFAULT_HORIZON_SEC
    feature_schema_version: Literal["v1"] = FEATURE_SCHEMA_VERSION
    sensor_id: str | None = Field(default=None, max_length=128)
    tenant_id: str | None = Field(default=None, max_length=128)
    include_explanation: bool = True
    alert_threshold: float = Field(default=DEFAULT_ALERT_THRESHOLD, ge=0, le=100)
    previous_windows: list[WindowFeaturesV1] | None = Field(default=None, max_length=3)


class ExplanationFeature(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feature: str
    contribution: float
    description: str = Field(min_length=1)
    feature_value: float | None = None
    baseline_value: float | None = None


class Explanation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1)
    top_features: list[ExplanationFeature] = Field(min_length=1, max_length=10)
    mitigation_recommendation: str | None = None
    model_version: str | None = None
    method: ExplanationMethod | None = None
    inference_latency_ms: float | None = Field(default=None, ge=0)


class InferenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_id: str
    timestamp: str
    risk_score: float = Field(ge=0, le=100)
    risk_level: RiskLevel
    predicted_attack_type: AttackType
    forecast_horizon_sec: Horizon
    confidence_score: float = Field(ge=0, le=1)
    explanation_json: Explanation
    alert_triggered: bool | None = None
    stage_progression: Stage | None = None
    is_fallback: bool = False
    fallback_reason: str | None = None
    is_uncertain: bool = False
    is_ood: bool = False
    model_name: str | None = None
    model_version: str | None = None
    feature_schema_version: Literal["v1"] | None = None


class InferenceErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error_code: ErrorCode
    message: str
    details: dict = Field(default_factory=dict)
    window_id: str | None = None
    feature_schema_version: str | None = None


def risk_level_for(risk_score: float) -> RiskLevel:
    """Bands from the contract: <20 low, <50 medium, <75 high, else critical."""
    if risk_score < 20.0:
        return "low"
    if risk_score < 50.0:
        return "medium"
    if risk_score < 75.0:
        return "high"
    return "critical"
