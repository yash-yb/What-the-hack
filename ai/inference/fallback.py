"""
Rule-based forecasting fallback (no ML dependencies).

Used when no trained model is registered, when the model times out or raises, or when
the backend is running the demo without artifacts. It scores three precursor families
described in docs/research/forecasting_formulation.md section 4 and returns a fully
contract-conformant InferenceResponse with ``is_fallback: true``.

Reference rules only: the trained model replaces this, it does not extend it.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from ai.inference.contract import (
    ALLOWED_HORIZONS_SEC,
    BASELINE_VALUES,
    DEFAULT_ALERT_THRESHOLD,
    DEFAULT_HORIZON_SEC,
    FEATURE_SCHEMA_VERSION,
    LOW_CONFIDENCE_THRESHOLD,
    InferenceError,
    risk_level_for,
    stage_for,
    validate_features,
)

FALLBACK_MODEL_NAME = "rule-fallback"
FALLBACK_MODEL_VERSION = "rule-fallback-v1.0.0"

MITIGATION = {
    "Reconnaissance": "Rate-limit the scanning source subnet, confirm exposed services on the probed ports, and raise logging on the targeted hosts.",
    "BruteForce": "Check failed-login bursts on the targeted service, enable account lockout or exponential back-off, and block the offending source range.",
    "DDoS": "Enable TCP SYN cookies, pre-stage upstream rate limiting, and inspect source concentration for a block list.",
    "BENIGN": "No action required. Continue monitoring.",
    "UNKNOWN": "Pattern unseen. Investigate manually and monitor the next windows before acting.",
}


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def _ramp(value: float, start: float, full: float) -> float:
    """0 below ``start``, 1 at or above ``full``, linear in between."""
    if full <= start:
        return 1.0 if value >= full else 0.0
    return _clamp01((value - start) / (full - start))


def _score_families(f: dict[str, float]) -> dict[str, tuple[float, list[tuple[str, float, str]]]]:
    """Return {family: (score in [0,1], [(feature, weight, description), ...])}."""
    recon_terms = [
        ("dst_port_entropy", 0.35 * _ramp(f["dst_port_entropy"], 1.8, 6.0),
         f"Destination port entropy {f['dst_port_entropy']:.2f} bits (baseline about 1.5): vertical scan pattern."),
        ("short_flow_ratio", 0.20 * _ramp(f["short_flow_ratio"], 0.3, 0.8),
         f"{f['short_flow_ratio']:.0%} of flows are shorter than 100 ms: ephemeral probe flows."),
        ("syn_ack_ratio", 0.25 * _ramp(f["syn_ack_ratio"], 2.0, 10.0),
         f"SYN/ACK asymmetry {f['syn_ack_ratio']:.1f}x: many handshakes never complete."),
        ("delta_unique_dst_ports", 0.20 * _ramp(f["delta_unique_dst_ports"], 5, 50),
         f"Distinct destination ports rose by {int(f['delta_unique_dst_ports'])} since the previous window."),
    ]
    brute_terms = [
        ("failed_conn_ratio", 0.40 * _ramp(f["failed_conn_ratio"], 0.15, 0.70),
         f"Failed connection ratio {f['failed_conn_ratio']:.0%} (baseline about 3%): repeated rejected attempts."),
        ("retry_rate", 0.25 * _ramp(f["retry_rate"], 0.10, 0.50),
         f"Retry rate {f['retry_rate']:.0%}: the same source keeps re-connecting to the same service."),
        ("rst_ratio", 0.15 * _ramp(f["rst_ratio"], 0.10, 0.50),
         f"RST ratio {f['rst_ratio']:.0%}: connections are being aborted after authentication attempts."),
        ("delta_failed_conn_ratio", 0.20 * _ramp(f["delta_failed_conn_ratio"], 0.05, 0.30),
         f"Failed connection ratio increased by {f['delta_failed_conn_ratio']:+.2f} since the previous window."),
    ]
    ddos_terms = [
        ("syn_burst_score", 0.30 * _ramp(f["syn_burst_score"], 1.5, 6.0),
         f"SYN burst score {f['syn_burst_score']:.1f}x the recent average: SYN flood build-up."),
        ("packet_burst_score", 0.25 * _ramp(f["packet_burst_score"], 1.5, 6.0),
         f"Packet volume {f['packet_burst_score']:.1f}x the recent average: volumetric surge."),
        ("syn_ratio", 0.20 * _ramp(f["syn_ratio"], 0.5, 0.9),
         f"{f['syn_ratio']:.0%} of flows are SYN-only: unreciprocated connection attempts."),
        ("src_ip_entropy", 0.15 * _ramp(f["src_ip_entropy"], 3.0, 7.0),
         f"Source IP entropy {f['src_ip_entropy']:.2f} bits: traffic from an unusually wide set of sources."),
        ("delta_packet_rate", 0.10 * _ramp(f["delta_packet_rate"], 50.0, 1000.0),
         f"Packet rate rose by {f['delta_packet_rate']:.0f} packets/s since the previous window."),
    ]
    return {
        "Reconnaissance": (_clamp01(sum(w for _, w, _ in recon_terms)), recon_terms),
        "BruteForce": (_clamp01(sum(w for _, w, _ in brute_terms)), brute_terms),
        "DDoS": (_clamp01(sum(w for _, w, _ in ddos_terms)), ddos_terms),
    }


def rule_based_forecast(request: dict[str, Any], fallback_reason: str = "MODEL_UNAVAILABLE") -> dict[str, Any]:
    """Score one InferenceRequest with the precursor rules. Raises InferenceError on bad input."""
    started = time.perf_counter()
    if not isinstance(request, dict):
        raise InferenceError("INVALID_FEATURES", "request must be an object")

    window_id = request.get("window_id")
    if not isinstance(window_id, str) or not window_id:
        raise InferenceError("INVALID_FEATURES", "window_id is required")
    horizon = request.get("requested_horizon_sec", DEFAULT_HORIZON_SEC)
    if horizon not in ALLOWED_HORIZONS_SEC:
        raise InferenceError("INVALID_FEATURES", f"requested_horizon_sec must be one of {list(ALLOWED_HORIZONS_SEC)}")
    threshold = float(request.get("alert_threshold", DEFAULT_ALERT_THRESHOLD))

    features = validate_features(request.get("features"), request.get("feature_schema_version", FEATURE_SCHEMA_VERSION))

    families = _score_families(features)
    ranked = sorted(families.items(), key=lambda item: item[1][0], reverse=True)
    top_family, (top_score, _) = ranked[0]
    second_score = ranked[1][1][0]

    # Composite probability: strongest family, nudged up when a second family also fires.
    probability = _clamp01(top_score + 0.15 * second_score * (1.0 - top_score))
    risk_score = round(100.0 * probability, 1)
    risk_level = risk_level_for(risk_score)

    if probability < 0.20:
        attack_type = "BENIGN"
    else:
        attack_type = top_family

    # Confident when the evidence is clearly benign or clearly malicious; least confident near 50.
    confidence = round(min(0.85, 0.45 + 0.40 * abs(2.0 * probability - 1.0)), 3)
    is_uncertain = confidence < LOW_CONFIDENCE_THRESHOLD

    contributions = [
        (name, weight, text)
        for _, (_, terms) in ranked
        for name, weight, text in terms
        if weight > 0.0
    ]
    contributions.sort(key=lambda item: item[1], reverse=True)
    total_weight = sum(w for _, w, _ in contributions) or 1.0
    top_features = [
        {
            "feature": name,
            "contribution": round(weight / total_weight, 3),
            "description": text,
            "feature_value": features[name],
            "baseline_value": BASELINE_VALUES.get(name, 0.0),
        }
        for name, weight, text in contributions[:3]
    ]
    if not top_features:
        top_features = [{
            "feature": "failed_conn_ratio",
            "contribution": 0.0,
            "description": "All precursor indicators are within their benign baselines.",
            "feature_value": features["failed_conn_ratio"],
            "baseline_value": BASELINE_VALUES["failed_conn_ratio"],
        }]

    if attack_type == "BENIGN":
        summary = f"Low attack risk in the next {horizon} seconds. Precursor indicators are within benign baselines."
    else:
        summary = (
            f"{risk_level.capitalize()} risk of {top_family} activity in the next {horizon} seconds: "
            + top_features[0]["description"]
        )
    if is_uncertain:
        summary = "Uncertain forecast. " + summary

    response: dict[str, Any] = {
        "window_id": window_id,
        "timestamp": request.get("timestamp") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "predicted_attack_type": attack_type,
        "forecast_horizon_sec": horizon,
        "confidence_score": confidence,
        "explanation_json": {
            "summary": summary,
            "top_features": top_features,
            "mitigation_recommendation": MITIGATION[attack_type],
            "model_version": FALLBACK_MODEL_VERSION,
            "method": "rule_based",
            "inference_latency_ms": round((time.perf_counter() - started) * 1000.0, 3),
        },
        "alert_triggered": risk_score >= threshold,
        "stage_progression": stage_for(risk_score),
        "is_fallback": True,
        "fallback_reason": fallback_reason,
        "is_uncertain": is_uncertain,
        "is_ood": False,
        "model_name": FALLBACK_MODEL_NAME,
        "model_version": FALLBACK_MODEL_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
    }
    return response
