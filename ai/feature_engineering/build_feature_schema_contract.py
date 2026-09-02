#!/usr/bin/env python3
"""
Generate docs/api/feature_schema_contract.json (Deliverable R3) from ai/inference/contract.py.

Run from the repository root:

    python3 ai/feature_engineering/build_feature_schema_contract.py

The JSON is committed so that the backend, the frontend, and CI can read the contract
without importing Python. Regenerate it whenever ai/inference/contract.py changes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ai.datasets.download_cicids2017 import STANDARD_84_HEADERS, clean_cicids_header  # noqa: E402
from ai.inference import contract as c  # noqa: E402

OUTPUT_PATH = REPO_ROOT / "docs" / "api" / "feature_schema_contract.json"

IPV4 = r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
IPV6 = r"^(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}$"
ISO_TIMESTAMP = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$"
TCP_FLAG = "(?:SYN|ACK|FIN|RST|PSH|URG|ECE|CWE)"
FLAGS = rf"^(?:NONE|{TCP_FLAG}(?:,{TCP_FLAG})*)$"

RAW_FLOW_LABELS = ["BENIGN", *c.CANONICAL_ATTACK_LABELS]


def ip_schema(description: str) -> dict:
    return {
        "description": description,
        "type": "string",
        "anyOf": [{"pattern": IPV4}, {"pattern": IPV6}],
    }


def raw_flow_definition() -> dict:
    return {
        "title": "RawFlow",
        "description": "One normalised network flow as stored in raw_flows and as produced by the CSV/CICIDS2017 ingestion path.",
        "type": "object",
        "additionalProperties": False,
        "required": ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp", "packets", "bytes", "duration_ms", "flags", "failed_conn_info", "label"],
        "properties": {
            "src_ip": ip_schema("Source IPv4 or IPv6 address."),
            "dst_ip": ip_schema("Destination IPv4 or IPv6 address."),
            "src_port": {"type": "integer", "minimum": 0, "maximum": 65535, "description": "Source port; 0 for ICMP/OTHER."},
            "dst_port": {"type": "integer", "minimum": 0, "maximum": 65535, "description": "Destination port; 0 for ICMP/OTHER."},
            "protocol": {"type": "string", "enum": ["TCP", "UDP", "ICMP", "OTHER"]},
            "timestamp": {"type": "string", "pattern": ISO_TIMESTAMP, "description": "Flow start time, ISO-8601 UTC."},
            "packets": {"type": "integer", "minimum": 1, "description": "Forward + backward packets."},
            "bytes": {"type": "integer", "minimum": 0, "description": "Forward + backward payload bytes."},
            "duration_ms": {"type": "number", "minimum": 0.0, "description": "Flow duration in milliseconds."},
            "flags": {"type": "string", "pattern": FLAGS, "description": "Comma-separated TCP flags seen in the flow, or NONE."},
            "failed_conn_info": {"type": "string", "enum": ["CLEAN", "SYN_NO_ACK", "RST_ABORT", "ZERO_WIN", "NA"], "description": "TCP connection health; NA for non-TCP."},
            "label": {"type": "string", "enum": RAW_FLOW_LABELS, "description": "Ground-truth label when the source is a labelled dataset."},
        },
    }


def traffic_window_definition() -> dict:
    return {
        "title": "TrafficWindow",
        "description": "Metadata for one observation window W(t) = [window_start, window_end).",
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "window_start", "window_end", "duration_sec", "flow_count", "stride_sec"],
        "properties": {
            "id": {"type": "string", "pattern": IDENTIFIER},
            "window_start": {"type": "string", "pattern": ISO_TIMESTAMP},
            "window_end": {"type": "string", "pattern": ISO_TIMESTAMP},
            "duration_sec": {"type": "number", "minimum": 1.0},
            "flow_count": {"type": "integer", "minimum": 0},
            "stride_sec": {"type": "number", "minimum": 0.1},
            "profile": {"type": "string", "enum": ["micro", "standard", "macro"]},
            "packet_count": {"type": "integer", "minimum": 0},
            "byte_count": {"type": "integer", "minimum": 0},
            "scope_type": {"type": "string", "enum": ["source", "host", "flow"]},
            "scope_key": {"type": "string"},
        },
    }


def window_features_definition() -> dict:
    props = {}
    for spec in c.FEATURE_SPECS:
        prop: dict = {"type": spec.type, "unit": spec.unit, "missing_rule": spec.missing_rule, "description": spec.description}
        if spec.minimum is not None:
            prop["minimum"] = float(spec.minimum) if spec.type == "number" else int(spec.minimum)
        if spec.maximum is not None:
            prop["maximum"] = float(spec.maximum) if spec.type == "number" else int(spec.maximum)
        props[spec.name] = prop
    return {
        "title": "WindowFeatures",
        "description": f"Feature vector x_t for one window, schema {c.FEATURE_SCHEMA_VERSION}. All {len(c.FEATURE_SPECS)} features are required; no extras.",
        "type": "object",
        "additionalProperties": False,
        "required": list(c.FEATURE_NAMES),
        "properties": props,
    }


def inference_request_definition() -> dict:
    return {
        "title": "InferenceRequest",
        "description": "Backend -> model call for one window. Python: ai.inference.forecast(request).",
        "type": "object",
        "additionalProperties": False,
        "required": ["window_id", "timestamp", "features", "requested_horizon_sec"],
        "properties": {
            "window_id": {"type": "string", "pattern": IDENTIFIER, "description": "traffic_windows.id (UUID or replay id)."},
            "timestamp": {"type": "string", "pattern": ISO_TIMESTAMP, "description": "window_end of the observation window (the forecast epoch t)."},
            "features": {"$ref": "#/definitions/WindowFeatures"},
            "requested_horizon_sec": {"type": "integer", "enum": list(c.ALLOWED_HORIZONS_SEC), "default": c.DEFAULT_HORIZON_SEC},
            "feature_schema_version": {"type": "string", "const": c.FEATURE_SCHEMA_VERSION, "default": c.FEATURE_SCHEMA_VERSION},
            "sensor_id": {"type": "string", "maxLength": 128},
            "tenant_id": {"type": "string", "maxLength": 128},
            "include_explanation": {"type": "boolean", "default": True},
            "alert_threshold": {"type": "number", "minimum": 0.0, "maximum": 100.0, "default": c.DEFAULT_ALERT_THRESHOLD},
            "previous_windows": {
                "type": "array",
                "maxItems": 3,
                "description": "Optional: up to 3 preceding feature vectors, oldest first, for sequence-aware models.",
                "items": {"$ref": "#/definitions/WindowFeatures"},
            },
        },
    }


def explanation_definitions() -> dict:
    return {
        "ExplanationFeature": {
            "type": "object",
            "additionalProperties": False,
            "required": ["feature", "contribution", "description"],
            "properties": {
                "feature": {"type": "string", "enum": list(c.FEATURE_NAMES)},
                "contribution": {"type": "number", "description": "Signed share of the risk attributed to this feature (SHAP value or normalised rule weight)."},
                "description": {"type": "string", "minLength": 1, "description": "One analyst-readable sentence."},
                "feature_value": {"type": "number"},
                "baseline_value": {"type": "number"},
            },
        },
        "Explanation": {
            "type": "object",
            "additionalProperties": False,
            "required": ["summary", "top_features"],
            "properties": {
                "summary": {"type": "string", "minLength": 1},
                "top_features": {"type": "array", "minItems": 1, "maxItems": 10, "items": {"$ref": "#/definitions/ExplanationFeature"}},
                "mitigation_recommendation": {"type": "string"},
                "model_version": {"type": "string"},
                "method": {"type": "string", "enum": ["treeshap", "feature_importance", "rule_based"]},
                "inference_latency_ms": {"type": "number", "minimum": 0.0},
            },
        },
        "InferenceError": {
            "type": "object",
            "additionalProperties": False,
            "required": ["error_code", "message"],
            "properties": {
                "error_code": {"type": "string", "enum": sorted(c.ERROR_CODES)},
                "message": {"type": "string"},
                "details": {"type": "object"},
                "window_id": {"type": "string"},
                "feature_schema_version": {"type": "string"},
            },
        },
    }


def inference_response_definition() -> dict:
    return {
        "title": "InferenceResponse",
        "description": "Model -> backend result for one window. Persisted into predictions; alerts are derived from it.",
        "type": "object",
        "additionalProperties": False,
        "required": ["window_id", "timestamp", "risk_score", "risk_level", "predicted_attack_type", "forecast_horizon_sec", "confidence_score", "explanation_json"],
        "properties": {
            "window_id": {"type": "string", "pattern": IDENTIFIER},
            "timestamp": {"type": "string", "pattern": ISO_TIMESTAMP, "description": "Forecast epoch t; the forecast covers (t, t + forecast_horizon_sec]."},
            "risk_score": {"type": "number", "minimum": 0.0, "maximum": 100.0},
            "risk_level": {"type": "string", "enum": list(c.RISK_LEVELS)},
            "predicted_attack_type": {"type": "string", "enum": list(c.ATTACK_TYPES), "description": "BENIGN when no attack is forecast; UNKNOWN when out-of-distribution."},
            "forecast_horizon_sec": {"type": "integer", "enum": list(c.ALLOWED_HORIZONS_SEC)},
            "confidence_score": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "explanation_json": {"$ref": "#/definitions/Explanation"},
            "alert_triggered": {"type": "boolean", "description": "risk_score >= alert_threshold."},
            "stage_progression": {"type": "string", "enum": list(c.STAGES)},
            "is_fallback": {"type": "boolean", "default": False},
            "fallback_reason": {"type": "string", "enum": sorted(c.ERROR_CODES) + ["MODEL_ERROR"]},
            "is_uncertain": {"type": "boolean", "default": False, "description": f"confidence_score < {c.LOW_CONFIDENCE_THRESHOLD}."},
            "is_ood": {"type": "boolean", "default": False, "description": "Feature vector is outside the training envelope."},
            "model_name": {"type": "string"},
            "model_version": {"type": "string"},
            "feature_schema_version": {"type": "string", "const": c.FEATURE_SCHEMA_VERSION},
        },
    }


# ---------------------------------------------------------------------------
# CICIDS2017 85-column mapping
# ---------------------------------------------------------------------------

FLAG_INPUT = ("RawFlow", "flags", "string", "input to synthesize_tcp_flags(): count > 0 adds the flag token", "sanitize_inf_nan -> int")
FAILED_INPUT = ("RawFlow", "failed_conn_info", "string", "input to classify_failed_connection(): RST>0 -> RST_ABORT; SYN>0 and ACK==0 -> SYN_NO_ACK; Init_Win_bwd==0 and Init_Win_fwd>0 and duration>1000ms -> ZERO_WIN; else CLEAN; non-TCP -> NA", "sanitize_inf_nan -> float")
DROP = ("dropped", None, None, "not used by feature schema v1; retained in extra_json by the ingestion parser only when present in the uploaded CSV", "none")

COLUMN_RULES: dict[str, tuple] = {
    "Flow ID": ("dropped", None, None, "not stored; the 5-tuple is reconstructed from the address/port/protocol columns", "none"),
    "Source IP": ("RawFlow", "src_ip", "string", "strip whitespace; empty -> 192.168.10.50 (synthetic placeholder)", "strip"),
    "Source Port": ("RawFlow", "src_port", "integer", "to_numeric, clip to [0, 65535]", "coerce -> 0"),
    "Destination IP": ("RawFlow", "dst_ip", "string", "strip whitespace; empty -> 172.16.0.1 (synthetic placeholder)", "strip"),
    "Destination Port": ("RawFlow", "dst_port", "integer", "to_numeric, clip to [0, 65535]", "coerce -> 0"),
    "Protocol": ("RawFlow", "protocol", "string", "6 -> TCP, 17 -> UDP, 1 -> ICMP, anything else -> OTHER", "coerce -> TCP"),
    "Timestamp": ("RawFlow", "timestamp", "string", "parse_flexible_timestamp(): dd/MM/yyyy and M/d/yyyy variants -> ISO-8601 UTC", "invalid -> ingestion time"),
    "Flow Duration": ("RawFlow", "duration_ms", "number", "microseconds / 1000, clamp >= 0", "sanitize_inf_nan -> 0.0"),
    "Total Fwd Packets": ("RawFlow", "packets", "integer", "packets = max(1, Total Fwd Packets + Total Backward Packets)", "coerce -> 0"),
    "Total Backward Packets": ("RawFlow", "packets", "integer", "packets = max(1, Total Fwd Packets + Total Backward Packets)", "coerce -> 0"),
    "Total Length of Fwd Packets": ("RawFlow", "bytes", "integer", "bytes = max(0, Total Length of Fwd Packets + Total Length of Bwd Packets)", "coerce -> 0"),
    "Total Length of Bwd Packets": ("RawFlow", "bytes", "integer", "bytes = max(0, Total Length of Fwd Packets + Total Length of Bwd Packets)", "coerce -> 0"),
    "Flow Bytes/s": ("WindowFeatures", "byte_rate_per_sec", "number", "not copied per flow; byte_rate_per_sec is recomputed per window as byte_count / window_size_sec", "replace inf/-inf/NaN -> 0.0"),
    "Flow Packets/s": ("WindowFeatures", "packet_rate_per_sec", "number", "not copied per flow; packet_rate_per_sec is recomputed per window as packet_count / window_size_sec", "replace inf/-inf/NaN -> 0.0"),
    "Fwd PSH Flags": FLAG_INPUT,
    "Bwd PSH Flags": FLAG_INPUT,
    "Fwd URG Flags": FLAG_INPUT,
    "Bwd URG Flags": FLAG_INPUT,
    "Packet Length Mean": ("WindowFeatures", "packet_length_mean", "number", "per-window mean of per-flow means, weighted by packets", "sanitize_inf_nan -> 0.0"),
    "Packet Length Std": ("WindowFeatures", "packet_length_std", "number", "per-window std of per-flow means", "sanitize_inf_nan -> 0.0"),
    "FIN Flag Count": FLAG_INPUT,
    "SYN Flag Count": FAILED_INPUT,
    "RST Flag Count": FAILED_INPUT,
    "PSH Flag Count": FLAG_INPUT,
    "ACK Flag Count": FAILED_INPUT,
    "URG Flag Count": FLAG_INPUT,
    "CWE Flag Count": FLAG_INPUT,
    "ECE Flag Count": FLAG_INPUT,
    "Down/Up Ratio": ("WindowFeatures", "inbound_outbound_ratio", "number", "reference only; v1 computes inbound_outbound_ratio from flow direction relative to the monitored subnet", "sanitize_inf_nan -> 0.0"),
    "Fwd Header Length.1": ("dropped", None, None, "duplicate of column 41; dropped by map_cicids_to_raw_flows()", "drop duplicate column"),
    "Init_Win_bytes_forward": FAILED_INPUT,
    "Init_Win_bytes_backward": FAILED_INPUT,
    "Label": ("RawFlow", "label", "string", "LABEL_MAPPING: normalise case, hyphen and en-dash variants, and the 'Infilteration' typo to the canonical label set", "unknown -> BENIGN with a warning"),
}


def column_mapping() -> dict:
    mapping = {}
    for index, raw_header in enumerate(STANDARD_84_HEADERS, start=1):
        sanitized = clean_cicids_header(raw_header)
        entity, field, ftype, rule, cleaning = COLUMN_RULES.get(sanitized, DROP)
        mapping[sanitized] = {
            "column_index": index,
            "raw_header": raw_header,
            "sanitized_name": sanitized,
            "target_entity": entity,
            "target_field": field,
            "target_type": ftype,
            "transformation_rule": rule,
            "cleaning_action": cleaning,
        }
    assert len(mapping) == 85, len(mapping)
    return mapping


def windowing_parameters() -> dict:
    return {
        "description": "Sliding-window profiles. Training uses the macro profile with a 10 s stride; the backend MVP materialises fixed (stride = window) 60 s windows and will move to the 10 s stride in the strong version.",
        "micro": {"window_size_sec": 10, "stride_sec": 2, "overlap_ratio": 0.8, "forecast_horizon_sec": 60},
        "standard": {"window_size_sec": 30, "stride_sec": 5, "overlap_ratio": 0.8333, "forecast_horizon_sec": 120},
        "macro": {"window_size_sec": 60, "stride_sec": 10, "overlap_ratio": 0.8333, "forecast_horizon_sec": 300},
        "default_window_profile": "macro",
        "backend_mvp_stride_sec": 60,
        "default_forecast_horizon_sec": c.DEFAULT_HORIZON_SEC,
        "allowed_forecast_horizons_sec": list(c.ALLOWED_HORIZONS_SEC),
        "short_flow_threshold_ms": 100,
        "burst_lookback_windows": 3,
        "delta_lookback_windows": 1,
        "label_rule": "y_t = 1 if any flow with label != BENIGN starts in (t, t + forecast_horizon_sec]; the observation window itself is never used for the label.",
        "anti_leakage_invariants": {
            "formula": "purge_buffer_sec >= window_size_sec + forecast_horizon_sec",
            "zero_lookahead_filtration": True,
            "micro_purge_buffer_sec": 70,
            "standard_purge_buffer_sec": 150,
            "macro_purge_buffer_sec": 360,
            "split_rule": "Chronological train/validation/test split; drop every window whose forecast horizon crosses a split boundary (purge embargo).",
        },
    }


def contract_decisions() -> dict:
    return {
        "feature_schema_version": c.FEATURE_SCHEMA_VERSION,
        "feature_count": len(c.FEATURE_SPECS),
        "forecast_horizon": {
            "default_sec": c.DEFAULT_HORIZON_SEC,
            "allowed_sec": list(c.ALLOWED_HORIZONS_SEC),
            "semantics": "Forecast covers (t, t + horizon] where t = observation window_end. It is not a label for the observation window.",
        },
        "risk_level_bands": {level: {"min_inclusive": lo, "max_exclusive": hi if level != "critical" else None} for level, (lo, hi) in c.RISK_LEVEL_BANDS.items()},
        "default_alert_threshold": c.DEFAULT_ALERT_THRESHOLD,
        "attack_type_taxonomy": {
            "benign": "BENIGN",
            "unknown": "UNKNOWN",
            "canonical_labels": list(c.CANONICAL_ATTACK_LABELS),
            "families": list(c.ATTACK_FAMILIES),
            "label_to_family": dict(c.LABEL_TO_FAMILY),
            "rule": "Return a canonical label when the model is trained for it; otherwise the family. BENIGN when risk_score < 20. UNKNOWN when is_ood is true.",
        },
        "missing_data_policy": {
            "no_flows_reject": "A window with flow_count = 0 is not sent to the model; the backend stores window_features.is_complete = false.",
            "zero_if_denominator_zero": "Ratios and averages whose denominator is 0 are 0.0.",
            "zero_if_no_previous_window": "delta_* features are 0.0 for the first window of a traffic source.",
            "one_if_no_history": "packet_burst_score and syn_burst_score are 1.0 until three prior windows exist.",
            "always_defined": "Counts and sums are always computable for a non-empty window.",
            "nan_or_inf": "Any NaN/inf/missing feature after the rules above => INVALID_FEATURES; the request is rejected, no imputation, no fallback.",
            "imputation": "No mean/median imputation in v1. Revisit only with training-set statistics stored in model_versions.metrics_json.",
        },
        "inference_interface": {
            "mode": "in_process_python",
            "call": "ai.inference.forecast(request: dict) -> dict",
            "raises": "ai.inference.InferenceError with .code in [FEATURE_SCHEMA_MISMATCH, INVALID_FEATURES]",
            "timeout_sec": c.INFERENCE_TIMEOUT_SEC,
            "http_equivalent": {"method": "POST", "path": "/internal/predict", "note": "Same request/response bodies. Reserved for the strong version when inference moves to its own container; not exposed in the MVP."},
            "model_dependencies": "The fallback is pure Python. The trained model adds xgboost (and optionally shap) to backend/requirements.txt when it ships.",
        },
        "failure_behaviour": {
            "low_confidence": {"rule": f"confidence_score < {c.LOW_CONFIDENCE_THRESHOLD}", "effect": "is_uncertain = true; explanation summary is prefixed 'Uncertain forecast.'; alerts are still created from risk_score but severity is capped at high."},
            "out_of_distribution": {"rule": f"at least {c.OOD_MIN_FEATURES} features with |z-score| > {c.OOD_ZSCORE_THRESHOLD} against the training statistics in model_versions.metrics_json", "effect": "is_ood = true; predicted_attack_type = UNKNOWN; confidence_score <= 0.3; summary 'Pattern unseen, investigate manually.'"},
            "invalid_input": {"codes": ["FEATURE_SCHEMA_MISMATCH", "INVALID_FEATURES"], "effect": "InferenceError; backend returns 422 to callers, writes an audit event, stores no prediction, does not fall back."},
            "model_failure": {"codes": ["MODEL_UNAVAILABLE", "INFERENCE_TIMEOUT", "INTERNAL_ERROR"], "effect": "Backend calls the rule-based fallback; response has is_fallback = true, fallback_reason = code, model_version = rule-fallback-v1.0.0; predictions.is_fallback = true."},
            "error_codes": dict(c.ERROR_CODES),
        },
    }


def build() -> dict:
    definitions = {
        "RawFlow": raw_flow_definition(),
        "TrafficWindow": traffic_window_definition(),
        "WindowFeatures": window_features_definition(),
        **explanation_definitions(),
        "InferenceRequest": inference_request_definition(),
        "InferenceResponse": inference_response_definition(),
    }
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": "https://github.com/DurgeshLabs/What-the-hack/docs/api/feature_schema_contract.json",
        "title": "SIH26153 feature schema and inference contract",
        "description": "Deliverable R3. Generated by ai/feature_engineering/build_feature_schema_contract.py from ai/inference/contract.py; do not edit by hand.",
        "version": c.CONTRACT_VERSION,
        "feature_schema_version": c.FEATURE_SCHEMA_VERSION,
        "definitions": definitions,
        "cicids2017_column_mapping": column_mapping(),
        "windowing_parameters": windowing_parameters(),
        "contract_decisions": contract_decisions(),
    }


def main() -> int:
    contract = build()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(contract, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT_PATH.relative_to(REPO_ROOT)} ({OUTPUT_PATH.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
