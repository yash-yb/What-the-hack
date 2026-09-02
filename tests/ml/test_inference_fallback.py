"""
Contract tests for ai.inference: every fallback response must validate against
docs/api/feature_schema_contract.json, and bad input must fail closed with the
documented error codes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, RefResolver

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai.inference import (  # noqa: E402
    ATTACK_TYPES,
    FEATURE_NAMES,
    InferenceError,
    forecast,
    risk_level_for,
    validate_features,
)

SCHEMA_PATH = PROJECT_ROOT / "docs" / "api" / "feature_schema_contract.json"


@pytest.fixture(scope="session")
def schema():
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def response_validator(schema):
    return Draft7Validator(schema["definitions"]["InferenceResponse"], resolver=RefResolver.from_schema(schema))


@pytest.fixture(scope="session")
def request_validator(schema):
    return Draft7Validator(schema["definitions"]["InferenceRequest"], resolver=RefResolver.from_schema(schema))


def benign_features() -> dict:
    return {
        "flow_count": 120, "packet_count": 1450, "byte_count": 185000,
        "avg_packets_per_flow": 12.08, "avg_bytes_per_flow": 1541.67, "avg_duration_ms": 250.4,
        "packet_length_mean": 127.58, "packet_length_std": 240.12,
        "unique_src_ips": 15, "unique_dst_ips": 4, "unique_src_ports": 85, "unique_dst_ports": 12,
        "src_ip_entropy": 2.45, "dst_port_entropy": 1.85,
        "protocol_tcp_ratio": 0.85, "protocol_udp_ratio": 0.12, "protocol_icmp_ratio": 0.03,
        "syn_ratio": 0.25, "ack_ratio": 0.70, "fin_ratio": 0.15, "rst_ratio": 0.05, "syn_ack_ratio": 0.35,
        "failed_conn_ratio": 0.04, "short_flow_ratio": 0.18, "inbound_outbound_ratio": 1.45, "retry_rate": 0.02,
        "packet_rate_per_sec": 24.16, "byte_rate_per_sec": 3083.33, "flow_rate_per_sec": 2.0,
        "packet_burst_score": 1.15, "syn_burst_score": 1.05,
        "delta_packet_rate": 3.5, "delta_byte_rate": 450.0, "delta_syn_ratio": 0.05,
        "delta_failed_conn_ratio": 0.01, "delta_unique_dst_ports": 2, "delta_packet_burst_score": 0.10,
    }


def make_request(features: dict, **overrides) -> dict:
    request = {
        "window_id": "win-20260828-0001",
        "timestamp": "2026-08-28T18:00:00Z",
        "features": features,
        "requested_horizon_sec": 300,
    }
    request.update(overrides)
    return request


SCENARIOS = {
    "benign": (benign_features(), "BENIGN", "low"),
    "port_scan": (dict(benign_features(), dst_port_entropy=7.5, short_flow_ratio=0.9, syn_ack_ratio=25.0, delta_unique_dst_ports=120, rst_ratio=0.6), "Reconnaissance", "critical"),
    "brute_force": (dict(benign_features(), failed_conn_ratio=0.8, retry_rate=0.6, rst_ratio=0.55, delta_failed_conn_ratio=0.35), "BruteForce", "critical"),
    "ddos": (dict(benign_features(), syn_burst_score=8.0, packet_burst_score=7.0, syn_ratio=0.95, src_ip_entropy=7.5, delta_packet_rate=2000.0), "DDoS", "critical"),
    "early_precursor": (dict(benign_features(), dst_port_entropy=4.5, syn_ack_ratio=5.0, short_flow_ratio=0.5), "Reconnaissance", "medium"),
}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_fallback_response_conforms_to_contract(name, request_validator, response_validator):
    features, expected_type, expected_level = SCENARIOS[name]
    request = make_request(features)
    request_validator.validate(request)

    response = forecast(request)
    response_validator.validate(response)

    assert response["predicted_attack_type"] == expected_type
    assert response["risk_level"] == expected_level
    assert response["risk_level"] == risk_level_for(response["risk_score"])
    assert response["is_fallback"] is True
    assert response["forecast_horizon_sec"] == 300
    assert response["window_id"] == request["window_id"]
    assert response["explanation_json"]["top_features"]
    assert all(item["feature"] in FEATURE_NAMES for item in response["explanation_json"]["top_features"])
    assert response["predicted_attack_type"] in ATTACK_TYPES


def test_alert_triggered_follows_threshold():
    assert forecast(make_request(SCENARIOS["ddos"][0]))["alert_triggered"] is True
    assert forecast(make_request(benign_features()))["alert_triggered"] is False
    medium = SCENARIOS["early_precursor"][0]
    medium_score = forecast(make_request(medium))["risk_score"]
    assert 20.0 <= medium_score < 50.0
    assert forecast(make_request(medium, alert_threshold=50.0))["alert_triggered"] is False
    assert forecast(make_request(medium, alert_threshold=20.0))["alert_triggered"] is True


def test_uncertain_flag_matches_confidence_rule():
    response = forecast(make_request(SCENARIOS["early_precursor"][0]))
    assert response["is_uncertain"] == (response["confidence_score"] < 0.55)
    if response["is_uncertain"]:
        assert response["explanation_json"]["summary"].startswith("Uncertain forecast.")


def test_horizon_is_echoed_for_every_allowed_value():
    for horizon in (60, 120, 300):
        assert forecast(make_request(benign_features(), requested_horizon_sec=horizon))["forecast_horizon_sec"] == horizon


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ({"syn_ratio": 1.5}, "INVALID_FEATURES"),
        ({"flow_count": 0}, "INVALID_FEATURES"),
        ({"packet_count": float("nan")}, "INVALID_FEATURES"),
        ({"byte_count": float("inf")}, "INVALID_FEATURES"),
        ({"unique_dst_ports": "12"}, "INVALID_FEATURES"),
        ({"unapproved_feature": 1.0}, "INVALID_FEATURES"),
    ],
)
def test_invalid_features_fail_closed(mutation, code):
    features = dict(benign_features(), **mutation)
    with pytest.raises(InferenceError) as excinfo:
        forecast(make_request(features))
    assert excinfo.value.code == code
    assert excinfo.value.to_dict()["error_code"] == code


def test_missing_feature_is_reported_by_name():
    features = benign_features()
    del features["packet_burst_score"]
    with pytest.raises(InferenceError) as excinfo:
        validate_features(features)
    assert excinfo.value.details["missing"] == ["packet_burst_score"]


def test_schema_version_mismatch_fails_closed():
    with pytest.raises(InferenceError) as excinfo:
        forecast(make_request(benign_features(), feature_schema_version="v0"))
    assert excinfo.value.code == "FEATURE_SCHEMA_MISMATCH"


def test_bad_horizon_is_rejected():
    with pytest.raises(InferenceError):
        forecast(make_request(benign_features(), requested_horizon_sec=90))


def test_contract_json_matches_python_source(schema):
    assert schema["definitions"]["WindowFeatures"]["required"] == list(FEATURE_NAMES)
    assert schema["definitions"]["InferenceResponse"]["properties"]["predicted_attack_type"]["enum"] == list(ATTACK_TYPES)
