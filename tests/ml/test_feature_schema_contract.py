"""
Empirical Validation and Stress Testing Suite for Cogitate AI Feature Schema Contract
Deliverable: docs/api/feature_schema_contract.json (Milestone 3 Deliverable R3)
Specification: Draft-07 JSON Schema Validation and Interface Verification
"""

import json
import os
import pytest
import jsonschema
from jsonschema import Draft7Validator, RefResolver, validate, ValidationError

SCHEMA_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "docs", "api", "feature_schema_contract.json")
)


@pytest.fixture(scope="session")
def schema_data():
    """Load the feature schema contract JSON."""
    assert os.path.exists(SCHEMA_PATH), f"Schema contract not found at {SCHEMA_PATH}"
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


@pytest.fixture(scope="session")
def resolver(schema_data):
    """Create a JSON Schema RefResolver using the root schema."""
    return RefResolver.from_schema(schema_data)


def test_schema_validates_against_draft07_metaschema(schema_data):
    """Verify that the top-level contract is a valid Draft-07 JSON Schema."""
    Draft7Validator.check_schema(schema_data)
    validator = Draft7Validator(Draft7Validator.META_SCHEMA)
    validator.validate(schema_data)
    assert schema_data["$schema"] == "http://json-schema.org/draft-07/schema#"
    assert schema_data["version"] == "1.0.0"
    assert "definitions" in schema_data
    assert "cicids2017_column_mapping" in schema_data
    assert "windowing_parameters" in schema_data


def test_definitions_exist(schema_data):
    """Verify that all required entity definitions exist."""
    required_defs = [
        "RawFlow",
        "TrafficWindow",
        "WindowFeatures",
        "InferenceRequest",
        "InferenceResponse",
    ]
    for d in required_defs:
        assert d in schema_data["definitions"], f"Definition {d} is missing from schema definitions."


# =========================================================================
# 1. RawFlow Empirical Tests (Positive & Negative)
# =========================================================================

def test_valid_raw_flow(schema_data, resolver):
    """Test valid RawFlow schema validation."""
    raw_flow_schema = schema_data["definitions"]["RawFlow"]
    validator = Draft7Validator(raw_flow_schema, resolver=resolver)

    valid_sample = {
        "src_ip": "192.168.10.50",
        "dst_ip": "172.16.0.1",
        "src_port": 49152,
        "dst_port": 80,
        "protocol": "TCP",
        "timestamp": "2026-08-28T18:00:00.000Z",
        "packets": 12,
        "bytes": 1540,
        "duration_ms": 125.5,
        "flags": "SYN,ACK",
        "failed_conn_info": "CLEAN",
        "label": "BENIGN",
    }
    validator.validate(valid_sample)


def test_raw_flow_rejections(schema_data, resolver):
    """Stress-test rejection of invalid RawFlow instances."""
    raw_flow_schema = schema_data["definitions"]["RawFlow"]
    validator = Draft7Validator(raw_flow_schema, resolver=resolver)

    base = {
        "src_ip": "192.168.10.50",
        "dst_ip": "172.16.0.1",
        "src_port": 49152,
        "dst_port": 80,
        "protocol": "TCP",
        "timestamp": "2026-08-28T18:00:00.000Z",
        "packets": 12,
        "bytes": 1540,
        "duration_ms": 125.5,
        "flags": "SYN,ACK",
        "failed_conn_info": "CLEAN",
        "label": "BENIGN",
    }

    # 1. Port out of range > 65535
    with pytest.raises(ValidationError):
        invalid = dict(base, src_port=65536)
        validator.validate(invalid)

    # 2. Port negative < 0
    with pytest.raises(ValidationError):
        invalid = dict(base, dst_port=-1)
        validator.validate(invalid)

    # 3. Invalid IP format
    with pytest.raises(ValidationError):
        invalid = dict(base, src_ip="999.999.999.999")
        validator.validate(invalid)

    with pytest.raises(ValidationError):
        invalid = dict(base, dst_ip="192.168.1.256")
        validator.validate(invalid)

    # 4. Packets < 1
    with pytest.raises(ValidationError):
        invalid = dict(base, packets=0)
        validator.validate(invalid)

    # 5. Bytes < 0
    with pytest.raises(ValidationError):
        invalid = dict(base, bytes=-10)
        validator.validate(invalid)

    # 6. Negative duration
    with pytest.raises(ValidationError):
        invalid = dict(base, duration_ms=-0.5)
        validator.validate(invalid)

    # 7. Invalid Protocol enum
    with pytest.raises(ValidationError):
        invalid = dict(base, protocol="SCTP")
        validator.validate(invalid)

    # 8. Invalid Flags format
    with pytest.raises(ValidationError):
        invalid = dict(base, flags="INVALID_FLAG")
        validator.validate(invalid)

    # 9. Invalid Failed Conn Info enum
    with pytest.raises(ValidationError):
        invalid = dict(base, failed_conn_info="CORRUPT")
        validator.validate(invalid)

    # 10. Missing required field
    with pytest.raises(ValidationError):
        invalid = dict(base)
        del invalid["label"]
        validator.validate(invalid)

    # 11. Extra unexpected property (additionalProperties: false)
    with pytest.raises(ValidationError):
        invalid = dict(base, extra_field="forbidden")
        validator.validate(invalid)


# =========================================================================
# 2. TrafficWindow Empirical Tests (Positive & Negative)
# =========================================================================

def test_valid_traffic_window(schema_data, resolver):
    """Test valid TrafficWindow schema validation."""
    window_schema = schema_data["definitions"]["TrafficWindow"]
    validator = Draft7Validator(window_schema, resolver=resolver)

    valid_sample = {
        "id": "win-20260828-0001",
        "window_start": "2026-08-28T18:00:00Z",
        "window_end": "2026-08-28T18:01:00Z",
        "duration_sec": 60.0,
        "flow_count": 150,
        "stride_sec": 10.0,
    }
    validator.validate(valid_sample)


def test_traffic_window_rejections(schema_data, resolver):
    """Stress-test rejection of invalid TrafficWindow instances."""
    window_schema = schema_data["definitions"]["TrafficWindow"]
    validator = Draft7Validator(window_schema, resolver=resolver)

    base = {
        "id": "win-20260828-0001",
        "window_start": "2026-08-28T18:00:00Z",
        "window_end": "2026-08-28T18:01:00Z",
        "duration_sec": 60.0,
        "flow_count": 150,
        "stride_sec": 10.0,
    }

    # 1. Invalid duration < 1.0
    with pytest.raises(ValidationError):
        invalid = dict(base, duration_sec=0.5)
        validator.validate(invalid)

    # 2. Invalid flow_count < 0
    with pytest.raises(ValidationError):
        invalid = dict(base, flow_count=-1)
        validator.validate(invalid)

    # 3. Invalid stride_sec < 0.1
    with pytest.raises(ValidationError):
        invalid = dict(base, stride_sec=0.05)
        validator.validate(invalid)

    # 4. Invalid ID with illegal characters
    with pytest.raises(ValidationError):
        invalid = dict(base, id="win#invalid@id!")
        validator.validate(invalid)

    # 5. Missing required field
    with pytest.raises(ValidationError):
        invalid = dict(base)
        del invalid["window_end"]
        validator.validate(invalid)


# =========================================================================
# 3. WindowFeatures Empirical Tests (Positive & Negative)
# =========================================================================

def get_valid_window_features():
    return {
        "flow_count": 120,
        "packet_count": 1450,
        "byte_count": 185000,
        "avg_packets_per_flow": 12.08,
        "avg_bytes_per_flow": 1541.67,
        "avg_duration_ms": 250.4,
        "packet_length_mean": 127.58,
        "packet_length_std": 240.12,
        "unique_src_ips": 15,
        "unique_dst_ips": 4,
        "unique_src_ports": 85,
        "unique_dst_ports": 12,
        "src_ip_entropy": 2.45,
        "dst_port_entropy": 1.85,
        "protocol_tcp_ratio": 0.85,
        "protocol_udp_ratio": 0.12,
        "protocol_icmp_ratio": 0.03,
        "syn_ratio": 0.25,
        "ack_ratio": 0.70,
        "fin_ratio": 0.15,
        "rst_ratio": 0.05,
        "syn_ack_ratio": 0.35,
        "failed_conn_ratio": 0.04,
        "short_flow_ratio": 0.18,
        "inbound_outbound_ratio": 1.45,
        "retry_rate": 0.02,
        "packet_rate_per_sec": 24.16,
        "byte_rate_per_sec": 3083.33,
        "flow_rate_per_sec": 2.0,
        "packet_burst_score": 1.15,
        "syn_burst_score": 1.05,
        "delta_packet_rate": 3.5,
        "delta_byte_rate": 450.0,
        "delta_syn_ratio": 0.05,
        "delta_failed_conn_ratio": 0.01,
        "delta_unique_dst_ports": 2,
        "delta_packet_burst_score": 0.10,
    }


def test_valid_window_features(schema_data, resolver):
    """Test valid WindowFeatures schema validation."""
    features_schema = schema_data["definitions"]["WindowFeatures"]
    validator = Draft7Validator(features_schema, resolver=resolver)

    valid_sample = get_valid_window_features()
    validator.validate(valid_sample)


def test_window_features_rejections(schema_data, resolver):
    """Stress-test rejection of invalid WindowFeatures instances."""
    features_schema = schema_data["definitions"]["WindowFeatures"]
    validator = Draft7Validator(features_schema, resolver=resolver)

    base = get_valid_window_features()

    # 1. syn_ratio > 1.0
    with pytest.raises(ValidationError):
        invalid = dict(base, syn_ratio=1.05)
        validator.validate(invalid)

    # 2. syn_ratio < 0.0
    with pytest.raises(ValidationError):
        invalid = dict(base, syn_ratio=-0.1)
        validator.validate(invalid)

    # 3. dst_port_entropy > 16.0
    with pytest.raises(ValidationError):
        invalid = dict(base, dst_port_entropy=16.5)
        validator.validate(invalid)

    # 4. delta_syn_ratio < -1.0
    with pytest.raises(ValidationError):
        invalid = dict(base, delta_syn_ratio=-1.5)
        validator.validate(invalid)

    # 5. delta_syn_ratio > 1.0
    with pytest.raises(ValidationError):
        invalid = dict(base, delta_syn_ratio=1.2)
        validator.validate(invalid)

    # 6. delta_unique_dst_ports > 65536
    with pytest.raises(ValidationError):
        invalid = dict(base, delta_unique_dst_ports=70000)
        validator.validate(invalid)

    # 7. unique_src_ports > 65536
    with pytest.raises(ValidationError):
        invalid = dict(base, unique_src_ports=65537)
        validator.validate(invalid)

    # 8. Missing required feature
    with pytest.raises(ValidationError):
        invalid = dict(base)
        del invalid["packet_burst_score"]
        validator.validate(invalid)

    # 9. Additional unexpected property
    with pytest.raises(ValidationError):
        invalid = dict(base, unapproved_synthetic_feature=42.0)
        validator.validate(invalid)


# =========================================================================
# 4. InferenceRequest Empirical Tests (Positive & Negative)
# =========================================================================

def test_valid_inference_request(schema_data, resolver):
    """Test valid InferenceRequest schema validation."""
    req_schema = schema_data["definitions"]["InferenceRequest"]
    validator = Draft7Validator(req_schema, resolver=resolver)

    valid_sample = {
        "window_id": "win-20260828-0001",
        "timestamp": "2026-08-28T18:00:00Z",
        "features": get_valid_window_features(),
        "requested_horizon_sec": 60,
        "sensor_id": "probe-edge-01",
        "tenant_id": "enterprise-alpha",
        "include_explanation": True,
        "alert_threshold": 50.0,
    }
    validator.validate(valid_sample)


def test_inference_request_rejections(schema_data, resolver):
    """Stress-test rejection of invalid InferenceRequest instances."""
    req_schema = schema_data["definitions"]["InferenceRequest"]
    validator = Draft7Validator(req_schema, resolver=resolver)

    base = {
        "window_id": "win-20260828-0001",
        "timestamp": "2026-08-28T18:00:00Z",
        "features": get_valid_window_features(),
        "requested_horizon_sec": 60,
    }

    # 1. Invalid requested horizon (not in [60, 120, 300])
    with pytest.raises(ValidationError):
        invalid = dict(base, requested_horizon_sec=45)
        validator.validate(invalid)

    # 2. Invalid window_id pattern (contains special characters)
    with pytest.raises(ValidationError):
        invalid = dict(base, window_id="win/2026:01")
        validator.validate(invalid)

    # 3. Invalid alert_threshold > 100.0
    with pytest.raises(ValidationError):
        invalid = dict(base, alert_threshold=150.0)
        validator.validate(invalid)

    # 4. Missing nested features object
    with pytest.raises(ValidationError):
        invalid = dict(base)
        del invalid["features"]
        validator.validate(invalid)

    # 5. Invalid nested features within request
    with pytest.raises(ValidationError):
        bad_features = dict(get_valid_window_features(), syn_ratio=2.5)
        invalid = dict(base, features=bad_features)
        validator.validate(invalid)


# =========================================================================
# 5. InferenceResponse Empirical Tests (Positive & Negative)
# =========================================================================

def test_valid_inference_response(schema_data, resolver):
    """Test valid InferenceResponse schema validation."""
    resp_schema = schema_data["definitions"]["InferenceResponse"]
    validator = Draft7Validator(resp_schema, resolver=resolver)

    valid_sample = {
        "window_id": "win-20260828-0001",
        "timestamp": "2026-08-28T18:00:00Z",
        "risk_score": 84.5,
        "risk_level": "critical",
        "predicted_attack_type": "DDoS_LOIC",
        "forecast_horizon_sec": 60,
        "confidence_score": 0.92,
        "explanation_json": {
            "summary": "Imminent high-volume DDoS LOIC attack forecasted within 60 seconds driven by SYN burst and connection asymmetry.",
            "top_features": [
                {
                    "feature": "syn_burst_score",
                    "contribution": 0.42,
                    "description": "SYN burst score elevated 4.5x above baseline.",
                    "feature_value": 4.5,
                    "baseline_value": 1.0,
                },
                {
                    "feature": "syn_ack_ratio",
                    "contribution": 0.31,
                    "description": "High handshake asymmetry indicating unreciprocated SYN flooding.",
                    "feature_value": 45.2,
                    "baseline_value": 1.05,
                },
            ],
            "mitigation_recommendation": "Activate upstream BGP Flowspec rate-limiting and enable TCP SYN cookies.",
            "model_version": "xgboost-forecaster-v1.0.0",
            "inference_latency_ms": 12.4,
        },
        "alert_triggered": True,
        "stage_progression": "S3_ACTIVE_PEAK",
    }
    validator.validate(valid_sample)


def test_inference_response_rejections(schema_data, resolver):
    """Stress-test rejection of invalid InferenceResponse instances."""
    resp_schema = schema_data["definitions"]["InferenceResponse"]
    validator = Draft7Validator(resp_schema, resolver=resolver)

    base = {
        "window_id": "win-20260828-0001",
        "timestamp": "2026-08-28T18:00:00Z",
        "risk_score": 84.5,
        "risk_level": "critical",
        "predicted_attack_type": "DDoS_LOIC",
        "forecast_horizon_sec": 60,
        "confidence_score": 0.92,
        "explanation_json": {
            "summary": "High risk DDoS predicted",
            "top_features": [
                {
                    "feature": "syn_burst_score",
                    "contribution": 0.42,
                    "description": "SYN burst momentum",
                }
            ],
        },
    }

    # 1. Risk score out of bounds > 100.0
    with pytest.raises(ValidationError):
        invalid = dict(base, risk_score=105.0)
        validator.validate(invalid)

    # 2. Risk score out of bounds < 0.0
    with pytest.raises(ValidationError):
        invalid = dict(base, risk_score=-5.0)
        validator.validate(invalid)

    # 3. Invalid risk_level enum
    with pytest.raises(ValidationError):
        invalid = dict(base, risk_level="catastrophic")
        validator.validate(invalid)

    # 4. Invalid predicted_attack_type enum
    with pytest.raises(ValidationError):
        invalid = dict(base, predicted_attack_type="ZeroDayExploitXYZ")
        validator.validate(invalid)

    # 5. Confidence score > 1.0
    with pytest.raises(ValidationError):
        invalid = dict(base, confidence_score=1.5)
        validator.validate(invalid)

    # 6. Forecast horizon not in [60, 120, 300]
    with pytest.raises(ValidationError):
        invalid = dict(base, forecast_horizon_sec=90)
        validator.validate(invalid)

    # 7. Invalid stage_progression enum
    with pytest.raises(ValidationError):
        invalid = dict(base, stage_progression="STAGE_UNKNOWN")
        validator.validate(invalid)

    # 8. Empty top_features array (minItems: 1)
    with pytest.raises(ValidationError):
        invalid_explanation = {
            "summary": "Summary text",
            "top_features": [],
        }
        invalid = dict(base, explanation_json=invalid_explanation)
        validator.validate(invalid)


# =========================================================================
# 6. CICIDS2017 Column Mapping Empirical Tests
# =========================================================================

def test_cicids2017_column_mapping_completeness(schema_data):
    """Verify that all 85 columns of CICIDS2017 are documented and mapped."""
    mapping = schema_data["cicids2017_column_mapping"]
    assert len(mapping) == 85, f"Expected 85 CICIDS2017 columns, found {len(mapping)}."

    indices = []
    required_keys = [
        "column_index",
        "raw_header",
        "sanitized_name",
        "target_entity",
        "target_field",
        "target_type",
        "transformation_rule",
        "cleaning_action",
    ]

    for col_name, col_meta in mapping.items():
        for k in required_keys:
            assert k in col_meta, f"Column '{col_name}' is missing required key '{k}'."
        indices.append(col_meta["column_index"])

    # Ensure indices span 1 to 85 continuously without gaps or duplicates
    assert sorted(indices) == list(range(1, 86)), "Column indices must form a contiguous sequence from 1 to 85."


# =========================================================================
# 7. Windowing Parameters Empirical Tests
# =========================================================================

def test_windowing_parameters_integrity(schema_data):
    """Verify mathematical integrity of windowing profiles and anti-leakage invariants."""
    params = schema_data["windowing_parameters"]

    assert "micro" in params
    assert "standard" in params
    assert "macro" in params
    assert params["default_window_profile"] == "macro"

    # Verify macro configuration matching formulation W=60s, stride=10s, overlap=0.8333
    macro = params["macro"]
    assert macro["window_size_sec"] == 60
    assert macro["stride_sec"] == 10
    expected_overlap = 1.0 - (macro["stride_sec"] / macro["window_size_sec"])
    assert abs(macro["overlap_ratio"] - expected_overlap) < 1e-3

    # Verify anti-leakage embargo formula: Delta_purge >= W_size + H_horizon
    anti_leak = params["anti_leakage_invariants"]
    assert anti_leak["micro_purge_buffer_sec"] >= (10 + 60)
    assert anti_leak["standard_purge_buffer_sec"] >= (30 + 120)
    assert anti_leak["macro_purge_buffer_sec"] >= (60 + 300)
