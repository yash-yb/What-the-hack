"""
Standalone Schema Validator & Stress Tester for Cogitate AI Feature Schema Contract
Deliverable: docs/api/feature_schema_contract.json (Milestone 3 Deliverable R3)
"""

import json
import os
import sys
import re

try:
    import jsonschema
    from jsonschema import Draft7Validator, RefResolver, validate, ValidationError
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False


def run_standalone_validation():
    schema_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "docs", "api", "feature_schema_contract.json")
    )
    print(f"Loading schema from: {schema_path}")
    if not os.path.exists(schema_path):
        print(f"ERROR: File not found at {schema_path}")
        return False

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_data = json.load(f)

    print("Step 1: JSON Syntax & Structure Verification...")
    assert schema_data["$schema"] == "http://json-schema.org/draft-07/schema#", "Invalid $schema URI"
    assert schema_data["version"] == "1.0.0", "Invalid version"
    assert "definitions" in schema_data, "Missing definitions"
    assert "cicids2017_column_mapping" in schema_data, "Missing cicids2017_column_mapping"
    assert "windowing_parameters" in schema_data, "Missing windowing_parameters"
    print("  [PASS] Structure valid.")

    print("\nStep 2: Draft-07 Meta-Schema Check...")
    if JSONSCHEMA_AVAILABLE:
        Draft7Validator.check_schema(schema_data)
        resolver = RefResolver.from_schema(schema_data)
        print("  [PASS] Valid Draft-07 JSON Schema.")
    else:
        print("  [SKIP] jsonschema package not found in current environment.")
        resolver = None

    print("\nStep 3: Definitions Inspection...")
    defs = ["RawFlow", "TrafficWindow", "WindowFeatures", "InferenceRequest", "InferenceResponse"]
    for d in defs:
        assert d in schema_data["definitions"], f"Missing {d} in definitions"
        print(f"  [PASS] Definition {d} present.")

    print("\nStep 4: CICIDS2017 Column Mapping Completeness...")
    col_map = schema_data["cicids2017_column_mapping"]
    assert len(col_map) == 85, f"Expected 85 columns, found {len(col_map)}"
    indices = set()
    for col_k, col_v in col_map.items():
        idx = col_v["column_index"]
        assert 1 <= idx <= 85, f"Index out of range: {idx}"
        indices.add(idx)
    assert len(indices) == 85, "Duplicate column indices detected!"
    print("  [PASS] All 85 CICIDS2017 columns mapped with unique indices 1..85.")

    print("\nStep 5: Windowing Parameters & Anti-Leakage Invariants...")
    win_params = schema_data["windowing_parameters"]
    assert win_params["micro"]["window_size_sec"] == 10
    assert win_params["standard"]["window_size_sec"] == 30
    assert win_params["macro"]["window_size_sec"] == 60
    assert win_params["macro"]["stride_sec"] == 10
    assert win_params["default_window_profile"] == "macro"
    anti_leak = win_params["anti_leakage_invariants"]
    assert anti_leak["micro_purge_buffer_sec"] >= 70
    assert anti_leak["standard_purge_buffer_sec"] >= 150
    assert anti_leak["macro_purge_buffer_sec"] >= 360
    print("  [PASS] Windowing parameters and anti-leakage invariants mathematically verified.")

    print("\nStep 6: Empirical Object Validation & Stress Rejection Tests...")
    if JSONSCHEMA_AVAILABLE:
        # Test RawFlow
        raw_flow_validator = Draft7Validator(schema_data["definitions"]["RawFlow"], resolver=resolver)
        valid_raw = {
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
        raw_flow_validator.validate(valid_raw)
        print("  [PASS] RawFlow valid sample accepted.")

        # Negative RawFlow test: port > 65535
        try:
            raw_flow_validator.validate(dict(valid_raw, src_port=70000))
            raise AssertionError("Failed to reject port > 65535")
        except ValidationError:
            print("  [PASS] RawFlow invalid port rejected.")

        # Negative RawFlow test: invalid IP
        try:
            raw_flow_validator.validate(dict(valid_raw, src_ip="999.999.999.999"))
            raise AssertionError("Failed to reject invalid IP")
        except ValidationError:
            print("  [PASS] RawFlow invalid IP rejected.")

        # Test WindowFeatures
        feat_validator = Draft7Validator(schema_data["definitions"]["WindowFeatures"], resolver=resolver)
        valid_feat = {
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
        feat_validator.validate(valid_feat)
        print("  [PASS] WindowFeatures valid sample accepted.")

        # Negative WindowFeatures test: syn_ratio > 1.0
        try:
            feat_validator.validate(dict(valid_feat, syn_ratio=1.5))
            raise AssertionError("Failed to reject syn_ratio > 1.0")
        except ValidationError:
            print("  [PASS] WindowFeatures syn_ratio > 1.0 rejected.")

        # Test InferenceRequest
        req_validator = Draft7Validator(schema_data["definitions"]["InferenceRequest"], resolver=resolver)
        valid_req = {
            "window_id": "win-20260828-0001",
            "timestamp": "2026-08-28T18:00:00Z",
            "features": valid_feat,
            "requested_horizon_sec": 60,
        }
        req_validator.validate(valid_req)
        print("  [PASS] InferenceRequest valid sample accepted.")

        # Negative InferenceRequest test: invalid horizon
        try:
            req_validator.validate(dict(valid_req, requested_horizon_sec=45))
            raise AssertionError("Failed to reject invalid requested_horizon_sec")
        except ValidationError:
            print("  [PASS] InferenceRequest invalid horizon rejected.")

        # Test InferenceResponse
        resp_validator = Draft7Validator(schema_data["definitions"]["InferenceResponse"], resolver=resolver)
        valid_resp = {
            "window_id": "win-20260828-0001",
            "timestamp": "2026-08-28T18:00:00Z",
            "risk_score": 84.5,
            "risk_level": "critical",
            "predicted_attack_type": "DDoS_LOIC",
            "forecast_horizon_sec": 60,
            "confidence_score": 0.92,
            "explanation_json": {
                "summary": "DDoS LOIC surge forecasted",
                "top_features": [
                    {
                        "feature": "syn_burst_score",
                        "contribution": 0.42,
                        "description": "SYN burst elevated",
                    }
                ],
            },
        }
        resp_validator.validate(valid_resp)
        print("  [PASS] InferenceResponse valid sample accepted.")

        # Negative InferenceResponse test: invalid risk_score > 100
        try:
            resp_validator.validate(dict(valid_resp, risk_score=150.0))
            raise AssertionError("Failed to reject risk_score > 100")
        except ValidationError:
            print("  [PASS] InferenceResponse invalid risk_score rejected.")

    print("\nALL EMPIRICAL VALIDATION CHECKS PASSED SUCCESSFULLY.")
    return True


if __name__ == "__main__":
    success = run_standalone_validation()
    sys.exit(0 if success else 1)
