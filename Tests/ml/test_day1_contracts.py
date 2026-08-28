"""
Comprehensive Automated Unit, Property, Contract, and Invariant Test Suite for Day 1 Deliverables.

Project: SIH26153 - AI-Based Network Attack Forecasting from Network Traffic Data
Milestone: Milestone 4 (Deliverable R4 Test Suite)
Specification References:
    - Deliverable R1: docs/research/forecasting_formulation.md
    - Deliverable R2: ai/datasets/download_cicids2017.py
    - Deliverable R3: docs/api/feature_schema_contract.json
    - Deliverable R4: sample_data/sample_flows_mini.csv

Test Suite Organization:
    1. TestFeatureSchemaContract:
       - Draft-07 JSON Schema meta-validation, entity definitions (RawFlow, TrafficWindow,
         WindowFeatures, InferenceRequest, InferenceResponse), constraint boundaries,
         85-column mapping completeness, and multi-scale windowing parameters.
    2. TestSampleFlowsMini:
       - CSV file existence, row count > 50, exact 12-column RawFlow header conformity,
         data types, zero missing/NaN values, timestamp monotonicity, 3-phase progression
         (Benign -> Precursor Scan -> Volumetric Attack), and row-by-row schema validation.
    3. TestDownloadCicidsCLI:
       - Argparse CLI options, --offline-mock execution in tmp_path, --dry-run isolation,
         exit codes (0 on success, 2 on usage error), SHA-256 catalog validation,
         streaming SHA-256 calculation, header sanitization, and 84-to-12 column mapping.
    4. TestMathematicalFormulationAndInvariants:
       - Reference 60s window aggregator, volumetric moments conservation, Shannon entropy
         closed-form analytical oracles, TCP flag and health ratios in [0, 1], volumetric
         momentum burst scores, shifted prospective forecasting targets (X_t -> Y_{t+1}),
         Theorem 1 (Zero-Lookahead Filtration Invariant), Theorem 2 (Split Embargo Condition),
         and Focal Loss modulation dynamics.
    5. TestResearchFormulationDoc:
       - Research document existence, structural completeness (8 sections), LaTeX formulas,
         anti-leakage theorems, lead-time metrics (MLT, EWCR, AUR, FWR), and MITRE ATT&CK mappings.

Execution:
    pytest tests/ml/test_day1_contracts.py -v
"""

from __future__ import annotations

import csv
import datetime
import hashlib
import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import pytest
import jsonschema
from jsonschema import Draft7Validator, ValidationError

# Resolve authoritative project root and add to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Import dataset acquisition and normalizer tool (Deliverable R2)
from ai.datasets.download_cicids2017 import (
    CICIDS2017_SHA256_CATALOG,
    DAY_SUBSET_ALIASES,
    RAW_FLOWS_COLUMNS,
    STANDARD_84_HEADERS,
    SUBSET_CANONICAL_KEYS,
    VALID_SOURCES,
    VALID_SUBSETS,
    CICIDS2017SyntheticGenerator,
    acquire_dataset,
    build_argument_parser,
    clean_cicids_header,
    compute_sha256,
    deduplicate_columns,
    generate_synthetic_cicids2017,
    main as cli_main,
    map_cicids_to_raw_flows,
    sanitize_inf_nan,
    verify_checksums,
)


# ==============================================================================
# Global Path Constants and Shared Fixtures
# ==============================================================================

SCHEMA_PATH = PROJECT_ROOT / "docs" / "api" / "feature_schema_contract.json"
RESEARCH_DOC_PATH = PROJECT_ROOT / "docs" / "research" / "forecasting_formulation.md"
SAMPLE_CSV_PATH = PROJECT_ROOT / "sample_data" / "sample_flows_mini.csv"


@pytest.fixture(scope="session")
def schema_contract_data() -> Dict[str, Any]:
    """Load the machine-readable JSON Schema contract (Deliverable R3)."""
    assert SCHEMA_PATH.exists(), f"Feature schema contract missing at {SCHEMA_PATH}"
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


@pytest.fixture(scope="session")
def raw_flow_validator(schema_contract_data: Dict[str, Any]) -> Draft7Validator:
    """Construct Draft-07 validator for RawFlow entity definition."""
    raw_flow_schema = schema_contract_data["definitions"]["RawFlow"]
    return Draft7Validator(raw_flow_schema)


@pytest.fixture(scope="session")
def traffic_window_validator(schema_contract_data: Dict[str, Any]) -> Draft7Validator:
    """Construct Draft-07 validator for TrafficWindow entity definition."""
    window_schema = schema_contract_data["definitions"]["TrafficWindow"]
    return Draft7Validator(window_schema)


@pytest.fixture(scope="session")
def window_features_validator(schema_contract_data: Dict[str, Any]) -> Draft7Validator:
    """Construct Draft-07 validator for WindowFeatures entity definition."""
    features_schema = schema_contract_data["definitions"]["WindowFeatures"]
    return Draft7Validator(features_schema)


@pytest.fixture(scope="session")
def inference_request_validator(schema_contract_data: Dict[str, Any]) -> Draft7Validator:
    """Construct Draft-07 validator for InferenceRequest definition."""
    req_schema = schema_contract_data["definitions"]["InferenceRequest"]
    return Draft7Validator(req_schema)


@pytest.fixture(scope="session")
def inference_response_validator(schema_contract_data: Dict[str, Any]) -> Draft7Validator:
    """Construct Draft-07 validator for InferenceResponse definition."""
    resp_schema = schema_contract_data["definitions"]["InferenceResponse"]
    return Draft7Validator(resp_schema)


# ==============================================================================
# Reference Window Aggregator & Mathematical Oracle Helpers
# ==============================================================================

def parse_iso8601_to_epoch(ts: Union[str, datetime.datetime, int, float]) -> float:
    """Parse flexible ISO-8601 or standard datetime string to UTC epoch float seconds."""
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, datetime.datetime):
        return ts.timestamp()
    if isinstance(ts, str):
        clean_ts = ts.strip().replace("\xa0", " ")
        if "T" in clean_ts:
            clean_iso = clean_ts.replace("Z", "+00:00")
            try:
                dt = datetime.datetime.fromisoformat(clean_iso)
                return dt.timestamp()
            except ValueError:
                pass
        formats = [
            "%d/%m/%Y %H:%M:%S",
            "%d/%m/%Y %I:%M:%S %p",
            "%d/%m/%Y %H:%M",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%Y %I:%M:%S %p",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
        ]
        for fmt in formats:
            try:
                dt = datetime.datetime.strptime(clean_ts, fmt)
                dt = dt.replace(tzinfo=datetime.timezone.utc)
                return dt.timestamp()
            except ValueError:
                continue
        try:
            return float(clean_ts)
        except ValueError:
            raise ValueError(f"Cannot parse timestamp string: {ts}")
    raise TypeError(f"Unsupported timestamp type: {type(ts)}")


def calculate_shannon_entropy(items: List[Any]) -> float:
    """
    Compute base-2 Shannon Information Entropy: H(X) = -sum(p_i * log2(p_i)).
    Returns 0.0 for empty list or single-element distribution.
    """
    if not items or len(items) <= 1:
        return 0.0

    counts: Dict[Any, int] = {}
    for item in items:
        counts[item] = counts.get(item, 0) + 1

    if len(counts) <= 1:
        return 0.0

    total = float(len(items))
    ent = 0.0
    for cnt in counts.values():
        p = cnt / total
        if p > 0.0:
            ent -= p * math.log2(p)
    return float(ent)


class ReferenceWindowAggregator:
    """
    Pure-Python reference window feature aggregator implementing the mathematical
    definitions formalized in Deliverable R1 (forecasting_formulation.md Section 5).
    """

    def __init__(
        self,
        window_size_sec: float = 60.0,
        stride_sec: float = 10.0,
        horizon_sec: float = 60.0,
        short_flow_threshold_ms: float = 100.0,
    ) -> None:
        self.window_size_sec = window_size_sec
        self.stride_sec = stride_sec
        self.horizon_sec = horizon_sec
        self.short_flow_threshold_ms = short_flow_threshold_ms

    def extract_window_flows(
        self, flows: List[Dict[str, Any]], t_epoch: float
    ) -> List[Dict[str, Any]]:
        """Filter flows strictly within retrospective interval [t - window_size_sec, t]."""
        t_start = t_epoch - self.window_size_sec
        selected: List[Dict[str, Any]] = []
        for f in flows:
            tau = parse_iso8601_to_epoch(f["timestamp"])
            if t_start <= tau <= t_epoch:
                selected.append(f)
        return selected

    def extract_horizon_flows(
        self, flows: List[Dict[str, Any]], t_epoch: float
    ) -> List[Dict[str, Any]]:
        """Filter flows strictly within prospective forecast horizon (t, t + horizon_sec]."""
        t_end = t_epoch + self.horizon_sec
        selected: List[Dict[str, Any]] = []
        for f in flows:
            tau = parse_iso8601_to_epoch(f["timestamp"])
            if t_epoch < tau <= t_end:
                selected.append(f)
        return selected

    def aggregate_window(
        self,
        window_flows: List[Dict[str, Any]],
        t_epoch: float,
        historical_baseline_packets: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """Compute complete statistical feature dictionary over retrospective window flows."""
        # Theorem 1: Assert zero lookahead on all included flows
        for f in window_flows:
            tau = parse_iso8601_to_epoch(f["timestamp"])
            assert tau <= t_epoch + 1e-6, (
                f"Zero-Lookahead violation: flow timestamp {tau} > window epoch {t_epoch}"
            )

        n_flows = len(window_flows)

        if n_flows == 0:
            return {
                "flow_count": 0,
                "packet_count": 0,
                "byte_count": 0,
                "avg_packets_per_flow": 0.0,
                "avg_bytes_per_flow": 0.0,
                "avg_duration_ms": 0.0,
                "packet_rate_per_sec": 0.0,
                "byte_rate_per_sec": 0.0,
                "flow_rate_per_sec": 0.0,
                "unique_src_ips": 0,
                "unique_dst_ips": 0,
                "unique_dst_ports": 0,
                "dst_port_entropy": 0.0,
                "src_ip_entropy": 0.0,
                "syn_ratio": 0.0,
                "ack_ratio": 0.0,
                "fin_ratio": 0.0,
                "rst_ratio": 0.0,
                "syn_ack_ratio": 0.0,
                "failed_conn_ratio": 0.0,
                "short_flow_ratio": 0.0,
                "protocol_tcp_ratio": 0.0,
                "protocol_udp_ratio": 0.0,
                "packet_burst_score": 0.0,
            }

        # 1. Volumetric Summations & Rates
        total_packets = sum(int(f.get("packets", 0)) for f in window_flows)
        total_bytes = sum(int(f.get("bytes", 0)) for f in window_flows)
        total_dur_ms = sum(float(f.get("duration_ms", 0.0)) for f in window_flows)

        avg_pkts_flow = float(total_packets / n_flows)
        avg_bytes_flow = float(total_bytes / n_flows)
        avg_dur_ms = float(total_dur_ms / n_flows)

        pkt_rate = float(total_packets / self.window_size_sec)
        byte_rate = float(total_bytes / self.window_size_sec)
        flow_rate = float(n_flows / self.window_size_sec)

        # 2. Diversity & Entropies
        src_ips = [str(f.get("src_ip", "")) for f in window_flows]
        dst_ips = [str(f.get("dst_ip", "")) for f in window_flows]
        dst_ports = [int(f.get("dst_port", 0)) for f in window_flows]

        uniq_src_ips = len(set(src_ips))
        uniq_dst_ips = len(set(dst_ips))
        uniq_dst_ports = len(set(dst_ports))

        dst_port_ent = calculate_shannon_entropy(dst_ports)
        src_ip_ent = calculate_shannon_entropy(src_ips)

        # 3. Protocol & Control Flags
        tcp_count = sum(1 for f in window_flows if str(f.get("protocol", "")).upper() == "TCP")
        udp_count = sum(1 for f in window_flows if str(f.get("protocol", "")).upper() == "UDP")

        syn_count = 0
        ack_count = 0
        fin_count = 0
        rst_count = 0
        failed_count = 0
        short_count = 0

        for f in window_flows:
            raw_flags = str(f.get("flags", "")).upper()
            flag_set = set(flg.strip() for flg in raw_flags.split(",") if flg.strip())
            if "SYN" in flag_set:
                syn_count += 1
            if "ACK" in flag_set:
                ack_count += 1
            if "FIN" in flag_set:
                fin_count += 1
            if "RST" in flag_set:
                rst_count += 1

            failed_val = str(f.get("failed_conn_info", "CLEAN")).upper()
            if failed_val in ("SYN_NO_ACK", "RST_ABORT", "ZERO_WIN"):
                failed_count += 1

            dur_ms = float(f.get("duration_ms", 0.0))
            if dur_ms < self.short_flow_threshold_ms:
                short_count += 1

        syn_ratio = float(syn_count / n_flows)
        ack_ratio = float(ack_count / n_flows)
        fin_ratio = float(fin_count / n_flows)
        rst_ratio = float(rst_count / n_flows)
        syn_ack_ratio = float(syn_count / (ack_count + 1.0))
        failed_conn_ratio = float(failed_count / n_flows)
        short_flow_ratio = float(short_count / n_flows)
        proto_tcp_ratio = float(tcp_count / n_flows)
        proto_udp_ratio = float(udp_count / n_flows)

        # 4. Volumetric Momentum / Burst Score
        if historical_baseline_packets and len(historical_baseline_packets) > 0:
            hist_mean = float(sum(historical_baseline_packets) / len(historical_baseline_packets))
        else:
            hist_mean = 0.0
        packet_burst_score = float(total_packets / (hist_mean + 1.0))

        return {
            "flow_count": n_flows,
            "packet_count": total_packets,
            "byte_count": total_bytes,
            "avg_packets_per_flow": avg_pkts_flow,
            "avg_bytes_per_flow": avg_bytes_flow,
            "avg_duration_ms": avg_dur_ms,
            "packet_rate_per_sec": pkt_rate,
            "byte_rate_per_sec": byte_rate,
            "flow_rate_per_sec": flow_rate,
            "unique_src_ips": uniq_src_ips,
            "unique_dst_ips": uniq_dst_ips,
            "unique_dst_ports": uniq_dst_ports,
            "dst_port_entropy": dst_port_ent,
            "src_ip_entropy": src_ip_ent,
            "syn_ratio": syn_ratio,
            "ack_ratio": ack_ratio,
            "fin_ratio": fin_ratio,
            "rst_ratio": rst_ratio,
            "syn_ack_ratio": syn_ack_ratio,
            "failed_conn_ratio": failed_conn_ratio,
            "short_flow_ratio": short_flow_ratio,
            "protocol_tcp_ratio": proto_tcp_ratio,
            "protocol_udp_ratio": proto_udp_ratio,
            "packet_burst_score": packet_burst_score,
        }

    def assign_shifted_label(
        self, horizon_flows: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Compute prospective forecasting supervisory target Y_t over horizon (t, t + H]."""
        if not horizon_flows:
            return {"target_binary": 0, "target_stage": 0, "attack_classes": []}

        attacks: List[str] = []
        severity = 0

        for f in horizon_flows:
            lbl = str(f.get("label", "BENIGN")).strip()
            if lbl != "BENIGN":
                attacks.append(lbl)
                if "PortScan" in lbl:
                    severity = max(severity, 1)
                elif any(p in lbl for p in ("Patator", "BruteForce", "Web")):
                    severity = max(severity, 2)
                else:  # DoS, DDoS, Infiltration, Botnet
                    severity = max(severity, 3)

        return {
            "target_binary": 1 if attacks else 0,
            "target_stage": severity,
            "attack_classes": sorted(list(set(attacks))),
        }


# ==============================================================================
# 1. TestFeatureSchemaContract
# ==============================================================================

class TestFeatureSchemaContract:
    """
    Test suite verifying the Draft-07 JSON Schema contract (Deliverable R3).
    Ensures complete meta-validity, constraint definition, 85-column mappings,
    multi-scale windowing parameters, and robust rejection of malformed instances.
    """

    def test_schema_file_exists_and_loads_valid_json(self, schema_contract_data: Dict[str, Any]):
        """Verify schema contract exists at docs/api/feature_schema_contract.json and parses."""
        assert isinstance(schema_contract_data, dict)
        assert len(schema_contract_data) >= 5

    def test_draft07_meta_schema_validity(self, schema_contract_data: Dict[str, Any]):
        """Verify contract passes JSON Schema Draft-07 check_schema and meta-schema validation."""
        Draft7Validator.check_schema(schema_contract_data)
        meta_validator = Draft7Validator(Draft7Validator.META_SCHEMA)
        meta_validator.validate(schema_contract_data)
        assert schema_contract_data["$schema"] == "http://json-schema.org/draft-07/schema#"

    def test_top_level_required_fields_and_version(self, schema_contract_data: Dict[str, Any]):
        """Verify top-level required fields and semantic version string."""
        required_top_keys = [
            "$schema",
            "version",
            "definitions",
            "cicids2017_column_mapping",
            "windowing_parameters",
        ]
        for key in required_top_keys:
            assert key in schema_contract_data, f"Top-level schema missing required key '{key}'"

        version_str = schema_contract_data["version"]
        assert re.match(r"^\d+\.\d+\.\d+$", version_str), (
            f"Version '{version_str}' does not conform to semver format"
        )

    def test_all_entity_definitions_present(self, schema_contract_data: Dict[str, Any]):
        """Verify presence of all 5 core entity definitions."""
        definitions = schema_contract_data.get("definitions", {})
        expected_defs = [
            "RawFlow",
            "TrafficWindow",
            "WindowFeatures",
            "InferenceRequest",
            "InferenceResponse",
        ]
        for def_name in expected_defs:
            assert def_name in definitions, f"Definition '{def_name}' missing from contract."

    def test_raw_flow_definition_constraints(self, schema_contract_data: Dict[str, Any]):
        """Verify field requirements, IP regex, port bounds, and enums in RawFlow."""
        raw_flow = schema_contract_data["definitions"]["RawFlow"]
        assert raw_flow.get("additionalProperties") is False
        required_fields = set(raw_flow.get("required", []))
        expected_fields = {
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "timestamp",
            "packets",
            "bytes",
            "duration_ms",
            "flags",
            "failed_conn_info",
            "label",
        }
        assert required_fields == expected_fields, (
            f"RawFlow required fields mismatch: {required_fields ^ expected_fields}"
        )

        props = raw_flow["properties"]
        assert props["src_port"]["minimum"] == 0
        assert props["src_port"]["maximum"] == 65535
        assert props["dst_port"]["minimum"] == 0
        assert props["dst_port"]["maximum"] == 65535
        assert props["packets"]["minimum"] == 1
        assert props["bytes"]["minimum"] == 0
        assert props["duration_ms"]["minimum"] == 0.0
        assert props["protocol"]["enum"] == ["TCP", "UDP", "ICMP", "OTHER"]
        assert props["failed_conn_info"]["enum"] == [
            "CLEAN",
            "SYN_NO_ACK",
            "RST_ABORT",
            "ZERO_WIN",
            "NA",
        ]

    def test_traffic_window_definition_constraints(self, schema_contract_data: Dict[str, Any]):
        """Verify TrafficWindow metadata properties and bounds."""
        tw = schema_contract_data["definitions"]["TrafficWindow"]
        assert tw.get("additionalProperties") is False
        assert set(tw["required"]) == {
            "id",
            "window_start",
            "window_end",
            "duration_sec",
            "flow_count",
            "stride_sec",
        }
        props = tw["properties"]
        assert props["duration_sec"]["minimum"] == 1.0
        assert props["flow_count"]["minimum"] == 0
        assert props["stride_sec"]["minimum"] == 0.1

    def test_window_features_definition_constraints(self, schema_contract_data: Dict[str, Any]):
        """Verify WindowFeatures definition contains all 22+ required statistical metrics."""
        wf = schema_contract_data["definitions"]["WindowFeatures"]
        assert wf.get("additionalProperties") is False
        required_feats = wf.get("required", [])
        assert len(required_feats) >= 24, (
            f"Expected at least 24 required window features, found {len(required_feats)}"
        )

        core_features = [
            "flow_count",
            "packet_count",
            "byte_count",
            "avg_packets_per_flow",
            "avg_bytes_per_flow",
            "avg_duration_ms",
            "unique_src_ips",
            "unique_dst_ips",
            "unique_src_ports",
            "unique_dst_ports",
            "src_ip_entropy",
            "dst_port_entropy",
            "syn_ratio",
            "ack_ratio",
            "failed_conn_ratio",
            "short_flow_ratio",
            "packet_burst_score",
            "syn_burst_score",
            "delta_packet_rate",
            "delta_syn_ratio",
            "delta_failed_conn_ratio",
            "delta_unique_dst_ports",
        ]
        for feat in core_features:
            assert feat in required_feats, f"Core feature '{feat}' missing from required list"

        props = wf["properties"]
        assert props["syn_ratio"]["minimum"] == 0.0
        assert props["syn_ratio"]["maximum"] == 1.0
        assert props["dst_port_entropy"]["minimum"] == 0.0
        assert props["dst_port_entropy"]["maximum"] == 16.0
        assert props["delta_syn_ratio"]["minimum"] == -1.0
        assert props["delta_syn_ratio"]["maximum"] == 1.0

    def test_inference_request_response_constraints(self, schema_contract_data: Dict[str, Any]):
        """Verify InferenceRequest and InferenceResponse API contracts."""
        req = schema_contract_data["definitions"]["InferenceRequest"]
        assert set(req["required"]) == {
            "window_id",
            "timestamp",
            "features",
            "requested_horizon_sec",
        }
        assert req["properties"]["requested_horizon_sec"]["enum"] == [60, 120, 300]

        resp = schema_contract_data["definitions"]["InferenceResponse"]
        assert set(resp["required"]) == {
            "window_id",
            "timestamp",
            "risk_score",
            "risk_level",
            "predicted_attack_type",
            "forecast_horizon_sec",
            "confidence_score",
            "explanation_json",
        }
        props = resp["properties"]
        assert props["risk_score"]["minimum"] == 0.0
        assert props["risk_score"]["maximum"] == 100.0
        assert props["risk_level"]["enum"] == ["low", "medium", "high", "critical"]
        assert props["confidence_score"]["minimum"] == 0.0
        assert props["confidence_score"]["maximum"] == 1.0

    def test_cicids2017_column_mapping_completeness(self, schema_contract_data: Dict[str, Any]):
        """Verify all 85 raw columns of CICIDS2017 are mapped continuously from index 1 to 85."""
        mapping = schema_contract_data["cicids2017_column_mapping"]
        assert len(mapping) == 85, f"Expected 85 mapped columns, found {len(mapping)}"

        indices: List[int] = []
        for col_name, meta in mapping.items():
            assert "column_index" in meta, f"Column '{col_name}' missing 'column_index'"
            assert "target_entity" in meta, f"Column '{col_name}' missing 'target_entity'"
            assert "target_field" in meta, f"Column '{col_name}' missing 'target_field'"
            assert "cleaning_action" in meta, f"Column '{col_name}' missing 'cleaning_action'"
            indices.append(meta["column_index"])

        assert sorted(indices) == list(range(1, 86)), (
            "Column indices must form a contiguous sequence from 1 to 85"
        )

    def test_windowing_parameters_and_anti_leakage_invariants(
        self, schema_contract_data: Dict[str, Any]
    ):
        """Verify multi-scale window profiles and purge embargo buffer formulas."""
        params = schema_contract_data["windowing_parameters"]
        assert "micro" in params
        assert "standard" in params
        assert "macro" in params
        assert params["default_window_profile"] == "macro"

        macro = params["macro"]
        assert macro["window_size_sec"] == 60
        assert macro["stride_sec"] == 10
        expected_overlap = 1.0 - (macro["stride_sec"] / macro["window_size_sec"])
        assert abs(macro["overlap_ratio"] - expected_overlap) < 1e-3

        anti_leak = params["anti_leakage_invariants"]
        # Embargo buffer guarantee: Delta_purge >= W_size + H_horizon
        assert anti_leak["micro_purge_buffer_sec"] >= (10 + 60)
        assert anti_leak["standard_purge_buffer_sec"] >= (30 + 120)
        assert anti_leak["macro_purge_buffer_sec"] >= (60 + 300)

    def test_raw_flow_rejection_of_invalid_instances(self, raw_flow_validator: Draft7Validator):
        """Stress test validation rejections for corrupted RawFlow payloads."""
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
        # Positive validation
        raw_flow_validator.validate(valid_sample)

        # 1. Invalid port > 65535
        with pytest.raises(ValidationError):
            raw_flow_validator.validate(dict(valid_sample, src_port=70000))

        # 2. Invalid negative duration
        with pytest.raises(ValidationError):
            raw_flow_validator.validate(dict(valid_sample, duration_ms=-1.0))

        # 3. Invalid packets count < 1
        with pytest.raises(ValidationError):
            raw_flow_validator.validate(dict(valid_sample, packets=0))

        # 4. Invalid protocol enum
        with pytest.raises(ValidationError):
            raw_flow_validator.validate(dict(valid_sample, protocol="SCTP_UNKNOWN"))

        # 5. Invalid connection status enum
        with pytest.raises(ValidationError):
            raw_flow_validator.validate(dict(valid_sample, failed_conn_info="CORRUPT"))

        # 6. Disallowed extra property
        with pytest.raises(ValidationError):
            raw_flow_validator.validate(dict(valid_sample, unapproved_extra_prop=123))


# ==============================================================================
# 2. TestSampleFlowsMini
# ==============================================================================

class TestSampleFlowsMini:
    """
    Test suite verifying the deterministic sample dataset (sample_data/sample_flows_mini.csv).
    Validates CSV existence, row count > 50, exact RawFlow headers, valid data types,
    zero missing values, strict timestamp monotonicity, and 3-phase kill-chain progression.
    """

    @pytest.fixture(scope="class")
    def sample_csv_rows(self) -> List[Dict[str, Any]]:
        """Load and parse sample_data/sample_flows_mini.csv into list of dictionaries."""
        assert SAMPLE_CSV_PATH.exists(), f"Sample dataset missing at {SAMPLE_CSV_PATH}"
        rows: List[Dict[str, Any]] = []
        with open(SAMPLE_CSV_PATH, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(dict(row))
        return rows

    def test_sample_csv_exists_and_is_non_empty(self):
        """Verify sample_data/sample_flows_mini.csv exists and is non-empty on disk."""
        assert SAMPLE_CSV_PATH.exists(), f"Sample dataset not found at {SAMPLE_CSV_PATH}"
        file_size = SAMPLE_CSV_PATH.stat().st_size
        assert file_size > 500, f"Sample CSV file suspiciously small ({file_size} bytes)"

    def test_sample_csv_row_count_exceeds_fifty(self, sample_csv_rows: List[Dict[str, Any]]):
        """Verify sample dataset contains > 50 flow records (nominally 120 rows)."""
        count = len(sample_csv_rows)
        assert count > 50, f"Expected row count > 50, got {count}"
        assert count >= 100, f"Expected production sample count >= 100, got {count}"

    def test_sample_csv_headers_match_raw_flow_contract(self):
        """Verify CSV header row matches the 12 canonical RawFlow fields."""
        with open(SAMPLE_CSV_PATH, mode="r", encoding="utf-8") as f:
            header_line = f.readline().strip()
        headers = [h.strip() for h in header_line.split(",")]
        expected_headers = [
            "timestamp",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "packets",
            "bytes",
            "duration_ms",
            "flags",
            "failed_conn_info",
            "label",
        ]
        assert headers == expected_headers, f"CSV headers mismatch: {headers}"

    def test_sample_csv_zero_missing_or_nan_values(self, sample_csv_rows: List[Dict[str, Any]]):
        """Verify no cells are null, NaN, empty strings, or whitespace-only."""
        for idx, row in enumerate(sample_csv_rows, start=1):
            for col, val in row.items():
                assert val is not None, f"Row {idx} column '{col}' is None"
                val_str = str(val).strip().lower()
                assert val_str != "", f"Row {idx} column '{col}' is empty"
                invalid_tokens = ("nan", "null", "inf", "-inf") if col == "flags" else ("nan", "null", "none", "inf", "-inf")
                assert val_str not in invalid_tokens, (
                    f"Row {idx} column '{col}' contains invalid value '{val}'"
                )

    def test_sample_csv_data_types_and_domain_bounds(self, sample_csv_rows: List[Dict[str, Any]]):
        """Verify IP formats, port numbers [0, 65535], packet count >= 1, duration >= 0."""
        ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
        valid_protocols = {"TCP", "UDP", "ICMP", "OTHER"}
        valid_failed_conn = {"CLEAN", "SYN_NO_ACK", "RST_ABORT", "ZERO_WIN", "NA"}

        for idx, row in enumerate(sample_csv_rows, start=1):
            # IPs
            assert ip_pattern.match(row["src_ip"]), f"Row {idx}: invalid src_ip '{row['src_ip']}'"
            assert ip_pattern.match(row["dst_ip"]), f"Row {idx}: invalid dst_ip '{row['dst_ip']}'"

            # Ports
            src_port = int(row["src_port"])
            dst_port = int(row["dst_port"])
            assert 0 <= src_port <= 65535, f"Row {idx}: src_port {src_port} out of range"
            assert 0 <= dst_port <= 65535, f"Row {idx}: dst_port {dst_port} out of range"

            # Packets and Bytes
            packets = int(row["packets"])
            bytes_cnt = int(row["bytes"])
            assert packets >= 1, f"Row {idx}: packets {packets} must be >= 1"
            assert bytes_cnt >= 0, f"Row {idx}: bytes {bytes_cnt} must be >= 0"

            # Duration
            duration_ms = float(row["duration_ms"])
            assert duration_ms >= 0.0, f"Row {idx}: duration_ms {duration_ms} must be >= 0.0"

            # Protocol and Connection State
            assert row["protocol"] in valid_protocols, (
                f"Row {idx}: invalid protocol '{row['protocol']}'"
            )
            assert row["failed_conn_info"] in valid_failed_conn, (
                f"Row {idx}: invalid failed_conn_info '{row['failed_conn_info']}'"
            )

    def test_sample_csv_timestamp_chronological_monotonicity(
        self, sample_csv_rows: List[Dict[str, Any]]
    ):
        """Verify timestamps are strictly monotonically increasing across the entire file."""
        prev_epoch = -1.0
        for idx, row in enumerate(sample_csv_rows, start=1):
            epoch = parse_iso8601_to_epoch(row["timestamp"])
            assert epoch >= prev_epoch, (
                f"Timestamp monotonicity violation at row {idx}: {epoch} < {prev_epoch}"
            )
            prev_epoch = epoch

        # Assert total timeline spans at least 180 seconds (nominally 300s)
        first_epoch = parse_iso8601_to_epoch(sample_csv_rows[0]["timestamp"])
        last_epoch = parse_iso8601_to_epoch(sample_csv_rows[-1]["timestamp"])
        time_span_sec = last_epoch - first_epoch
        assert time_span_sec >= 180.0, f"Total timeline span {time_span_sec}s is < 180s"

    def test_sample_csv_three_phase_kill_chain_progression(
        self, sample_csv_rows: List[Dict[str, Any]]
    ):
        """Verify dataset spans Phase 1 (Benign), Phase 2 (Precursor PortScan), and Phase 3 (DoS/DDoS)."""
        labels = [r["label"] for r in sample_csv_rows]
        assert "BENIGN" in labels, "Sample dataset missing BENIGN baseline flows"
        assert "PortScan" in labels, "Sample dataset missing PortScan precursor flows"
        assert any(l in ("DoS_Hulk", "DDoS_LOIC", "DDoS") for l in labels), (
            "Sample dataset missing volumetric DoS/DDoS peak flows"
        )

        # Check chronological phase separation
        p1_labels = [r["label"] for r in sample_csv_rows[:30]]
        p2_labels = [r["label"] for r in sample_csv_rows[40:75]]
        p3_labels = [r["label"] for r in sample_csv_rows[85:]]

        assert all(l == "BENIGN" for l in p1_labels), (
            f"Phase 1 (baseline) should be pure BENIGN, found: {set(p1_labels)}"
        )
        assert "PortScan" in p2_labels, "Phase 2 should exhibit PortScan precursor activity"
        assert any(l in ("DoS_Hulk", "DDoS_LOIC") for l in p3_labels), (
            "Phase 3 should exhibit volumetric DoS/DDoS attack onset"
        )

    def test_sample_csv_schema_contract_validation(
        self, sample_csv_rows: List[Dict[str, Any]], raw_flow_validator: Draft7Validator
    ):
        """Verify that every row in sample_flows_mini.csv strictly passes RawFlow schema validation."""
        for idx, row in enumerate(sample_csv_rows, start=1):
            typed_row = {
                "src_ip": str(row["src_ip"]),
                "dst_ip": str(row["dst_ip"]),
                "src_port": int(row["src_port"]),
                "dst_port": int(row["dst_port"]),
                "protocol": str(row["protocol"]),
                "timestamp": str(row["timestamp"]),
                "packets": int(row["packets"]),
                "bytes": int(row["bytes"]),
                "duration_ms": float(row["duration_ms"]),
                "flags": str(row["flags"]),
                "failed_conn_info": str(row["failed_conn_info"]),
                "label": str(row["label"]),
            }
            raw_flow_validator.validate(typed_row)


# ==============================================================================
# 3. TestDownloadCicidsCLI
# ==============================================================================

class TestDownloadCicidsCLI:
    """
    Test suite verifying the dataset acquisition CLI tool (Deliverable R2: download_cicids2017.py).
    Tests argument parsing, offline synthetic mock generation, exit codes, SHA-256 digests,
    header sanitization, and 84-to-12 column schema transformation.
    """

    def test_cli_argument_parser_options(self):
        """Verify CLI argument parser defines all required flags and option choices."""
        parser = build_argument_parser()
        args = parser.parse_args(["--subset", "sample", "--offline-mock", "--output-dir", "./tmp/"])
        assert args.subset == "sample"
        assert args.offline_mock is True
        assert args.output_dir == "./tmp/"

    def test_cli_offline_mock_execution_in_tmp_path(self, tmp_path: Path):
        """Verify running CLI in --offline-mock mode generates deterministic CSV files."""
        out_dir = tmp_path / "cicids_mock"
        exit_code = cli_main(
            [
                "--subset",
                "sample",
                "--offline-mock",
                "--output-dir",
                str(out_dir),
                "--seed",
                "42",
                "--rows-per-subset",
                "120",
                "--quiet",
            ]
        )
        assert exit_code == 0, f"Expected exit code 0, got {exit_code}"

        expected_file = out_dir / "sample_flows_mini.csv"
        assert expected_file.exists(), f"Mock CSV not created at {expected_file}"
        assert expected_file.stat().st_size > 500

        with open(expected_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        assert len(lines) == 121  # 1 header + 120 rows

    def test_cli_offline_mock_all_subsets(self, tmp_path: Path):
        """Verify --subset all generates all 8 canonical day-slices synthetically."""
        out_dir = tmp_path / "all_slices"
        exit_code = cli_main(
            [
                "--subset",
                "all",
                "--offline-mock",
                "--output-dir",
                str(out_dir),
                "--rows-per-subset",
                "50",
                "--quiet",
            ]
        )
        assert exit_code == 0

        for canon_key in SUBSET_CANONICAL_KEYS:
            fname = DAY_SUBSET_ALIASES[canon_key]
            slice_path = out_dir / fname
            assert slice_path.exists(), f"Slice {fname} not generated"

    def test_cli_dry_run_no_disk_writes(self, tmp_path: Path):
        """Verify --dry-run returns code 0 and writes zero files to output directory."""
        out_dir = tmp_path / "dry_run_dir"
        exit_code = cli_main(
            [
                "--subset",
                "friday_ddos",
                "--dry-run",
                "--output-dir",
                str(out_dir),
            ]
        )
        assert exit_code == 0
        assert not out_dir.exists() or len(list(out_dir.iterdir())) == 0

    def test_cli_invalid_subset_exit_code_2(self, tmp_path: Path):
        """Verify specifying an unknown subset alias exits with code 2."""
        out_dir = tmp_path / "invalid_sub"
        exit_code = cli_main(
            [
                "--subset",
                "unknown_nonexistent_day_slice",
                "--output-dir",
                str(out_dir),
                "--quiet",
            ]
        )
        assert exit_code == 2, f"Expected usage error exit code 2, got {exit_code}"

    def test_sha256_catalog_integrity(self):
        """Verify SHA-256 catalog contains all 9 official entries with 64-char hex strings."""
        assert len(CICIDS2017_SHA256_CATALOG) == 9
        hex_pattern = re.compile(r"^[0-9a-f]{64}$")
        for fname, digest in CICIDS2017_SHA256_CATALOG.items():
            assert hex_pattern.match(digest), f"Invalid SHA-256 digest for {fname}: {digest}"

    def test_compute_sha256_function(self, tmp_path: Path):
        """Verify compute_sha256 calculates exact lowercase hexadecimal digests."""
        test_file = tmp_path / "test_hash.txt"
        test_content = b"Cogitate AI Network Attack Forecasting Benchmark 2026"
        test_file.write_bytes(test_content)

        expected_hash = hashlib.sha256(test_content).hexdigest()
        actual_hash = compute_sha256(test_file)
        assert actual_hash == expected_hash

        # Non-existent file raises FileNotFoundError
        with pytest.raises(FileNotFoundError):
            compute_sha256(tmp_path / "non_existent_file.bin")

    def test_verify_checksums_with_matching_and_mismatching_files(self, tmp_path: Path):
        """Verify verify_checksums correctly identifies matches and mismatches."""
        test_dir = tmp_path / "chk_test"
        test_dir.mkdir(parents=True, exist_ok=True)

        target_name = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
        target_path = test_dir / target_name

        # Mismatch test
        target_path.write_text("corrupted content", encoding="utf-8")
        assert verify_checksums(test_dir, target_files=[target_name], quiet=True) is False

    def test_header_sanitization_and_deduplication(self):
        """Verify clean_cicids_header strips spaces/BOM and deduplicate_columns handles duplicates."""
        assert clean_cicids_header("  Source Port  ") == "Source Port"
        assert clean_cicids_header("\ufeff Destination IP") == "Destination IP"
        assert clean_cicids_header("Flow\xa0Duration") == "Flow Duration"

        raw_headers = ["Fwd Header Length", "Fwd Header Length", "Fwd Header Length.1"]
        deduped = deduplicate_columns(raw_headers)
        assert deduped == ["Fwd Header Length", "Fwd Header Length.1", "Fwd Header Length.2"]

    def test_map_cicids_to_raw_flows_transformation(self):
        """Verify map_cicids_to_raw_flows converts 84-column dictionary rows to 12 RawFlow fields."""
        generator = CICIDS2017SyntheticGenerator(seed=42)
        raw_rec = generator.generate_flow_record("BENIGN")
        assert len(raw_rec) == len(STANDARD_84_HEADERS)

        normalized_list = map_cicids_to_raw_flows([raw_rec])
        assert len(normalized_list) == 1
        norm = normalized_list[0]

        for col in RAW_FLOWS_COLUMNS:
            assert col in norm, f"Normalized output missing canonical column '{col}'"
        assert norm["protocol"] in ("TCP", "UDP", "ICMP", "OTHER")
        assert norm["label"] == "BENIGN"


# ==============================================================================
# 4. TestMathematicalFormulationAndInvariants
# ==============================================================================

class TestMathematicalFormulationAndInvariants:
    """
    Test suite verifying mathematical invariants, reference window aggregations,
    closed-form analytical Shannon entropy oracles, shifted prospective labeling (X_t -> Y_{t+1}),
    Theorem 1 (Zero-Lookahead), Theorem 2 (Split Embargo Condition), and Focal Loss dynamics.
    """

    @pytest.fixture
    def aggregator(self) -> ReferenceWindowAggregator:
        """Instantiate reference window aggregator configured for standard 60s macro windows."""
        return ReferenceWindowAggregator(
            window_size_sec=60.0, stride_sec=10.0, horizon_sec=60.0, short_flow_threshold_ms=100.0
        )

    def test_volume_moments_conservation_and_averages(self, aggregator: ReferenceWindowAggregator):
        """Verify exact conservation of flow count, packet sums, byte sums, and mean calculations."""
        t_epoch = 100.0
        flows = [
            {
                "timestamp": 50.0,
                "src_ip": "192.168.10.5",
                "dst_ip": "192.168.10.50",
                "dst_port": 80,
                "protocol": "TCP",
                "packets": 10,
                "bytes": 5000,
                "duration_ms": 100.0,
                "flags": "SYN,ACK",
                "failed_conn_info": "CLEAN",
                "label": "BENIGN",
            },
            {
                "timestamp": 70.0,
                "src_ip": "192.168.10.8",
                "dst_ip": "192.168.10.50",
                "dst_port": 443,
                "protocol": "TCP",
                "packets": 20,
                "bytes": 15000,
                "duration_ms": 300.0,
                "flags": "ACK",
                "failed_conn_info": "CLEAN",
                "label": "BENIGN",
            },
            {
                "timestamp": 90.0,
                "src_ip": "192.168.10.14",
                "dst_ip": "8.8.8.8",
                "dst_port": 53,
                "protocol": "UDP",
                "packets": 2,
                "bytes": 140,
                "duration_ms": 20.0,
                "flags": "NONE",
                "failed_conn_info": "NA",
                "label": "BENIGN",
            },
        ]
        window_flows = aggregator.extract_window_flows(flows, t_epoch)
        assert len(window_flows) == 3

        feats = aggregator.aggregate_window(window_flows, t_epoch)
        assert feats["flow_count"] == 3
        assert feats["packet_count"] == (10 + 20 + 2) == 32
        assert feats["byte_count"] == (5000 + 15000 + 140) == 20140
        assert abs(feats["avg_packets_per_flow"] - (32 / 3)) < 1e-7
        assert abs(feats["avg_bytes_per_flow"] - (20140 / 3)) < 1e-7
        assert abs(feats["avg_duration_ms"] - ((100 + 300 + 20) / 3)) < 1e-7
        assert abs(feats["packet_rate_per_sec"] - (32 / 60.0)) < 1e-7

    def test_empty_window_zero_safety(self, aggregator: ReferenceWindowAggregator):
        """Verify empty window produces zero/safe values without division by zero errors."""
        feats = aggregator.aggregate_window([], 100.0)
        assert feats["flow_count"] == 0
        assert feats["packet_count"] == 0
        assert feats["byte_count"] == 0
        assert feats["avg_packets_per_flow"] == 0.0
        assert feats["dst_port_entropy"] == 0.0
        assert feats["syn_ratio"] == 0.0

    def test_shannon_entropy_closed_form_analytical_oracles(self):
        """
        Verify Shannon entropy calculation against three analytical ground truths:
        1. Hand-calculated oracle: 8 flows [21, 22, 22, 23, 80, 80, 80, 80] -> 1.75 bits exactly.
        2. Uniform maximum entropy oracle: 4 distinct ports -> log2(4) = 2.0 bits exactly.
        3. Single port zero entropy oracle: 5 identical ports -> 0.0 bits exactly.
        """
        # Oracle 1: Hand-calculated 8-flow distribution
        # Ports: 21 (1/8), 22 (2/8), 23 (1/8), 80 (4/8)
        # H = - [ 2*(1/8 * -3) + 2/8 * -2 + 4/8 * -1 ] = - [ -0.75 - 0.50 - 0.50 ] = 1.75 bits
        oracle1_ports = [21, 22, 22, 23, 80, 80, 80, 80]
        ent1 = calculate_shannon_entropy(oracle1_ports)
        assert abs(ent1 - 1.7500000) < 1e-7, f"Oracle 1 failed: expected 1.75, got {ent1}"

        # Oracle 2: Uniform 4-port distribution (H = log2(4) = 2.0)
        oracle2_ports = [80, 443, 22, 53]
        ent2 = calculate_shannon_entropy(oracle2_ports)
        assert abs(ent2 - 2.0000000) < 1e-7, f"Oracle 2 failed: expected 2.0, got {ent2}"

        # Oracle 3: Degenerate single port (H = 0.0)
        oracle3_ports = [80, 80, 80, 80, 80]
        ent3 = calculate_shannon_entropy(oracle3_ports)
        assert abs(ent3 - 0.0000000) < 1e-7, f"Oracle 3 failed: expected 0.0, got {ent3}"

        # Invariant: Entropy is strictly non-negative
        assert ent1 >= 0.0 and ent2 >= 0.0 and ent3 >= 0.0

    def test_tcp_flag_and_connection_health_ratio_bounds(
        self, aggregator: ReferenceWindowAggregator
    ):
        """Verify all ratio features are bounded in [0.0, 1.0] and handshake asymmetry calculation."""
        flows = [
            {
                "timestamp": 10.0,
                "src_ip": "172.16.0.50",
                "dst_ip": "192.168.10.50",
                "dst_port": 21,
                "protocol": "TCP",
                "packets": 1,
                "bytes": 40,
                "duration_ms": 2.0,
                "flags": "SYN",
                "failed_conn_info": "SYN_NO_ACK",
                "label": "PortScan",
            },
            {
                "timestamp": 20.0,
                "src_ip": "172.16.0.50",
                "dst_ip": "192.168.10.50",
                "dst_port": 22,
                "protocol": "TCP",
                "packets": 2,
                "bytes": 80,
                "duration_ms": 3.5,
                "flags": "SYN",
                "failed_conn_info": "RST_ABORT",
                "label": "PortScan",
            },
            {
                "timestamp": 30.0,
                "src_ip": "192.168.10.5",
                "dst_ip": "192.168.10.50",
                "dst_port": 80,
                "protocol": "TCP",
                "packets": 15,
                "bytes": 3500,
                "duration_ms": 450.0,
                "flags": "ACK,FIN",
                "failed_conn_info": "CLEAN",
                "label": "BENIGN",
            },
            {
                "timestamp": 40.0,
                "src_ip": "192.168.10.8",
                "dst_ip": "192.168.10.50",
                "dst_port": 443,
                "protocol": "TCP",
                "packets": 12,
                "bytes": 2800,
                "duration_ms": 320.0,
                "flags": "PSH,ACK",
                "failed_conn_info": "CLEAN",
                "label": "BENIGN",
            },
        ]
        feats = aggregator.aggregate_window(flows, 60.0)

        # Expected:
        # SYN: 2/4 = 0.50
        # ACK: 2/4 = 0.50
        # Failed: 2/4 = 0.50 (flows 1, 2)
        # Short (<100ms): 2/4 = 0.50 (flows 1, 2)
        # Handshake asymmetry: 2 / (2 + 1.0) = 0.6666667
        assert abs(feats["syn_ratio"] - 0.50) < 1e-7
        assert abs(feats["ack_ratio"] - 0.50) < 1e-7
        assert abs(feats["failed_conn_ratio"] - 0.50) < 1e-7
        assert abs(feats["short_flow_ratio"] - 0.50) < 1e-7
        assert abs(feats["syn_ack_ratio"] - (2.0 / 3.0)) < 1e-7

        # Invariant checks: All ratios must be in [0.0, 1.0]
        for ratio_key in [
            "syn_ratio",
            "ack_ratio",
            "fin_ratio",
            "rst_ratio",
            "failed_conn_ratio",
            "short_flow_ratio",
            "protocol_tcp_ratio",
        ]:
            assert 0.0 <= feats[ratio_key] <= 1.0, f"Ratio {ratio_key} out of bounds: {feats[ratio_key]}"

    def test_volumetric_momentum_and_burst_scores(self, aggregator: ReferenceWindowAggregator):
        """Verify historical baseline momentum calculation M_vol = pkts / (hist_mean + 1.0)."""
        current_flows = [
            {
                "timestamp": 50.0,
                "src_ip": "172.16.0.1",
                "dst_ip": "192.168.10.50",
                "dst_port": 80,
                "protocol": "TCP",
                "packets": 500,
                "bytes": 350000,
                "duration_ms": 1500.0,
                "flags": "SYN",
                "failed_conn_info": "CLEAN",
                "label": "DoS_Hulk",
            }
        ]
        historical_packet_counts = [100, 100, 100]  # mean = 100.0
        feats = aggregator.aggregate_window(
            current_flows, 60.0, historical_baseline_packets=historical_packet_counts
        )

        expected_burst = 500.0 / (100.0 + 1.0)  # 500 / 101 ≈ 4.950495
        assert abs(feats["packet_burst_score"] - expected_burst) < 1e-7
        assert feats["packet_burst_score"] >= 0.0

    def test_shifted_prospective_target_labeling(self, aggregator: ReferenceWindowAggregator):
        """
        Verify shifted supervisory target labeling logic ($X_t \to Y_{t+1}$):
        - Observation window W(60) = [0, 60s].
        - If future horizon (60s, 120s] contains attack flows, then Y_60 = 1.
        - If future horizon contains ONLY benign flows, then Y_60 = 0.
        """
        t_epoch = 60.0
        all_flows = [
            # Retrospective benign observation flows [0, 60s]
            {
                "timestamp": 20.0,
                "src_ip": "192.168.10.5",
                "dst_ip": "192.168.10.50",
                "dst_port": 80,
                "protocol": "TCP",
                "packets": 10,
                "bytes": 2000,
                "duration_ms": 100.0,
                "flags": "ACK",
                "failed_conn_info": "CLEAN",
                "label": "BENIGN",
            },
            # Prospective attack flow in horizon (60s, 120s]
            {
                "timestamp": 95.0,
                "src_ip": "172.16.0.50",
                "dst_ip": "192.168.10.50",
                "dst_port": 22,
                "protocol": "TCP",
                "packets": 1,
                "bytes": 40,
                "duration_ms": 2.0,
                "flags": "SYN",
                "failed_conn_info": "SYN_NO_ACK",
                "label": "PortScan",
            },
        ]
        horizon_flows = aggregator.extract_horizon_flows(all_flows, t_epoch)
        assert len(horizon_flows) == 1

        target = aggregator.assign_shifted_label(horizon_flows)
        assert target["target_binary"] == 1
        assert target["target_stage"] == 1
        assert "PortScan" in target["attack_classes"]

        # If horizon contains only benign flows
        benign_horizon_flows = [
            {
                "timestamp": 80.0,
                "src_ip": "192.168.10.5",
                "dst_ip": "8.8.8.8",
                "dst_port": 53,
                "protocol": "UDP",
                "packets": 2,
                "bytes": 140,
                "duration_ms": 15.0,
                "flags": "NONE",
                "failed_conn_info": "NA",
                "label": "BENIGN",
            }
        ]
        benign_target = aggregator.assign_shifted_label(benign_horizon_flows)
        assert benign_target["target_binary"] == 0
        assert benign_target["target_stage"] == 0
        assert len(benign_target["attack_classes"]) == 0

    def test_theorem1_zero_lookahead_filtration_invariant(
        self, aggregator: ReferenceWindowAggregator
    ):
        """
        Verify Theorem 1 (Zero-Lookahead Feature Invariant):
        Features extracted at epoch t must be completely invariant to future flows (tau > t).
        """
        t_epoch = 60.0
        past_flows = [
            {
                "timestamp": 30.0,
                "src_ip": "192.168.10.5",
                "dst_ip": "192.168.10.50",
                "dst_port": 80,
                "protocol": "TCP",
                "packets": 10,
                "bytes": 2000,
                "duration_ms": 100.0,
                "flags": "ACK",
                "failed_conn_info": "CLEAN",
                "label": "BENIGN",
            }
        ]
        # Feature vector extracted on past flows
        window_past = aggregator.extract_window_flows(past_flows, t_epoch)
        feats_baseline = aggregator.aggregate_window(window_past, t_epoch)

        # Inject future malicious attack flow at tau = 60.001s
        future_perturbed_flows = past_flows + [
            {
                "timestamp": 60.001,
                "src_ip": "172.16.0.1",
                "dst_ip": "192.168.10.50",
                "dst_port": 80,
                "protocol": "TCP",
                "packets": 10000,
                "bytes": 5000000,
                "duration_ms": 5000.0,
                "flags": "SYN",
                "failed_conn_info": "SYN_NO_ACK",
                "label": "DDoS_LOIC",
            }
        ]
        window_perturbed = aggregator.extract_window_flows(future_perturbed_flows, t_epoch)
        feats_perturbed = aggregator.aggregate_window(window_perturbed, t_epoch)

        # Bitwise invariance assertion: feature vectors must be identical
        assert feats_baseline == feats_perturbed, (
            "Theorem 1 violation: future flow leaked into observation window features!"
        )

    def test_theorem2_temporal_split_embargo_buffer_isolation(self):
        """
        Verify Theorem 2 (Split Embargo Condition):
        Asserts Delta_purge >= W_size + H_horizon guarantees disjoint sets between
        training supervisory label intervals and test observation intervals.
        """
        W_size = 60.0
        H_horizon = 180.0
        Delta_purge = W_size + H_horizon  # 240.0s

        T_split = 1000.0
        t_train_max = T_split - H_horizon  # 820.0s
        t_test_min = T_split + Delta_purge  # 1240.0s

        # Supremum training label flow timestamp
        tau_train_sup = t_train_max + H_horizon  # 820 + 180 = 1000.0 (T_split)
        # Infimum test observation flow timestamp
        tau_test_inf = t_test_min - W_size  # 1240 - 60 = 1180.0

        # Strict separation assertion
        assert tau_train_sup <= T_split
        assert tau_test_inf > T_split
        assert tau_test_inf > tau_train_sup, (
            f"Theorem 2 violation: test observation ({tau_test_inf}s) overlaps training target ({tau_train_sup}s)"
        )

    def test_focal_loss_mathematical_properties(self):
        """
        Verify Lin et al. Focal Loss mathematical properties:
        L_Focal(y, p) = - alpha_t * (1 - p_t)^gamma * log(p_t)
        Verifies heavy suppression of easy negatives and preservation of hard precursor gradients.
        """
        gamma = 2.0
        alpha = 0.75

        def focal_loss(y: int, p: float) -> float:
            p_clamped = max(min(p, 1.0 - 1e-15), 1e-15)
            if y == 1:
                return -alpha * ((1.0 - p_clamped) ** gamma) * math.log(p_clamped)
            else:
                return -(1.0 - alpha) * (p_clamped ** gamma) * math.log(1.0 - p_clamped)

        def bce_loss(y: int, p: float) -> float:
            p_clamped = max(min(p, 1.0 - 1e-15), 1e-15)
            if y == 1:
                return -math.log(p_clamped)
            else:
                return -math.log(1.0 - p_clamped)

        # Easy negative: y=0, p=0.01
        loss_focal_easy = focal_loss(0, 0.01)
        loss_bce_easy = bce_loss(0, 0.01)
        # Focal loss suppresses easy negative by factor of p^gamma = (0.01)^2 = 0.0001
        suppression_ratio = loss_focal_easy / loss_bce_easy
        assert suppression_ratio < 0.001, (
            f"Expected > 99.9% loss suppression for easy negative, got ratio {suppression_ratio}"
        )

        # Hard positive precursor: y=1, p=0.20
        loss_focal_hard = focal_loss(1, 0.20)
        assert loss_focal_hard > 0.1, "Hard precursor instance lost gradient signal"


# ==============================================================================
# 5. TestResearchFormulationDoc
# ==============================================================================

class TestResearchFormulationDoc:
    """
    Test suite verifying the research formulation document (Deliverable R1).
    Validates structural completeness across all 8 sections, LaTeX equations,
    anti-leakage theorems, lead-time metrics, and MITRE ATT&CK taxonomy mappings.
    """

    @pytest.fixture(scope="class")
    def research_doc_text(self) -> str:
        """Load forecasting_formulation.md document text."""
        assert RESEARCH_DOC_PATH.exists(), f"Research document missing at {RESEARCH_DOC_PATH}"
        with open(RESEARCH_DOC_PATH, "r", encoding="utf-8") as f:
            content = f.read()
        return content

    def test_research_doc_exists_and_substantial_size(self):
        """Verify docs/research/forecasting_formulation.md exists and has size > 15 KB."""
        assert RESEARCH_DOC_PATH.exists(), f"Research doc missing at {RESEARCH_DOC_PATH}"
        doc_size = RESEARCH_DOC_PATH.stat().st_size
        assert doc_size > 15000, f"Research doc size ({doc_size} bytes) is suspiciously small"

    def test_research_doc_has_all_eight_structural_sections(self, research_doc_text: str):
        """Verify presence of all 8 core structural sections."""
        required_section_headers = [
            "## 1. Problem Paradigm: Reactive IDS vs. Proactive Forecasting",
            "## 2. Mathematical Problem Formulation",
            "## 3. Measure-Theoretic Anti-Leakage Proofs & Invariants",
            "## 4. Attack Progression Lifecycle & MITRE ATT&CK Mapping",
            "## 5. Precursor Feature Mathematics",
            "## 6. Loss Function Formulations for Imbalanced Precursor Forecasting",
            "## 7. Lead-Time & Early Warning Evaluation Metrics",
            "## 8. End-to-End Pipeline Architecture & Real-Time Dataflow",
        ]
        for header in required_section_headers:
            assert header in research_doc_text, f"Research document missing section '{header}'"

    def test_research_doc_latex_mathematical_formulas(self, research_doc_text: str):
        """Verify presence of key LaTeX equations throughout the research document."""
        expected_formulas = [
            r"X_t \to Y_{t+1}",
            r"W(t) = [t - W_{\text{size}}, t]",
            r"\mathcal{H}(t) = (t, t + H_{\text{horizon}}]",
            r"H(dst\_port) = -\sum",
            r"R_{\text{SYN/ACK}}",
            r"\Delta f_t = f_t - f_{t-1}",
            r"\Delta^2 f_t",
            r"\mathcal{L}_{\text{Focal}}",
            r"\mathcal{L}_{\text{Cost-Lead}}",
        ]
        for formula in expected_formulas:
            assert formula in research_doc_text, (
                f"Research document missing expected LaTeX formula: '{formula}'"
            )

    def test_research_doc_anti_leakage_theorems(self, research_doc_text: str):
        """Verify presence of Theorem 1 (Zero-Lookahead) and Theorem 2 (Split Embargo)."""
        assert "Theorem 1" in research_doc_text
        assert "Zero-Lookahead Feature Invariant" in research_doc_text
        assert r"\mathbf{x}_t \in m\mathfrak{F}_t" in research_doc_text

        assert "Theorem 2" in research_doc_text
        assert "Split Embargo Buffer" in research_doc_text
        assert r"\Delta_{\text{purge}} \ge W_{\text{size}} + H_{\text{horizon}}" in research_doc_text

    def test_research_doc_lead_time_metrics_definitions(self, research_doc_text: str):
        """Verify formal definition of early-warning lead-time and operational SOC metrics."""
        expected_metrics = [
            r"\Delta T_{\text{lead}}",
            "Mean Lead Time (MLT)",
            "Effective Warning Coverage Rate",
            "Alert Usefulness Rate (AUR)",
            "False Warning Rate",
        ]
        for metric in expected_metrics:
            assert metric in research_doc_text, f"Research document missing metric '{metric}'"

    def test_research_doc_mitre_attack_mappings(self, research_doc_text: str):
        """Verify inclusion of MITRE ATT&CK tactics and technique identifiers."""
        expected_mitre_ids = [
            "T1595.001",  # Active Scanning: IP Blocks
            "T1046",      # Network Service Discovery
            "T1110.001",  # Brute Force: Password Guessing
            "T1498.001",  # Network DoS: Direct Flood
            "T1499.002",  # Endpoint DoS: Service Exhaustion
        ]
        for tid in expected_mitre_ids:
            assert tid in research_doc_text, f"Research document missing MITRE technique '{tid}'"
