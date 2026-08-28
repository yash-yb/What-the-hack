# Tier 5 Adversarial Coverage Hardening Suite
import csv, datetime, io, json, math, os, re, sys, zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import pytest, jsonschema
from jsonschema import Draft7Validator, ValidationError

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOTI))

from ai.datasets.download_cicids2017 import (
    CICIDS_SHA256_CATALOG, DAY_SUBSET_ALIASES, RAW_FLOWS_COLUMNS,
    STANDARD_84_HEADERS, SUBSET_CANONICAL_KEYS, VALID_SOURCES, VALID_SUBSETS,
    CICIDSSyntheticGenerator, acquire_dataset, build_argument_parser,
    calculate_sha256, classify_failed_connection, clean_cicids_header,
    compute_sha256, convert_duration_us_to_ms, deduplicate_columns,
    generate_synthetic_cicids2017, main as cli_main, map_cicids_to_raw_flows,
    parse_flexible_timestamp, safe_extract_zip, sanitize_header,
    sanitize_inf_nan, synthesize_tcp_flags, verify_checksums,
)

SCHEMA_PATH = PROJECT_ROOT / 'docs' / 'api' / 'feature_schema_contract.json'
RESEARCH_DOC_PATH = PROJECT_ROOT / 'docs' / 'research' / 'forecasting_formulation.md'
SAMPLE_CSV_PATH = PROJECT_ROOT / 'sample_data' / 'sample_flows_mini.csv'

@pytest.fixture(scope='session')
def schema_contract():
    with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)

@pytest.fixture(scope='session')
def raw_flow_validator(schema_contract):
    return Draft7Validator(schema_contract['definitions']['RawFlow'])

@pytest.fixture(scope='session')
def traffic_window_validator(schema_contract):
    return Draft7Validator(schema_contract['definitions']['traffic_window'])

@pytest.fixture(scope='session')
def window_features_validator(schema_contract):
    return Draft7Validator(schema_contract['definitions']['window_features'])

@pytest.fixture(scope='session')
def inference_request_validator(schema_contract):
    return Draft7Validator(schema_contract['definitions']['inference_request'])

@pytest.fixture(scope='session')
def inference_response_validator(schema_contract):
    return Draft7Validator(schema_contract['definitions']['inference_response'])

