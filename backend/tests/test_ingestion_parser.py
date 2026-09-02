from pathlib import Path

import pytest

from app.services.ingestion import CsvValidationError, parse_csv_flows, parse_failed_connection, parse_flags, parse_protocol

SAMPLE_CSV = Path(__file__).resolve().parents[2] / "sample_data" / "sample_flows_mini.csv"

CSV = """timestamp,src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes,duration_ms,flags,failed_conn_info,label
2026-08-28T18:00:00.000Z,192.168.10.5,172.217.16.206,49152,443,TCP,18,4820,1250.5,SYN,CLEAN,BENIGN
bad-time,not-an-ip,172.217.16.206,1,443,TCP,18,4820,1,SYN,CLEAN,BENIGN
"""


def test_parser_accepts_valid_rows_and_skips_malformed_ones() -> None:
    result = parse_csv_flows(CSV)
    assert result.total_rows == 2
    assert result.skipped_rows == 1
    assert len(result.flows) == 1
    assert result.flows[0].duration_ms == 1250
    assert result.flows[0].extra_json == {"label": "BENIGN"}


def test_parser_rejects_missing_required_columns() -> None:
    with pytest.raises(CsvValidationError, match="src_ip"):
        parse_csv_flows("timestamp,dst_ip,protocol,packets,bytes\n2026-08-28T18:00:00Z,1.1.1.1,TCP,1,2\n")


def test_sample_dataset_loads_without_skips() -> None:
    result = parse_csv_flows(SAMPLE_CSV.read_text(encoding="utf-8"))
    assert result.total_rows == 120
    assert result.skipped_rows == 0
    assert {flow.protocol for flow in result.flows} <= {"TCP", "UDP", "ICMP", "OTHER"}


def test_failed_connection_follows_contract_enum() -> None:
    assert parse_failed_connection("ZERO_WIN") is True
    assert parse_failed_connection("SYN_NO_ACK") is True
    assert parse_failed_connection("RST_ABORT") is True
    assert parse_failed_connection("CLEAN") is False
    assert parse_failed_connection("NA") is None
    assert parse_failed_connection(None) is None
    with pytest.raises(ValueError):
        parse_failed_connection("CORRUPT")


def test_protocol_is_normalised_to_contract_enum() -> None:
    assert parse_protocol("tcp") == "TCP"
    assert parse_protocol("17") == "UDP"
    assert parse_protocol("1") == "ICMP"
    assert parse_protocol("SCTP") == "OTHER"


def test_flags_are_validated_and_canonicalised() -> None:
    assert parse_flags("psh,ack") == "PSH,ACK"
    assert parse_flags("NONE") is None
    assert parse_flags("") is None
    with pytest.raises(ValueError):
        parse_flags("INVALID_FLAG")


def test_row_with_unknown_flag_is_skipped_not_fatal() -> None:
    csv = CSV + "2026-08-28T18:00:01.000Z,192.168.10.5,172.217.16.206,49152,443,TCP,1,10,1,BOGUS,CLEAN,BENIGN\n"
    result = parse_csv_flows(csv)
    assert result.total_rows == 3
    assert result.skipped_rows == 2
