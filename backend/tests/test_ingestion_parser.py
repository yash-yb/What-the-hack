import pytest

from app.services.ingestion import CsvValidationError, parse_csv_flows

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
