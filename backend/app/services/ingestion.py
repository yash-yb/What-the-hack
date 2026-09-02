import csv
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO
from typing import Any

REQUIRED_COLUMNS = {"timestamp", "src_ip", "dst_ip", "protocol", "packets", "bytes"}

# Values follow docs/api/feature_schema_contract.json (RawFlow). Legacy truthy/falsy spellings
# are kept so older CSVs still load; anything else is an invalid row.
PROTOCOLS = {"TCP", "UDP", "ICMP", "OTHER"}
PROTOCOL_ALIASES = {"6": "TCP", "17": "UDP", "1": "ICMP"}
TCP_FLAG_TOKENS = {"SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWE"}
FAILED_CONNECTION_TRUE = {"syn_no_ack", "rst_abort", "zero_win", "failed", "true", "1", "yes"}
FAILED_CONNECTION_FALSE = {"clean", "false", "0", "no"}
FAILED_CONNECTION_UNKNOWN = {"na", "n/a", "none", "null"}


@dataclass
class ParsedFlow:
    observed_at: datetime
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    packet_count: int
    byte_count: int
    duration_ms: int | None
    tcp_flags: str | None
    failed_connection: bool | None
    extra_json: dict[str, Any]


@dataclass
class ParseResult:
    flows: list[ParsedFlow]
    total_rows: int
    skipped_rows: int


class CsvValidationError(ValueError):
    pass


def parse_csv_flows(content: str) -> ParseResult:
    reader = csv.DictReader(StringIO(content))
    headers = set(reader.fieldnames or [])
    missing_columns = REQUIRED_COLUMNS - headers
    if missing_columns:
        raise CsvValidationError(f"CSV is missing required columns: {', '.join(sorted(missing_columns))}")

    flows: list[ParsedFlow] = []
    total_rows = 0
    skipped_rows = 0
    for row in reader:
        total_rows += 1
        try:
            flows.append(parse_row(row))
        except (TypeError, ValueError):
            skipped_rows += 1
    return ParseResult(flows=flows, total_rows=total_rows, skipped_rows=skipped_rows)


def parse_row(row: dict[str, str | None]) -> ParsedFlow:
    observed_at = parse_timestamp(required_value(row, "timestamp"))
    src_ip = str(ipaddress.ip_address(required_value(row, "src_ip")))
    dst_ip = str(ipaddress.ip_address(required_value(row, "dst_ip")))
    protocol = parse_protocol(required_value(row, "protocol"))
    mapped_fields = {"timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packets", "bytes", "duration_ms", "flags", "failed_conn_info"}
    return ParsedFlow(
        observed_at=observed_at,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=parse_port(row.get("src_port")),
        dst_port=parse_port(row.get("dst_port")),
        protocol=protocol,
        packet_count=parse_nonnegative_int(required_value(row, "packets"), "packets"),
        byte_count=parse_nonnegative_int(required_value(row, "bytes"), "bytes"),
        duration_ms=parse_duration(row.get("duration_ms")),
        tcp_flags=parse_flags(row.get("flags")),
        failed_connection=parse_failed_connection(row.get("failed_conn_info")),
        extra_json={key: value for key, value in row.items() if key not in mapped_fields and value not in (None, "")},
    )


def required_value(row: dict[str, str | None], name: str) -> str:
    value = optional_value(row.get(name))
    if value is None:
        raise ValueError(f"{name} is required")
    return value


def optional_value(value: str | None) -> str | None:
    return value.strip() or None if value is not None else None


def parse_protocol(value: str) -> str:
    """Normalise to the contract enum: TCP, UDP, ICMP, or OTHER (IANA numbers accepted)."""
    normalized = value.strip().upper()
    normalized = PROTOCOL_ALIASES.get(normalized, normalized)
    return normalized if normalized in PROTOCOLS else "OTHER"


def parse_flags(value: str | None) -> str | None:
    """Return a canonical comma-separated flag list, None for missing/NONE, ValueError for junk."""
    normalized = optional_value(value)
    if normalized is None or normalized.upper() == "NONE":
        return None
    tokens = [token.strip().upper() for token in normalized.split(",") if token.strip()]
    unknown = [token for token in tokens if token not in TCP_FLAG_TOKENS]
    if not tokens or unknown:
        raise ValueError(f"Unknown TCP flags: {', '.join(unknown) or value}")
    return ",".join(dict.fromkeys(tokens))


def parse_failed_connection(value: str | None) -> bool | None:
    """Map failed_conn_info to True (failed), False (clean), or None (not applicable)."""
    normalized = optional_value(value)
    if normalized is None:
        return None
    lowered = normalized.lower()
    if lowered in FAILED_CONNECTION_TRUE:
        return True
    if lowered in FAILED_CONNECTION_FALSE:
        return False
    if lowered in FAILED_CONNECTION_UNKNOWN:
        return None
    raise ValueError(f"Unknown failed_conn_info value: {value}")


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def parse_port(value: str | None) -> int | None:
    normalized = optional_value(value)
    if normalized is None:
        return None
    port = int(normalized)
    if not 0 <= port <= 65535:
        raise ValueError("Port must be between 0 and 65535")
    return port


def parse_nonnegative_int(value: str, field_name: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise ValueError(f"{field_name} must not be negative")
    return parsed


def parse_duration(value: str | None) -> int | None:
    normalized = optional_value(value)
    if normalized is None:
        return None
    duration_ms = round(float(normalized))
    if duration_ms < 0:
        raise ValueError("duration_ms must not be negative")
    return duration_ms
