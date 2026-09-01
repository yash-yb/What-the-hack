from datetime import datetime, timezone
from types import SimpleNamespace

from app.services.windows import aggregate_raw_flows


def flow(seconds: int, packets: int, byte_count: int, dst_port: int = 443, minute: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        observed_at=datetime(2026, 8, 28, 18, minute, seconds, tzinfo=timezone.utc),
        src_ip="192.168.1.10",
        dst_ip="10.0.0.2",
        src_port=50000,
        dst_port=dst_port,
        protocol="TCP",
        packet_count=packets,
        byte_count=byte_count,
    )


def test_aggregate_groups_fixed_minute_and_distinct_flows() -> None:
    result = aggregate_raw_flows([flow(5, 2, 100), flow(40, 3, 200), flow(45, 1, 40, 53), flow(0, 4, 300)], 60)
    assert len(result) == 1
    assert result[0].flow_count == 2
    assert result[0].packet_count == 10
    assert result[0].byte_count == 640


def test_aggregate_creates_a_new_window_at_the_boundary() -> None:
    result = aggregate_raw_flows([flow(59, 1, 10), flow(0, 2, 20, minute=1)], 60)
    assert len(result) == 2
