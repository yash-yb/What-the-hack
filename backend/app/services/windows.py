import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.network import AuditLog, IngestionJob, RawFlow, TrafficWindow, WindowScope

logger = logging.getLogger(__name__)


@dataclass
class WindowAggregate:
    window_start: datetime
    window_end: datetime
    flow_count: int
    packet_count: int
    byte_count: int


@dataclass
class WindowBuildResult:
    traffic_source_id: UUID
    raw_flows_processed: int
    windows_written: int
    window_seconds: int


def aggregate_raw_flows(raw_flows: Iterable[RawFlow], window_seconds: int) -> list[WindowAggregate]:
    buckets: dict[datetime, dict[str, object]] = {}
    for flow in raw_flows:
        start = floor_to_window(flow.observed_at, window_seconds)
        bucket = buckets.setdefault(start, {"flows": set(), "packets": 0, "bytes": 0})
        bucket["flows"].add((flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol))
        bucket["packets"] += flow.packet_count
        bucket["bytes"] += flow.byte_count
    return [
        WindowAggregate(
            window_start=start,
            window_end=start + timedelta(seconds=window_seconds),
            flow_count=len(bucket["flows"]),
            packet_count=bucket["packets"],
            byte_count=bucket["bytes"],
        )
        for start, bucket in sorted(buckets.items())
    ]


def as_utc(value: datetime) -> datetime:
    """Treat naive datetimes as UTC (SQLite drops the offset); normalise aware ones to UTC."""
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def floor_to_window(observed_at: datetime, window_seconds: int) -> datetime:
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    timestamp = as_utc(observed_at).timestamp()
    return datetime.fromtimestamp(int(timestamp // window_seconds) * window_seconds, tz=timezone.utc)


def build_traffic_windows(db: Session, traffic_source_id: UUID) -> WindowBuildResult:
    raw_flows = list(db.scalars(select(RawFlow).where(RawFlow.traffic_source_id == traffic_source_id).order_by(RawFlow.observed_at)))
    aggregates = aggregate_raw_flows(raw_flows, settings.traffic_window_seconds)
    scope_key = str(traffic_source_id)
    existing_windows = {
        as_utc(window.window_start): window
        for window in db.scalars(
            select(TrafficWindow).where(
                TrafficWindow.traffic_source_id == traffic_source_id,
                TrafficWindow.scope_type == WindowScope.SOURCE,
                TrafficWindow.scope_key == scope_key,
                TrafficWindow.window_seconds == settings.traffic_window_seconds,
            )
        )
    }
    for aggregate in aggregates:
        window = existing_windows.get(aggregate.window_start)
        if window is None:
            window = TrafficWindow(
                traffic_source_id=traffic_source_id,
                window_start=aggregate.window_start,
                window_end=aggregate.window_end,
                window_seconds=settings.traffic_window_seconds,
                scope_type=WindowScope.SOURCE,
                scope_key=scope_key,
            )
            db.add(window)
        window.flow_count = aggregate.flow_count
        window.packet_count = aggregate.packet_count
        window.byte_count = aggregate.byte_count
    return WindowBuildResult(
        traffic_source_id=traffic_source_id,
        raw_flows_processed=len(raw_flows),
        windows_written=len(aggregates),
        window_seconds=settings.traffic_window_seconds,
    )


def build_traffic_windows_in_background(traffic_source_id: UUID, ingestion_job_id: UUID | None = None) -> None:
    """
    Run after a successful upload without keeping the upload request open.

    The outcome is recorded so a failed build is never silent: success writes an audit
    row, failure writes an audit row and stores the reason on the ingestion job.
    """
    with SessionLocal() as db:
        try:
            result = build_traffic_windows(db, traffic_source_id)
            db.add(AuditLog(
                actor_user_id=None,
                action="windows.build.auto",
                resource_type="ingestion_job" if ingestion_job_id else "traffic_source",
                resource_id=ingestion_job_id or traffic_source_id,
                metadata_json={"raw_flows_processed": result.raw_flows_processed, "windows_written": result.windows_written},
            ))
            db.commit()
        except Exception as exc:  # noqa: BLE001 - background task: record, never raise into the server loop
            db.rollback()
            logger.exception("Background window build failed for source %s", traffic_source_id)
            if ingestion_job_id is not None:
                job = db.get(IngestionJob, ingestion_job_id)
                if job is not None:
                    job.error_message = f"Window build failed: {exc}"[:2000]
            db.add(AuditLog(
                actor_user_id=None,
                action="windows.build.failed",
                resource_type="traffic_source",
                resource_id=traffic_source_id,
                metadata_json={"error": str(exc)[:500]},
            ))
            db.commit()
