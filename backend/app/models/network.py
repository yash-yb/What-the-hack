import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, CheckConstraint, DateTime, Enum, ForeignKey, Index, Integer, Numeric, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RoleName(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class IngestionStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SourceType(str, enum.Enum):
    CSV_REPLAY = "csv_replay"


class WindowScope(str, enum.Enum):
    SOURCE = "source"
    HOST = "host"
    FLOW = "flow"


class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class Role(Base, TimestampMixin):
    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[RoleName] = mapped_column(Enum(RoleName, name="role_name", native_enum=False), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true", nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"
    __table_args__ = (Index("ix_revoked_tokens_expires_at", "expires_at"),)

    token_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class TrafficSource(Base, TimestampMixin):
    __tablename__ = "traffic_sources"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    source_type: Mapped[SourceType] = mapped_column(Enum(SourceType, name="source_type", native_enum=False), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true", nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class IngestionJob(Base, TimestampMixin):
    __tablename__ = "ingestion_jobs"
    __table_args__ = (Index("ix_ingestion_jobs_source_status_created", "traffic_source_id", "status", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    traffic_source_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("traffic_sources.id", ondelete="RESTRICT"), nullable=False)
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[IngestionStatus] = mapped_column(Enum(IngestionStatus, name="ingestion_status", native_enum=False), nullable=False)
    total_rows: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    accepted_rows: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    skipped_rows: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RawFlow(Base, TimestampMixin):
    __tablename__ = "raw_flows"
    __table_args__ = (
        Index("ix_raw_flows_observed_at", "observed_at"),
        Index("ix_raw_flows_src_dst_ip", "src_ip", "dst_ip"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    traffic_source_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("traffic_sources.id", ondelete="RESTRICT"), nullable=False)
    ingestion_job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ingestion_jobs.id", ondelete="CASCADE"), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    packet_count: Mapped[int] = mapped_column(Integer, nullable=False)
    byte_count: Mapped[int] = mapped_column(Integer, nullable=False)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    tcp_flags: Mapped[str | None] = mapped_column(String(32))
    failed_connection: Mapped[bool | None] = mapped_column(Boolean)
    extra_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}", nullable=False)


class TrafficWindow(Base, TimestampMixin):
    __tablename__ = "traffic_windows"
    __table_args__ = (
        CheckConstraint("window_end > window_start", name="ck_traffic_windows_valid_range"),
        Index("ix_traffic_windows_source_range", "traffic_source_id", "window_start", "window_end"),
        UniqueConstraint("traffic_source_id", "scope_type", "scope_key", "window_start", "window_end", name="uq_traffic_windows_source_scope_range"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    traffic_source_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("traffic_sources.id", ondelete="RESTRICT"), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    scope_type: Mapped[WindowScope] = mapped_column(Enum(WindowScope, name="window_scope", native_enum=False), nullable=False)
    scope_key: Mapped[str] = mapped_column(String(255), nullable=False)
    flow_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    packet_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    byte_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)


class WindowFeature(Base, TimestampMixin):
    __tablename__ = "window_features"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    traffic_window_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("traffic_windows.id", ondelete="CASCADE"), unique=True, nullable=False)
    feature_schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    features_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    is_complete: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true", nullable=False)
    missing_fields_json: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default="[]", nullable=False)


class ModelVersion(Base, TimestampMixin):
    __tablename__ = "model_versions"
    __table_args__ = (UniqueConstraint("name", "version", name="uq_model_versions_name_version"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    feature_schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    artifact_uri: Mapped[str] = mapped_column(Text, nullable=False)
    metrics_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false", nullable=False)
    trained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Prediction(Base):
    __tablename__ = "predictions"
    __table_args__ = (
        CheckConstraint("forecast_window_end > forecast_window_start", name="ck_predictions_valid_forecast_range"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_predictions_risk_score"),
        CheckConstraint("confidence_score >= 0 AND confidence_score <= 1", name="ck_predictions_confidence_score"),
        Index("ix_predictions_created_risk_level", "created_at", "risk_level"),
        Index("ix_predictions_forecast_range", "forecast_window_start", "forecast_window_end"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    observation_window_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("traffic_windows.id", ondelete="RESTRICT"), nullable=False)
    model_version_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("model_versions.id", ondelete="SET NULL"))
    forecast_window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    forecast_window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    risk_score: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(Enum(RiskLevel, name="risk_level", native_enum=False), nullable=False)
    predicted_attack_type: Mapped[str | None] = mapped_column(String(80))
    confidence_score: Mapped[float] = mapped_column(Numeric(4, 3), nullable=False)
    is_fallback: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false", nullable=False)
    is_uncertain: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false", nullable=False)
    is_ood: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false", nullable=False)
    explanation_json: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, server_default="[]", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class HostEntity(Base, TimestampMixin):
    __tablename__ = "host_entities"
    __table_args__ = (UniqueConstraint("traffic_source_id", "ip_address", name="uq_host_entities_source_ip"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    traffic_source_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("traffic_sources.id", ondelete="CASCADE"), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255))
    entity_type: Mapped[str] = mapped_column(String(40), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Alert(Base, TimestampMixin):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_status_severity_created", "status", "severity", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    prediction_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("predictions.id", ondelete="CASCADE"), unique=True, nullable=False)
    target_host_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("host_entities.id", ondelete="SET NULL"))
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[AlertSeverity] = mapped_column(Enum(AlertSeverity, name="alert_severity", native_enum=False), nullable=False)
    status: Mapped[AlertStatus] = mapped_column(Enum(AlertStatus, name="alert_status", native_enum=False), nullable=False)
    recommended_actions_json: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default="[]", nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AlertEvent(Base):
    __tablename__ = "alert_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    from_status: Mapped[AlertStatus | None] = mapped_column(Enum(AlertStatus, name="alert_status", native_enum=False))
    to_status: Mapped[AlertStatus | None] = mapped_column(Enum(AlertStatus, name="alert_status", native_enum=False))
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_created_at", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    request_id: Mapped[str | None] = mapped_column(String(80))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
