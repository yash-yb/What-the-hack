"""Create the initial forecasting database schema.

Revision ID: 20260829_0001
Revises:
Create Date: 2026-08-29
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260829_0001"
down_revision = None
branch_labels = None
depends_on = None

uuid = postgresql.UUID(as_uuid=True)
jsonb = postgresql.JSONB
timestamp = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "roles",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("name", sa.Enum("admin", "analyst", "viewer", name="role_name", native_enum=False), nullable=False, unique=True),
        sa.Column("description", sa.Text()),
        sa.Column("created_at", timestamp, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", timestamp, server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "users",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("role_id", uuid, sa.ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("email", sa.String(320), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("last_login_at", timestamp),
        sa.Column("created_at", timestamp, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", timestamp, server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "traffic_sources",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("name", sa.String(160), nullable=False, unique=True),
        sa.Column("source_type", sa.Enum("csv_replay", name="source_type", native_enum=False), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_by_user_id", uuid, sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", timestamp, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", timestamp, server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "ingestion_jobs",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("traffic_source_id", uuid, sa.ForeignKey("traffic_sources.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("requested_by_user_id", uuid, sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("original_filename", sa.String(255), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.Enum("pending", "running", "completed", "failed", name="ingestion_status", native_enum=False), nullable=False),
        sa.Column("total_rows", sa.Integer(), server_default="0", nullable=False),
        sa.Column("accepted_rows", sa.Integer(), server_default="0", nullable=False),
        sa.Column("skipped_rows", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error_message", sa.Text()),
        sa.Column("started_at", timestamp),
        sa.Column("completed_at", timestamp),
        sa.Column("created_at", timestamp, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", timestamp, server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_ingestion_jobs_source_status_created", "ingestion_jobs", ["traffic_source_id", "status", "created_at"])
    op.create_table(
        "raw_flows",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("traffic_source_id", uuid, sa.ForeignKey("traffic_sources.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("ingestion_job_id", uuid, sa.ForeignKey("ingestion_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("observed_at", timestamp, nullable=False),
        sa.Column("src_ip", sa.String(45), nullable=False), sa.Column("dst_ip", sa.String(45), nullable=False),
        sa.Column("src_port", sa.Integer()), sa.Column("dst_port", sa.Integer()),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("packet_count", sa.Integer(), nullable=False), sa.Column("byte_count", sa.Integer(), nullable=False),
        sa.Column("duration_ms", sa.Integer()), sa.Column("tcp_flags", sa.String(32)),
        sa.Column("failed_connection", sa.Boolean()),
        sa.Column("extra_json", jsonb, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", timestamp, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", timestamp, server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_raw_flows_observed_at", "raw_flows", ["observed_at"])
    op.create_index("ix_raw_flows_src_dst_ip", "raw_flows", ["src_ip", "dst_ip"])
    op.create_table(
        "traffic_windows",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("traffic_source_id", uuid, sa.ForeignKey("traffic_sources.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("window_start", timestamp, nullable=False), sa.Column("window_end", timestamp, nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("scope_type", sa.Enum("source", "host", "flow", name="window_scope", native_enum=False), nullable=False),
        sa.Column("scope_key", sa.String(255), nullable=False),
        sa.Column("flow_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("packet_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("byte_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("created_at", timestamp, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", timestamp, server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("window_end > window_start", name="ck_traffic_windows_valid_range"),
    )
    op.create_index("ix_traffic_windows_source_range", "traffic_windows", ["traffic_source_id", "window_start", "window_end"])
    op.create_table(
        "window_features",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("traffic_window_id", uuid, sa.ForeignKey("traffic_windows.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("feature_schema_version", sa.String(32), nullable=False),
        sa.Column("features_json", jsonb, nullable=False),
        sa.Column("is_complete", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("missing_fields_json", jsonb, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("created_at", timestamp, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", timestamp, server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "model_versions",
        sa.Column("id", uuid, primary_key=True), sa.Column("name", sa.String(160), nullable=False),
        sa.Column("version", sa.String(64), nullable=False), sa.Column("feature_schema_version", sa.String(32), nullable=False),
        sa.Column("artifact_uri", sa.Text(), nullable=False),
        sa.Column("metrics_json", jsonb, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("trained_at", timestamp), sa.Column("created_at", timestamp, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", timestamp, server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("name", "version", name="uq_model_versions_name_version"),
    )
    op.create_table(
        "predictions",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("observation_window_id", uuid, sa.ForeignKey("traffic_windows.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("model_version_id", uuid, sa.ForeignKey("model_versions.id", ondelete="SET NULL")),
        sa.Column("forecast_window_start", timestamp, nullable=False), sa.Column("forecast_window_end", timestamp, nullable=False),
        sa.Column("risk_score", sa.Numeric(5, 2), nullable=False),
        sa.Column("risk_level", sa.Enum("low", "medium", "high", name="risk_level", native_enum=False), nullable=False),
        sa.Column("predicted_attack_type", sa.String(80)), sa.Column("confidence_score", sa.Numeric(4, 3), nullable=False),
        sa.Column("is_fallback", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("is_uncertain", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("is_ood", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("explanation_json", jsonb, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("created_at", timestamp, server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("forecast_window_end > forecast_window_start", name="ck_predictions_valid_forecast_range"),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_predictions_risk_score"),
        sa.CheckConstraint("confidence_score >= 0 AND confidence_score <= 1", name="ck_predictions_confidence_score"),
    )
    op.create_index("ix_predictions_created_risk_level", "predictions", ["created_at", "risk_level"])
    op.create_index("ix_predictions_forecast_range", "predictions", ["forecast_window_start", "forecast_window_end"])
    op.create_table(
        "host_entities",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("traffic_source_id", uuid, sa.ForeignKey("traffic_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=False), sa.Column("hostname", sa.String(255)),
        sa.Column("entity_type", sa.String(40), nullable=False),
        sa.Column("first_seen_at", timestamp, nullable=False), sa.Column("last_seen_at", timestamp, nullable=False),
        sa.Column("created_at", timestamp, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", timestamp, server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("traffic_source_id", "ip_address", name="uq_host_entities_source_ip"),
    )
    op.create_table(
        "alerts",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("prediction_id", uuid, sa.ForeignKey("predictions.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("target_host_id", uuid, sa.ForeignKey("host_entities.id", ondelete="SET NULL")),
        sa.Column("title", sa.String(255), nullable=False), sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("severity", sa.Enum("low", "medium", "high", "critical", name="alert_severity", native_enum=False), nullable=False),
        sa.Column("status", sa.Enum("open", "acknowledged", "investigating", "resolved", name="alert_status", native_enum=False), nullable=False),
        sa.Column("recommended_actions_json", jsonb, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("resolved_at", timestamp), sa.Column("created_at", timestamp, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", timestamp, server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_alerts_status_severity_created", "alerts", ["status", "severity", "created_at"])
    op.create_table(
        "alert_events",
        sa.Column("id", uuid, primary_key=True), sa.Column("alert_id", uuid, sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("actor_user_id", uuid, sa.ForeignKey("users.id", ondelete="SET NULL")), sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("from_status", sa.Enum("open", "acknowledged", "investigating", "resolved", name="alert_status", native_enum=False)),
        sa.Column("to_status", sa.Enum("open", "acknowledged", "investigating", "resolved", name="alert_status", native_enum=False)),
        sa.Column("note", sa.Text()), sa.Column("created_at", timestamp, server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "audit_logs",
        sa.Column("id", uuid, primary_key=True), sa.Column("actor_user_id", uuid, sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("action", sa.String(120), nullable=False), sa.Column("resource_type", sa.String(80), nullable=False),
        sa.Column("resource_id", uuid), sa.Column("request_id", sa.String(80)), sa.Column("ip_address", sa.String(45)),
        sa.Column("metadata_json", jsonb, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", timestamp, server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])


def downgrade() -> None:
    for table in (
        "audit_logs", "alert_events", "alerts", "host_entities", "predictions", "model_versions",
        "window_features", "traffic_windows", "raw_flows", "ingestion_jobs", "traffic_sources", "users", "roles",
    ):
        op.drop_table(table)
