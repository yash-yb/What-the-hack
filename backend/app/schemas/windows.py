from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, model_validator

from app.models.network import WindowScope


class WindowBuildRequest(BaseModel):
    traffic_source_id: UUID | None = None
    ingestion_job_id: UUID | None = None

    @model_validator(mode="after")
    def require_exactly_one_target(self) -> "WindowBuildRequest":
        if (self.traffic_source_id is None) == (self.ingestion_job_id is None):
            raise ValueError("Provide exactly one of traffic_source_id or ingestion_job_id")
        return self


class WindowBuildResponse(BaseModel):
    traffic_source_id: UUID
    raw_flows_processed: int
    windows_written: int
    window_seconds: int


class TrafficWindowResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    traffic_source_id: UUID
    window_start: datetime
    window_end: datetime
    window_seconds: int
    scope_type: WindowScope
    scope_key: str
    flow_count: int
    packet_count: int
    byte_count: int


class TrafficWindowListResponse(BaseModel):
    items: list[TrafficWindowResponse]
    next_cursor: str | None = None
