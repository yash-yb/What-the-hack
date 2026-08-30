from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.models.network import IngestionStatus


class IngestionJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    traffic_source_id: UUID
    original_filename: str
    status: IngestionStatus
    total_rows: int
    accepted_rows: int
    skipped_rows: int
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
