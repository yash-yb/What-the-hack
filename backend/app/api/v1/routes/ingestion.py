import hashlib
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import require_admin, require_viewer
from app.core.config import settings
from app.db.session import get_db
from app.models.network import AuditLog, IngestionJob, IngestionStatus, RawFlow, SourceType, TrafficSource, User
from app.schemas.ingestion import IngestionJobResponse
from app.services.ingestion import CsvValidationError, parse_csv_flows
from app.services.windows import build_traffic_windows_in_background

router = APIRouter(prefix="/ingestion")
ALLOWED_CONTENT_TYPES = {"text/csv", "application/csv", "application/vnd.ms-excel", "application/octet-stream"}


@router.post("/upload", response_model=IngestionJobResponse, status_code=status.HTTP_201_CREATED)
async def upload_csv(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    source_name: str | None = Form(default=None, max_length=160),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> IngestionJob:
    filename = file.filename or "upload.csv"
    if Path(filename).suffix.lower() != ".csv" or file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Only CSV files are accepted")
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f"File exceeds the {settings.max_upload_size_mb} MB upload limit")
    if not content:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="CSV file is empty")
    try:
        parsed = parse_csv_flows(content.decode("utf-8-sig"))
    except UnicodeDecodeError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="CSV must be UTF-8 encoded") from None
    except CsvValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    normalized_source_name = (source_name or Path(filename).stem).strip()
    if not normalized_source_name:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="source_name must not be empty")
    content_hash = hashlib.sha256(content).hexdigest()
    source = db.scalar(select(TrafficSource).where(TrafficSource.name == normalized_source_name))
    if source is None:
        source = TrafficSource(name=normalized_source_name, source_type=SourceType.CSV_REPLAY, description="CSV flow replay source", created_by_user_id=user.id)
        db.add(source)
        db.flush()
    else:
        # Windows aggregate every raw flow of a source, so the same file loaded twice would
        # double every count. Refuse the duplicate and point at the job that already holds it.
        duplicate = db.scalar(
            select(IngestionJob).where(
                IngestionJob.traffic_source_id == source.id,
                IngestionJob.content_hash == content_hash,
                IngestionJob.status == IngestionStatus.COMPLETED,
            )
        )
        if duplicate is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": f"This file was already ingested into source '{normalized_source_name}'",
                    "existing_job_id": str(duplicate.id),
                    "traffic_source_id": str(source.id),
                },
            )
    job = IngestionJob(
        traffic_source_id=source.id, requested_by_user_id=user.id, original_filename=filename,
        content_hash=content_hash, status=IngestionStatus.RUNNING,
        total_rows=parsed.total_rows, accepted_rows=0, skipped_rows=parsed.skipped_rows, started_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.flush()
    db.add_all(RawFlow(traffic_source_id=source.id, ingestion_job_id=job.id, observed_at=flow.observed_at, src_ip=flow.src_ip, dst_ip=flow.dst_ip, src_port=flow.src_port, dst_port=flow.dst_port, protocol=flow.protocol, packet_count=flow.packet_count, byte_count=flow.byte_count, duration_ms=flow.duration_ms, tcp_flags=flow.tcp_flags, failed_connection=flow.failed_connection, extra_json=flow.extra_json) for flow in parsed.flows)
    job.accepted_rows = len(parsed.flows)
    job.status = IngestionStatus.COMPLETED
    job.completed_at = datetime.now(timezone.utc)
    db.add(AuditLog(actor_user_id=user.id, action="ingestion.upload", resource_type="ingestion_job", resource_id=job.id, metadata_json={"accepted_rows": job.accepted_rows, "skipped_rows": job.skipped_rows}))
    db.commit()
    db.refresh(job)
    background_tasks.add_task(build_traffic_windows_in_background, source.id)
    return job


@router.get("/{job_id}/status", response_model=IngestionJobResponse)
def ingestion_status(job_id: UUID, user: User = Depends(require_viewer), db: Session = Depends(get_db)) -> IngestionJob:
    job = db.scalar(select(IngestionJob).where(IngestionJob.id == job_id))
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ingestion job not found")
    return job
