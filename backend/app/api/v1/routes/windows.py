from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import require_admin, require_viewer
from app.db.session import get_db
from app.models.network import AuditLog, IngestionJob, TrafficSource, TrafficWindow, User, WindowScope
from app.schemas.windows import TrafficWindowListResponse, WindowBuildRequest, WindowBuildResponse
from app.services.windows import build_traffic_windows

router = APIRouter(prefix="/windows")


@router.post("/build", response_model=WindowBuildResponse, status_code=status.HTTP_201_CREATED)
def build_windows(payload: WindowBuildRequest, user: User = Depends(require_admin), db: Session = Depends(get_db)) -> WindowBuildResponse:
    source_id = payload.traffic_source_id
    if source_id is None:
        source_id = db.scalar(select(IngestionJob.traffic_source_id).where(IngestionJob.id == payload.ingestion_job_id))
    if source_id is None or db.scalar(select(TrafficSource.id).where(TrafficSource.id == source_id)) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Traffic source or ingestion job not found")
    result = build_traffic_windows(db, source_id)
    db.add(AuditLog(
        actor_user_id=user.id,
        action="windows.build",
        resource_type="traffic_source",
        resource_id=source_id,
        metadata_json={"raw_flows_processed": result.raw_flows_processed, "windows_written": result.windows_written},
    ))
    db.commit()
    return WindowBuildResponse(**result.__dict__)


@router.get("", response_model=TrafficWindowListResponse)
def list_windows(
    traffic_source_id: UUID = Query(...),
    limit: int = Query(default=200, ge=1, le=1000, description="Page size"),
    after: datetime | None = Query(default=None, description="Return windows starting after this window_start (the previous page's next_cursor)"),
    user: User = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> TrafficWindowListResponse:
    query = (
        select(TrafficWindow)
        .where(TrafficWindow.traffic_source_id == traffic_source_id, TrafficWindow.scope_type == WindowScope.SOURCE)
        .order_by(TrafficWindow.window_start)
        .limit(limit + 1)
    )
    if after is not None:
        query = query.where(TrafficWindow.window_start > after)
    windows = list(db.scalars(query))
    next_cursor = None
    if len(windows) > limit:
        windows = windows[:limit]
        next_cursor = windows[-1].window_start.isoformat()
    return TrafficWindowListResponse(items=windows, next_cursor=next_cursor)
