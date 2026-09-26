"""Manual detection runs and read helpers for the detection API."""

import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.events import AuditAction, EntityType
from app.audit.service import record
from app.core.errors import AppError
from app.detection.engine import MAX_MANUAL_RANGE, run
from app.models.detection import DetectionRun, RunTrigger
from app.models.user import User


def run_manual(
    db: Session, start: datetime, end: datetime, requested_by: User | None
) -> DetectionRun:
    """Re-runs every enabled rule over [start, end]. Used after tuning a rule, after a batch
    whose detection failed, or to look at older data again. Audited (who asked, which range)."""
    if start.tzinfo is None or end.tzinfo is None:
        raise AppError(400, "Times must include a time zone")
    if start >= end:
        raise AppError(400, "The time range is empty: 'from' must be before 'to'")
    if end - start > MAX_MANUAL_RANGE:
        raise AppError(400, "A manual run covers at most 31 days")
    record(
        db,
        AuditAction.DETECTION_RUN_REQUESTED,
        actor=requested_by,
        entity_type=EntityType.DETECTION_RUN,
        details={"from": start.isoformat(), "to": end.isoformat()},
    )
    return run(db, start, end, trigger=RunTrigger.MANUAL, requested_by=requested_by)


def list_runs(
    db: Session, trigger: RunTrigger | None, limit: int, offset: int
) -> tuple[list[DetectionRun], int]:
    statement = select(DetectionRun)
    if trigger is not None:
        statement = statement.where(DetectionRun.trigger == trigger)
    total = db.scalar(select(func.count()).select_from(statement.subquery())) or 0
    rows = db.scalars(
        statement.order_by(DetectionRun.started_at.desc()).limit(limit).offset(offset)
    )
    return list(rows), int(total)


def get_run(db: Session, run_id: uuid.UUID) -> DetectionRun:
    detection_run = db.get(DetectionRun, run_id)
    if detection_run is None:
        raise AppError(404, "Detection run not found")
    return detection_run
