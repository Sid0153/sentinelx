"""Log sources: configured origins of records. Admin-managed and audited."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit.events import AuditAction, EntityType
from app.audit.service import record
from app.core.errors import AppError
from app.models.event import LogSource
from app.models.user import User
from app.schemas.ingestion import SourceCreate, SourceUpdate


def list_sources(db: Session, limit: int, offset: int) -> tuple[list[LogSource], int]:
    total = db.scalar(select(func.count()).select_from(LogSource)) or 0
    rows = db.scalars(select(LogSource).order_by(LogSource.name).limit(limit).offset(offset))
    return list(rows), int(total)


def get_source(db: Session, source_id: uuid.UUID) -> LogSource:
    source = db.get(LogSource, source_id)
    if source is None:
        raise AppError(404, "Log source not found")
    return source


def get_source_by_name(db: Session, name: str) -> LogSource:
    source = db.scalar(select(LogSource).where(LogSource.name == name))
    if source is None:
        raise AppError(404, "Log source not found")
    return source


def create_source(db: Session, data: SourceCreate, actor: User | None) -> LogSource:
    if db.scalar(select(LogSource).where(LogSource.name == data.name)) is not None:
        raise AppError(409, "A log source with this name already exists")
    source = LogSource(**data.model_dump())
    db.add(source)
    db.flush()
    record(
        db,
        AuditAction.SOURCE_CREATED,
        actor=actor,
        entity_type=EntityType.LOG_SOURCE,
        entity_id=source.id,
        details={"name": source.name, "source_type": source.source_type},
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise AppError(409, "A log source with this name already exists") from None
    return source


def update_source(db: Session, source_id: uuid.UUID, data: SourceUpdate, actor: User) -> LogSource:
    source = get_source(db, source_id)
    changes = {}
    for field in data.model_fields_set:
        new, old = getattr(data, field), getattr(source, field)
        if new != old:
            changes[field] = {"from": old, "to": new}
            setattr(source, field, new)
    if changes:
        record(
            db,
            AuditAction.SOURCE_UPDATED,
            actor=actor,
            entity_type=EntityType.LOG_SOURCE,
            entity_id=source.id,
            details={"name": source.name, "changes": changes},
        )
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise AppError(409, "A log source with this name already exists") from None
        db.refresh(source)
    return source
