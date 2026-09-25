"""Recording and reading audit events.

record() only adds the row to the session: the caller's commit stores the event together with
the change it describes, so an action is never saved without its audit record (or the other
way round). Events about failures, where nothing else is saved, are committed by the caller
right after recording.
"""

import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.audit.events import AuditAction, AuditResult, EntityType
from app.core.logging import client_ip_var, request_id_var
from app.core.redaction import redact
from app.models.audit_log import AuditLog
from app.models.user import User

MAX_TEXT = 300
MAX_ITEMS = 20
# Keys that must never be stored, even if a caller passes them by mistake.
_SECRET_KEY = re.compile(r"(?i)(password|passwd|secret|token|credential|api[_-]?key|cookie)")


def sanitize(value: Any, depth: int = 0) -> Any:
    """Plain JSON only, secret-looking keys dropped, strings redacted and shortened."""
    if depth > 3:
        return "[truncated]"
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return redact(value)[:MAX_TEXT]
    if isinstance(value, dict):
        return {
            str(key)[:64]: sanitize(item, depth + 1)
            for key, item in list(value.items())[:MAX_ITEMS]
            if not _SECRET_KEY.search(str(key))
        }
    if isinstance(value, list | tuple):
        return [sanitize(item, depth + 1) for item in list(value)[:MAX_ITEMS]]
    return redact(str(value))[:MAX_TEXT]


def record(
    db: Session,
    action: AuditAction,
    *,
    result: AuditResult = AuditResult.SUCCESS,
    actor: User | None = None,
    entity_type: EntityType | None = None,
    entity_id: uuid.UUID | str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    request_id = request_id_var.get()
    entry = AuditLog(
        action=str(action),
        result=str(result),
        actor_id=actor.id if actor else None,
        actor_label=actor.email if actor else None,
        entity_type=str(entity_type) if entity_type else None,
        entity_id=str(entity_id)[:64] if entity_id is not None else None,
        client_ip=client_ip_var.get(),
        request_id=None if request_id == "-" else request_id,
        details=sanitize(details or {}),
    )
    db.add(entry)
    return entry


@dataclass(frozen=True)
class AuditFilters:
    actions: list[AuditAction] | None = None
    result: AuditResult | None = None
    actor_id: uuid.UUID | None = None
    entity_type: EntityType | None = None
    entity_id: str | None = None
    since: datetime | None = None
    until: datetime | None = None


def _filtered(statement: Select[Any], filters: AuditFilters) -> Select[Any]:
    if filters.actions:
        statement = statement.where(AuditLog.action.in_([str(a) for a in filters.actions]))
    if filters.result is not None:
        statement = statement.where(AuditLog.result == str(filters.result))
    if filters.actor_id is not None:
        statement = statement.where(AuditLog.actor_id == filters.actor_id)
    if filters.entity_type is not None:
        statement = statement.where(AuditLog.entity_type == str(filters.entity_type))
    if filters.entity_id is not None:
        statement = statement.where(AuditLog.entity_id == filters.entity_id)
    if filters.since is not None:
        statement = statement.where(AuditLog.occurred_at >= filters.since)
    if filters.until is not None:
        statement = statement.where(AuditLog.occurred_at < filters.until)
    return statement


def list_audit_logs(
    db: Session, filters: AuditFilters, limit: int, offset: int
) -> tuple[list[AuditLog], int]:
    """Newest first, and the total number of matching events."""
    total = db.scalar(_filtered(select(func.count()).select_from(AuditLog), filters)) or 0
    statement = (
        _filtered(select(AuditLog), filters)
        .order_by(AuditLog.occurred_at.desc(), AuditLog.id)
        .limit(limit)
        .offset(offset)
    )
    return list(db.scalars(statement)), int(total)
