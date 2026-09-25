import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import DbSession
from app.audit.events import AuditAction, AuditResult, EntityType
from app.audit.service import AuditFilters, list_audit_logs
from app.auth.deps import AdminUser
from app.schemas.audit import AuditLogPublic
from app.schemas.common import Page, error_responses

router = APIRouter(prefix="/audit", tags=["audit"], responses=error_responses(401, 403))


@router.get("", response_model=Page[AuditLogPublic])
def list_all_audit_logs(
    _admin: AdminUser,
    db: DbSession,
    action: Annotated[list[AuditAction] | None, Query()] = None,
    result: AuditResult | None = None,
    actor_id: uuid.UUID | None = None,
    entity_type: EntityType | None = None,
    entity_id: Annotated[str | None, Query(max_length=64)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[AuditLogPublic]:
    """Security-relevant actions, newest first. ADMIN only. Read-only: there is no route (and,
    in the database, no permission) to change or delete an entry."""
    filters = AuditFilters(
        actions=action,
        result=result,
        actor_id=actor_id,
        entity_type=entity_type,
        entity_id=entity_id,
        since=since,
        until=until,
    )
    entries, total = list_audit_logs(db, filters, limit, offset)
    return Page(
        items=[AuditLogPublic.model_validate(e) for e in entries],
        total=total,
        limit=limit,
        offset=offset,
    )
