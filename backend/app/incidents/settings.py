"""Admin-configurable correlation settings, stored in app_settings and audited on change.

Only values an admin may reasonably tune at runtime live here, each with fixed bounds.
Everything else (internal networks, limits) stays in environment configuration, which is
reviewed with deployments.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.audit.events import AuditAction, EntityType
from app.audit.service import record
from app.core.errors import AppError
from app.models.incident import AppSetting
from app.models.user import User

DEFAULTS = {"correlation_window_minutes": 120, "sequence_window_minutes": 30}


class SettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # How far apart an alert and an incident may be (time) and still be linked.
    correlation_window_minutes: int | None = Field(default=None, ge=15, le=1440)
    # For "same host, new attack stage" links: a tighter window, since sharing only a host is
    # weak evidence on its own.
    sequence_window_minutes: int | None = Field(default=None, ge=5, le=240)


@dataclass(frozen=True)
class Windows:
    correlation: timedelta
    sequence: timedelta


def current(db: Session) -> dict[str, int]:
    values = dict(DEFAULTS)
    for key in DEFAULTS:
        row = db.get(AppSetting, key)
        if row is not None:
            values[key] = int(row.value)
    return values


def windows(db: Session) -> Windows:
    values = current(db)
    return Windows(
        correlation=timedelta(minutes=values["correlation_window_minutes"]),
        sequence=timedelta(minutes=values["sequence_window_minutes"]),
    )


def update(db: Session, changes: SettingsUpdate, actor: User) -> dict[str, int]:
    requested = changes.model_dump(exclude_none=True)
    if not requested:
        raise AppError(400, "Send at least one setting to change")
    before = current(db)
    after = {**before, **requested}
    if after["sequence_window_minutes"] > after["correlation_window_minutes"]:
        raise AppError(400, "The sequence window cannot be longer than the correlation window")
    diff = {k: {"from": before[k], "to": v} for k, v in requested.items() if before[k] != v}
    if not diff:
        return before
    now = datetime.now(UTC)
    for key, value in requested.items():
        db.merge(AppSetting(key=key, value=value, updated_at=now, updated_by=actor.id))
    record(
        db,
        AuditAction.SETTINGS_CHANGED,
        actor=actor,
        entity_type=EntityType.SETTINGS,
        details={"changes": diff},
    )
    db.commit()
    return after
