"""Running hunts and keeping saved hunts (docs/threat-hunting.md).

Hunts only read. Each one runs under a statement timeout, so a pathological query fails with
a clear message instead of starving ingestion, and counts its matches only up to a cap.
Running a hunt is not audited (reading is not a security-relevant change, and it would flood
the log); saving, changing, sharing and deleting a saved hunt are.
"""

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi.exceptions import RequestValidationError
from psycopg import errors as pg_errors
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError
from sqlalchemy import func, or_, select, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.audit.events import AuditAction, EntityType
from app.audit.service import record
from app.core.config import get_settings
from app.core.errors import AppError
from app.events.queries import decode_cursor, encode_cursor
from app.hunting import templates
from app.hunting.query import HuntQuery, TimeRange, after_cursor
from app.models.event import Event
from app.models.hunt import SavedHunt
from app.models.user import User

COUNT_CAP = 10_000


@contextmanager
def statement_timeout(db: Session, milliseconds: int | None = None) -> Iterator[None]:
    """Statements inside run with a time limit (SET LOCAL: this transaction only)."""
    limit = int(milliseconds or get_settings().hunt_timeout_ms)
    db.execute(text(f"SET LOCAL statement_timeout = {limit}"))  # an int, never user text
    try:
        yield
    except OperationalError as exc:
        if not isinstance(exc.orig, pg_errors.QueryCanceled):
            raise
        db.rollback()
        raise AppError(
            503,
            f"The hunt took longer than {limit / 1000:g} s and was stopped. "
            "Narrow the time range or add filters.",
            code="hunt_timeout",
        ) from None
    db.execute(text("SET LOCAL statement_timeout = DEFAULT"))


@dataclass(frozen=True)
class HuntResult:
    events: list[Event]
    next_cursor: str | None
    total: int
    total_capped: bool  # more than COUNT_CAP matches: `total` is the cap
    start: datetime
    end: datetime


def run_query(
    db: Session,
    query: HuntQuery,
    cursor: str | None = None,
    now: datetime | None = None,
    timeout_ms: int | None = None,
) -> HuntResult:
    start, end = query.time_range.resolve(now)
    where = query.where(start, end)
    order = (
        (Event.timestamp.asc(), Event.id.asc())
        if query.sort == "oldest"
        else (Event.timestamp.desc(), Event.id.desc())
    )
    page = select(Event).where(*where)
    if cursor:
        page = page.where(after_cursor(query.sort, *decode_cursor(cursor)))
    with statement_timeout(db, timeout_ms):
        rows = list(db.scalars(page.order_by(*order).limit(query.limit + 1)))
        # Counting stops at the cap: a month of events is not counted on every page.
        capped = select(Event.id).where(*where).limit(COUNT_CAP + 1).subquery()
        total = int(db.scalar(select(func.count()).select_from(capped)) or 0)
    has_more = len(rows) > query.limit
    rows = rows[: query.limit]
    return HuntResult(
        events=rows,
        next_cursor=encode_cursor(rows[-1]) if has_more and rows else None,
        total=min(total, COUNT_CAP),
        total_capped=total > COUNT_CAP,
        start=start,
        end=end,
    )


def template_params(template_id: str, params: dict[str, Any]) -> BaseModel:
    template = get_template(template_id)
    try:
        return template.params.model_validate(params)
    except ValidationError as exc:
        # The same 422 shape as a request body error (values are never echoed).
        raise RequestValidationError(
            [{**error, "loc": ("body", "params", *error["loc"])} for error in exc.errors()]
        ) from None


def get_template(template_id: str) -> templates.Template:
    template = templates.TEMPLATES.get(template_id)
    if template is None:
        raise AppError(404, "Hunt template not found")
    return template


@dataclass(frozen=True)
class TemplateResult:
    template: templates.Template
    rows: list[dict[str, Any]]
    truncated: bool
    start: datetime
    end: datetime


def run_template(
    db: Session,
    template_id: str,
    params: dict[str, Any],
    time_range: TimeRange,
    now: datetime | None = None,
    timeout_ms: int | None = None,
) -> TemplateResult:
    template = get_template(template_id)
    values = template_params(template_id, params)
    start, end = time_range.resolve(now)
    with statement_timeout(db, timeout_ms):
        rows, truncated = templates.run(db, template, values, start, end)
    return TemplateResult(template, rows, truncated, start, end)


# ---------- saved hunts ----------


class QueryDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["query"] = "query"
    query: HuntQuery


class TemplateDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["template"] = "template"
    template_id: str = Field(max_length=64)
    params: dict[str, Any] = Field(default_factory=dict)
    time_range: TimeRange


Definition = Annotated[QueryDefinition | TemplateDefinition, Field(discriminator="kind")]
DEFINITION: TypeAdapter[QueryDefinition | TemplateDefinition] = TypeAdapter(Definition)


def check_definition(definition: QueryDefinition | TemplateDefinition) -> None:
    if not isinstance(definition, TemplateDefinition):
        return
    if definition.template_id not in templates.TEMPLATES:
        raise RequestValidationError(
            [
                {
                    "loc": ("body", "definition", "template_id"),
                    "msg": "Unknown hunt template",
                    "type": "value_error",
                }
            ]
        )
    template_params(definition.template_id, definition.params)


def load_definition(hunt: SavedHunt) -> tuple[QueryDefinition | TemplateDefinition | None, str]:
    """The stored definition validated again; (None, reason) when it no longer is valid."""
    try:
        definition = DEFINITION.validate_python(hunt.definition)
        check_definition(definition)
    except (ValidationError, RequestValidationError, AppError):
        return None, "This saved hunt no longer matches the hunt format and cannot be run."
    return definition, ""


def _stored(definition: QueryDefinition | TemplateDefinition) -> dict[str, Any]:
    """Only what the analyst set: defaults are filled in again when the hunt is loaded, so a
    saved hunt also picks up a changed default (and its link stays short)."""
    stored: dict[str, Any] = definition.model_dump(
        mode="json", by_alias=True, exclude_none=True, exclude_defaults=True
    )
    stored["kind"] = definition.kind  # a default too, but it tells the two shapes apart
    return stored


def list_saved(db: Session, user: User) -> list[SavedHunt]:
    statement = (
        select(SavedHunt)
        .where(or_(SavedHunt.owner_id == user.id, SavedHunt.shared.is_(True)))
        .order_by(SavedHunt.name, SavedHunt.id)
    )
    return list(db.scalars(statement))


def get_saved(db: Session, user: User, hunt_id: uuid.UUID) -> SavedHunt:
    hunt = db.get(SavedHunt, hunt_id)
    if hunt is None or (hunt.owner_id != user.id and not hunt.shared):
        raise AppError(404, "Saved hunt not found")  # a private hunt is not even confirmed
    return hunt


def _owned(db: Session, user: User, hunt_id: uuid.UUID) -> SavedHunt:
    hunt = get_saved(db, user, hunt_id)
    if hunt.owner_id != user.id:
        raise AppError(403, "Only the owner can change or delete a saved hunt")
    return hunt


def _audit(db: Session, action: AuditAction, actor: User, hunt: SavedHunt, **extra: Any) -> None:
    # The name and shape, never the filter values: those can be investigation details.
    details = {"name": hunt.name, "kind": hunt.kind, "shared": hunt.shared, **extra}
    record(
        db, action, actor=actor, entity_type=EntityType.SAVED_HUNT, entity_id=hunt.id,
        details=details,
    )  # fmt: skip


DUPLICATE_NAME = "You already have a saved hunt with this name"


@contextmanager
def _unique_name(db: Session) -> Iterator[None]:
    """The (owner, name) constraint decides: a race between two saves gets 409, not 500.
    It fires at the flush, so the flush and the commit both run inside this block."""
    try:
        yield
    except IntegrityError:
        db.rollback()
        raise AppError(409, DUPLICATE_NAME) from None


def create_saved(
    db: Session,
    user: User,
    name: str,
    description: str | None,
    definition: QueryDefinition | TemplateDefinition,
    shared: bool,
) -> SavedHunt:
    check_definition(definition)
    hunt = SavedHunt(
        owner_id=user.id,
        name=name,
        description=description,
        kind=definition.kind,
        definition=_stored(definition),
        shared=shared,
    )
    db.add(hunt)
    with _unique_name(db):
        db.flush()
        _audit(db, AuditAction.HUNT_SAVED, user, hunt)
        db.commit()
    return hunt


def update_saved(db: Session, user: User, hunt_id: uuid.UUID, changes: dict[str, Any]) -> SavedHunt:
    hunt = _owned(db, user, hunt_id)
    changed = []
    if "definition" in changes:
        definition = changes["definition"]
        check_definition(definition)
        hunt.kind, hunt.definition = definition.kind, _stored(definition)
        changed.append("definition")
    for field in ("name", "description", "shared"):
        if field in changes and getattr(hunt, field) != changes[field]:
            setattr(hunt, field, changes[field])
            changed.append(field)
    if not changed:
        return hunt
    with _unique_name(db):
        db.flush()
        _audit(db, AuditAction.HUNT_UPDATED, user, hunt, changed=changed)
        db.commit()
    db.refresh(hunt)
    return hunt


def delete_saved(db: Session, user: User, hunt_id: uuid.UUID) -> None:
    hunt = _owned(db, user, hunt_id)
    _audit(db, AuditAction.HUNT_DELETED, user, hunt)
    db.delete(hunt)
    db.commit()
