"""Threat hunting (docs/threat-hunting.md). Everyone signed in may hunt, which only reads;
analysts and admins may save hunts. A saved hunt is private unless shared, and only its
owner changes or deletes it."""

import uuid

from fastapi import APIRouter, Response, status
from sqlalchemy import select

from app.api.deps import DbSession
from app.auth.deps import AnalystUser, CurrentUser
from app.detection.conditions import IP_COLUMNS, NUMERIC_COLUMNS
from app.events.queries import MAX_RANGE
from app.hunting import service, templates
from app.hunting.query import (
    BOOLEAN_COLUMNS,
    FIELDS,
    MAX_FILTERS,
    allowed_operators,
)
from app.models.hunt import SavedHunt
from app.models.user import User
from app.schemas.common import error_responses
from app.schemas.hunt import (
    HuntField,
    HuntFields,
    HuntResult,
    HuntRunRequest,
    SavedHuntCreate,
    SavedHuntPublic,
    SavedHuntUpdate,
    TemplateColumn,
    TemplateInfo,
    TemplateParam,
    TemplateResult,
    TemplateRunRequest,
)
from app.schemas.ingestion import EventPublic

hunt = APIRouter(prefix="/hunt", tags=["hunt"], responses=error_responses(401, 403))


def _kind(field: str) -> str:
    if field in IP_COLUMNS:
        return "ip"
    if field in NUMERIC_COLUMNS:
        return "number"
    if field in BOOLEAN_COLUMNS:
        return "boolean"
    return "text"


@hunt.get("/fields", response_model=HuntFields)
def list_fields(_user: CurrentUser) -> HuntFields:
    """The fields a hunt may filter on and the operators each accepts (for the query
    builder). Any `attributes.<key>` is also accepted, with text operators."""
    return HuntFields(
        fields=[
            HuntField(field=f, kind=_kind(f), operators=sorted(allowed_operators(f)))
            for f in FIELDS
        ],
        attribute_operators=sorted(allowed_operators("attributes.key")),
        max_filters=MAX_FILTERS,
        max_range_days=MAX_RANGE.days,
    )


@hunt.post("/query", response_model=HuntResult, responses=error_responses(400, 422, 503))
def run_query(payload: HuntRunRequest, _user: CurrentUser, db: DbSession) -> HuntResult:
    """Events matching every filter, in the time range (required, at most 31 days), newest
    or oldest first. Keyset-paged: pass `next_cursor` back as `cursor` with the same query.
    `total` counts matches up to 10,000 (`total_capped` beyond). A hunt that runs longer
    than the statement timeout (5 s by default) is stopped: 503 `hunt_timeout`."""
    result = service.run_query(db, payload, payload.cursor)
    return HuntResult(
        items=[EventPublic.model_validate(e) for e in result.events],
        next_cursor=result.next_cursor,
        total=result.total,
        total_capped=result.total_capped,
        start=result.start,
        end=result.end,
        limit=payload.limit,
    )


def _template_info(template: templates.Template) -> TemplateInfo:
    params = []
    for name, field in template.params.model_fields.items():
        bounds = {type(m).__name__: m for m in field.metadata}
        params.append(
            TemplateParam(
                name=name,
                description=field.description or name,
                default=int(field.default),
                minimum=int(getattr(bounds.get("Ge"), "ge", 0)),
                maximum=int(getattr(bounds.get("Le"), "le", 0)),
            )
        )
    return TemplateInfo(
        id=template.id,
        name=template.name,
        question=template.question,
        technique=template.technique,
        mirrors_rule=template.mirrors_rule,
        params=params,
        columns=[TemplateColumn(key=c.key, label=c.label, kind=c.kind) for c in template.columns],
    )


@hunt.get("/templates", response_model=list[TemplateInfo])
def list_templates(_user: CurrentUser) -> list[TemplateInfo]:
    """Reviewed hunts for questions a flat filter cannot ask, with their parameters."""
    return [_template_info(t) for t in templates.TEMPLATES.values()]


@hunt.post(
    "/templates/{template_id}/run",
    response_model=TemplateResult,
    responses=error_responses(404, 422, 503),
)
def run_template(
    template_id: str, payload: TemplateRunRequest, _user: CurrentUser, db: DbSession
) -> TemplateResult:
    """At most 200 rows (`truncated` when there were more)."""
    result = service.run_template(db, template_id, payload.params, payload.time_range)
    return TemplateResult(
        template_id=result.template.id,
        columns=[
            TemplateColumn(key=c.key, label=c.label, kind=c.kind) for c in result.template.columns
        ],
        rows=result.rows,
        truncated=result.truncated,
        start=result.start,
        end=result.end,
    )


def _public(db: DbSession, hunt_row: SavedHunt, user: User) -> SavedHuntPublic:
    _, problem = service.load_definition(hunt_row)
    owner = db.scalar(select(User.email).where(User.id == hunt_row.owner_id))
    return SavedHuntPublic(
        id=hunt_row.id,
        name=hunt_row.name,
        description=hunt_row.description,
        kind=hunt_row.kind,
        definition=hunt_row.definition,
        shared=hunt_row.shared,
        owner_id=hunt_row.owner_id,
        owner_email=owner,
        is_owner=hunt_row.owner_id == user.id,
        valid=not problem,
        problem=problem or None,
        created_at=hunt_row.created_at,
        updated_at=hunt_row.updated_at,
    )


@hunt.get("/saved", response_model=list[SavedHuntPublic])
def list_saved(user: CurrentUser, db: DbSession) -> list[SavedHuntPublic]:
    """Your saved hunts and those shared by others. A hunt saved by an older version that no
    longer validates is listed with `valid: false` and a `problem`, never run."""
    return [_public(db, h, user) for h in service.list_saved(db, user)]


@hunt.get("/saved/{hunt_id}", response_model=SavedHuntPublic, responses=error_responses(404))
def get_saved(hunt_id: uuid.UUID, user: CurrentUser, db: DbSession) -> SavedHuntPublic:
    return _public(db, service.get_saved(db, user, hunt_id), user)


@hunt.post(
    "/saved",
    response_model=SavedHuntPublic,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(409, 422),
)
def create_saved(payload: SavedHuntCreate, user: AnalystUser, db: DbSession) -> SavedHuntPublic:
    """Private unless `shared`. Names are unique per owner (409). Audited (`HUNT_SAVED`) with
    the name, kind and sharing, never the filter values."""
    created = service.create_saved(
        db, user, payload.name, payload.description, payload.definition, payload.shared
    )
    return _public(db, created, user)


@hunt.patch(
    "/saved/{hunt_id}",
    response_model=SavedHuntPublic,
    responses=error_responses(404, 409, 422),
)
def update_saved(
    hunt_id: uuid.UUID, payload: SavedHuntUpdate, user: AnalystUser, db: DbSession
) -> SavedHuntPublic:
    """Owner only (403 for someone else's shared hunt). Audited as `HUNT_UPDATED`."""
    changes = {field: getattr(payload, field) for field in payload.model_fields_set}
    return _public(db, service.update_saved(db, user, hunt_id, changes), user)


@hunt.delete(
    "/saved/{hunt_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=error_responses(404),
)
def delete_saved(hunt_id: uuid.UUID, user: AnalystUser, db: DbSession) -> Response:
    """Owner only. Audited as `HUNT_DELETED`."""
    service.delete_saved(db, user, hunt_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
