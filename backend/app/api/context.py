"""Asset and identity inventory. Everyone signed in may read; only admins change it.
Nothing is deleted: past events and incidents still point to retired assets and disabled
identities."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, status

from app.api.deps import DbSession
from app.auth.deps import AdminUser, CurrentUser
from app.context import service
from app.events.schema import Criticality
from app.models.context import AssetStatus, Environment, IdentityStatus, PrivilegeLevel
from app.schemas.common import Page, error_responses
from app.schemas.context import (
    AssetCreate,
    AssetPublic,
    AssetUpdate,
    IdentityCreate,
    IdentityPublic,
    IdentityUpdate,
)

assets = APIRouter(prefix="/assets", tags=["assets"], responses=error_responses(401, 403))
identities = APIRouter(
    prefix="/identities", tags=["identities"], responses=error_responses(401, 403)
)

Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0)]
Search = Annotated[str | None, Query(max_length=100)]
Tag = Annotated[str | None, Query(max_length=32)]


@assets.get("", response_model=Page[AssetPublic])
def list_assets(
    _user: CurrentUser,
    db: DbSession,
    search: Search = None,
    criticality: Criticality | None = None,
    environment: Environment | None = None,
    status: AssetStatus | None = None,
    tag: Tag = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[AssetPublic]:
    """Filter by criticality, environment, status or tag; `search` matches part of the
    hostname, owner or description."""
    filters = service.AssetFilters(search, criticality, environment, status, tag)
    items, total = service.list_assets(db, filters, limit, offset)
    return Page(
        items=[AssetPublic.model_validate(a) for a in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@assets.get("/{asset_id}", response_model=AssetPublic, responses=error_responses(404))
def get_asset(asset_id: uuid.UUID, _user: CurrentUser, db: DbSession) -> AssetPublic:
    return AssetPublic.model_validate(service.get_asset(db, asset_id))


@assets.post(
    "",
    response_model=AssetPublic,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(409),
)
def create_asset(payload: AssetCreate, admin: AdminUser, db: DbSession) -> AssetPublic:
    return AssetPublic.model_validate(service.create_asset(db, payload, admin))


@assets.patch("/{asset_id}", response_model=AssetPublic, responses=error_responses(404))
def update_asset(
    asset_id: uuid.UUID, payload: AssetUpdate, admin: AdminUser, db: DbSession
) -> AssetPublic:
    """Only the fields sent change. To stop using an asset, set `status` to `retired`."""
    return AssetPublic.model_validate(service.update_asset(db, asset_id, payload, admin))


@identities.get("", response_model=Page[IdentityPublic])
def list_identities(
    _user: CurrentUser,
    db: DbSession,
    search: Search = None,
    privilege_level: PrivilegeLevel | None = None,
    status: IdentityStatus | None = None,
    tag: Tag = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[IdentityPublic]:
    """`search` matches part of the username, display name or department."""
    filters = service.IdentityFilters(search, privilege_level, status, tag)
    items, total = service.list_identities(db, filters, limit, offset)
    return Page(
        items=[IdentityPublic.model_validate(i) for i in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@identities.get("/{identity_id}", response_model=IdentityPublic, responses=error_responses(404))
def get_identity(identity_id: uuid.UUID, _user: CurrentUser, db: DbSession) -> IdentityPublic:
    return IdentityPublic.model_validate(service.get_identity(db, identity_id))


@identities.post(
    "",
    response_model=IdentityPublic,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(409),
)
def create_identity(payload: IdentityCreate, admin: AdminUser, db: DbSession) -> IdentityPublic:
    return IdentityPublic.model_validate(service.create_identity(db, payload, admin))


@identities.patch("/{identity_id}", response_model=IdentityPublic, responses=error_responses(404))
def update_identity(
    identity_id: uuid.UUID, payload: IdentityUpdate, admin: AdminUser, db: DbSession
) -> IdentityPublic:
    """Only the fields sent change. To stop using an identity, set `status` to `disabled`."""
    return IdentityPublic.model_validate(service.update_identity(db, identity_id, payload, admin))
