"""Asset and identity inventory. Changes are audited: criticality and privilege feed the risk
score (docs/risk-model.md), so changing them changes how alerts are prioritized."""

import uuid
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel
from sqlalchemy import Select, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.alerts import service as alerts
from app.audit.events import AuditAction, EntityType
from app.audit.service import record
from app.core.errors import AppError
from app.models.context import Asset, Identity
from app.models.user import User
from app.schemas.context import AssetCreate, AssetUpdate, IdentityCreate, IdentityUpdate


def _changes(target: Asset | Identity, update: BaseModel) -> dict[str, dict[str, Any]]:
    """Applies the explicitly sent fields and returns {field: {from, to}} for real changes."""
    changes: dict[str, dict[str, Any]] = {}
    for field in update.model_fields_set:
        new = getattr(update, field)
        old = getattr(target, field)
        old_value = [str(v) for v in old] if isinstance(old, list) else old
        if new != old_value:
            changes[field] = {"from": old_value, "to": new}
            setattr(target, field, new)
    return changes


def _like(value: str) -> str:
    """A LIKE pattern matching `value` literally (%, _ and \\ in the input match themselves)."""
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _page[T](
    db: Session, statement: Select[tuple[T]], limit: int, offset: int
) -> tuple[list[T], int]:
    total = db.scalar(select(func.count()).select_from(statement.subquery())) or 0
    return list(db.scalars(statement.limit(limit).offset(offset))), int(total)


# ---------- assets ----------


@dataclass(frozen=True)
class AssetFilters:
    search: str | None = None  # substring of hostname, owner or description
    criticality: str | None = None
    environment: str | None = None
    status: str | None = None
    tag: str | None = None


def list_assets(
    db: Session, filters: AssetFilters, limit: int, offset: int
) -> tuple[list[Asset], int]:
    statement = select(Asset)
    if filters.search:
        pattern = _like(filters.search.lower())
        statement = statement.where(
            or_(
                Asset.hostname.like(pattern, escape="\\"),
                func.lower(Asset.owner).like(pattern, escape="\\"),
                func.lower(Asset.description).like(pattern, escape="\\"),
            )
        )
    if filters.criticality:
        statement = statement.where(Asset.criticality == filters.criticality)
    if filters.environment:
        statement = statement.where(Asset.environment == filters.environment)
    if filters.status:
        statement = statement.where(Asset.status == filters.status)
    if filters.tag:
        statement = statement.where(Asset.tags.contains([filters.tag.lower()]))
    return _page(db, statement.order_by(Asset.hostname), limit, offset)


def get_asset(db: Session, asset_id: uuid.UUID) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise AppError(404, "Asset not found")
    return asset


def create_asset(db: Session, data: AssetCreate, actor: User) -> Asset:
    if db.scalar(select(Asset).where(Asset.hostname == data.hostname)) is not None:
        raise AppError(409, "An asset with this hostname already exists")
    asset = Asset(**data.model_dump())
    db.add(asset)
    db.flush()
    reprioritized = alerts.reprioritize_for_asset(db, asset)
    record(
        db,
        AuditAction.ASSET_CREATED,
        actor=actor,
        entity_type=EntityType.ASSET,
        entity_id=asset.id,
        details={
            "hostname": asset.hostname,
            "criticality": asset.criticality,
            "open_alerts_reprioritized": reprioritized,
        },
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise AppError(409, "An asset with this hostname already exists") from None
    return asset


def update_asset(db: Session, asset_id: uuid.UUID, data: AssetUpdate, actor: User) -> Asset:
    asset = get_asset(db, asset_id)
    old_ips = list(asset.ip_addresses)
    changes = _changes(asset, data)
    if changes:
        # Criticality and addresses decide alert priority: open alerts follow at once.
        reprioritized = (
            alerts.reprioritize_for_asset(db, asset, old_ips)
            if {"criticality", "ip_addresses"} & set(changes)
            else 0
        )
        record(
            db,
            AuditAction.ASSET_UPDATED,
            actor=actor,
            entity_type=EntityType.ASSET,
            entity_id=asset.id,
            details={
                "hostname": asset.hostname,
                "changes": changes,
                "open_alerts_reprioritized": reprioritized,
            },
        )
        db.commit()
        db.refresh(asset)
    return asset


# ---------- identities ----------


@dataclass(frozen=True)
class IdentityFilters:
    search: str | None = None  # substring of username, display name or department
    privilege_level: str | None = None
    status: str | None = None
    tag: str | None = None


def list_identities(
    db: Session, filters: IdentityFilters, limit: int, offset: int
) -> tuple[list[Identity], int]:
    statement = select(Identity)
    if filters.search:
        pattern = _like(filters.search.lower())
        statement = statement.where(
            or_(
                Identity.username.like(pattern, escape="\\"),
                func.lower(Identity.display_name).like(pattern, escape="\\"),
                func.lower(Identity.department).like(pattern, escape="\\"),
            )
        )
    if filters.privilege_level:
        statement = statement.where(Identity.privilege_level == filters.privilege_level)
    if filters.status:
        statement = statement.where(Identity.status == filters.status)
    if filters.tag:
        statement = statement.where(Identity.tags.contains([filters.tag.lower()]))
    return _page(db, statement.order_by(Identity.username), limit, offset)


def get_identity(db: Session, identity_id: uuid.UUID) -> Identity:
    identity = db.get(Identity, identity_id)
    if identity is None:
        raise AppError(404, "Identity not found")
    return identity


def create_identity(db: Session, data: IdentityCreate, actor: User) -> Identity:
    if db.scalar(select(Identity).where(Identity.username == data.username)) is not None:
        raise AppError(409, "An identity with this username already exists")
    identity = Identity(**data.model_dump())
    db.add(identity)
    db.flush()
    reprioritized = alerts.reprioritize_for_identity(db, identity)
    record(
        db,
        AuditAction.IDENTITY_CREATED,
        actor=actor,
        entity_type=EntityType.IDENTITY,
        entity_id=identity.id,
        details={
            "username": identity.username,
            "privilege_level": identity.privilege_level,
            "open_alerts_reprioritized": reprioritized,
        },
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise AppError(409, "An identity with this username already exists") from None
    return identity


def update_identity(
    db: Session, identity_id: uuid.UUID, data: IdentityUpdate, actor: User
) -> Identity:
    identity = get_identity(db, identity_id)
    changes = _changes(identity, data)
    if changes:
        reprioritized = (
            alerts.reprioritize_for_identity(db, identity) if "privilege_level" in changes else 0
        )
        record(
            db,
            AuditAction.IDENTITY_UPDATED,
            actor=actor,
            entity_type=EntityType.IDENTITY,
            entity_id=identity.id,
            details={
                "username": identity.username,
                "changes": changes,
                "open_alerts_reprioritized": reprioritized,
            },
        )
        db.commit()
        db.refresh(identity)
    return identity
