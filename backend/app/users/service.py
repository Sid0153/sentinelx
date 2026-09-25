"""User administration. Users are created and changed here only; never deleted."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit.events import AuditAction, EntityType
from app.audit.service import record
from app.auth.passwords import hash_password
from app.auth.service import revoke_all_for_user
from app.core.errors import AppError
from app.models.refresh_token import RevokedReason
from app.models.user import Role, User


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email))


def create_user(
    db: Session, email: str, password: str, role: Role, actor: User | None = None
) -> User:
    """actor is the admin creating the user, or None for the command-line create-admin."""
    if get_user_by_email(db, email) is not None:
        raise AppError(409, "A user with this email already exists")
    user = User(email=email, password_hash=hash_password(password), role=role)
    db.add(user)
    db.flush()  # assigns the ID for the audit record
    record(
        db,
        AuditAction.USER_CREATED,
        actor=actor,
        entity_type=EntityType.USER,
        entity_id=user.id,
        details={"email": email, "role": str(role), "via": "api" if actor else "cli"},
    )
    try:
        db.commit()
    except IntegrityError:
        # Two requests created the same email at the same moment; the unique index won.
        db.rollback()
        raise AppError(409, "A user with this email already exists") from None
    return user


def list_users(db: Session, limit: int, offset: int) -> tuple[list[User], int]:
    total = db.scalar(select(func.count()).select_from(User)) or 0
    statement = select(User).order_by(User.created_at, User.email).limit(limit).offset(offset)
    return list(db.scalars(statement)), int(total)


def update_user(
    db: Session, actor: User, user_id: uuid.UUID, role: Role | None, is_active: bool | None
) -> User:
    # An admin who demotes or deactivates themselves could leave nobody able to administer.
    if actor.id == user_id:
        raise AppError(400, "You cannot change your own role or active status")
    user = db.get(User, user_id)
    if user is None:
        raise AppError(404, "User not found")

    if role is not None and role != user.role:
        record(
            db,
            AuditAction.USER_ROLE_CHANGED,
            actor=actor,
            entity_type=EntityType.USER,
            entity_id=user.id,
            details={"email": user.email, "from": str(user.role), "to": str(role)},
        )
        user.role = role
    if is_active is not None and is_active != user.is_active:
        user.is_active = is_active
        if not is_active:
            revoke_all_for_user(db, user.id, RevokedReason.DEACTIVATED)  # signed out now
        record(
            db,
            AuditAction.USER_REACTIVATED if is_active else AuditAction.USER_DEACTIVATED,
            actor=actor,
            entity_type=EntityType.USER,
            entity_id=user.id,
            details={"email": user.email},
        )
    db.commit()
    return user
