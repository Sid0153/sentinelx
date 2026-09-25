import uuid
from typing import Annotated

from fastapi import APIRouter, Query, status

from app.api.deps import DbSession
from app.auth.deps import AdminUser
from app.schemas.common import Page, error_responses
from app.schemas.users import UserCreate, UserPublic, UserUpdate
from app.users.service import create_user, list_users, update_user

router = APIRouter(prefix="/users", tags=["users"], responses=error_responses(401, 403))


@router.get("", response_model=Page[UserPublic])
def list_all_users(
    _admin: AdminUser,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[UserPublic]:
    users, total = list_users(db, limit, offset)
    return Page(
        items=[UserPublic.model_validate(u) for u in users], total=total, limit=limit, offset=offset
    )


@router.post(
    "",
    response_model=UserPublic,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(409),
)
def create_new_user(payload: UserCreate, admin: AdminUser, db: DbSession) -> UserPublic:
    user = create_user(db, payload.email, payload.password, payload.role, actor=admin)
    return UserPublic.model_validate(user)


@router.patch("/{user_id}", response_model=UserPublic, responses=error_responses(400, 404))
def update_existing_user(
    user_id: uuid.UUID, payload: UserUpdate, admin: AdminUser, db: DbSession
) -> UserPublic:
    """Change a user's role and/or deactivate them (deactivation ends their sessions).
    Users are never deleted, and admins cannot change their own role or status."""
    user = update_user(db, admin, user_id, payload.role, payload.is_active)
    return UserPublic.model_validate(user)
