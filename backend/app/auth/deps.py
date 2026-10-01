"""FastAPI dependencies that authenticate the caller and enforce roles on the server.

The backend is the enforcement point (ADR-0007): every protected route depends on one of the
annotated types at the bottom, and tests/api/test_rbac.py checks that for every route.
"""

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.audit.events import AuditAction, AuditResult, EntityType
from app.audit.service import record
from app.auth.tokens import InvalidTokenError, decode_access_token
from app.core.config import Settings, get_settings
from app.core.errors import AppError
from app.database.session import get_db
from app.models.user import ROLE_RANK, Role, User

bearer_scheme = HTTPBearer(auto_error=False)


def _unauthorized() -> AppError:
    return AppError(401, "Not authenticated", headers={"WWW-Authenticate": "Bearer"})


# The only routes open to a user who must change their password (after an admin reset).
# Logout is public anyway.
PASSWORD_CHANGE_ROUTES = frozenset({"/api/auth/me", "/api/auth/change-password"})


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> User:
    if credentials is None:
        raise _unauthorized()
    try:
        user_id = decode_access_token(credentials.credentials, settings.secret_key)
    except InvalidTokenError:
        raise _unauthorized() from None

    # The user (and therefore the role) is loaded fresh on every request, so a demotion or
    # deactivation takes effect immediately, not when the token expires.
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise _unauthorized()
    if user.must_change_password and request.url.path not in PASSWORD_CHANGE_ROUTES:
        # A temporary password from an admin reset is known to two people: until it is
        # replaced, the account can do nothing else.
        raise AppError(403, "Change your password to continue", code="password_change_required")
    return user


def require_role(minimum: Role) -> Callable[..., User]:
    """Roles are ordered: VIEWER < ANALYST < ADMIN. `minimum` and above may pass."""

    def dependency(
        request: Request,
        user: Annotated[User, Depends(get_current_user)],
        db: Annotated[Session, Depends(get_db)],
    ) -> User:
        if ROLE_RANK[user.role] < ROLE_RANK[minimum]:
            # A signed-in user probing routes above their role is worth an admin's attention.
            record(
                db,
                AuditAction.ACCESS_DENIED,
                result=AuditResult.DENIED,
                actor=user,
                entity_type=EntityType.ROUTE,
                details={
                    "method": request.method,
                    "path": request.url.path,
                    "role": str(user.role),
                    "required": str(minimum),
                },
            )
            db.commit()
            raise AppError(403, "Insufficient permissions")
        return user

    return dependency


def can_read_raw_records(user: User) -> bool:
    """Raw log records can hold secrets typed into the wrong field (a password entered as a
    username); they are stored as received, so their full text is shown to analysts and
    admins only. Viewers see the normalized event (Phase 13, docs/security.md)."""
    return ROLE_RANK[user.role] >= ROLE_RANK[Role.ANALYST]


CurrentUser = Annotated[User, Depends(get_current_user)]
AnalystUser = Annotated[User, Depends(require_role(Role.ANALYST))]
AdminUser = Annotated[User, Depends(require_role(Role.ADMIN))]
