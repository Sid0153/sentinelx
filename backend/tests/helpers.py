import uuid
from datetime import timedelta

import httpx2
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.passwords import hash_password
from app.auth.tokens import create_access_token
from app.core.config import get_settings
from app.models.audit_log import AuditLog
from app.models.user import Role, User

TEST_PASSWORD = "correct-horse-battery-staple"
REFRESH_COOKIE = "sx_refresh"


def make_user(
    db: Session,
    role: Role = Role.VIEWER,
    *,
    email: str | None = None,
    password: str | None = None,
    is_active: bool = True,
) -> User:
    """Insert a user. Without a password no (slow) hash is computed and login is impossible."""
    user = User(
        email=email or f"{uuid.uuid4().hex[:12]}@example.com",
        password_hash=hash_password(password) if password else "not-a-real-hash",
        role=role,
        is_active=is_active,
    )
    db.add(user)
    db.commit()
    return user


def access_token_for(user: User, expires_in: timedelta = timedelta(minutes=5)) -> str:
    return create_access_token(user.id, get_settings().secret_key, expires_in)


def bearer(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token_for(user)}"}


def login(client: httpx2.Client, email: str, password: str) -> httpx2.Response:
    return client.post("/api/auth/login", json={"email": email, "password": password})


def refresh_cookie_value(response: httpx2.Response) -> str:
    value = response.cookies.get(REFRESH_COOKIE)
    assert value, "response did not set the refresh cookie"
    return value


def cookie_header(value: str) -> dict[str, str]:
    """Send a specific refresh cookie, regardless of what the client's cookie jar holds."""
    return {"Cookie": f"{REFRESH_COOKIE}={value}"}


def audit_entries(db: Session, action: str | None = None) -> list[AuditLog]:
    statement = select(AuditLog).order_by(AuditLog.occurred_at)
    if action is not None:
        statement = statement.where(AuditLog.action == action)
    return list(db.scalars(statement))
