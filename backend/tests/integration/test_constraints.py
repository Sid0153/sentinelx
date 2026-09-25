"""The database itself enforces the rules the application relies on (docs/database-schema.md).

Each statement runs in a savepoint, so a rejected write does not end the test's transaction.
"""

import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from app.audit.events import AuditAction
from app.audit.service import record
from app.models.refresh_token import RefreshToken
from tests.helpers import make_user

pytestmark = pytest.mark.integration


def rejected(db: Session, statement: str, params: dict[str, object] | None = None) -> str:
    """Runs a statement that must fail, and returns the database's error message."""
    savepoint = db.begin_nested()
    with pytest.raises((IntegrityError, DBAPIError)) as caught:
        db.execute(text(statement), params or {})
    savepoint.rollback()
    return str(caught.value)


INSERT_USER = (
    "INSERT INTO users (id, email, password_hash, role) "
    "VALUES (gen_random_uuid(), :email, 'x', :role)"
)


@pytest.mark.parametrize("role", ["SUPERUSER", "admin", ""])
def test_users_role_must_be_one_of_the_three_roles(db_session: Session, role: str) -> None:
    message = rejected(db_session, INSERT_USER, {"email": "r@example.com", "role": role})
    assert "ck_users_role_valid" in message


def test_users_email_must_be_stored_lowercase(db_session: Session) -> None:
    message = rejected(db_session, INSERT_USER, {"email": "Mixed@Example.com", "role": "VIEWER"})
    assert "ck_users_email_lowercase" in message


def test_users_email_is_unique(db_session: Session) -> None:
    make_user(db_session, email="taken@example.com")
    message = rejected(db_session, INSERT_USER, {"email": "taken@example.com", "role": "VIEWER"})
    assert "uq_users_email" in message


def test_refresh_token_hash_is_unique_and_needs_an_existing_user(db_session: Session) -> None:
    user = make_user(db_session)
    insert = (
        "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) "
        "VALUES (gen_random_uuid(), :user_id, :hash, now())"
    )
    db_session.execute(text(insert), {"user_id": user.id, "hash": "a" * 64})
    assert "uq_refresh_tokens_token_hash" in rejected(
        db_session, insert, {"user_id": user.id, "hash": "a" * 64}
    )
    assert "fk_refresh_tokens_user_id_users" in rejected(
        db_session, insert, {"user_id": uuid.uuid4(), "hash": "b" * 64}
    )


def test_a_user_without_audit_history_can_be_removed_with_their_tokens(
    db_session: Session,
) -> None:
    # Only reachable from SQL: the application never deletes users. Tokens go with the user.
    user = make_user(db_session)
    db_session.add(RefreshToken(user_id=user.id, token_hash="c" * 64, expires_at=user.created_at))
    db_session.flush()
    db_session.execute(text("DELETE FROM users WHERE id = :id"), {"id": user.id})
    assert db_session.scalar(select(RefreshToken).where(RefreshToken.user_id == user.id)) is None


def test_a_user_who_appears_in_the_audit_log_cannot_be_deleted(db_session: Session) -> None:
    user = make_user(db_session)
    record(db_session, AuditAction.LOGIN_SUCCEEDED, actor=user)
    db_session.flush()
    message = rejected(db_session, "DELETE FROM users WHERE id = :id", {"id": user.id})
    assert "fk_audit_logs_actor_id_users" in message


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO audit_logs (id, occurred_at, action, result) "
        "VALUES (gen_random_uuid(), now(), NULL, 'SUCCESS')",
        "INSERT INTO audit_logs (id, occurred_at, action, result) "
        "VALUES (gen_random_uuid(), now(), 'X', NULL)",
        "INSERT INTO audit_logs (id, occurred_at, action, result) "
        "VALUES (gen_random_uuid(), NULL, 'X', 'SUCCESS')",
    ],
    ids=["action", "result", "occurred_at"],
)
def test_audit_log_required_columns(db_session: Session, statement: str) -> None:
    assert "null value" in rejected(db_session, statement)
