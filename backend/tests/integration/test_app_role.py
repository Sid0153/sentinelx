"""The least-privilege runtime role (Phase 13): what the application's database user can and
cannot do. Everything runs in one transaction that is rolled back (role creation and grants
are transactional in PostgreSQL), so the test leaves nothing behind."""

import uuid
from collections.abc import Iterator

import pytest
from psycopg import errors as pg
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError

from app.database.roles import APPEND_ONLY_TABLES, setup_app_role

pytestmark = pytest.mark.integration


@pytest.fixture
def as_app_role(db_engine: Engine) -> Iterator[tuple[Connection, str]]:
    role = f"sx_app_{uuid.uuid4().hex[:8]}"
    with db_engine.connect() as connection:
        transaction = connection.begin()
        try:
            tables = setup_app_role(connection, role, "a-long-test-password-123")
            assert tables >= 20
            connection.execute(text(f'SET LOCAL ROLE "{role}"'))
            yield connection, role
        finally:
            transaction.rollback()


def refused(connection: Connection, statement: str) -> object:
    """Runs `statement` in a savepoint and returns the PostgreSQL error class it raised."""
    savepoint = connection.begin_nested()
    try:
        connection.execute(text(statement))
    except DBAPIError as exc:
        savepoint.rollback()
        return type(exc.orig)
    savepoint.rollback()
    raise AssertionError(f"allowed: {statement}")


def test_the_app_role_cannot_change_the_schema_or_the_evidence(
    as_app_role: tuple[Connection, str],
) -> None:
    connection, role = as_app_role
    assert (
        connection.scalar(text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user"))
        is False
    )
    assert connection.scalar(text("SELECT current_user")) == role
    denied = pg.InsufficientPrivilege
    # The triggers that keep evidence append-only cannot be switched off (only an owner can).
    assert refused(connection, "ALTER TABLE audit_logs DISABLE TRIGGER ALL") is denied
    assert refused(connection, "DROP TRIGGER audit_logs_no_update_delete ON audit_logs") is denied
    # No schema changes, no truncation, no dropping.
    assert refused(connection, "TRUNCATE events") is denied
    assert refused(connection, "DROP TABLE alerts") is denied
    assert refused(connection, "CREATE TABLE sneaky (id int)") is denied
    assert refused(connection, "ALTER TABLE users ADD COLUMN sneaky int") is denied
    # Append-only tables: no UPDATE or DELETE grant at all (a layer under the triggers).
    for table in APPEND_ONLY_TABLES:
        assert refused(connection, f"UPDATE {table} SET id = id") is denied
        assert refused(connection, f"DELETE FROM {table}") is denied
    # It cannot make itself more powerful.
    assert refused(connection, f'ALTER ROLE "{role}" SUPERUSER') is denied


def test_the_app_role_can_do_what_the_application_does(
    as_app_role: tuple[Connection, str],
) -> None:
    connection, _ = as_app_role
    # Reads everywhere, row changes on ordinary tables, inserts on evidence tables.
    for table in ("users", "alerts", "incidents", "events", "audit_logs", "alembic_version"):
        connection.execute(text(f"SELECT count(*) FROM {table}"))
    savepoint = connection.begin_nested()
    connection.execute(
        text(
            "INSERT INTO audit_logs (id, occurred_at, action, result, details) "
            "VALUES (gen_random_uuid(), now(), 'TEST', 'SUCCESS', '{}')"
        )
    )
    connection.execute(text("UPDATE users SET last_login_at = now() WHERE false"))
    connection.execute(text("DELETE FROM saved_hunts WHERE false"))
    connection.execute(text("SELECT pg_advisory_xact_lock(1)"))  # detection's run lock
    connection.execute(text("SET LOCAL statement_timeout = 5000"))  # hunting's timeout
    savepoint.rollback()


def test_role_names_and_passwords_are_checked(db_engine: Engine) -> None:
    with db_engine.connect() as connection:
        with pytest.raises(ValueError, match="identifier"):
            setup_app_role(connection, 'app"; DROP TABLE users; --', "a-long-test-password-123")
        with pytest.raises(ValueError, match="16 characters"):
            setup_app_role(connection, "sx_app", "short")
