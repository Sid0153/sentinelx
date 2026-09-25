"""Readiness, the migration chain and check-config against a real PostgreSQL."""

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from app import cli
from app.database.migrations import alembic_config, expected_revision
from app.database.session import get_engine

pytestmark = pytest.mark.integration


def test_ready_when_database_is_up_and_migrated(db_client: TestClient) -> None:
    response = db_client.get("/api/ready")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "checks": {"database": "up", "migrations": "current"},
    }


def test_not_ready_when_schema_is_behind_the_code(
    db_client: TestClient, db_session: Session
) -> None:
    # Rolled back after the test by the db_session fixture.
    db_session.execute(text("UPDATE alembic_version SET version_num = 'older'"))
    response = db_client.get("/api/ready")
    assert response.status_code == 503
    assert response.json()["checks"] == {"database": "up", "migrations": "pending"}


def test_not_ready_when_database_was_never_migrated(
    db_client: TestClient, db_session: Session
) -> None:
    db_session.execute(text("DROP TABLE alembic_version"))
    response = db_client.get("/api/ready")
    assert response.status_code == 503
    assert response.json()["checks"]["migrations"] == "pending"


def test_migrations_upgrade_downgrade_and_upgrade_again(db_engine: Engine) -> None:
    def has_pg_trgm() -> bool:
        with db_engine.connect() as connection:
            found = connection.execute(
                text("SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'")
            ).first()
        return found is not None

    def revision() -> str | None:
        with db_engine.connect() as connection:
            return connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one_or_none()

    assert has_pg_trgm()
    assert revision() == expected_revision()

    command.downgrade(alembic_config(), "base")
    assert not has_pg_trgm()
    assert revision() is None

    command.upgrade(alembic_config(), "head")
    assert has_pg_trgm()
    assert revision() == expected_revision()


def test_pg_trgm_similarity_is_usable(db_session: Session) -> None:
    score = db_session.execute(text("SELECT similarity('powershell -enc', 'powershell')")).scalar()
    assert score is not None and score > 0


def test_check_config_succeeds_with_a_reachable_database(
    db_engine: Engine, capsys: pytest.CaptureFixture[str]
) -> None:
    get_engine.cache_clear()
    try:
        assert cli.main(["check-config"]) == 0
    finally:
        get_engine.cache_clear()
    assert "Configuration OK" in capsys.readouterr().out
