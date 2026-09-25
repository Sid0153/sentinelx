import os

# Must run before app modules are imported.
# Tests never use a DATABASE_URL inherited from the developer's shell: they use
# TEST_DATABASE_URL (a scratch database) or, without it, a placeholder that nothing connects to.
_TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
os.environ["DATABASE_URL"] = (
    _TEST_DATABASE_URL or "postgresql+psycopg://test:test@127.0.0.1:1/unreachable"
)
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("LOG_FORMAT", "json")

from collections.abc import Iterator  # noqa: E402

import pytest  # noqa: E402
from alembic import command  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import Engine, create_engine  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.database.migrations import alembic_config  # noqa: E402
from app.database.session import get_db  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture
def app() -> FastAPI:
    return create_app()


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def db_engine() -> Iterator[Engine]:
    """A real PostgreSQL schema built by running the Alembic migrations."""
    if not _TEST_DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL not set")
    get_settings.cache_clear()
    command.upgrade(alembic_config(), "head")
    engine = create_engine(_TEST_DATABASE_URL)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Iterator[Session]:
    """A session inside a transaction that is rolled back after each test.

    Code under test may call commit(): with create_savepoint that only releases a SAVEPOINT,
    and the outer transaction (and all test data) is still discarded at the end.
    """
    connection = db_engine.connect()
    transaction = connection.begin()
    session = Session(
        bind=connection,
        join_transaction_mode="create_savepoint",
        autoflush=False,
        expire_on_commit=False,
    )
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture
def db_client(app: FastAPI, db_session: Session) -> Iterator[TestClient]:
    """A test client whose requests use the rolled-back test session."""

    def _get_db() -> Iterator[Session]:
        yield db_session

    app.dependency_overrides[get_db] = _get_db
    with TestClient(app) as test_client:
        yield test_client
