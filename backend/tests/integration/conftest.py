"""Fixtures for integration tests that need their own database (real concurrency)."""

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from alembic import command
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from app.alerts import service
from app.core.config import get_settings
from app.database.migrations import alembic_config
from app.detection.library import get_library
from app.detection.storage import seed
from tests.concurrency import WAIT_SECONDS, Factory, Pause
from tests.conftest import _TEST_DATABASE_URL


@pytest.fixture(scope="module")
def scratch() -> Iterator[Factory]:
    if not _TEST_DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL not set")
    base = make_url(_TEST_DATABASE_URL)
    name = f"sx_concurrency_{uuid.uuid4().hex[:8]}"
    admin = create_engine(base, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    settings = get_settings()
    original = settings.database_url
    url = base.set(database=name).render_as_string(hide_password=False)
    try:
        settings.database_url = url  # alembic/env.py migrates the configured database
        command.upgrade(alembic_config(), "head")
    finally:
        settings.database_url = original
    engine = create_engine(url)
    # The same settings as the application's sessions (app/database/session.py).
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with factory() as db:
        seed(db, get_library())
    try:
        yield factory
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.fixture
def pause(monkeypatch: pytest.MonkeyPatch) -> Iterator[Pause]:
    control = Pause()
    original = service.apply

    def apply(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        if control.armed:
            control.armed = False
            control.reached.set()
            control.release.wait(WAIT_SECONDS)
        return result

    monkeypatch.setattr(service, "apply", apply)
    yield control
    control.release.set()
