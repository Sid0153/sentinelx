from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session

from app import cli
from app.database.session import get_engine, get_session_factory
from app.models.user import Role, User
from tests.helpers import TEST_PASSWORD

pytestmark = pytest.mark.integration

EMAIL = "cli-admin@example.com"


@pytest.fixture
def cli_db(db_engine: Engine) -> Iterator[Session]:
    """The CLI commits through its own sessions, so clean up the user it creates.

    Its audit entry stays (the audit log is append-only), which is why the actor reference in
    audit_logs points at nothing here: USER_CREATED from the CLI has no actor.
    """
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    with Session(db_engine) as session:
        yield session
        session.execute(delete(User).where(User.email == EMAIL))
        session.commit()
    get_engine.cache_clear()
    get_session_factory.cache_clear()


def test_create_admin_from_the_environment_variable(
    cli_db: Session, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(cli.ADMIN_PASSWORD_ENV, TEST_PASSWORD)
    assert cli.main(["create-admin", "--email", " CLI-Admin@Example.com "]) == 0
    user = cli_db.scalar(select(User).where(User.email == EMAIL))
    assert user is not None and user.role == Role.ADMIN
    assert TEST_PASSWORD not in capsys.readouterr().out

    # Running it again is refused rather than silently resetting the password.
    assert cli.main(["create-admin", "--email", EMAIL]) == 1
    assert "already exists" in capsys.readouterr().err


def test_create_admin_rejects_a_weak_password(
    cli_db: Session, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(cli.ADMIN_PASSWORD_ENV, "short")
    assert cli.main(["create-admin", "--email", EMAIL]) == 1
    assert "at least" in capsys.readouterr().err
    assert cli_db.scalar(select(User).where(User.email == EMAIL)) is None


def test_create_admin_prompts_and_checks_the_repeat(
    cli_db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(cli.ADMIN_PASSWORD_ENV, raising=False)
    answers = iter([TEST_PASSWORD, "something-else-entirely"])
    monkeypatch.setattr("getpass.getpass", lambda prompt: next(answers))
    assert cli.main(["create-admin", "--email", EMAIL]) == 1
    assert cli_db.scalar(select(User).where(User.email == EMAIL)) is None


def test_create_admin_rejects_an_invalid_email(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["create-admin", "--email", "not-an-email"]) == 1
    assert "valid email" in capsys.readouterr().err
