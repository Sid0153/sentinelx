import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import cli
from app.models.user import Role, User
from tests.helpers import TEST_PASSWORD, audit_entries

pytestmark = pytest.mark.integration

EMAIL = "cli-admin@example.com"


def test_create_admin_from_the_environment_variable(
    cli_sessions: Session, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(cli.ADMIN_PASSWORD_ENV, TEST_PASSWORD)
    assert cli.main(["create-admin", "--email", " CLI-Admin@Example.com "]) == 0
    user = cli_sessions.scalar(select(User).where(User.email == EMAIL))
    assert user is not None and user.role == Role.ADMIN
    assert TEST_PASSWORD not in capsys.readouterr().out
    (entry,) = audit_entries(cli_sessions, "USER_CREATED")
    assert entry.details["via"] == "cli" and entry.actor_id is None

    # Running it again is refused rather than silently resetting the password.
    assert cli.main(["create-admin", "--email", EMAIL]) == 1
    assert "already exists" in capsys.readouterr().err


def test_create_admin_rejects_a_weak_password(
    cli_sessions: Session, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(cli.ADMIN_PASSWORD_ENV, "short")
    assert cli.main(["create-admin", "--email", EMAIL]) == 1
    assert "at least" in capsys.readouterr().err
    assert cli_sessions.scalar(select(User).where(User.email == EMAIL)) is None


def test_create_admin_prompts_and_checks_the_repeat(
    cli_sessions: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(cli.ADMIN_PASSWORD_ENV, raising=False)
    answers = iter([TEST_PASSWORD, "something-else-entirely"])
    monkeypatch.setattr("getpass.getpass", lambda prompt: next(answers))
    assert cli.main(["create-admin", "--email", EMAIL]) == 1
    assert cli_sessions.scalar(select(User).where(User.email == EMAIL)) is None


def test_create_admin_rejects_an_invalid_email(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["create-admin", "--email", "not-an-email"]) == 1
    assert "valid email" in capsys.readouterr().err
