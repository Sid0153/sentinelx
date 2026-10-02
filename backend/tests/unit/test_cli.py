import json
from collections.abc import Callable

import pytest

from app import cli
from app.core.config import get_settings


def test_openapi_export_is_up_to_date() -> None:
    """docs/openapi.json must match the code. Fix: python -m app.cli export-openapi"""
    committed = json.loads(cli.OPENAPI_PATH.read_text(encoding="utf-8"))
    assert committed == cli.openapi_document()


def test_check_config_fails_cleanly_on_invalid_settings(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DATABASE_URL", "mysql://root:t0p-secret@db/x")
    get_settings.cache_clear()
    try:
        assert cli.main(["check-config"]) == 1
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()
    err = capsys.readouterr().err
    assert "Configuration invalid" in err
    assert "t0p-secret" not in err


def test_check_config_reports_unreachable_database_without_the_url(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "app.database.session.get_settings",
        lambda: get_settings().model_copy(
            update={"database_url": "postgresql+psycopg://u:pw-s3cret@127.0.0.1:1/x"}
        ),
    )
    from app.database.session import get_engine

    get_engine.cache_clear()
    try:
        assert cli.main(["check-config"]) == 1
    finally:
        get_engine.cache_clear()
    err = capsys.readouterr().err
    assert "Database unreachable" in err
    assert "pw-s3cret" not in err


def _record_steps(monkeypatch: pytest.MonkeyPatch, fail: str | None = None) -> list[str]:
    calls: list[str] = []

    def step(name: str) -> Callable[..., int]:
        def run(*args: object, **kwargs: object) -> int:
            calls.append(name if name != "_demo_load" else f"demo:{kwargs.get('if_empty')}")
            return int(name == fail)

        return run

    monkeypatch.setattr("alembic.command.upgrade", lambda *args: calls.append("migrate"))
    for name in (
        "_setup_app_role",
        "_check_config",
        "_seed_rules",
        "_reconcile_batches",
        "_rescore",
        "_ensure_guest",
        "_demo_load",
    ):
        monkeypatch.setattr(cli, name, step(name))
    return calls


def test_startup_runs_every_step_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    """One process for the whole start (docker-entrypoint.sh): owner migrations, then the
    role, then the configuration as that role, then what needs schema and rules."""
    monkeypatch.setenv("APP_DB_USER", "sentinelx_app")
    monkeypatch.setenv("GUEST_EMAIL", "guest@sentinelx.example")
    monkeypatch.setenv("DEMO_AUTOLOAD", "true")
    get_settings.cache_clear()
    calls = _record_steps(monkeypatch)
    try:
        assert cli.main(["startup"]) == 0
    finally:
        get_settings.cache_clear()
    assert calls == [
        "migrate",
        "_setup_app_role",
        "_check_config",
        "_seed_rules",
        "_reconcile_batches",
        "_rescore",
        "_ensure_guest",
        "demo:True",
    ]


def test_startup_skips_what_is_not_configured_and_stops_at_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Empty values, not unset: the repository's .env may set them for the local stack.
    for name, value in (("APP_DB_USER", ""), ("GUEST_EMAIL", ""), ("DEMO_AUTOLOAD", "false")):
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()
    calls = _record_steps(monkeypatch, fail="_seed_rules")
    try:
        assert cli.main(["startup"]) == 1
    finally:
        get_settings.cache_clear()
    assert calls == ["migrate", "_check_config", "_seed_rules"]
