import json

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
