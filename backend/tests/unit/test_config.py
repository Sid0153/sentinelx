import pytest
from pydantic import ValidationError

from app.core.config import Settings

VALID_URL = "postgresql+psycopg://user:pw@127.0.0.1:5432/db"


def make(**overrides: object) -> Settings:
    values: dict[str, object] = {"database_url": VALID_URL, "app_env": "development"}
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[call-arg,arg-type]


def test_database_url_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValidationError, match="database_url"):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_database_url_must_use_psycopg_driver() -> None:
    with pytest.raises(ValidationError, match="postgresql\\+psycopg://"):
        make(database_url="postgresql://user:pw@127.0.0.1/db")


def test_validation_error_does_not_echo_the_database_password() -> None:
    with pytest.raises(ValidationError) as caught:
        make(database_url="mysql://user:hunter2-secret@db/x")
    assert "hunter2-secret" not in str(caught.value)


def test_wildcard_cors_origin_is_rejected() -> None:
    with pytest.raises(ValidationError, match="wildcards"):
        make(cors_origins="*")


def test_cors_origin_list_is_split_and_trimmed() -> None:
    settings = make(cors_origins=" http://a.test , http://b.test ,")
    assert settings.cors_origin_list == ["http://a.test", "http://b.test"]


def test_production_requires_https_origins() -> None:
    with pytest.raises(ValidationError, match="https"):
        make(app_env="production", cors_origins="http://soc.example")


def test_production_rejects_debug_logging() -> None:
    with pytest.raises(ValidationError, match="DEBUG"):
        make(app_env="production", cors_origins="https://soc.example", log_level="DEBUG")


def test_production_disables_interactive_docs() -> None:
    production = make(app_env="production", cors_origins="https://soc.example")
    assert production.docs_enabled is False
    assert make().docs_enabled is True
