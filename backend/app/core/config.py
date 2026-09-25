"""Application settings, loaded from environment variables (and an optional .env file).

Nothing secret has a default value: a missing DATABASE_URL stops the app at startup instead of
silently connecting somewhere unexpected. Settings that are fine on a laptop but unsafe on a
server are rejected when APP_ENV=production.
"""

from functools import lru_cache
from typing import Literal, Self

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DATABASE_URL_PREFIX = "postgresql+psycopg://"


class Settings(BaseSettings):
    # Later files override earlier ones: backend/.env overrides the repo-root .env.
    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",  # the shared .env also holds POSTGRES_* values used by docker compose
        # Validation errors must never echo a submitted value: it could be a password.
        hide_input_in_errors=True,
    )

    app_env: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    # json: one JSON object per line (containers, log shippers). text: readable local output.
    log_format: Literal["json", "text"] = "json"
    database_url: str
    cors_origins: str = "http://localhost:5174"  # comma-separated list

    @field_validator("database_url")
    @classmethod
    def _database_url_uses_psycopg(cls, value: str) -> str:
        if not value.startswith(DATABASE_URL_PREFIX):
            raise ValueError(f"DATABASE_URL must start with {DATABASE_URL_PREFIX}")
        return value

    @field_validator("cors_origins")
    @classmethod
    def _cors_has_no_wildcard(cls, value: str) -> str:
        # Refresh tokens will travel in cookies (Phase 3), so a wildcard origin would be unsafe.
        if "*" in value:
            raise ValueError("CORS_ORIGINS must list explicit origins, wildcards are not allowed")
        return value

    @model_validator(mode="after")
    def _production_is_locked_down(self) -> Self:
        if self.app_env != "production":
            return self
        insecure = [o for o in self.cors_origin_list if not o.startswith("https://")]
        if insecure:
            raise ValueError("In production every CORS_ORIGINS entry must use https://")
        if self.log_level == "DEBUG":
            raise ValueError("LOG_LEVEL=DEBUG is not allowed in production")
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def docs_enabled(self) -> bool:
        """Interactive API docs are off in production."""
        return self.app_env != "production"


@lru_cache
def get_settings() -> Settings:
    # The required fields are read from the environment, which mypy cannot see.
    return Settings()  # type: ignore[call-arg,unused-ignore]
