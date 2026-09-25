"""Application settings, loaded from environment variables (and an optional .env file).

Nothing secret has a default value: a missing DATABASE_URL or SECRET_KEY stops the app at
startup instead of silently running with something guessable. Settings that are fine on a
laptop but unsafe on a server are rejected when APP_ENV=production.
"""

from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.client_ip import Network, parse_networks

DATABASE_URL_PREFIX = "postgresql+psycopg://"
MIN_SECRET_KEY_LENGTH = 32
MIN_SECRET_KEY_DISTINCT_CHARS = 10  # rejects "aaaa..." and other obviously weak keys


class Settings(BaseSettings):
    # Later files override earlier ones: backend/.env overrides the repo-root .env.
    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",  # the shared .env also holds POSTGRES_* values used by docker compose
        # Validation errors must never echo a submitted value: it could be the secret key.
        hide_input_in_errors=True,
    )

    app_env: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    # json: one JSON object per line (containers, log shippers). text: readable local output.
    log_format: Literal["json", "text"] = "json"
    database_url: str
    secret_key: str  # signs access tokens (JWT)
    cors_origins: str = "http://localhost:5174"  # comma-separated list

    # Authentication tuning (docs/security.md). Change only with a reason.
    access_token_expire_minutes: int = Field(default=15, ge=1, le=120)
    refresh_token_expire_days: int = Field(default=7, ge=1, le=90)
    max_failed_logins: int = Field(default=5, ge=1)
    lockout_minutes: int = Field(default=15, ge=1)
    login_rate_limit_per_minute: int = Field(default=10, ge=1)

    # Networks of the reverse proxies in front of the app, as comma-separated CIDRs. Only a
    # request whose direct peer is inside them may say who the client is (X-Forwarded-For);
    # see core/client_ip.py. Empty: the direct peer address is always the client.
    trusted_proxies: str = ""

    @field_validator("database_url")
    @classmethod
    def _database_url_uses_psycopg(cls, value: str) -> str:
        if not value.startswith(DATABASE_URL_PREFIX):
            raise ValueError(f"DATABASE_URL must start with {DATABASE_URL_PREFIX}")
        return value

    @field_validator("secret_key")
    @classmethod
    def _secret_key_is_strong_enough(cls, value: str) -> str:
        if len(value) < MIN_SECRET_KEY_LENGTH:
            raise ValueError(f"SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters")
        if len(set(value)) < MIN_SECRET_KEY_DISTINCT_CHARS:
            raise ValueError("SECRET_KEY looks too simple; generate a random one")
        return value

    @field_validator("cors_origins")
    @classmethod
    def _cors_has_no_wildcard(cls, value: str) -> str:
        # The refresh token travels in a cookie, so a wildcard origin would be unsafe.
        if "*" in value:
            raise ValueError("CORS_ORIGINS must list explicit origins, wildcards are not allowed")
        return value

    @field_validator("trusted_proxies")
    @classmethod
    def _trusted_proxies_are_networks(cls, value: str) -> str:
        try:
            parse_networks(value)
        except ValueError:
            raise ValueError("TRUSTED_PROXIES must be a comma-separated list of CIDRs") from None
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
    def trusted_networks(self) -> tuple[Network, ...]:
        return parse_networks(self.trusted_proxies)

    @property
    def docs_enabled(self) -> bool:
        """Interactive API docs are off in production."""
        return self.app_env != "production"

    @property
    def cookie_secure(self) -> bool:
        """The refresh cookie is HTTPS-only in production (plain http works for local dev)."""
        return self.app_env == "production"


@lru_cache
def get_settings() -> Settings:
    # The required fields are read from the environment, which mypy cannot see.
    return Settings()  # type: ignore[call-arg,unused-ignore]
