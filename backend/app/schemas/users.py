import re
import uuid
from datetime import datetime
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.auth.passwords import MAX_PASSWORD_LENGTH, validate_password_policy
from app.models.user import Role

_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(value: str) -> str:
    """Trim, lowercase and sanity-check an email address (not a full RFC parser)."""
    email = value.strip().lower()
    if not _EMAIL_PATTERN.match(email):
        raise ValueError("Enter a valid email address")
    return email


class UserPublic(BaseModel):
    """What the API ever reveals about a user. There is deliberately no password field."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    role: Role
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")  # a misspelled field is an error, not ignored

    email: str = Field(max_length=254)
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)
    role: Role

    @field_validator("email")
    @classmethod
    def _valid_email(cls, value: str) -> str:
        return normalize_email(value)

    @field_validator("password")
    @classmethod
    def _valid_password(cls, value: str) -> str:
        return validate_password_policy(value)


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Role | None = None
    is_active: bool | None = None

    @model_validator(mode="after")
    def _at_least_one_field(self) -> Self:
        if self.role is None and self.is_active is None:
            raise ValueError("Provide role and/or is_active")
        return self
