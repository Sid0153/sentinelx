from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.auth.passwords import MAX_PASSWORD_LENGTH, validate_password_policy
from app.schemas.users import UserPublic


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    # Second step for users with two-factor sign-in: a code from the app, or a recovery code.
    otp: str | None = Field(default=None, max_length=16)
    recovery_code: str | None = Field(default=None, max_length=32)

    @field_validator("email")
    @classmethod
    def _normalize(cls, value: str) -> str:
        return value.strip().lower()


class TokenResponse(BaseModel):
    access_token: str
    expires_in: int  # seconds
    user: UserPublic


class ChangePasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(max_length=MAX_PASSWORD_LENGTH)

    @field_validator("new_password")
    @classmethod
    def _valid_password(cls, value: str) -> str:
        return validate_password_policy(value)


class MfaSetup(BaseModel):
    """The new secret, to type in or to scan as a QR code of `otpauth_uri`. Shown once."""

    secret: str
    otpauth_uri: str


class MfaCode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1, max_length=16)


class MfaRecoveryCodes(BaseModel):
    """Shown once, when two-factor sign-in is turned on. Each works once."""

    recovery_codes: list[str]


class MfaDisableRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    code: str = Field(min_length=1, max_length=32)  # a code from the app or a recovery code
