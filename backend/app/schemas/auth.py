from pydantic import BaseModel, Field, field_validator

from app.auth.passwords import MAX_PASSWORD_LENGTH, validate_password_policy
from app.schemas.users import UserPublic


class LoginRequest(BaseModel):
    email: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)

    @field_validator("email")
    @classmethod
    def _normalize(cls, value: str) -> str:
        return value.strip().lower()


class TokenResponse(BaseModel):
    access_token: str
    expires_in: int  # seconds
    user: UserPublic


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(max_length=MAX_PASSWORD_LENGTH)

    @field_validator("new_password")
    @classmethod
    def _valid_password(cls, value: str) -> str:
        return validate_password_policy(value)
