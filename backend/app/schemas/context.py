import ipaddress
import re
import uuid
from datetime import datetime
from typing import ClassVar, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.events.schema import Criticality, canonical_hostname, canonical_ip
from app.models.context import (
    AssetStatus,
    AssetType,
    Environment,
    IdentityStatus,
    PrivilegeLevel,
)

MAX_TAGS = 20
MAX_IPS = 16
_TAG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")


def clean_tags(tags: list[str]) -> list[str]:
    cleaned = sorted({tag.strip().lower() for tag in tags if tag.strip()})
    if len(cleaned) > MAX_TAGS:
        raise ValueError(f"at most {MAX_TAGS} tags")
    for tag in cleaned:
        if not _TAG.match(tag):
            raise ValueError("tags use a-z, 0-9, '.', '_' and '-' (at most 32 characters)")
    return cleaned


def clean_ips(values: list[str]) -> list[str]:
    cleaned = sorted({canonical_ip(v) for v in values}, key=ipaddress.ip_address)
    if len(cleaned) > MAX_IPS:
        raise ValueError(f"at most {MAX_IPS} IP addresses")
    return cleaned


def clean_username(value: str) -> str:
    username = value.strip().lower()
    if not username or any(ch.isspace() or ch == "\x00" for ch in username):
        raise ValueError("usernames cannot be empty or contain whitespace")
    return username


class _Strict(BaseModel):
    """Unknown fields are errors, not silently ignored: a misspelled field in an admin
    change must fail loudly instead of looking like it worked."""

    model_config = ConfigDict(extra="forbid")


class _Updatable(_Strict):
    """PATCH semantics: only fields present in the request change. Sending null clears a field,
    which is allowed only for the optional ones listed in CLEARABLE."""

    CLEARABLE: ClassVar[frozenset[str]] = frozenset()

    @model_validator(mode="after")
    def _at_least_one_field(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("provide at least one field to change")
        for field in self.model_fields_set - self.CLEARABLE:
            if getattr(self, field) is None:
                raise ValueError(f"{field} cannot be empty")
        return self


# ---------- assets ----------


class AssetPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    hostname: str
    ip_addresses: list[str]
    asset_type: AssetType
    environment: Environment
    criticality: Criticality
    owner: str | None
    description: str | None
    tags: list[str]
    status: AssetStatus
    created_at: datetime
    updated_at: datetime

    @field_validator("ip_addresses", mode="before")
    @classmethod
    def _ips_as_text(cls, value: list[object]) -> list[str]:
        return [str(v) for v in value]


class AssetCreate(_Strict):
    hostname: str = Field(max_length=253)
    ip_addresses: list[str] = Field(default_factory=list, max_length=MAX_IPS)
    asset_type: AssetType
    environment: Environment
    criticality: Criticality
    owner: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=500)
    tags: list[str] = Field(default_factory=list, max_length=MAX_TAGS)

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, value: str) -> str:
        return canonical_hostname(value)

    @field_validator("ip_addresses")
    @classmethod
    def _ips(cls, value: list[str]) -> list[str]:
        return clean_ips(value)

    @field_validator("tags")
    @classmethod
    def _tags(cls, value: list[str]) -> list[str]:
        return clean_tags(value)


class AssetUpdate(_Updatable):
    """Hostname is the asset's identity for enrichment, so it cannot change: retire the asset
    and register the new name instead."""

    CLEARABLE = frozenset({"owner", "description"})

    ip_addresses: list[str] | None = Field(default=None, max_length=MAX_IPS)
    asset_type: AssetType | None = None
    environment: Environment | None = None
    criticality: Criticality | None = None
    owner: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=500)
    tags: list[str] | None = Field(default=None, max_length=MAX_TAGS)
    status: AssetStatus | None = None

    @field_validator("ip_addresses")
    @classmethod
    def _ips(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else clean_ips(value)

    @field_validator("tags")
    @classmethod
    def _tags(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else clean_tags(value)


# ---------- identities ----------


class IdentityPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    display_name: str | None
    department: str | None
    title: str | None
    privilege_level: PrivilegeLevel
    status: IdentityStatus
    tags: list[str]
    created_at: datetime
    updated_at: datetime


class IdentityCreate(_Strict):
    username: str = Field(max_length=256)
    display_name: str | None = Field(default=None, max_length=128)
    department: str | None = Field(default=None, max_length=128)
    title: str | None = Field(default=None, max_length=128)
    privilege_level: PrivilegeLevel
    tags: list[str] = Field(default_factory=list, max_length=MAX_TAGS)

    @field_validator("username")
    @classmethod
    def _username(cls, value: str) -> str:
        return clean_username(value)

    @field_validator("tags")
    @classmethod
    def _tags(cls, value: list[str]) -> list[str]:
        return clean_tags(value)


class IdentityUpdate(_Updatable):
    CLEARABLE = frozenset({"display_name", "department", "title"})

    display_name: str | None = Field(default=None, max_length=128)
    department: str | None = Field(default=None, max_length=128)
    title: str | None = Field(default=None, max_length=128)
    privilege_level: PrivilegeLevel | None = None
    status: IdentityStatus | None = None
    tags: list[str] | None = Field(default=None, max_length=MAX_TAGS)

    @field_validator("tags")
    @classmethod
    def _tags(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else clean_tags(value)
