"""The normalized event: the one shape every source format is turned into (ADR-0003).

Pure data and validation: no database, no HTTP. Parsers (Phase 5) produce these; the event
store persists them; detection (Phase 6) reads them. Field meanings: docs/event-model.md.

Validation here enforces the *canonical form* (lowercase hosts, UTC timestamps, a known
action for the category, bounded sizes). It does not guess: turning "CORP\\Alice" into
username "alice" + domain "corp" is the normalizer's job (Phase 5), which then builds this.
"""

import enum
import ipaddress
import re
from datetime import UTC, datetime
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_COMMAND_LINE = 8192  # longer command lines are cut by the parser, with a flag
MAX_MESSAGE = 1024
MAX_TEXT = 256
MAX_ATTRIBUTES = 50
MAX_ATTRIBUTE_VALUE = 1024


class SourceType(enum.StrEnum):
    """Which parser produced the event (one per supported input format)."""

    LINUX_AUTH = "linux_auth"
    WINDOWS_SECURITY = "windows_security"
    HTTP_ACCESS = "http_access"
    APP_JSON = "app_json"
    GENERIC_JSON = "generic_json"


class EventCategory(enum.StrEnum):
    AUTHENTICATION = "authentication"
    IAM = "iam"
    PRIVILEGE = "privilege"
    PROCESS = "process"
    NETWORK = "network"
    WEB = "web"
    APPLICATION = "application"


class EventOutcome(enum.StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class IpScope(enum.StrEnum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    UNKNOWN = "unknown"


class Criticality(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# The controlled vocabulary of actions per category. Rules match on these, so a parser cannot
# invent "login" in one place and "logon" in another. Adding one is a reviewed code change.
ACTIONS: dict[EventCategory, frozenset[str]] = {
    EventCategory.AUTHENTICATION: frozenset({"logon", "logoff"}),
    EventCategory.IAM: frozenset(
        {
            "user_created",
            "user_deleted",
            "user_modified",
            "password_changed",
            "group_member_added",
            "group_member_removed",
        }
    ),
    EventCategory.PRIVILEGE: frozenset({"sudo", "su", "special_privileges_assigned"}),
    EventCategory.PROCESS: frozenset({"process_started", "process_ended"}),
    EventCategory.NETWORK: frozenset({"connection"}),
    EventCategory.WEB: frozenset({"http_request"}),
    EventCategory.APPLICATION: frozenset({"app_event", "config_changed"}),
}

# RFC 1123 host labels, lowercase; single-label names ("web-01") and FQDNs are both valid.
# Underscores are also accepted: Windows NetBIOS names ("WS_042") use them, and refusing a real
# host's logs over a naming convention would lose evidence. Still no spaces, slashes or markup.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
    r"(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$"
)
_ATTRIBUTE_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def canonical_hostname(value: str) -> str:
    """Lowercase, no trailing dot, RFC 1123 labels. Raises ValueError otherwise."""
    host = value.strip().lower().rstrip(".")
    if not _HOSTNAME.match(host):
        raise ValueError("not a valid hostname")
    return host


def canonical_ip(value: str) -> str:
    """Normalized text form; IPv4-mapped IPv6 (::ffff:10.0.0.1) becomes plain IPv4."""
    ip = ipaddress.ip_address(value.strip())
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def _without_nul(value: Any) -> Any:
    """PostgreSQL text cannot hold NUL bytes. The raw record keeps the original bytes; the
    normalized copy shows U+FFFD (the replacement character) in their place."""
    if isinstance(value, str):
        return value.replace("\x00", "�")
    if isinstance(value, dict):
        return {_without_nul(k): _without_nul(v) for k, v in value.items()}
    return value


class NormalizedEvent(BaseModel):
    """One security event in SentinelX's own vocabulary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def _replace_nul(cls, data: Any) -> Any:
        return _without_nul(data) if isinstance(data, dict) else data

    timestamp: datetime  # event time, from the record itself
    source_type: SourceType
    event_category: EventCategory
    event_action: str
    event_outcome: EventOutcome = EventOutcome.UNKNOWN

    host: str | None = None
    host_ip: str | None = None
    username: str | None = Field(default=None, max_length=MAX_TEXT)  # the actor
    user_domain: str | None = Field(default=None, max_length=MAX_TEXT)
    target_username: str | None = Field(default=None, max_length=MAX_TEXT)  # acted upon
    source_ip: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_ip: str | None = None
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=32)
    service: str | None = Field(default=None, max_length=128)
    process_name: str | None = Field(default=None, max_length=MAX_TEXT)
    parent_process_name: str | None = Field(default=None, max_length=MAX_TEXT)
    command_line: str | None = Field(default=None, max_length=MAX_COMMAND_LINE)
    session_id: str | None = Field(default=None, max_length=128)
    message: str | None = Field(default=None, max_length=MAX_MESSAGE)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        # A timestamp without a zone is ambiguous evidence: the parser must decide it.
        if value.tzinfo is None:
            raise ValueError("timestamp must include a time zone")
        return value.astimezone(UTC)

    @field_validator("host")
    @classmethod
    def _host(cls, value: str | None) -> str | None:
        return canonical_hostname(value) if value else None

    @field_validator("host_ip", "source_ip", "destination_ip")
    @classmethod
    def _ip(cls, value: str | None) -> str | None:
        return canonical_ip(value) if value else None

    @field_validator("username", "target_username", "user_domain")
    @classmethod
    def _lowercase_identity(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip().lower()
        if not cleaned:
            return None
        # A NUL has already become U+FFFD; in a name it is as suspicious as a newline.
        if any(ch in cleaned for ch in "\r\n\t�"):
            raise ValueError("control characters are not allowed in names")
        return cleaned

    @field_validator("process_name", "parent_process_name", "protocol", "service")
    @classmethod
    def _lowercase(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip().lower() or None

    @field_validator("attributes")
    @classmethod
    def _bounded_attributes(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > MAX_ATTRIBUTES:
            raise ValueError(f"at most {MAX_ATTRIBUTES} attributes")
        for key, item in value.items():
            if not _ATTRIBUTE_KEY.match(key):
                raise ValueError(f"attribute key {key[:32]!r} must be snake_case")
            if not (item is None or isinstance(item, str | int | float | bool)):
                raise ValueError("attribute values must be scalars")
            if isinstance(item, str) and len(item) > MAX_ATTRIBUTE_VALUE:
                raise ValueError(f"attribute {key!r} is too long")
        return value

    @model_validator(mode="after")
    def _known_action(self) -> Self:
        allowed = ACTIONS[self.event_category]
        if self.event_action not in allowed:
            raise ValueError(
                f"event_action {self.event_action[:40]!r} is not valid for "
                f"{self.event_category}; expected one of {sorted(allowed)}"
            )
        return self
