"""Application security events: one JSON object per line, in a small documented format.

    {"ts": "2026-09-25T10:31:02Z", "event": "login_failure", "user": "alice",
     "ip": "203.0.113.9", "app": "billing", "host": "app-01", "detail": "bad password"}

`event` must be one of EVENT_TYPES. An unknown name is a contract violation between the
application and SentinelX, so the record FAILS (instead of being silently skipped): somebody
should notice that the application logs something SentinelX does not understand.
"""

from app.events.schema import EventCategory, EventOutcome, NormalizedEvent, SourceType
from app.ingestion.normalize import clean, optional_ip, parse_iso_timestamp, split_user
from app.ingestion.parsers.base import ParseContext, ParseFailure
from app.ingestion.parsers.json_common import load_object

# event name -> (category, action, outcome). `user` is always the actor; `target_user` the
# account acted upon (the created user, the user whose role changed).
EVENT_TYPES: dict[str, tuple[EventCategory, str, EventOutcome]] = {
    "login_success": (EventCategory.AUTHENTICATION, "logon", EventOutcome.SUCCESS),
    "login_failure": (EventCategory.AUTHENTICATION, "logon", EventOutcome.FAILURE),
    "logout": (EventCategory.AUTHENTICATION, "logoff", EventOutcome.SUCCESS),
    "password_change": (EventCategory.IAM, "password_changed", EventOutcome.SUCCESS),
    "user_created": (EventCategory.IAM, "user_created", EventOutcome.SUCCESS),
    "role_changed": (EventCategory.IAM, "user_modified", EventOutcome.SUCCESS),
    "config_changed": (EventCategory.APPLICATION, "config_changed", EventOutcome.SUCCESS),
    "admin_action": (EventCategory.APPLICATION, "app_event", EventOutcome.SUCCESS),
    "access_denied": (EventCategory.APPLICATION, "app_event", EventOutcome.FAILURE),
}


def parse(raw: bytes, context: ParseContext) -> NormalizedEvent:
    record = load_object(raw)
    name = clean(record.get("event"), 64)
    if name is None:
        raise ParseFailure("missing_event_type")
    if name not in EVENT_TYPES:
        raise ParseFailure("unknown_event_type")
    category, action, outcome = EVENT_TYPES[name]
    try:
        timestamp = parse_iso_timestamp(record.get("ts"))
    except (ValueError, TypeError):
        raise ParseFailure("invalid_timestamp") from None

    user, domain = split_user(record.get("user"))
    target, _ = split_user(record.get("target_user"))
    attributes = {
        "app_event": name,
        "role": clean(record.get("role"), 64),
        "detail": clean(record.get("detail"), 1024),
    }
    return NormalizedEvent(
        timestamp=timestamp,
        source_type=SourceType.APP_JSON,
        event_category=category,
        event_action=action,
        event_outcome=outcome,
        host=clean(record.get("host")) or context.default_host,
        username=user,
        user_domain=domain,
        target_username=target,
        source_ip=optional_ip(record.get("ip")),
        service=clean(record.get("app"), 128) or "app",
        session_id=clean(record.get("session"), 128),
        message=name,
        attributes={k: v for k, v in attributes.items() if v is not None},
    )
