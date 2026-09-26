"""Windows Security log events, one JSON object per record.

The accepted shape is the common subset of `Get-WinEvent | ConvertTo-Json` and log shippers:

    {"EventID": 4625, "TimeCreated": "2026-09-25T10:31:02.1234567Z", "Computer": "ws-042",
     "EventRecordID": 123456, "EventData": {"TargetUserName": "alice", "IpAddress": "...", ...}}

TimeCreated may also be PowerShell 5's "/Date(1758796262123)/" (milliseconds since the epoch).
Only the event IDs below are modelled; others are kept as SKIPPED raw records.
"""

import re
from datetime import UTC, datetime
from typing import Any

from app.events.schema import EventCategory, EventOutcome, NormalizedEvent, SourceType
from app.ingestion.normalize import (
    basename,
    clean,
    optional_ip,
    optional_port,
    parse_iso_timestamp,
    split_user,
)
from app.ingestion.parsers.base import ParseContext, ParseFailure, Skipped
from app.ingestion.parsers.json_common import load_object

_PS_DATE = re.compile(r"^/Date\((?P<ms>-?\d{1,15})\)/$")

LOGON_TYPES = {
    2: "interactive",
    3: "network",
    4: "batch",
    5: "service",
    7: "unlock",
    8: "network_cleartext",
    9: "new_credentials",
    10: "remote_interactive",
    11: "cached_interactive",
}


def _timestamp(value: Any) -> datetime:
    text = clean(value)
    if text and (ps := _PS_DATE.match(text)):
        return datetime.fromtimestamp(int(ps["ms"]) / 1000, UTC)
    try:
        return parse_iso_timestamp(text)
    except ValueError:
        raise ParseFailure("invalid_timestamp") from None


def _int(value: Any) -> int | None:
    text = clean(value)
    return int(text) if text is not None and text.lstrip("-").isdigit() else None


def _account_kind(name: str | None) -> str | None:
    if name is None:
        return None
    return "machine" if name.endswith("$") else "user"


def parse(raw: bytes, context: ParseContext) -> NormalizedEvent | Skipped:
    record = load_object(raw)
    event_id = _int(record.get("EventID", record.get("Id")))
    if event_id is None:
        raise ParseFailure("missing_event_id")
    data = record.get("EventData") or {}
    if not isinstance(data, dict):
        raise ParseFailure("invalid_event_data")
    host = clean(record.get("Computer") or record.get("MachineName")) or context.default_host
    timestamp = _timestamp(record.get("TimeCreated"))

    def event(**fields: Any) -> NormalizedEvent:
        attributes = {"event_id": event_id, **fields.pop("attributes", {})}
        if (record_id := _int(record.get("EventRecordID", record.get("RecordId")))) is not None:
            attributes["record_id"] = record_id
        return NormalizedEvent(
            timestamp=timestamp,
            source_type=SourceType.WINDOWS_SECURITY,
            host=host,
            service="microsoft-windows-security-auditing",
            attributes={k: v for k, v in attributes.items() if v is not None},
            **fields,
        )

    if event_id in (4624, 4625):
        user, domain = clean(data.get("TargetUserName")), clean(data.get("TargetDomainName"))
        logon_type = _int(data.get("LogonType"))
        failed = event_id == 4625
        return event(
            event_category=EventCategory.AUTHENTICATION,
            event_action="logon",
            event_outcome=EventOutcome.FAILURE if failed else EventOutcome.SUCCESS,
            username=user,
            user_domain=domain,
            source_ip=optional_ip(data.get("IpAddress")),
            source_port=optional_port(data.get("IpPort")),
            session_id=clean(data.get("TargetLogonId"), 128),
            protocol="rdp" if logon_type == 10 else ("network" if logon_type == 3 else None),
            message=f"{'Failed' if failed else 'Successful'} logon (type {logon_type})",
            attributes={
                "logon_type": logon_type,
                "logon_type_name": LOGON_TYPES.get(logon_type or -1),
                "auth_package": clean(data.get("AuthenticationPackageName"), 64),
                "workstation": clean(data.get("WorkstationName"), 64),
                "status": clean(data.get("Status"), 16) if failed else None,
                "sub_status": clean(data.get("SubStatus"), 16) if failed else None,
                "account_kind": _account_kind(user),
            },
        )
    if event_id == 4634:
        user = clean(data.get("TargetUserName"))
        return event(
            event_category=EventCategory.AUTHENTICATION,
            event_action="logoff",
            event_outcome=EventOutcome.SUCCESS,
            username=user,
            user_domain=clean(data.get("TargetDomainName")),
            session_id=clean(data.get("TargetLogonId"), 128),
            attributes={
                "logon_type": _int(data.get("LogonType")),
                "account_kind": _account_kind(user),
            },
        )
    if event_id == 4672:
        user = clean(data.get("SubjectUserName"))
        return event(
            event_category=EventCategory.PRIVILEGE,
            event_action="special_privileges_assigned",
            event_outcome=EventOutcome.SUCCESS,
            username=user,
            user_domain=clean(data.get("SubjectDomainName")),
            session_id=clean(data.get("SubjectLogonId"), 128),
            attributes={
                "privileges": clean(data.get("PrivilegeList"), 1024),
                "account_kind": _account_kind(user),
            },
        )
    if event_id == 4688:
        path = clean(data.get("NewProcessName"), 1024)
        return event(
            event_category=EventCategory.PROCESS,
            event_action="process_started",
            event_outcome=EventOutcome.SUCCESS,
            username=clean(data.get("SubjectUserName")),
            user_domain=clean(data.get("SubjectDomainName")),
            session_id=clean(data.get("SubjectLogonId"), 128),
            process_name=basename(path),
            parent_process_name=basename(data.get("ParentProcessName")),
            command_line=clean(data.get("CommandLine"), 8192),
            attributes={
                "process_path": path,
                "process_id": clean(data.get("NewProcessId"), 32),
                "token_elevation_type": clean(data.get("TokenElevationType"), 32),
            },
        )
    if event_id == 4720:
        return event(
            event_category=EventCategory.IAM,
            event_action="user_created",
            event_outcome=EventOutcome.SUCCESS,
            username=clean(data.get("SubjectUserName")),
            user_domain=clean(data.get("SubjectDomainName")),
            target_username=clean(data.get("TargetUserName")),
            # The SID identifies the account across 4720 and 4732 (which often has no name).
            attributes={"target_sid": clean(data.get("TargetSid"), 128)},
        )
    if event_id == 4732:
        member, _ = split_user(data.get("MemberName"))
        return event(
            event_category=EventCategory.IAM,
            event_action="group_member_added",
            event_outcome=EventOutcome.SUCCESS,
            username=clean(data.get("SubjectUserName")),
            user_domain=clean(data.get("SubjectDomainName")),
            # MemberName is often "-" for local accounts; the SID is always present.
            target_username=member if member and "=" not in member else None,
            attributes={
                "group_name": clean(data.get("TargetUserName"), 256),
                "target_sid": clean(data.get("MemberSid"), 128),
            },
        )
    return Skipped("unsupported_event_id")
