"""Linux auth.log / secure lines (syslog), for sshd, sudo, su and account management.

Accepted line shapes (docs/event-model.md):

    Sep 25 10:31:02 web-01 sshd[4122]: Failed password for root from 203.0.113.45 port 50412 ssh2
    2026-09-25T10:31:02.123456+00:00 web-01 sshd[4122]: Accepted publickey for deploy from ...

RFC 3164 timestamps have no year and no zone: the zone comes from the log source, and the year
from the receive time (a December line received in January belongs to the previous year).

All patterns are anchored and have no nested quantifiers, so matching time is linear in the
line length (no catastrophic backtracking on hostile input).
"""

import re
from datetime import datetime, timedelta

from app.events.schema import EventCategory, EventOutcome, NormalizedEvent, SourceType
from app.ingestion.normalize import clean, optional_ip, optional_port, parse_iso_timestamp
from app.ingestion.parsers.base import ParseContext, ParseFailure, Skipped, decode_utf8

_MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}

_HEADER = re.compile(
    r"^(?:(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<clock>\d{2}:\d{2}:\d{2})"
    r"|(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})))"
    r" (?P<host>[^\s:]{1,253}) (?P<prog>[A-Za-z0-9_./-]{1,64})(?:\[(?P<pid>\d{1,10})\])?: "
    r"(?P<msg>.*)$"
)

# ---------- sshd ----------
_SSH_AUTH = re.compile(
    r"^(?P<result>Failed|Accepted) (?P<method>password|publickey|keyboard-interactive/pam|"
    r"hostbased|gssapi-with-mic) for (?P<invalid>invalid user )?(?P<user>\S*) "
    r"from (?P<ip>\S+) port (?P<port>\d{1,5})(?: ssh2)?(?:: .*)?$"
)
_SSH_SESSION_CLOSED = re.compile(
    r"^pam_unix\(sshd:session\): session closed for user (?P<user>\S+)$"
)
# Understood, but no event of their own: the Failed/Accepted lines carry the attempt.
_SSH_NOISE = (
    "Invalid user ",
    "Connection closed by ",
    "Connection reset by ",
    "Disconnected from ",
    "Received disconnect from ",
    "pam_unix(sshd:session): session opened",
    "pam_unix(sshd:auth): authentication failure",
    "PAM ",
    "error: maximum authentication attempts exceeded",
    "Server listening on ",
)

# ---------- sudo ----------
# "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
# "bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id"
# "bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=..."
_SUDO = re.compile(r"^\s*(?P<user>[^\s:;]{1,256}) : (?P<fields>.*)$")
_SUDO_ATTEMPTS = re.compile(r"^(?P<count>\d{1,3}) incorrect password attempts?$")

# ---------- su ----------
_SU = re.compile(
    r"^(?P<failed>FAILED SU )?\(to (?P<target>[^)\s]{1,256})\) (?P<user>\S+) on (?P<tty>\S+)$"
)

# ---------- account management ----------
_NEW_USER_PREFIX = "new user: "
_ADD_TO_GROUP = re.compile(r"^add '(?P<name>[^']+)' to group '(?P<group>[^']+)'$")
_GPASSWD_ADD = re.compile(r"^user (?P<name>\S+) added by (?P<actor>\S+) to group (?P<group>\S+)$")
_DELETE_USER = re.compile(r"^delete user '(?P<name>[^']+)'$")
_PASSWORD_CHANGED = re.compile(
    r"^pam_unix\(passwd:chauthtok\): password changed for (?P<name>\S+)$"
)

_ACCOUNT_PROGRAMS = {"useradd", "usermod", "userdel", "gpasswd", "groupadd", "passwd", "chpasswd"}


def _timestamp(match: re.Match[str], context: ParseContext) -> datetime:
    if match["iso"]:
        try:
            return parse_iso_timestamp(match["iso"])
        except ValueError:
            raise ParseFailure("invalid_timestamp") from None
    local_now = context.received_at.astimezone(context.timezone)
    try:
        hour, minute, second = (int(part) for part in match["clock"].split(":"))
        stamp = datetime(
            local_now.year,
            _MONTHS[match["mon"]],
            int(match["day"]),
            hour,
            minute,
            second,
            tzinfo=context.timezone,
        )
    except (KeyError, ValueError):
        raise ParseFailure("invalid_timestamp") from None
    # No year in the line: more than a day in the future means it was written last year.
    if stamp > local_now + timedelta(days=1):
        stamp = stamp.replace(year=stamp.year - 1)
    return stamp


class _Base:
    """The fields every event from one syslog line shares."""

    def __init__(self, match: re.Match[str], context: ParseContext) -> None:
        self.timestamp = _timestamp(match, context)
        self.host = match["host"]
        self.program = match["prog"].lower()
        self.pid = match["pid"]
        self.message = match["msg"]

    def event(self, **fields: object) -> NormalizedEvent:
        return NormalizedEvent(
            timestamp=self.timestamp,
            source_type=SourceType.LINUX_AUTH,
            host=self.host,
            service=self.program,
            process_name=self.program,
            session_id=self.pid,
            message=self.message[:1024],
            **fields,  # type: ignore[arg-type]
        )


def _sshd(line: _Base) -> NormalizedEvent | Skipped:
    auth = _SSH_AUTH.match(line.message)
    if auth:
        return line.event(
            event_category=EventCategory.AUTHENTICATION,
            event_action="logon",
            event_outcome=EventOutcome.SUCCESS
            if auth["result"] == "Accepted"
            else EventOutcome.FAILURE,
            username=auth["user"] or None,
            source_ip=optional_ip(auth["ip"]),
            source_port=optional_port(auth["port"]),
            protocol="ssh",
            attributes={
                "auth_method": auth["method"],
                "invalid_user": bool(auth["invalid"]),
            },
        )
    closed = _SSH_SESSION_CLOSED.match(line.message)
    if closed:
        return line.event(
            event_category=EventCategory.AUTHENTICATION,
            event_action="logoff",
            event_outcome=EventOutcome.SUCCESS,
            username=closed["user"],
            protocol="ssh",
        )
    if line.message.startswith(_SSH_NOISE):
        return Skipped("sshd_informational")
    return Skipped("unmodelled_message")


def _sudo(line: _Base) -> NormalizedEvent | Skipped:
    if line.message.startswith("pam_unix(sudo:"):
        return Skipped("sudo_session")
    match = _SUDO.match(line.message)
    if not match:
        return Skipped("unmodelled_message")
    parts = [part.strip() for part in match["fields"].split(" ; ")]
    fields = dict(part.split("=", 1) for part in parts if "=" in part)
    reasons = [part for part in parts if "=" not in part]
    if "COMMAND" not in fields:
        return Skipped("unmodelled_message")

    attributes: dict[str, str | int | bool | None] = {
        "tty": clean(fields.get("TTY"), 64),
        "working_directory": clean(fields.get("PWD"), 256),
    }
    outcome = EventOutcome.SUCCESS
    for reason in reasons:
        attempts = _SUDO_ATTEMPTS.match(reason)
        if attempts:
            outcome = EventOutcome.FAILURE
            attributes["failure_reason"] = "incorrect_password"
            attributes["attempts"] = int(attempts["count"])
        elif reason == "user NOT in sudoers":
            outcome = EventOutcome.FAILURE
            attributes["failure_reason"] = "not_in_sudoers"
        elif reason.startswith("command not allowed"):
            outcome = EventOutcome.FAILURE
            attributes["failure_reason"] = "command_not_allowed"
    return line.event(
        event_category=EventCategory.PRIVILEGE,
        event_action="sudo",
        event_outcome=outcome,
        username=match["user"],
        target_username=clean(fields.get("USER")),
        command_line=clean(fields.get("COMMAND"), 8192),
        attributes={k: v for k, v in attributes.items() if v is not None},
    )


def _su(line: _Base) -> NormalizedEvent | Skipped:
    if line.message.startswith("pam_unix(su"):
        return Skipped("su_session")
    match = _SU.match(line.message)
    if not match:
        return Skipped("unmodelled_message")
    return line.event(
        event_category=EventCategory.PRIVILEGE,
        event_action="su",
        event_outcome=EventOutcome.FAILURE if match["failed"] else EventOutcome.SUCCESS,
        username=match["user"],
        target_username=match["target"],
        attributes={"tty": match["tty"][:64]},
    )


def _account(line: _Base) -> NormalizedEvent | Skipped:
    message = line.message
    if message.startswith(_NEW_USER_PREFIX):
        # "new user: name=x, UID=1002, GID=1002, home=/home/x, shell=/bin/bash, from=/dev/pts/0"
        fields = dict(
            part.split("=", 1)
            for part in message.removeprefix(_NEW_USER_PREFIX).split(", ")
            if "=" in part
        )
        if not clean(fields.get("name")):
            return Skipped("unmodelled_message")
        attributes: dict[str, str | int] = {}
        if (uid := fields.get("UID", "")).isdigit():
            attributes["uid"] = int(uid)
        if shell := clean(fields.get("shell"), 256):
            attributes["shell"] = shell
        return line.event(
            event_category=EventCategory.IAM,
            event_action="user_created",
            event_outcome=EventOutcome.SUCCESS,
            target_username=fields["name"],
            attributes=attributes,
        )
    if added := _ADD_TO_GROUP.match(message):
        return line.event(
            event_category=EventCategory.IAM,
            event_action="group_member_added",
            event_outcome=EventOutcome.SUCCESS,
            target_username=added["name"],
            attributes={"group_name": added["group"]},
        )
    if gpasswd := _GPASSWD_ADD.match(message):
        return line.event(
            event_category=EventCategory.IAM,
            event_action="group_member_added",
            event_outcome=EventOutcome.SUCCESS,
            username=gpasswd["actor"],
            target_username=gpasswd["name"],
            attributes={"group_name": gpasswd["group"]},
        )
    if deleted := _DELETE_USER.match(message):
        return line.event(
            event_category=EventCategory.IAM,
            event_action="user_deleted",
            event_outcome=EventOutcome.SUCCESS,
            target_username=deleted["name"],
        )
    if changed := _PASSWORD_CHANGED.match(message):
        return line.event(
            event_category=EventCategory.IAM,
            event_action="password_changed",
            event_outcome=EventOutcome.SUCCESS,
            target_username=changed["name"],
        )
    # "new group: ...", "add 'x' to shadow group 'y'", group creation: no event of their own.
    return Skipped("account_informational")


def parse(raw: bytes, context: ParseContext) -> NormalizedEvent | Skipped:
    text = decode_utf8(raw).rstrip("\r\n")
    header = _HEADER.match(text)
    if header is None:
        raise ParseFailure("unrecognized_format")
    line = _Base(header, context)
    if line.program == "sshd":
        return _sshd(line)
    if line.program == "sudo":
        return _sudo(line)
    if line.program == "su":
        return _su(line)
    if line.program in _ACCOUNT_PROGRAMS:
        return _account(line)
    return Skipped("not_security_relevant")  # cron, systemd-logind, ...
