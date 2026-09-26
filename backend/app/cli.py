"""Operator commands, run on the server.

    python -m app.cli check-config     # run first by docker-entrypoint.sh
    python -m app.cli export-openapi   # writes docs/openapi.json (a test fails if it is stale)
    python -m app.cli create-admin --email you@example.com
    python -m app.cli create-source --name web-01-auth --type linux_auth [--timezone UTC]
    python -m app.cli ingest-file --source web-01-auth --file /var/log/auth.log
    python -m app.cli demo-scenarios   # SIMULATED scenarios and the options each accepts
    python -m app.cli demo-ingest --scenario brute_force --source web-01-auth \
        [--host web-01] [--user root] [--source-ip 203.0.113.45] [--count 12] [--interval 3]

There is no public registration: the first ADMIN is created here, and admins create everyone
else. The password is read from a hidden prompt (or SENTINELX_ADMIN_PASSWORD for automation),
never from a command-line argument, so it does not end up in shell history.
"""

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

OPENAPI_PATH = Path(__file__).resolve().parents[2] / "docs" / "openapi.json"
ADMIN_PASSWORD_ENV = "SENTINELX_ADMIN_PASSWORD"  # noqa: S105  (a variable name, not a secret)


def _check_config() -> int:
    """Settings are valid and the database answers. Prints only safe messages."""
    from app.core.config import get_settings

    try:
        get_settings()
    except ValidationError as exc:
        # hide_input_in_errors keeps submitted values (secrets) out of this text.
        print(f"Configuration invalid:\n{exc}", file=sys.stderr)
        return 1

    from app.database.session import get_engine

    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        # The exception text can contain the connection URL; print only its type.
        print(f"Database unreachable ({type(exc).__name__})", file=sys.stderr)
        return 1
    print("Configuration OK")
    return 0


def openapi_document() -> dict[str, Any]:
    from app.core.config import Settings
    from app.main import create_app

    # Docs are generated from a development-mode app so the schema is always available.
    # These values are placeholders for building the schema; nothing connects or signs.
    settings = Settings(
        app_env="development",
        database_url="postgresql+psycopg://x@localhost/x",
        secret_key="openapi-export-placeholder-0123456789abcdef",  # noqa: S106
    )
    return create_app(settings).openapi()


def _export_openapi() -> int:
    OPENAPI_PATH.write_text(json.dumps(openapi_document(), indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OPENAPI_PATH}")
    return 0


def _read_new_password() -> str | None:
    from app.auth.passwords import validate_password_policy

    password = os.environ.get(ADMIN_PASSWORD_ENV)
    if password is None:
        password = getpass.getpass("Password for the new admin: ")
        if getpass.getpass("Repeat the password: ") != password:
            print("Passwords do not match", file=sys.stderr)
            return None
    try:
        return validate_password_policy(password)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return None


def _create_admin(email: str) -> int:
    from app.core.errors import AppError
    from app.database.session import get_session_factory
    from app.models.user import Role
    from app.schemas.users import normalize_email
    from app.users.service import create_user

    try:
        email = normalize_email(email)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    password = _read_new_password()
    if password is None:
        return 1
    with get_session_factory()() as db:
        try:
            create_user(db, email, password, Role.ADMIN)
        except AppError as exc:
            print(exc.message, file=sys.stderr)
            return 1
    print(f"Admin {email} created")
    return 0


def _create_source(name: str, source_type: str, timezone: str, default_host: str | None) -> int:
    from app.core.errors import AppError
    from app.database.session import get_session_factory
    from app.ingestion.sources import create_source
    from app.schemas.ingestion import SourceCreate

    try:
        data = SourceCreate.model_validate(
            {
                "name": name,
                "source_type": source_type,
                "timezone": timezone,
                "default_host": default_host,
            }
        )
    except ValidationError as exc:
        print(f"Invalid source:\n{exc}", file=sys.stderr)
        return 1
    with get_session_factory()() as db:
        try:
            source = create_source(db, data, actor=None)
        except AppError as exc:
            print(exc.message, file=sys.stderr)
            return 1
    print(f"Log source {source.name} ({source.source_type}) created: {source.id}")
    return 0


def _ingest(source_name: str, records: list[bytes], channel: str, simulated: bool) -> int:
    from app.core.config import get_settings
    from app.core.errors import AppError
    from app.database.session import get_session_factory
    from app.ingestion.service import IngestRequest, ingest
    from app.ingestion.sources import get_source_by_name
    from app.models.event import BatchChannel

    with get_session_factory()() as db:
        try:
            source = get_source_by_name(db, source_name)
            batch = ingest(
                db,
                IngestRequest(source, records, BatchChannel(channel), None, simulated),
                get_settings(),
            )
        except AppError as exc:
            print(exc.message, file=sys.stderr)
            return 1
        print(
            f"Batch {batch.id}: received {batch.received_count}, parsed {batch.parsed_count}, "
            f"skipped {batch.skipped_count}, failed {batch.failed_count}, "
            f"duplicates {batch.duplicate_count}, rejected {batch.rejected_count}"
        )
    return 0


def _ingest_file(source_name: str, path: Path) -> int:
    try:
        content = path.read_bytes()
    except OSError as exc:
        print(f"Cannot read {path}: {exc.strerror}", file=sys.stderr)
        return 1
    lines = [line.removesuffix(b"\r") for line in content.split(b"\n")]
    return _ingest(source_name, [line for line in lines if line.strip()], "cli", simulated=False)


def _demo_ingest(args: argparse.Namespace) -> int:
    from datetime import UTC, datetime, timedelta

    from app.demo.scenarios import SCENARIOS, generate

    try:
        moment = (
            datetime.fromisoformat(args.start)
            if args.start
            else datetime.now(UTC) - timedelta(minutes=30)
        )
        lines = generate(
            args.scenario,
            moment,
            host=args.host,
            user=args.user,
            source_ip=args.source_ip,
            count=args.count,
            interval=args.interval,
        )
    except ValueError as exc:
        # fromisoformat's own message is fine to show; generate() writes operator messages.
        print(f"Cannot build the scenario: {exc}", file=sys.stderr)
        return 1
    scenario = SCENARIOS[args.scenario]
    print(f"Scenario {scenario.name} (SIMULATED): {scenario.description}")
    return _ingest(args.source, [line.encode() for line in lines], "demo", simulated=True)


def _list_scenarios() -> int:
    from app.demo.scenarios import SCENARIOS

    for scenario in SCENARIOS.values():
        options = ", ".join(f"--{o.replace('_', '-')}" for o in scenario.options)
        print(f"{scenario.name}: {scenario.description}")
        print(f"    options: {options}; --count = {scenario.count_meaning}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("check-config", help="Validate settings and database access")
    subcommands.add_parser("export-openapi", help="Write docs/openapi.json")
    create_admin = subcommands.add_parser("create-admin", help="Create an ADMIN user")
    create_admin.add_argument("--email", required=True)
    create_source = subcommands.add_parser("create-source", help="Register a log source")
    create_source.add_argument("--name", required=True)
    create_source.add_argument("--type", required=True, dest="source_type")
    create_source.add_argument("--timezone", default="UTC")
    create_source.add_argument("--default-host")
    ingest_file = subcommands.add_parser("ingest-file", help="Ingest a log file into a source")
    ingest_file.add_argument("--source", required=True)
    ingest_file.add_argument("--file", required=True, type=Path)
    demo = subcommands.add_parser("demo-ingest", help="Ingest a SIMULATED scenario")
    demo.add_argument("--scenario", required=True)
    demo.add_argument("--source", required=True)
    demo.add_argument("--start", help="ISO 8601 start time with zone (default: 30 min ago)")
    demo.add_argument("--host", help="host the activity happens on")
    demo.add_argument("--user", help="account targeted (brute-force scenarios)")
    demo.add_argument("--source-ip", help="attacking source address")
    demo.add_argument("--count", type=int, help="size of the scenario (see demo-scenarios)")
    demo.add_argument("--interval", type=int, help="seconds between attempts")
    subcommands.add_parser("demo-scenarios", help="List SIMULATED scenarios and their options")
    args = parser.parse_args(argv)
    if args.command == "check-config":
        return _check_config()
    if args.command == "export-openapi":
        return _export_openapi()
    if args.command == "create-source":
        return _create_source(args.name, args.source_type, args.timezone, args.default_host)
    if args.command == "ingest-file":
        return _ingest_file(args.source, args.file)
    if args.command == "demo-ingest":
        return _demo_ingest(args)
    if args.command == "demo-scenarios":
        return _list_scenarios()
    return _create_admin(args.email)


if __name__ == "__main__":
    raise SystemExit(main())
