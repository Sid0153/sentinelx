"""Operator commands, run on the server.

    python -m app.cli check-config     # run first by docker-entrypoint.sh
    python -m app.cli export-openapi   # writes docs/openapi.json (a test fails if it is stale)
    python -m app.cli create-admin --email you@example.com

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("check-config", help="Validate settings and database access")
    subcommands.add_parser("export-openapi", help="Write docs/openapi.json")
    create_admin = subcommands.add_parser("create-admin", help="Create an ADMIN user")
    create_admin.add_argument("--email", required=True)
    args = parser.parse_args(argv)
    if args.command == "check-config":
        return _check_config()
    if args.command == "export-openapi":
        return _export_openapi()
    return _create_admin(args.email)


if __name__ == "__main__":
    raise SystemExit(main())
