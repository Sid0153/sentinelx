"""Operator commands, run on the server.

    python -m app.cli check-config     # run first by docker-entrypoint.sh
    python -m app.cli export-openapi   # writes docs/openapi.json (a test fails if it is stale)
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

OPENAPI_PATH = Path(__file__).resolve().parents[2] / "docs" / "openapi.json"


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
    settings = Settings(app_env="development", database_url="postgresql+psycopg://x@localhost/x")
    return create_app(settings).openapi()


def _export_openapi() -> int:
    OPENAPI_PATH.write_text(json.dumps(openapi_document(), indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OPENAPI_PATH}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("check-config", help="Validate settings and database access")
    subcommands.add_parser("export-openapi", help="Write docs/openapi.json")
    args = parser.parse_args(argv)
    if args.command == "check-config":
        return _check_config()
    return _export_openapi()


if __name__ == "__main__":
    raise SystemExit(main())
