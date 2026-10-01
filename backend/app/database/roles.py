"""The least-privilege runtime database role (Phase 13, docs/security.md).

Migrations run as the database owner. The application itself connects as a separate role that
can only read and write rows: it owns nothing, so it cannot change the schema, drop tables,
truncate them, or disable the triggers that keep the evidence append-only. Before Phase 13 the
application connected as the owner, which in the official postgres image is a superuser:
anything that let an attacker run SQL through the app could have rewritten the audit log.

On the append-only tables the role may only SELECT and INSERT (no UPDATE or DELETE grant), a
second layer under the triggers. Run after every migration (`cli setup-app-role`, from the
container entrypoint): idempotent, and it also grants on tables a new migration added.
"""

import re
from typing import Any, cast

import psycopg
from psycopg import sql
from sqlalchemy import Connection

# Tables whose rows never change once written (their triggers reject UPDATE, DELETE, TRUNCATE).
APPEND_ONLY_TABLES = (
    "audit_logs",
    "raw_events",
    "events",
    "detection_rule_versions",
    "incident_notes",
    "incident_evidence",
    "incident_activity",
)
_ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def setup_app_role(connection: Connection, role: str, password: str) -> int:
    """Creates or updates `role` and grants it what the application needs, nothing more.
    `connection` must belong to the database owner. Returns how many tables were granted."""
    if not _ROLE_NAME.match(role):
        raise ValueError("APP_DB_USER must be a lowercase PostgreSQL identifier")
    if len(password) < 16:
        raise ValueError("APP_DB_PASSWORD must be at least 16 characters")
    raw = cast("psycopg.Connection[Any]", connection.connection.driver_connection)
    name = sql.Identifier(role)
    with raw.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,))
        verb = sql.SQL("ALTER") if cursor.fetchone() else sql.SQL("CREATE")
        # Utility statements take no bound parameters: the password is quoted as a literal.
        cursor.execute(
            sql.SQL(
                "{} ROLE {} WITH LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS INHERIT"
            ).format(verb, name, sql.Literal(password))
        )
        cursor.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(raw.info.dbname),
                name,
            )
        )
        cursor.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(name))
        cursor.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename"
        )
        tables = [row[0] for row in cursor.fetchall()]
        for table in tables:
            privileges = (
                "SELECT, INSERT"
                if table in APPEND_ONLY_TABLES
                else "SELECT, INSERT, UPDATE, DELETE"
            )
            cursor.execute(
                sql.SQL("REVOKE ALL ON TABLE {} FROM {}").format(sql.Identifier(table), name)
            )
            cursor.execute(
                sql.SQL("GRANT {} ON TABLE {} TO {}").format(
                    sql.SQL(privileges), sql.Identifier(table), name
                )
            )
        # Identity columns and sequences (incident numbers, activity order).
        cursor.execute(
            sql.SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}").format(name)
        )
    return len(tables)
