"""assets, identities, log_sources, raw_events, events (append-only evidence)

raw_events and events get the same append-only triggers as audit_logs, including TRUNCATE:
security logs are evidence, and the application never changes or removes them. How the demo
environment is reset (Phase 16) is designed then, without weakening this now.

Indexes follow the queries in docs/database-schema.md; the index test checks each query shape
can use its index.

Revision ID: 0003
Revises: 0002
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APPEND_ONLY_TABLES = ("raw_events", "events")


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("hostname", sa.String(length=253), nullable=False),
        sa.Column(
            "ip_addresses", postgresql.ARRAY(postgresql.INET()), server_default="{}", nullable=False
        ),
        sa.Column("asset_type", sa.String(length=32), nullable=False),
        sa.Column("environment", sa.String(length=16), nullable=False),
        sa.Column("criticality", sa.String(length=16), nullable=False),
        sa.Column("owner", sa.String(length=128), nullable=True),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column(
            "tags", postgresql.ARRAY(sa.String(length=32)), server_default="{}", nullable=False
        ),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "asset_type IN ('server', 'workstation', 'network_device', 'cloud_instance', 'container', 'other')",
            name=op.f("ck_assets_asset_type_valid"),
        ),
        sa.CheckConstraint(
            "criticality IN ('low', 'medium', 'high', 'critical')",
            name=op.f("ck_assets_criticality_valid"),
        ),
        sa.CheckConstraint(
            "environment IN ('production', 'staging', 'development', 'test')",
            name=op.f("ck_assets_environment_valid"),
        ),
        sa.CheckConstraint("status IN ('active', 'retired')", name=op.f("ck_assets_status_valid")),
        sa.CheckConstraint("hostname = lower(hostname)", name=op.f("ck_assets_hostname_lowercase")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_assets")),
        sa.UniqueConstraint("hostname", name=op.f("uq_assets_hostname")),
    )
    op.create_index(op.f("ix_assets_criticality"), "assets", ["criticality"], unique=False)
    op.create_index(
        "ix_assets_ip_addresses", "assets", ["ip_addresses"], unique=False, postgresql_using="gin"
    )
    op.create_table(
        "identities",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=256), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=True),
        sa.Column("department", sa.String(length=128), nullable=True),
        sa.Column("title", sa.String(length=128), nullable=True),
        sa.Column("privilege_level", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "tags", postgresql.ARRAY(sa.String(length=32)), server_default="{}", nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "privilege_level IN ('standard', 'privileged', 'service')",
            name=op.f("ck_identities_privilege_level_valid"),
        ),
        sa.CheckConstraint(
            "status IN ('active', 'disabled')", name=op.f("ck_identities_status_valid")
        ),
        sa.CheckConstraint(
            "username = lower(username)", name=op.f("ck_identities_username_lowercase")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_identities")),
        sa.UniqueConstraint("username", name=op.f("uq_identities_username")),
    )
    op.create_index(
        op.f("ix_identities_privilege_level"), "identities", ["privilege_level"], unique=False
    )
    op.create_table(
        "log_sources",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column("default_host", sa.String(length=253), nullable=True),
        sa.Column("timezone", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "source_type IN ('linux_auth', 'windows_security', 'http_access', 'app_json', 'generic_json')",
            name=op.f("ck_log_sources_source_type_valid"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_log_sources")),
        sa.UniqueConstraint("name", name=op.f("uq_log_sources_name")),
    )
    op.create_table(
        "raw_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw_data", sa.LargeBinary(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("parse_status", sa.String(length=8), nullable=False),
        sa.Column("parse_error", sa.String(length=64), nullable=True),
        sa.Column("simulated", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.CheckConstraint(
            "(parse_status = 'FAILED') = (parse_error IS NOT NULL)",
            name=op.f("ck_raw_events_parse_error_matches"),
        ),
        sa.CheckConstraint(
            "parse_status IN ('PARSED', 'FAILED')", name=op.f("ck_raw_events_parse_status_valid")
        ),
        sa.CheckConstraint(
            "octet_length(raw_data) <= 65536", name=op.f("ck_raw_events_raw_data_size")
        ),
        sa.ForeignKeyConstraint(
            ["source_id"], ["log_sources.id"], name=op.f("fk_raw_events_source_id_log_sources")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_raw_events")),
        sa.UniqueConstraint("fingerprint", name=op.f("uq_raw_events_fingerprint")),
    )
    op.create_index(op.f("ix_raw_events_source_id"), "raw_events", ["source_id"], unique=False)
    op.create_table(
        "events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("raw_event_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("host", sa.String(length=253), nullable=True),
        sa.Column("host_ip", postgresql.INET(), nullable=True),
        sa.Column("event_category", sa.String(length=32), nullable=False),
        sa.Column("event_action", sa.String(length=40), nullable=False),
        sa.Column("event_outcome", sa.String(length=8), nullable=False),
        sa.Column("username", sa.String(length=256), nullable=True),
        sa.Column("user_domain", sa.String(length=256), nullable=True),
        sa.Column("target_username", sa.String(length=256), nullable=True),
        sa.Column("source_ip", postgresql.INET(), nullable=True),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_ip", postgresql.INET(), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=32), nullable=True),
        sa.Column("service", sa.String(length=128), nullable=True),
        sa.Column("process_name", sa.String(length=256), nullable=True),
        sa.Column("parent_process_name", sa.String(length=256), nullable=True),
        sa.Column("command_line", sa.Text(), nullable=True),
        sa.Column("session_id", sa.String(length=128), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column(
            "attributes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("source_ip_scope", sa.String(length=16), nullable=True),
        sa.Column("asset_id", sa.Uuid(), nullable=True),
        sa.Column("asset_criticality", sa.String(length=16), nullable=True),
        sa.Column("identity_id", sa.Uuid(), nullable=True),
        sa.Column("identity_privileged", sa.Boolean(), nullable=True),
        sa.Column("simulated", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.CheckConstraint(
            "(asset_criticality IS NULL OR asset_criticality IN ('low', 'medium', 'high', 'critical'))",
            name=op.f("ck_events_criticality_valid"),
        ),
        sa.CheckConstraint(
            "(source_ip_scope IS NULL OR source_ip_scope IN ('internal', 'external', 'loopback', 'link_local', 'unknown'))",
            name=op.f("ck_events_ip_scope_valid"),
        ),
        sa.CheckConstraint(
            "event_action ~ '^[a-z][a-z_]{1,39}$'", name=op.f("ck_events_action_format")
        ),
        sa.CheckConstraint(
            "event_category IN ('authentication', 'iam', 'privilege', 'process', 'network', 'web', 'application')",
            name=op.f("ck_events_category_valid"),
        ),
        sa.CheckConstraint(
            "event_outcome IN ('success', 'failure', 'unknown')",
            name=op.f("ck_events_outcome_valid"),
        ),
        sa.CheckConstraint(
            "source_type IN ('linux_auth', 'windows_security', 'http_access', 'app_json', 'generic_json')",
            name=op.f("ck_events_source_type_valid"),
        ),
        sa.CheckConstraint(
            "destination_port IS NULL OR destination_port BETWEEN 0 AND 65535",
            name=op.f("ck_events_destination_port_range"),
        ),
        sa.CheckConstraint("host = lower(host)", name=op.f("ck_events_host_lowercase")),
        sa.CheckConstraint(
            "length(command_line) <= 8192", name=op.f("ck_events_command_line_size")
        ),
        sa.CheckConstraint("length(message) <= 1024", name=op.f("ck_events_message_size")),
        sa.CheckConstraint(
            "source_port IS NULL OR source_port BETWEEN 0 AND 65535",
            name=op.f("ck_events_source_port_range"),
        ),
        sa.CheckConstraint("username = lower(username)", name=op.f("ck_events_username_lowercase")),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name=op.f("fk_events_asset_id_assets")
        ),
        sa.ForeignKeyConstraint(
            ["identity_id"], ["identities.id"], name=op.f("fk_events_identity_id_identities")
        ),
        sa.ForeignKeyConstraint(
            ["raw_event_id"], ["raw_events.id"], name=op.f("fk_events_raw_event_id_raw_events")
        ),
        sa.ForeignKeyConstraint(
            ["source_id"], ["log_sources.id"], name=op.f("fk_events_source_id_log_sources")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_events")),
        sa.UniqueConstraint("raw_event_id", name=op.f("uq_events_raw_event_id")),
    )
    op.create_index(op.f("ix_events_asset_id"), "events", ["asset_id"], unique=False)
    op.create_index(
        "ix_events_category_action_ts",
        "events",
        ["event_category", "event_action", "timestamp"],
        unique=False,
    )
    op.create_index(
        "ix_events_command_line_trgm",
        "events",
        ["command_line"],
        unique=False,
        postgresql_using="gin",
        postgresql_ops={"command_line": "gin_trgm_ops"},
    )
    op.create_index(
        "ix_events_destination_ip_ts", "events", ["destination_ip", "timestamp"], unique=False
    )
    op.create_index("ix_events_host_ts", "events", ["host", "timestamp"], unique=False)
    op.create_index(op.f("ix_events_identity_id"), "events", ["identity_id"], unique=False)
    op.create_index(
        "ix_events_message_trgm",
        "events",
        ["message"],
        unique=False,
        postgresql_using="gin",
        postgresql_ops={"message": "gin_trgm_ops"},
    )
    op.create_index("ix_events_source_ip_ts", "events", ["source_ip", "timestamp"], unique=False)
    op.create_index(
        "ix_events_timestamp_id",
        "events",
        [sa.literal_column("timestamp DESC"), sa.literal_column("id DESC")],
        unique=False,
    )
    op.create_index("ix_events_username_ts", "events", ["username", "timestamp"], unique=False)

    # reject_modification() was created in migration 0002 for audit_logs.
    for table in APPEND_ONLY_TABLES:
        op.execute(
            f"CREATE TRIGGER {table}_no_update_delete BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION reject_modification()"
        )
        op.execute(
            f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION reject_modification()"
        )


def downgrade() -> None:
    # Dropping a table drops its indexes and triggers too.
    for table in ("events", "raw_events", "log_sources", "identities", "assets"):
        op.drop_table(table)
