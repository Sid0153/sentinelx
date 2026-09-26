"""ingestion_batches; raw records belong to a batch and can be SKIPPED

- ingestion_batches: one row per ingest request with per-outcome counts.
- raw_events.batch_id (NOT NULL): every stored record belongs to the batch that brought it.
  No ingestion existed before this migration, so raw_events is empty when it runs; adding a
  NOT NULL column to a non-empty table would fail, loudly, which is the right behaviour.
- raw_events.parse_error is renamed to parse_detail and gains a third status, SKIPPED
  (recognized, deliberately not normalized, e.g. sshd "Connection closed ... [preauth]").

Renaming a column and changing CHECK constraints do not fire the row-level append-only
triggers: they change the table, not its rows.

Revision ID: 0004
Revises: 0003
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ingestion_batches",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("submitted_by", sa.Uuid(), nullable=True),
        sa.Column("channel", sa.String(length=8), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("received_count", sa.Integer(), nullable=False),
        sa.Column("parsed_count", sa.Integer(), nullable=False),
        sa.Column("skipped_count", sa.Integer(), nullable=False),
        sa.Column("failed_count", sa.Integer(), nullable=False),
        sa.Column("duplicate_count", sa.Integer(), nullable=False),
        sa.Column("rejected_count", sa.Integer(), nullable=False),
        sa.Column(
            "issues",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("first_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("simulated", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "channel IN ('api', 'text', 'cli', 'demo')",
            name=op.f("ck_ingestion_batches_channel_valid"),
        ),
        sa.CheckConstraint("status IN ('STORED')", name=op.f("ck_ingestion_batches_status_valid")),
        sa.CheckConstraint(
            "received_count = parsed_count + skipped_count + failed_count + duplicate_count "
            "+ rejected_count",
            name=op.f("ck_ingestion_batches_counts_add_up"),
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["log_sources.id"],
            name=op.f("fk_ingestion_batches_source_id_log_sources"),
        ),
        sa.ForeignKeyConstraint(
            ["submitted_by"], ["users.id"], name=op.f("fk_ingestion_batches_submitted_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ingestion_batches")),
    )
    op.create_index("ix_ingestion_batches_created_at", "ingestion_batches", ["created_at"])
    op.create_index(op.f("ix_ingestion_batches_source_id"), "ingestion_batches", ["source_id"])

    op.add_column("raw_events", sa.Column("batch_id", sa.Uuid(), nullable=False))
    op.create_index(op.f("ix_raw_events_batch_id"), "raw_events", ["batch_id"])
    op.create_foreign_key(
        op.f("fk_raw_events_batch_id_ingestion_batches"),
        "raw_events",
        "ingestion_batches",
        ["batch_id"],
        ["id"],
    )

    op.drop_constraint(op.f("ck_raw_events_parse_error_matches"), "raw_events", type_="check")
    op.drop_constraint(op.f("ck_raw_events_parse_status_valid"), "raw_events", type_="check")
    op.alter_column("raw_events", "parse_error", new_column_name="parse_detail")
    op.create_check_constraint(
        op.f("ck_raw_events_parse_status_valid"),
        "raw_events",
        "parse_status IN ('PARSED', 'SKIPPED', 'FAILED')",
    )
    op.create_check_constraint(
        op.f("ck_raw_events_parse_detail_matches"),
        "raw_events",
        "(parse_status = 'PARSED') = (parse_detail IS NULL)",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_raw_events_parse_detail_matches"), "raw_events", type_="check")
    op.drop_constraint(op.f("ck_raw_events_parse_status_valid"), "raw_events", type_="check")
    op.alter_column("raw_events", "parse_detail", new_column_name="parse_error")
    # Only PARSED/FAILED existed before; a SKIPPED row makes this downgrade fail, loudly.
    op.create_check_constraint(
        op.f("ck_raw_events_parse_status_valid"),
        "raw_events",
        "parse_status IN ('PARSED', 'FAILED')",
    )
    op.create_check_constraint(
        op.f("ck_raw_events_parse_error_matches"),
        "raw_events",
        "(parse_status = 'FAILED') = (parse_error IS NOT NULL)",
    )
    op.drop_constraint(
        op.f("fk_raw_events_batch_id_ingestion_batches"), "raw_events", type_="foreignkey"
    )
    op.drop_index(op.f("ix_raw_events_batch_id"), table_name="raw_events")
    op.drop_column("raw_events", "batch_id")
    op.drop_table("ingestion_batches")
