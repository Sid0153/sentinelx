"""Security hardening (Phase 13): per-source ingest keys.

A log source may hold one ingest key (only its SHA-256 hash and a short prefix are stored);
each batch records the prefix of the key that sent it.

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-02 09:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("log_sources", sa.Column("ingest_key_hash", sa.String(length=64), nullable=True))
    op.add_column(
        "log_sources", sa.Column("ingest_key_prefix", sa.String(length=16), nullable=True)
    )
    op.add_column(
        "log_sources",
        sa.Column("ingest_key_created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "log_sources",
        sa.Column("ingest_key_last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_unique_constraint(
        op.f("uq_log_sources_ingest_key_hash"), "log_sources", ["ingest_key_hash"]
    )
    op.add_column(
        "ingestion_batches",
        sa.Column("ingest_key_prefix", sa.String(length=16), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("ingestion_batches", "ingest_key_prefix")
    op.drop_constraint(op.f("uq_log_sources_ingest_key_hash"), "log_sources", type_="unique")
    op.drop_column("log_sources", "ingest_key_last_used_at")
    op.drop_column("log_sources", "ingest_key_created_at")
    op.drop_column("log_sources", "ingest_key_prefix")
    op.drop_column("log_sources", "ingest_key_hash")
