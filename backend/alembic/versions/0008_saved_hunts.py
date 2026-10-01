"""Threat hunting (Phase 10): saved hunts, and trigram indexes that substring search can use.

The 0003 trigram indexes were on the raw command_line and message columns, but every
substring comparison (hunts and rule prefilters) is on the ASCII-folded text,
translate(column, 'A..Z', 'a..z'), so PostgreSQL never used them. They are replaced by
indexes on exactly that expression.

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-01 09:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ALPHABETS = "'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'"
TRIGRAM_COLUMNS = ("command_line", "message")


def upgrade() -> None:
    op.create_table(
        "saved_hunts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("definition", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("shared", sa.Boolean(), server_default=sa.text("false"), nullable=False),
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
        sa.CheckConstraint("kind IN ('query', 'template')", name=op.f("ck_saved_hunts_kind_valid")),
        sa.ForeignKeyConstraint(
            ["owner_id"], ["users.id"], name=op.f("fk_saved_hunts_owner_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_saved_hunts")),
        sa.UniqueConstraint("owner_id", "name", name=op.f("uq_saved_hunts_owner_id")),
    )
    op.create_index(op.f("ix_saved_hunts_owner_id"), "saved_hunts", ["owner_id"], unique=False)
    op.create_index(op.f("ix_saved_hunts_shared"), "saved_hunts", ["shared"], unique=False)

    for column in TRIGRAM_COLUMNS:
        op.drop_index(f"ix_events_{column}_trgm", table_name="events", postgresql_using="gin")
        op.execute(
            f"CREATE INDEX ix_events_{column}_folded_trgm ON events "
            f"USING gin (translate({column}, {ALPHABETS}) gin_trgm_ops)"
        )


def downgrade() -> None:
    for column in TRIGRAM_COLUMNS:
        op.drop_index(f"ix_events_{column}_folded_trgm", table_name="events")
        op.create_index(
            f"ix_events_{column}_trgm",
            "events",
            [column],
            postgresql_using="gin",
            postgresql_ops={column: "gin_trgm_ops"},
        )
    op.drop_index(op.f("ix_saved_hunts_shared"), table_name="saved_hunts")
    op.drop_index(op.f("ix_saved_hunts_owner_id"), table_name="saved_hunts")
    op.drop_table("saved_hunts")
