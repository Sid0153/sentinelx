"""Security hardening (Phase 13): rate-limit counters in PostgreSQL, shared by every backend
process and kept across restarts.

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-02 10:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rate_limit_counters",
        sa.Column("key", sa.String(length=200), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("key", "window_start", name=op.f("pk_rate_limit_counters")),
    )
    op.create_index(
        op.f("ix_rate_limit_counters_window_start"),
        "rate_limit_counters",
        ["window_start"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_rate_limit_counters_window_start"), table_name="rate_limit_counters")
    op.drop_table("rate_limit_counters")
