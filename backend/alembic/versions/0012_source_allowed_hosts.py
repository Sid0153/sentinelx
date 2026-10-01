"""Security hardening (Phase 13): the hosts a log source may speak for.

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-02 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "log_sources",
        sa.Column(
            "allowed_hosts",
            postgresql.ARRAY(sa.String(length=253)),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("log_sources", "allowed_hosts")
