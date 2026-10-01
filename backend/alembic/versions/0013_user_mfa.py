"""Security hardening (Phase 13): two-factor sign-in and forced password change.

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-02 14:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users", sa.Column("mfa_enabled", sa.Boolean(), server_default=sa.false(), nullable=False)
    )
    op.add_column("users", sa.Column("totp_salt", sa.String(length=64), nullable=True))
    op.add_column("users", sa.Column("totp_pending_salt", sa.String(length=64), nullable=True))
    op.add_column("users", sa.Column("totp_last_step", sa.BigInteger(), nullable=True))
    op.add_column(
        "users",
        sa.Column(
            "mfa_recovery_hashes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "users",
        sa.Column("must_change_password", sa.Boolean(), server_default=sa.false(), nullable=False),
    )


def downgrade() -> None:
    for column in (
        "must_change_password",
        "mfa_recovery_hashes",
        "totp_last_step",
        "totp_pending_salt",
        "totp_salt",
        "mfa_enabled",
    ):
        op.drop_column("users", column)
