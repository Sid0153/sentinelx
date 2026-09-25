"""Baseline: PostgreSQL extensions the design relies on.

pg_trgm backs substring search in threat hunting (docs/database-schema.md, ADR-0002). It is
created here, at the start of the migration chain, so a database that cannot provide it fails
at the first deployment instead of in Phase 10. pg_trgm is a "trusted" extension since
PostgreSQL 13: the database owner can create it without superuser rights.

Revision ID: 0001
Revises:
"""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")


def downgrade() -> None:
    op.execute("DROP EXTENSION IF EXISTS pg_trgm")
