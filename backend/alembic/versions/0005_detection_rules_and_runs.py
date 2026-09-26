"""detection rules, rule versions (append-only), ATT&CK reference, detection runs

Also: batches gain detection states and a detection count.

Revision ID: 0005
Revises: 0004
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "detection_rules",
        sa.Column("rule_id", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("library_definition", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("library_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "overrides",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("in_library", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_match_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("match_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error_count", sa.Integer(), server_default="0", nullable=False),
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
        sa.PrimaryKeyConstraint("rule_id", name=op.f("pk_detection_rules")),
    )
    op.create_table(
        "mitre_techniques",
        sa.Column("technique_id", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("tactics", postgresql.ARRAY(sa.String(length=64)), nullable=False),
        sa.Column("attack_version", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("technique_id", name=op.f("pk_mitre_techniques")),
    )
    op.create_table(
        "detection_rule_techniques",
        sa.Column("rule_id", sa.String(length=16), nullable=False),
        sa.Column("technique_id", sa.String(length=16), nullable=False),
        sa.Column("indicator", sa.String(length=40), nullable=False),
        sa.Column("reason", sa.String(length=600), nullable=False),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["detection_rules.rule_id"],
            name=op.f("fk_detection_rule_techniques_rule_id_detection_rules"),
        ),
        sa.ForeignKeyConstraint(
            ["technique_id"],
            ["mitre_techniques.technique_id"],
            name=op.f("fk_detection_rule_techniques_technique_id_mitre_techniques"),
        ),
        sa.PrimaryKeyConstraint(
            "rule_id", "technique_id", "indicator", name=op.f("pk_detection_rule_techniques")
        ),
    )
    op.create_table(
        "detection_rule_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=16), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("definition", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("overrides", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("library_hash", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=8), nullable=False),
        sa.Column("changed_by", sa.Uuid(), nullable=True),
        sa.Column("change_reason", sa.String(length=500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "source IN ('library', 'admin')", name=op.f("ck_detection_rule_versions_source_valid")
        ),
        sa.ForeignKeyConstraint(
            ["changed_by"], ["users.id"], name=op.f("fk_detection_rule_versions_changed_by_users")
        ),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["detection_rules.rule_id"],
            name=op.f("fk_detection_rule_versions_rule_id_detection_rules"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_detection_rule_versions")),
        sa.UniqueConstraint("rule_id", "version", name="uq_detection_rule_versions_rule_version"),
    )
    op.create_index(
        op.f("ix_detection_rule_versions_rule_id"),
        "detection_rule_versions",
        ["rule_id"],
        unique=False,
    )
    op.create_table(
        "detection_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("trigger", sa.String(length=8), nullable=False),
        sa.Column("batch_id", sa.Uuid(), nullable=True),
        sa.Column("requested_by", sa.Uuid(), nullable=True),
        sa.Column("range_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("range_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("rule_results", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("detections", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("detection_count", sa.Integer(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('COMPLETED', 'COMPLETED_WITH_ERRORS')",
            name=op.f("ck_detection_runs_status_valid"),
        ),
        sa.CheckConstraint(
            "trigger IN ('batch', 'manual')", name=op.f("ck_detection_runs_trigger_valid")
        ),
        sa.CheckConstraint(
            "range_start <= range_end", name=op.f("ck_detection_runs_range_ordered")
        ),
        sa.ForeignKeyConstraint(
            ["batch_id"],
            ["ingestion_batches.id"],
            name=op.f("fk_detection_runs_batch_id_ingestion_batches"),
        ),
        sa.ForeignKeyConstraint(
            ["requested_by"], ["users.id"], name=op.f("fk_detection_runs_requested_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_detection_runs")),
    )
    op.create_index(
        op.f("ix_detection_runs_batch_id"), "detection_runs", ["batch_id"], unique=False
    )
    op.create_index("ix_detection_runs_started_at", "detection_runs", ["started_at"], unique=False)
    op.add_column("ingestion_batches", sa.Column("detection_count", sa.Integer(), nullable=True))

    # A batch now moves on after its records are stored: detection runs over it.
    op.drop_constraint(
        op.f("ck_ingestion_batches_status_valid"), "ingestion_batches", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_ingestion_batches_status_valid"),
        "ingestion_batches",
        "status IN ('STORED', 'PROCESSED', 'PROCESSED_WITH_ERRORS', 'DETECTION_FAILED')",
    )
    # Rule history is evidence of what the rules were: never changed or removed
    # (reject_modification() comes from migration 0002).
    op.execute(
        "CREATE TRIGGER detection_rule_versions_no_update_delete BEFORE UPDATE OR DELETE "
        "ON detection_rule_versions FOR EACH ROW EXECUTE FUNCTION reject_modification()"
    )
    op.execute(
        "CREATE TRIGGER detection_rule_versions_no_truncate BEFORE TRUNCATE "
        "ON detection_rule_versions FOR EACH STATEMENT EXECUTE FUNCTION reject_modification()"
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_ingestion_batches_status_valid"), "ingestion_batches", type_="check"
    )
    # Batches that went through detection make this fail, loudly, instead of losing states.
    op.create_check_constraint(
        op.f("ck_ingestion_batches_status_valid"), "ingestion_batches", "status IN ('STORED')"
    )
    op.drop_column("ingestion_batches", "detection_count")
    op.drop_index("ix_detection_runs_started_at", table_name="detection_runs")
    op.drop_index(op.f("ix_detection_runs_batch_id"), table_name="detection_runs")
    op.drop_table("detection_runs")
    op.drop_index(op.f("ix_detection_rule_versions_rule_id"), table_name="detection_rule_versions")
    op.drop_table("detection_rule_versions")
    op.drop_table("detection_rule_techniques")
    op.drop_table("mitre_techniques")
    op.drop_table("detection_rules")
