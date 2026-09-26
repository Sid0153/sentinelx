"""Detection rules, their history, the ATT&CK reference, and detection runs.

- DetectionRule: one row per rule. The logic comes from the shipped library (library_definition,
  fingerprinted); admins only change tunable values (overrides). `enabled` mirrors the
  effective definition so queries can filter on it.
- DetectionRuleVersion: every change (library update or admin tuning) as a full effective
  definition. Append-only: history of what the rules were is evidence too.
- MitreTechnique / DetectionRuleTechnique: the pinned ATT&CK reference and which rule (or rule
  indicator) maps to which technique, for coverage queries.
- DetectionRun: one execution of the enabled rules over a time range, with the per-rule outcome
  and every detection it produced (explanations, evidence event IDs, ATT&CK).
"""

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


def _check_in(column: str, values: type[enum.StrEnum]) -> str:
    return f"{column} IN ({', '.join(repr(v.value) for v in values)})"


class VersionSource(enum.StrEnum):
    LIBRARY = "library"  # the shipped definition changed (or the rule was added)
    ADMIN = "admin"  # an admin changed a tunable value


class RunTrigger(enum.StrEnum):
    BATCH = "batch"  # after an ingest batch
    MANUAL = "manual"  # an admin re-ran detection over a time range


class RunStatus(enum.StrEnum):
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_ERRORS = "COMPLETED_WITH_ERRORS"  # at least one rule failed; others ran


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    technique_id: Mapped[str] = mapped_column(sa.String(16), primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(200))
    tactics: Mapped[list[str]] = mapped_column(ARRAY(sa.String(64)))
    attack_version: Mapped[str] = mapped_column(sa.String(16))


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    rule_id: Mapped[str] = mapped_column(sa.String(16), primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(120))
    category: Mapped[str] = mapped_column(sa.String(32))
    kind: Mapped[str] = mapped_column(sa.String(16))
    library_definition: Mapped[dict[str, Any]] = mapped_column(JSONB)
    library_hash: Mapped[str] = mapped_column(sa.String(64))
    overrides: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=sa.text("'{}'::jsonb")
    )
    version: Mapped[int] = mapped_column(default=1)
    enabled: Mapped[bool] = mapped_column(default=True)
    # False when the rule was removed from the shipped library: kept for history, never run.
    in_library: Mapped[bool] = mapped_column(default=True, server_default=sa.true())
    last_run_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    last_match_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    match_count: Mapped[int] = mapped_column(default=0, server_default="0")
    error_count: Mapped[int] = mapped_column(default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()
    )


class DetectionRuleVersion(Base):
    __tablename__ = "detection_rule_versions"
    __table_args__ = (
        sa.UniqueConstraint("rule_id", "version", name="uq_detection_rule_versions_rule_version"),
        sa.CheckConstraint(_check_in("source", VersionSource), name="source_valid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[str] = mapped_column(sa.ForeignKey("detection_rules.rule_id"), index=True)
    version: Mapped[int]
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB)  # the effective definition
    overrides: Mapped[dict[str, Any]] = mapped_column(JSONB)
    library_hash: Mapped[str] = mapped_column(sa.String(64))
    source: Mapped[str] = mapped_column(sa.String(8))
    changed_by: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("users.id"))
    change_reason: Mapped[str | None] = mapped_column(sa.String(500))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class DetectionRuleTechnique(Base):
    __tablename__ = "detection_rule_techniques"

    rule_id: Mapped[str] = mapped_column(sa.ForeignKey("detection_rules.rule_id"), primary_key=True)
    technique_id: Mapped[str] = mapped_column(
        sa.ForeignKey("mitre_techniques.technique_id"), primary_key=True
    )
    # Which indicator of the rule maps to the technique ("" = the rule as a whole).
    indicator: Mapped[str] = mapped_column(sa.String(40), primary_key=True, default="")
    reason: Mapped[str] = mapped_column(sa.String(600))


class DetectionRun(Base):
    __tablename__ = "detection_runs"
    __table_args__ = (
        sa.CheckConstraint(_check_in("trigger", RunTrigger), name="trigger_valid"),
        sa.CheckConstraint(_check_in("status", RunStatus), name="status_valid"),
        sa.CheckConstraint("range_start <= range_end", name="range_ordered"),
        sa.Index("ix_detection_runs_started_at", "started_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    trigger: Mapped[str] = mapped_column(sa.String(8))
    batch_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("ingestion_batches.id"), index=True
    )
    requested_by: Mapped[uuid.UUID | None] = mapped_column(sa.ForeignKey("users.id"))
    range_start: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    range_end: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    status: Mapped[str] = mapped_column(sa.String(24))
    # {"AUTH-001": {"version": 1, "candidates": 42, "detections": 1, "error": null, "ms": 3}}
    rule_results: Mapped[dict[str, Any]] = mapped_column(JSONB)
    detections: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    detection_count: Mapped[int]
    # What the detections did to alerts (Phase 7): new alerts, and open alerts they extended.
    alerts_created: Mapped[int] = mapped_column(default=0, server_default="0")
    alerts_updated: Mapped[int] = mapped_column(default=0, server_default="0")
    duration_ms: Mapped[int]
    started_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
