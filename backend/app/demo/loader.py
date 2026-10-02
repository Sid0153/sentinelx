"""Loads the demo environment (`app.demo.environment`) into the database (Phase 16).

Everything goes through the normal code paths: the inventory through the context service
(audited), the records through ingestion (stored as SIMULATED raw records, parsed, enriched,
detected, correlated). Nothing writes alerts or incidents directly, so the demo shows what the
pipeline really does with this input.

Safe to run again: existing sources and inventory entries are kept as they are (an
operator's changes are never overwritten), and records already stored are duplicates.
"""

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.events import AuditAction
from app.audit.service import record
from app.context.service import create_asset, create_identity
from app.core.config import Settings
from app.demo.environment import ASSETS, IDENTITIES, SOURCE_HOSTS, SOURCES, Step, story
from app.ingestion.service import IngestRequest, ingest
from app.ingestion.sources import create_source
from app.models.context import Asset, Identity
from app.models.detection import DetectionRun
from app.models.event import BatchChannel, IngestionBatch, LogSource, RawEvent
from app.models.user import User
from app.schemas.context import AssetCreate, IdentityCreate
from app.schemas.ingestion import SourceCreate


@dataclass
class StepResult:
    step: Step
    batch: IngestionBatch
    rules: set[str]


@dataclass
class LoadReport:
    anchor: datetime
    sources_created: list[str] = field(default_factory=list)
    assets_created: int = 0
    identities_created: int = 0
    steps: list[StepResult] = field(default_factory=list)

    @property
    def records(self) -> int:
        return sum(r.batch.received_count for r in self.steps)

    @property
    def duplicates(self) -> int:
        return sum(r.batch.duplicate_count for r in self.steps)

    @property
    def alerts_created(self) -> int:
        return sum(r.batch.alerts_created or 0 for r in self.steps)

    @property
    def incidents_created(self) -> int:
        return sum(r.batch.incidents_created or 0 for r in self.steps)


def _sources(db: Session, report: LoadReport) -> dict[str, LogSource]:
    sources = {}
    for source_type, name in SOURCES.items():
        source = db.scalar(select(LogSource).where(LogSource.name == name))
        if source is None:
            data = SourceCreate(
                name=name,
                source_type=source_type,
                description="SIMULATED demo data (python -m app.cli demo-load)",
                default_host=SOURCE_HOSTS.get(source_type),
            )
            source = create_source(db, data, actor=None)
            report.sources_created.append(name)
        elif source.source_type != source_type:
            raise ValueError(
                f"log source {name} exists with type {source.source_type}, not {source_type}"
            )
        sources[name] = source
    return sources


def _inventory(db: Session, report: LoadReport) -> None:
    """Before the records: enrichment takes its snapshot of criticality and privilege when an
    event is stored, as it would for real logs."""
    hostnames = set(db.scalars(select(Asset.hostname)))
    for asset in ASSETS:
        if asset.hostname not in hostnames:
            data = AssetCreate.model_validate(
                {**asset.__dict__, "ip_addresses": list(asset.ip_addresses),
                 "tags": list(asset.tags)}
            )  # fmt: skip
            create_asset(db, data, actor=None)
            report.assets_created += 1
    usernames = set(db.scalars(select(Identity.username)))
    for identity in IDENTITIES:
        if identity.username not in usernames:
            person = IdentityCreate.model_validate(
                {**identity.__dict__, "tags": list(identity.tags)}
            )
            create_identity(db, person, actor=None)
            report.identities_created += 1


def _rules(db: Session, batch: IngestionBatch) -> set[str]:
    run = db.scalar(select(DetectionRun).where(DetectionRun.batch_id == batch.id))
    return {d["rule_id"] for d in run.detections} if run is not None else set()


def load(
    db: Session,
    anchor: datetime,
    settings: Settings,
    *,
    previous_audit_head: tuple[int, str] | None = None,
) -> LoadReport:
    """Loads the story placed at `anchor`. After a reset, `previous_audit_head` is the newest
    entry of the audit log that was replaced; it becomes the first thing the new log records."""
    if previous_audit_head is not None:
        seq, digest = previous_audit_head
        record(
            db,
            AuditAction.DEMO_RESET,
            details={
                "previous_audit_head_seq": seq,
                "previous_audit_head_hash": digest,
                "users_kept": db.scalar(select(func.count()).select_from(User)) or 0,
            },
        )
        db.commit()
    report = LoadReport(anchor)
    steps = story(anchor)  # validates the anchor before anything is written
    sources = _sources(db, report)
    _inventory(db, report)
    for step in steps:
        request = IngestRequest(
            sources[step.source_name],
            [line.encode() for line in step.lines()],
            BatchChannel.DEMO,
            None,
            simulated=True,
        )
        batch = ingest(db, request, settings)
        report.steps.append(StepResult(step, batch, _rules(db, batch)))
    record(
        db,
        AuditAction.DEMO_LOADED,
        details={
            "anchor": anchor.isoformat(),
            "steps": len(report.steps),
            "records": report.records,
            "duplicates": report.duplicates,
            "alerts_created": report.alerts_created,
            "incidents_created": report.incidents_created,
        },
    )
    db.commit()
    return report


@dataclass(frozen=True)
class DemoStatus:
    simulated_records: int
    real_records: int

    @property
    def demo_only(self) -> bool:
        """Nothing but SIMULATED records: replacing the database loses no real evidence."""
        return self.real_records == 0


def status(db: Session) -> DemoStatus:
    rows = db.execute(select(RawEvent.simulated, func.count()).group_by(RawEvent.simulated))
    counts: dict[bool, int] = {simulated: count for simulated, count in rows}
    return DemoStatus(int(counts.get(True, 0)), int(counts.get(False, 0)))
