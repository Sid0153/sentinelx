"""Alerts from detections (dedup, evidence, priority) and the analyst workflow.

Called by the detection engine inside the run's transaction, under its advisory lock, so two
runs never race to create "the first" alert for a key; the partial unique index on open alerts
backs that up. Only this module writes alerts.

For each detection:
1. Its evidence is compared with every alert that has the same key (open or closed). No new
   evidence means the activity is already covered: nothing changes. This makes re-running
   detection idempotent, and a closed alert is never re-created by a re-run.
2. With new evidence, the open alert for the key is extended (new evidence linked, times,
   counts, explanation and priority updated), or a new alert is created. A new alert points
   to the latest closed one for the key (previous_alert_id), so recurrence is visible. The
   engine never reopens a closed alert: that is the analyst's decision.
"""

import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import ColumnElement, func, or_, select
from sqlalchemy.orm import Session

from app.alerts import workflow
from app.alerts.dedup import dedup_key, title
from app.audit.events import AuditAction, EntityType
from app.audit.service import record
from app.core.errors import AppError
from app.detection.library import Library
from app.detection.model import Detection
from app.ingestion.enrich import Snapshot, asset_for, load_snapshot
from app.models.alert import ACTIVE_STATUSES, Alert, AlertEvent, AlertStatus, Disposition
from app.models.context import Asset, Identity, PrivilegeLevel
from app.models.event import Event
from app.models.user import User
from app.risk.priority import AssetContext, IdentityContext, Priority, alert_priority

logger = logging.getLogger(__name__)

MAX_EVIDENCE_PER_ALERT = 1000  # links kept per alert; event_count says how many are linked
MAX_HISTORY = 50  # merged detections remembered per alert (the most recent)
_CRITICALITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
ENTITY_COLUMNS = ("host", "username", "target_username", "source_ip", "destination_ip")


@dataclass(frozen=True)
class Outcome:
    alert_id: uuid.UUID | None
    action: str  # "created", "updated" or "unchanged"


def _entity(detection: Detection, name: str) -> str | None:
    """The detection's value for an entity column: the grouped value, or the only value
    seen in its evidence. Several different values: None (the alert shows them in entities)."""
    if name in detection.group:
        return str(detection.group[name])
    values = detection.entities.get(name, [])
    return values[0] if len(values) == 1 else None


def _peak(detection: Detection) -> int:
    distinct = detection.facts.get("distinct_count")
    return int(distinct) if isinstance(distinct, int) else detection.event_count


def _mitre(detection: Detection, library: Library) -> list[dict[str, Any]]:
    known = library.attack.by_id()
    snapshot = []
    for ref in detection.mitre:
        technique = known.get(ref.technique)
        snapshot.append(
            {
                "technique": ref.technique,
                "name": technique.name if technique else ref.technique,
                "tactics": list(technique.tactics) if technique else [],
                "reason": ref.reason,
                "attack_version": library.attack.attack_version,
            }
        )
    return snapshot


@dataclass(frozen=True)
class EvidenceContext:
    asset: Asset | None
    identity: Identity | None
    simulated: bool
    first_event_at: datetime
    last_event_at: datetime


def _context(db: Session, alert_id: uuid.UUID, inventory: Snapshot) -> EvidenceContext:
    """From all linked evidence: its time span, whether it is simulated, and the current
    inventory context: the most critical asset, and a privileged actor if any (else any
    known actor).

    Assets and identities are found both through what enrichment recorded on the events
    and by matching the events' hosts and users against the current inventory (the same
    rules as enrichment). Events never change, so without the second path an asset added
    after the events were stored would never count."""
    evidence = select(AlertEvent.event_id).where(AlertEvent.alert_id == alert_id)
    rows = db.execute(
        select(
            Event.asset_id,
            Event.identity_id,
            Event.host,
            Event.host_ip,
            Event.username,
            Event.simulated,
            Event.timestamp,
        ).where(Event.id.in_(evidence))
    ).all()
    asset_ids = {r.asset_id for r in rows if r.asset_id}
    identity_ids = {r.identity_id for r in rows if r.identity_id}
    for r in rows:
        if found := asset_for(r.host, str(r.host_ip) if r.host_ip else None, inventory):
            asset_ids.add(found.id)
        if r.username and (ref := inventory.identities.get(r.username)):
            identity_ids.add(ref.id)
    simulated = any(r.simulated for r in rows)
    assets = list(db.scalars(select(Asset).where(Asset.id.in_(asset_ids)))) if asset_ids else []
    identities = (
        list(db.scalars(select(Identity).where(Identity.id.in_(identity_ids))))
        if identity_ids
        else []
    )
    asset = max(assets, key=lambda a: (_CRITICALITY_ORDER[a.criticality], a.hostname), default=None)
    identity = max(
        identities,
        key=lambda i: (i.privilege_level == PrivilegeLevel.PRIVILEGED, i.username),
        default=None,
    )
    times = [r.timestamp for r in rows]
    return EvidenceContext(asset, identity, simulated, min(times), max(times))


def _priority(alert: Alert, asset: Asset | None, identity: Identity | None) -> Priority:
    threshold = alert.facts.get("threshold") if alert.kind in ("threshold", "distinct") else None
    return alert_priority(
        severity=alert.severity,
        confidence=alert.confidence,
        asset=AssetContext(asset.hostname, asset.criticality) if asset else None,
        identity=(
            IdentityContext(
                identity.username, identity.privilege_level == PrivilegeLevel.PRIVILEGED
            )
            if identity
            else None
        ),
        peak_count=alert.peak_count,
        threshold=threshold if isinstance(threshold, int) else None,
    )


def _apply_detection_fields(alert: Alert, detection: Detection, library: Library) -> None:
    """What an alert takes from its latest detection (all computed from evidence)."""
    alert.rule_version = detection.rule_version
    alert.severity = str(detection.severity)
    alert.confidence = str(detection.confidence)
    alert.explanation = detection.explanation
    alert.facts = detection.facts
    alert.entities = detection.entities
    alert.investigation = detection.investigation
    alert.response = detection.response
    alert.mitre = _mitre(detection, library)
    for name in ENTITY_COLUMNS:
        setattr(alert, name, _entity(detection, name))


def _link(db: Session, alert: Alert, event_ids: list[uuid.UUID], now: datetime) -> bool:
    """Links evidence up to the per-alert cap. Returns False if some had to be left out."""
    room = MAX_EVIDENCE_PER_ALERT - alert.event_count
    for event_id in event_ids[: max(room, 0)]:
        db.add(AlertEvent(alert_id=alert.id, event_id=event_id, linked_at=now))
    alert.event_count += min(len(event_ids), max(room, 0))
    return len(event_ids) <= room


def apply(
    db: Session,
    detections: list[Detection],
    run_id: uuid.UUID,
    library: Library,
    now: datetime,
) -> list[Outcome]:
    """Creates or extends alerts for a run's detections. The caller commits."""
    outcomes = []
    inventory = load_snapshot(db, ())
    for detection in detections:
        key = dedup_key(detection.rule_id, detection.indicator, detection.group)
        evidence = [uuid.UUID(i) for i in detection.evidence_event_ids]
        already = set(
            db.scalars(
                select(AlertEvent.event_id)
                .join(Alert, Alert.id == AlertEvent.alert_id)
                .where(Alert.dedup_key == key, AlertEvent.event_id.in_(evidence))
            )
        )
        new = [i for i in evidence if i not in already]
        if not new:
            outcomes.append(Outcome(None, "unchanged"))
            continue
        alert = db.scalars(
            select(Alert)
            .where(Alert.dedup_key == key, Alert.status.in_(ACTIVE_STATUSES))
            .with_for_update()
        ).first()
        action = "updated"
        if alert is None:
            alert = _create(db, detection, key, library, now)
            action = "created"
        else:
            alert.peak_count = max(alert.peak_count, _peak(detection))
            alert.detection_count += 1
        _apply_detection_fields(alert, detection, library)
        complete = _link(db, alert, new, now)
        truncated = detection.event_count > len(evidence) or not complete
        alert.evidence_truncated = alert.evidence_truncated or truncated
        alert.history = [
            *alert.history,
            {
                "run_id": str(run_id),
                "at": now.isoformat(),
                "first_seen": detection.first_seen.isoformat(),
                "last_seen": detection.last_seen.isoformat(),
                "event_count": detection.event_count,
                "new_evidence": len(new),
                "explanation": detection.explanation,
            },
        ][-MAX_HISTORY:]
        alert.updated_at = now
        db.flush()
        _refresh(db, alert, inventory)
        outcomes.append(Outcome(alert.id, action))
    return outcomes


def _refresh(db: Session, alert: Alert, inventory: Snapshot) -> bool:
    """Recomputes what an alert derives from its evidence and the current inventory.
    Returns whether the priority changed."""
    context = _context(db, alert.id, inventory)
    priority = _priority(alert, context.asset, context.identity)
    changed = (alert.priority_score, alert.priority_breakdown) != (
        priority.score,
        priority.breakdown(),
    )
    alert.asset_id = context.asset.id if context.asset else None
    alert.identity_id = context.identity.id if context.identity else None
    alert.simulated = context.simulated
    alert.first_event_at = context.first_event_at
    alert.last_event_at = context.last_event_at
    alert.priority_score = priority.score
    alert.priority_band = priority.band
    alert.priority_breakdown = priority.breakdown()
    alert.risk_model_version = priority.version
    return changed


def reprioritize_for_asset(
    db: Session, asset: Asset, old_ips: Sequence[object] = (), now: datetime | None = None
) -> int:
    """After an asset is created or changed: recompute the open alerts whose evidence may
    involve it. Candidates are found generously (recorded asset, same short host name, one
    of its addresses before or after the change); the recomputation itself is exact.
    Closed alerts keep the priority they had when they were handled. Returns how many open
    alerts changed priority. The caller commits (with the audited inventory change)."""
    short = asset.hostname.split(".", 1)[0]
    addresses = {str(ip) for ip in (*asset.ip_addresses, *old_ips)}
    matches = [
        Event.asset_id == asset.id,
        func.split_part(Event.host, ".", 1) == short,
    ]
    if addresses:
        matches.append(func.host(Event.host_ip).in_(sorted(addresses)))
    return _reprioritize(db, or_(*matches), now)


def reprioritize_for_identity(db: Session, identity: Identity, now: datetime | None = None) -> int:
    """After an identity is created or changed: as reprioritize_for_asset."""
    return _reprioritize(
        db, or_(Event.identity_id == identity.id, Event.username == identity.username), now
    )


def _reprioritize(db: Session, involves: ColumnElement[bool], now: datetime | None) -> int:
    db.flush()  # the inventory change must be visible to the lookups below
    affected = db.scalars(
        select(Alert)
        .where(
            Alert.status.in_(ACTIVE_STATUSES),
            Alert.id.in_(
                select(AlertEvent.alert_id)
                .join(Event, Event.id == AlertEvent.event_id)
                .where(involves)
            ),
        )
        .order_by(Alert.id)
        .with_for_update()
    ).all()
    if not affected:
        return 0
    inventory = load_snapshot(db, ())
    changed = 0
    for alert in affected:
        before = alert.priority_score
        if _refresh(db, alert, inventory):
            changed += 1
            alert.updated_at = now or datetime.now(UTC)
            logger.info(
                "alert.reprioritized",
                extra={
                    "fields": {
                        "alert_id": str(alert.id),
                        "from": before,
                        "to": alert.priority_score,
                    }
                },
            )
    return changed


def _create(db: Session, detection: Detection, key: str, library: Library, now: datetime) -> Alert:
    rule = library.rules.get(detection.rule_id)
    indicator_name = detection.facts.get("indicator_name")
    previous = db.scalar(
        select(Alert.id)
        .where(Alert.dedup_key == key, Alert.status.notin_(ACTIVE_STATUSES))
        .order_by(Alert.created_at.desc())
        .limit(1)
    )
    alert = Alert(
        id=uuid.uuid4(),
        rule_id=detection.rule_id,
        indicator=detection.indicator,
        kind=detection.kind,
        category=detection.category,
        title=title(
            detection.rule_name, str(indicator_name) if indicator_name else None, detection.group
        ),
        description=rule.description if rule else detection.rule_name,
        status=AlertStatus.NEW,
        dedup_key=key,
        group_values={k: str(v) for k, v in detection.group.items()},
        first_event_at=detection.first_seen,
        last_event_at=detection.last_seen,
        event_count=0,
        peak_count=_peak(detection),
        detection_count=1,
        history=[],
        previous_alert_id=previous,
        created_at=now,
        # Filled right after (priority needs the linked evidence): placeholders only.
        priority_score=0,
        priority_band="low",
        priority_breakdown=[],
        risk_model_version="",
    )
    db.add(alert)
    return alert


# ---------- analyst workflow ----------


def transition(
    db: Session,
    alert_id: uuid.UUID,
    target: AlertStatus,
    disposition: Disposition | None,
    reason: str | None,
    actor: User,
    now: datetime,
) -> Alert:
    alert = db.scalars(select(Alert).where(Alert.id == alert_id).with_for_update()).first()
    if alert is None:
        raise AppError(404, "Alert not found")
    current = AlertStatus(alert.status)
    try:
        workflow.check(current, target, disposition, reason)
    except workflow.TransitionError as exc:
        raise AppError(409, str(exc)) from exc
    except workflow.MissingInput as exc:
        raise AppError(400, str(exc)) from exc
    if workflow.is_reopen(current, target):
        newer = db.scalar(
            select(Alert.id).where(
                Alert.dedup_key == alert.dedup_key,
                Alert.status.in_(ACTIVE_STATUSES),
                Alert.id != alert.id,
            )
        )
        if newer is not None:
            raise AppError(
                409,
                f"A newer open alert exists for the same activity ({newer}); work on that one",
            )
    alert.status = target
    alert.status_changed_at = now
    alert.status_changed_by = actor.id
    alert.updated_at = now
    if alert.triaged_at is None and target != AlertStatus.NEW:
        alert.triaged_at = now
    if target in ACTIVE_STATUSES:
        alert.disposition = None
        alert.resolved_at = None
        alert.resolved_by = None
    else:
        alert.disposition = disposition
        alert.resolved_at = now
        alert.resolved_by = actor.id
    alert.status_note = reason
    record(
        db,
        AuditAction.ALERT_STATUS_CHANGED,
        actor=actor,
        entity_type=EntityType.ALERT,
        entity_id=alert.id,
        details={
            "from": str(current),
            "to": str(target),
            "disposition": str(disposition) if disposition else None,
            "reason": reason,
            "rule_id": alert.rule_id,
        },
    )
    db.commit()
    return alert
