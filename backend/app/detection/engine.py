"""Detection runs: load candidate events from PostgreSQL, run every enabled rule, record it.

Stateless (ADR-0008): nothing is kept in memory between runs. Each run re-reads, for each rule,
the events in the time range widened by the rule's window, so late and out-of-order events are
seen, and a restart loses nothing.

- Serialized with a transaction-level advisory lock: two runs (two concurrent batches) cannot
  interleave. Ingestion itself stays concurrent.
- The SQL prefilter (conditions compiled to SQL) only narrows the rows read; the Python
  evaluation decides. It may read more rows than match, never fewer.
- A rule that fails is recorded with a fixed error code and the others still run.
- A rule with more candidates than MAX_CANDIDATES is not evaluated on a truncated set (that
  could hide or invent a detection): it is reported as `too_many_candidates`.
- For a run after a batch, only detections with at least one event from that batch are kept,
  so re-reading overlapping windows does not report the same activity again and again.
"""

import logging
import time
import uuid
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement, func, or_, select, true
from sqlalchemy.orm import Session

from app.detection.evaluate import evaluate
from app.detection.evaluators.common import group_key
from app.detection.events import DetectionEvent
from app.detection.explain import build
from app.detection.model import Detection, Rule
from app.detection.storage import enabled_rules
from app.models.detection import DetectionRule, DetectionRun, RunStatus, RunTrigger
from app.models.event import BatchStatus, Event, IngestionBatch, RawEvent
from app.models.user import User

logger = logging.getLogger(__name__)

MAX_CANDIDATES = 20_000
MAX_MANUAL_RANGE = timedelta(days=31)
LOCK_KEY = 0x5E17_DE7E  # any fixed number: "the detection lock"

_EVENT_FIELDS = tuple(
    name for name in DetectionEvent.__dataclass_fields__ if name not in ("id", "batch_id")
)


class TooManyCandidates(Exception):
    pass


def _to_event(row: Event, batch_id: uuid.UUID) -> DetectionEvent:
    values: dict[str, Any] = {name: getattr(row, name) for name in _EVENT_FIELDS}
    for name in ("host_ip", "source_ip", "destination_ip"):
        if values[name] is not None:
            values[name] = str(values[name])
    return DetectionEvent(id=str(row.id), batch_id=str(batch_id), **values)


def _prefilter(rule: Rule) -> ColumnElement[bool]:
    if rule.kind == "sequence":
        return or_(*(step.match.to_sql() for step in rule.steps or []))
    return rule.match.to_sql() if rule.match is not None else true()


def _load(db: Session, rule: Rule, start: datetime, end: datetime) -> list[DetectionEvent]:
    rows = db.execute(
        select(Event, RawEvent.batch_id)
        .join(RawEvent, RawEvent.id == Event.raw_event_id)
        .where(Event.timestamp >= start, Event.timestamp <= end, _prefilter(rule))
        .order_by(Event.timestamp, Event.id)
        .limit(MAX_CANDIDATES + 1)
    ).all()
    if len(rows) > MAX_CANDIDATES:
        raise TooManyCandidates
    return [_to_event(event, batch_id) for event, batch_id in rows]


def _history(
    db: Session, rule: Rule, before: datetime
) -> dict[tuple[Any, ...], list[tuple[datetime, Any]]]:
    """Earlier (time, value) pairs per group key, for new_value rules."""
    assert rule.lookback is not None and rule.value_field is not None  # noqa: S101
    history: dict[tuple[Any, ...], list[tuple[datetime, Any]]] = {}
    for event in _load(db, rule, before - rule.lookback, before - timedelta(microseconds=1)):
        if rule.match is not None and not rule.match.evaluate(event):
            continue
        key = group_key(rule, event)
        if key is not None:
            history.setdefault(key, []).append((event.timestamp, event.get(rule.value_field)))
    return history


def _serialize(detection: Detection) -> dict[str, Any]:
    data = asdict(detection)
    data["first_seen"] = detection.first_seen.isoformat()
    data["last_seen"] = detection.last_seen.isoformat()
    data["severity"] = str(detection.severity)
    data["confidence"] = str(detection.confidence)
    data["mitre"] = [ref.model_dump() for ref in detection.mitre]
    return data


def run(
    db: Session,
    start: datetime,
    end: datetime,
    *,
    trigger: RunTrigger,
    batch: IngestionBatch | None = None,
    requested_by: User | None = None,
) -> DetectionRun:
    """One detection run over [start, end] (event time). Commits."""
    started = time.perf_counter()
    started_at = datetime.now(UTC)
    db.execute(select(func.pg_advisory_xact_lock(LOCK_KEY)))

    detections: list[Detection] = []
    results: dict[str, dict[str, Any]] = {}
    for rule, version in enabled_rules(db):
        rule_started = time.perf_counter()
        outcome: dict[str, Any] = {
            "version": version,
            "candidates": 0,
            "detections": 0,
            "error": None,
        }
        try:
            window = rule.window()
            events = _load(db, rule, start - window, end + window)
            history = _history(db, rule, start - window) if rule.kind == "new_value" else None
            found = [build(rule, version, match) for match in evaluate(rule, events, history)]
            if batch is not None:
                found = [d for d in found if str(batch.id) in d.batch_ids]
            outcome["candidates"], outcome["detections"] = len(events), len(found)
            detections.extend(found)
        except TooManyCandidates:
            outcome["error"] = "too_many_candidates"
        except Exception as exc:  # one broken rule must not stop the others
            outcome["error"] = "evaluation_error"
            logger.error(
                "detection.rule_failed",
                extra={"fields": {"rule_id": rule.id, "error": type(exc).__name__}},
            )
        outcome["ms"] = round((time.perf_counter() - rule_started) * 1000, 1)
        results[rule.id] = outcome

    failed = [rule_id for rule_id, r in results.items() if r["error"]]
    detection_run = DetectionRun(
        trigger=trigger,
        batch_id=batch.id if batch else None,
        requested_by=requested_by.id if requested_by else None,
        range_start=start,
        range_end=end,
        status=RunStatus.COMPLETED_WITH_ERRORS if failed else RunStatus.COMPLETED,
        rule_results=results,
        detections=[_serialize(d) for d in detections],
        detection_count=len(detections),
        duration_ms=round((time.perf_counter() - started) * 1000),
        started_at=started_at,
    )
    db.add(detection_run)
    _update_stats(db, results, detections, started_at)
    if batch is not None:  # the batch's state changes in the same transaction as its run
        batch.status = BatchStatus.PROCESSED_WITH_ERRORS if failed else BatchStatus.PROCESSED
        batch.detection_count = len(detections)
    db.commit()
    logger.info(
        "detection.run_completed",
        extra={
            "fields": {
                "run_id": str(detection_run.id),
                "trigger": str(trigger),
                "rules": len(results),
                "detections": len(detections),
                "failed_rules": failed,
                "duration_ms": detection_run.duration_ms,
            }
        },
    )
    return detection_run


def _update_stats(
    db: Session, results: dict[str, dict[str, Any]], detections: list[Detection], now: datetime
) -> None:
    matched = {d.rule_id for d in detections}
    for row in db.scalars(select(DetectionRule).where(DetectionRule.rule_id.in_(list(results)))):
        outcome = results[row.rule_id]
        row.last_run_at = now
        row.match_count += outcome["detections"]
        if outcome["error"]:
            row.error_count += 1
        if row.rule_id in matched:
            row.last_match_at = now


def run_for_batch(db: Session, batch: IngestionBatch) -> DetectionRun | None:
    """Detection over what a batch brought in (called after the batch's records committed).

    A batch without new events is simply PROCESSED. If the run fails, the records are safe
    (already committed): the batch is marked DETECTION_FAILED and detection can be re-run
    over its time range (POST /api/detections/run), which is idempotent in its results.
    """
    if batch.first_event_at is None or batch.last_event_at is None:
        batch.status = BatchStatus.PROCESSED
        batch.detection_count = 0
        db.commit()
        return None
    batch_id = batch.id
    try:
        return run(
            db, batch.first_event_at, batch.last_event_at, trigger=RunTrigger.BATCH, batch=batch
        )
    except Exception as exc:
        db.rollback()
        logger.error(
            "detection.batch_failed",
            extra={"fields": {"batch_id": str(batch_id), "error": type(exc).__name__}},
        )
        failed = db.get(IngestionBatch, batch_id)
        if failed is not None:
            failed.status = BatchStatus.DETECTION_FAILED
            db.commit()
        return None


def reconcile_batches(db: Session, older_than: timedelta = timedelta(minutes=5)) -> int:
    """Batches left STORED by a crash between storing their records and running detection
    (run at startup). They are marked DETECTION_FAILED so they show up, and an admin can
    re-run detection over their time range. Returns how many were marked.

    One backend instance is assumed (ADR-0008): at startup no request is in flight, and the
    age limit keeps a batch that is being processed right now from being touched anyway.
    """
    cutoff = datetime.now(UTC) - older_than
    stuck = list(
        db.scalars(
            select(IngestionBatch).where(
                IngestionBatch.status == BatchStatus.STORED, IngestionBatch.created_at < cutoff
            )
        )
    )
    for batch in stuck:
        batch.status = BatchStatus.DETECTION_FAILED
    db.commit()
    if stuck:
        logger.warning(
            "detection.batches_reconciled",
            extra={"fields": {"batch_ids": [str(b.id) for b in stuck]}},
        )
    return len(stuck)
