"""Rules in the database: seeding the shipped library, effective definitions, admin tuning.

The effective rule = the library definition (which owns the logic) + admin overrides (only
the fields the rule declares tunable, within its bounds). Every change, from a library update
or an admin, creates a new version row with the full effective definition and is audited.
"""

import logging
from datetime import timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.audit.events import AuditAction, EntityType
from app.audit.service import record
from app.core.errors import AppError
from app.detection.library import Library
from app.detection.model import Confidence, Exclusion, Rule, Severity, parse_duration
from app.models.detection import (
    DetectionRule,
    DetectionRuleTechnique,
    DetectionRuleVersion,
    MitreTechnique,
    VersionSource,
)
from app.models.user import User

logger = logging.getLogger(__name__)

TUNABLE_FIELDS = ("threshold", "time_window", "severity", "confidence", "enabled", "exclusions")


class RuleChanges(BaseModel):
    """What an admin may send. Only fields the rule declares tunable are accepted."""

    model_config = ConfigDict(extra="forbid")

    threshold: int | None = Field(default=None, ge=1)
    time_window: timedelta | None = None
    severity: Severity | None = None
    confidence: Confidence | None = None
    enabled: bool | None = None
    exclusions: list[Exclusion] | None = Field(default=None, max_length=100)
    reason: str = Field(min_length=5, max_length=500)

    @field_validator("time_window", mode="before")
    @classmethod
    def _duration(cls, value: Any) -> Any:
        return parse_duration(value)


def _as_json(value: Any) -> Any:
    if isinstance(value, timedelta):
        return f"PT{int(value.total_seconds())}S"  # ISO 8601, what Rule parses back
    if isinstance(value, list):
        return [
            item.model_dump(mode="json") if isinstance(item, BaseModel) else item for item in value
        ]
    return value.value if hasattr(value, "value") else value


def effective(row: DetectionRule) -> Rule:
    """The rule as it runs: library definition with the admin overrides applied."""
    return Rule.model_validate({**row.library_definition, **row.overrides})


def _check_overrides(definition: Rule, overrides: dict[str, Any]) -> list[str]:
    """Which override keys are no longer valid for this definition (to drop them)."""
    invalid = []
    tunable = definition.tunable
    for key, value in overrides.items():
        allowed = {
            "threshold": tunable.threshold is not None,
            "time_window": tunable.time_window is not None,
            "severity": tunable.severity,
            "confidence": tunable.confidence,
            "enabled": tunable.enabled,
            "exclusions": tunable.exclusions,
        }.get(key, False)
        if not allowed:
            invalid.append(key)
            continue
        try:
            Rule.model_validate({**definition.model_dump(mode="json", by_alias=True), key: value})
        except ValidationError:
            invalid.append(key)
    return invalid


def _add_version(
    db: Session,
    row: DetectionRule,
    source: VersionSource,
    actor: User | None = None,
    reason: str | None = None,
) -> None:
    db.add(
        DetectionRuleVersion(
            rule_id=row.rule_id,
            version=row.version,
            definition=effective(row).model_dump(mode="json", by_alias=True),
            overrides=row.overrides,
            library_hash=row.library_hash,
            source=source,
            changed_by=actor.id if actor else None,
            change_reason=reason,
        )
    )


def _sync_techniques(db: Session, rule: Rule) -> None:
    db.execute(delete(DetectionRuleTechnique).where(DetectionRuleTechnique.rule_id == rule.id))
    mappings: dict[tuple[str, str], str] = {}
    for ref in rule.mitre:
        mappings[(ref.technique, "")] = ref.reason
    for indicator in rule.indicators or []:
        for ref in indicator.mitre:
            mappings[(ref.technique, indicator.id)] = ref.reason
    for (technique, indicator_id), reason in mappings.items():
        db.add(
            DetectionRuleTechnique(
                rule_id=rule.id, technique_id=technique, indicator=indicator_id, reason=reason
            )
        )


def seed(db: Session, library: Library) -> list[str]:
    """Brings the database in line with the shipped library. Returns what changed.

    New rules are added (version 1). A rule whose definition changed gets a new version; admin
    overrides that no longer fit are dropped and the drop is audited. Rules no longer shipped
    are kept, disabled and marked out of the library (their history stays).
    """
    changes: list[str] = []
    for technique in library.attack.techniques:
        db.merge(
            MitreTechnique(
                technique_id=technique.id,
                name=technique.name,
                tactics=technique.tactics,
                attack_version=library.attack.attack_version,
            )
        )
    db.flush()

    rows = {row.rule_id: row for row in db.scalars(select(DetectionRule))}
    for rule_id, rule in library.rules.items():
        definition = rule.model_dump(mode="json", by_alias=True)
        row = rows.get(rule_id)
        if row is None:
            row = DetectionRule(
                rule_id=rule_id,
                name=rule.name,
                category=rule.category,
                kind=rule.kind,
                library_definition=definition,
                library_hash=library.hashes[rule_id],
                overrides={},
                version=1,
                enabled=rule.enabled,
            )
            db.add(row)
            db.flush()
            _add_version(db, row, VersionSource.LIBRARY, reason="added from the rule library")
            _sync_techniques(db, rule)
            record(
                db,
                AuditAction.RULE_ADDED,
                entity_type=EntityType.DETECTION_RULE,
                entity_id=rule_id,
                details={"version": 1},
            )
            changes.append(f"{rule_id}: added")
            continue
        if row.library_hash == library.hashes[rule_id] and row.in_library:
            continue
        dropped = _check_overrides(rule, row.overrides)
        row.library_definition = definition
        row.library_hash = library.hashes[rule_id]
        row.overrides = {k: v for k, v in row.overrides.items() if k not in dropped}
        row.name, row.category, row.kind = rule.name, rule.category, rule.kind
        row.in_library = True
        row.version += 1
        row.enabled = effective(row).enabled
        _add_version(db, row, VersionSource.LIBRARY, reason="the rule library changed")
        _sync_techniques(db, rule)
        record(
            db,
            AuditAction.RULE_LIBRARY_UPDATED,
            entity_type=EntityType.DETECTION_RULE,
            entity_id=rule_id,
            details={"version": row.version, "dropped_overrides": dropped},
        )
        changes.append(f"{rule_id}: library update to version {row.version}")
    for rule_id, row in rows.items():
        if rule_id not in library.rules and row.in_library:
            row.in_library = False
            row.enabled = False
            record(
                db,
                AuditAction.RULE_RETIRED,
                entity_type=EntityType.DETECTION_RULE,
                entity_id=rule_id,
                details={"version": row.version},
            )
            changes.append(f"{rule_id}: retired (no longer in the library)")
    db.commit()
    return changes


def get_rule(db: Session, rule_id: str) -> DetectionRule:
    row = db.get(DetectionRule, rule_id)
    if row is None:
        raise AppError(404, "Detection rule not found")
    return row


def update_rule(db: Session, rule_id: str, changes: RuleChanges, actor: User) -> DetectionRule:
    row = get_rule(db, rule_id)
    if not row.in_library:
        raise AppError(409, "This rule was removed from the library and cannot be changed")
    current = effective(row)
    requested = changes.model_dump(exclude_unset=True, exclude={"reason"})
    if not requested:
        raise AppError(400, "Send at least one field to change")
    tunable = current.tunable
    allowed = {
        "threshold": tunable.threshold is not None,
        "time_window": tunable.time_window is not None,
        "severity": tunable.severity,
        "confidence": tunable.confidence,
        "enabled": tunable.enabled,
        "exclusions": tunable.exclusions,
    }
    for key in requested:
        if not allowed[key]:
            raise AppError(400, f"{key} is not tunable for {rule_id}")
    if changes.threshold is not None and tunable.threshold is not None:
        if not tunable.threshold.min <= changes.threshold <= tunable.threshold.max:
            raise AppError(
                400,
                f"threshold must be between {tunable.threshold.min} and {tunable.threshold.max}",
            )
    if changes.time_window is not None and tunable.time_window is not None:
        if not tunable.time_window.min <= changes.time_window <= tunable.time_window.max:
            raise AppError(400, "time_window is outside the bounds this rule allows")

    new_values = {key: _as_json(getattr(changes, key)) for key in requested}
    diff = {
        key: {"from": row.overrides.get(key, _as_json(getattr(current, key))), "to": value}
        for key, value in new_values.items()
        if value != row.overrides.get(key, _as_json(getattr(current, key)))
    }
    if not diff:
        return row
    row.overrides = {**row.overrides, **new_values}
    candidate = effective(row)  # re-validates the whole rule with the new values
    row.enabled = candidate.enabled
    row.version += 1
    _add_version(db, row, VersionSource.ADMIN, actor=actor, reason=changes.reason)
    record(
        db,
        AuditAction.RULE_UPDATED,
        actor=actor,
        entity_type=EntityType.DETECTION_RULE,
        entity_id=rule_id,
        details={"version": row.version, "reason": changes.reason, "changes": diff},
    )
    db.commit()
    return row


def enabled_rules(db: Session) -> list[tuple[Rule, int]]:
    rows = db.scalars(
        select(DetectionRule)
        .where(DetectionRule.enabled, DetectionRule.in_library)
        .order_by(DetectionRule.rule_id)
    )
    return [(effective(row), row.version) for row in rows]
