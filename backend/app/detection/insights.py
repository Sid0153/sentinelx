"""Detection metrics and implemented ATT&CK coverage (brief §43, §45; docs/detection-engine.md).

Everything is counted from the alerts analysts worked on, never estimated:
- triggers: alerts a rule created in the period;
- outcomes of those alerts: still open, confirmed malicious, resolved as benign/expected,
  false positive; the false-positive rate is false positives / closed alerts;
- how long analysts took: median time from creation to first triage and to closing.

Coverage lists only what SentinelX's own rules map to. Every ATT&CK tactic is shown, covered
or not, so the gaps are as visible as the coverage: this is "implemented coverage", never a
claim of complete ATT&CK coverage.
"""

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import Float, and_, case, cast, extract, func, or_, select
from sqlalchemy.orm import Session

from app.detection.library import AttackReference
from app.models.alert import ACTIVE_STATUSES, Alert, AlertStatus, Disposition
from app.models.detection import DetectionRule, DetectionRuleTechnique, MitreTechnique


@dataclass(frozen=True)
class RuleMetrics:
    rule_id: str
    alerts: int = 0
    open: int = 0
    confirmed: int = 0  # resolved: confirmed malicious
    benign: int = 0  # resolved: benign or expected activity
    false_positives: int = 0
    median_triage_seconds: float | None = None
    median_resolve_seconds: float | None = None

    @property
    def closed(self) -> int:
        return self.confirmed + self.benign + self.false_positives

    @property
    def false_positive_rate(self) -> float | None:
        """False positives among closed alerts; None until an alert of the rule is closed."""
        return round(self.false_positives / self.closed, 3) if self.closed else None


def _seconds(later: object, earlier: object) -> object:
    return extract("epoch", later - earlier)  # type: ignore[operator]


def rule_metrics(db: Session, start: datetime, end: datetime) -> dict[str, RuleMetrics]:
    """Per rule, for the alerts created in [start, end]."""
    status, disposition = Alert.status, Alert.disposition
    resolved = status == AlertStatus.RESOLVED
    rows = db.execute(
        select(
            Alert.rule_id,
            func.count(),
            func.count().filter(status.in_(ACTIVE_STATUSES)),
            func.count().filter(resolved, disposition == Disposition.CONFIRMED_MALICIOUS),
            func.count().filter(resolved, disposition == Disposition.BENIGN_EXPECTED),
            func.count().filter(status == AlertStatus.FALSE_POSITIVE),
            func.percentile_cont(0.5).within_group(
                cast(_seconds(Alert.triaged_at, Alert.created_at), Float)
            ),
            func.percentile_cont(0.5).within_group(
                cast(
                    case(
                        (
                            status.notin_(ACTIVE_STATUSES),
                            _seconds(Alert.resolved_at, Alert.created_at),
                        )
                    ),
                    Float,
                )
            ),
        )
        .where(Alert.created_at >= start, Alert.created_at <= end)
        .group_by(Alert.rule_id)
    ).all()
    return {
        row[0]: RuleMetrics(
            rule_id=row[0],
            alerts=row[1],
            open=row[2],
            confirmed=row[3],
            benign=row[4],
            false_positives=row[5],
            median_triage_seconds=row[6],
            median_resolve_seconds=row[7],
        )
        for row in rows
    }


# ---------- coverage ----------


@dataclass(frozen=True)
class CoveredRule:
    rule_id: str
    name: str
    category: str
    severity: str
    enabled: bool
    indicator: str | None  # the rule's indicator mapped to the technique (None: whole rule)
    reason: str
    alerts: int  # alerts in the period attributed to this technique through this rule
    last_triggered_at: datetime | None  # any time


@dataclass
class CoveredTechnique:
    technique_id: str
    name: str
    tactics: list[str]
    rules: list[CoveredRule] = field(default_factory=list)

    @property
    def active(self) -> bool:
        """Covered by at least one enabled rule."""
        return any(r.enabled for r in self.rules)


def coverage(
    db: Session, attack: AttackReference, start: datetime, end: datetime
) -> list[CoveredTechnique]:
    """The techniques SentinelX rules in the library map to, each with its rules and how
    often they fired for it. Alerts count for a technique when their rule maps to it as a
    whole, or when the alert's indicator is the one mapped (PROC-001, PRIV-001)."""
    maps_alert = and_(
        Alert.rule_id == DetectionRuleTechnique.rule_id,
        or_(
            DetectionRuleTechnique.indicator == "",
            Alert.indicator == DetectionRuleTechnique.indicator,
        ),
    )
    in_period = and_(Alert.created_at >= start, Alert.created_at <= end)
    rows = db.execute(
        select(
            DetectionRuleTechnique.technique_id,
            DetectionRuleTechnique.indicator,
            DetectionRuleTechnique.reason,
            MitreTechnique.name,
            MitreTechnique.tactics,
            DetectionRule.rule_id,
            DetectionRule.name,
            DetectionRule.category,
            DetectionRule.library_definition["severity"].astext,
            DetectionRule.overrides["severity"].astext,
            DetectionRule.enabled,
            func.count(Alert.id).filter(in_period),
            func.max(Alert.created_at),
        )
        .join(DetectionRule, DetectionRule.rule_id == DetectionRuleTechnique.rule_id)
        .join(MitreTechnique, MitreTechnique.technique_id == DetectionRuleTechnique.technique_id)
        .outerjoin(Alert, maps_alert)
        .where(DetectionRule.in_library.is_(True))
        .group_by(
            DetectionRuleTechnique.technique_id,
            DetectionRuleTechnique.indicator,
            DetectionRuleTechnique.reason,
            MitreTechnique.name,
            MitreTechnique.tactics,
            DetectionRule.rule_id,
        )
        .order_by(DetectionRuleTechnique.technique_id, DetectionRule.rule_id)
    ).all()
    found: dict[str, CoveredTechnique] = {}
    order = {t.name: i for i, t in enumerate(attack.tactics)}
    for row in rows:
        technique = found.setdefault(
            row[0],
            CoveredTechnique(row[0], row[3], sorted(row[4], key=lambda t: order.get(t, 99))),
        )
        technique.rules.append(
            CoveredRule(
                rule_id=row[5],
                name=row[6],
                category=row[7],
                severity=row[9] or row[8],  # an admin override wins
                enabled=row[10],
                indicator=row[1] or None,
                reason=row[2],
                alerts=row[11],
                last_triggered_at=row[12],
            )
        )
    return list(found.values())
