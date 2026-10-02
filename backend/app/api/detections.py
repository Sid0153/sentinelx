"""Detection rules (read, tune), detection runs (history, manual runs) and ATT&CK reference."""

import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Path, Query, status
from sqlalchemy import select

from app.api.deps import DbSession, SettingsDep
from app.auth.deps import AdminUser, AnalystUser, CurrentUser
from app.detection import insights, playground, service
from app.detection.library import get_library
from app.detection.model import format_duration
from app.detection.storage import RuleChanges, effective, get_rule, update_rule
from app.models.detection import (
    DetectionRule,
    DetectionRuleTechnique,
    DetectionRuleVersion,
    MitreTechnique,
    RunTrigger,
)
from app.schemas.common import Page, error_responses
from app.schemas.detection import (
    Coverage,
    CoverageRule,
    CoverageSummary,
    CoverageTactic,
    CoverageTechnique,
    DetectionMetrics,
    PlaygroundDetection,
    PlaygroundLine,
    PlaygroundResult,
    PlaygroundRule,
    PlaygroundSummary,
    RuleDetail,
    RuleMetricsPublic,
    RuleSummary,
    RuleVersionPublic,
    RunDetail,
    RunRequest,
    RunSummary,
    TechniquePublic,
    TechniqueRef,
)

detections = APIRouter(
    prefix="/detections", tags=["detections"], responses=error_responses(401, 403)
)
mitre = APIRouter(prefix="/mitre", tags=["mitre"], responses=error_responses(401, 403))

RuleId = Annotated[str, Path(pattern=r"^[A-Z]{3,5}-\d{3}$")]
Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0)]


def _technique_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def _summary(row: DetectionRule) -> RuleSummary:
    rule = effective(row)
    return RuleSummary(
        rule_id=row.rule_id,
        name=row.name,
        category=row.category,
        kind=row.kind,
        severity=str(rule.severity),
        confidence=str(rule.confidence),
        enabled=row.enabled,
        in_library=row.in_library,
        version=row.version,
        techniques=sorted(rule.techniques()),
        match_count=row.match_count,
        error_count=row.error_count,
        last_run_at=row.last_run_at,
        last_match_at=row.last_match_at,
    )


def _detail(db: DbSession, row: DetectionRule) -> RuleDetail:
    rule = effective(row)
    mappings = db.execute(
        select(DetectionRuleTechnique, MitreTechnique)
        .join(MitreTechnique, MitreTechnique.technique_id == DetectionRuleTechnique.technique_id)
        .where(DetectionRuleTechnique.rule_id == row.rule_id)
        .order_by(DetectionRuleTechnique.technique_id)
    ).all()
    return RuleDetail(
        **_summary(row).model_dump(),
        description=rule.description,
        definition=rule.model_dump(mode="json", by_alias=True),
        overrides=row.overrides,
        tunable=rule.tunable.model_dump(mode="json"),
        mitre=[
            TechniqueRef(
                technique_id=technique.technique_id,
                name=technique.name,
                tactics=technique.tactics,
                url=_technique_url(technique.technique_id),
                reason=mapping.reason,
                indicator=mapping.indicator or None,
            )
            for mapping, technique in mappings
        ],
    )


# /runs is declared before /{rule_id} so that "runs" is never read as a rule ID.


@detections.get("/runs", response_model=Page[RunSummary])
def list_runs(
    _user: CurrentUser,
    db: DbSession,
    trigger: RunTrigger | None = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[RunSummary]:
    rows, total = service.list_runs(db, trigger, limit, offset)
    return Page(
        items=[RunSummary.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
    )


@detections.get("/runs/{run_id}", response_model=RunDetail, responses=error_responses(404))
def get_run(run_id: uuid.UUID, _user: CurrentUser, db: DbSession) -> RunDetail:
    """One run: per-rule outcome and every detection with its explanation and evidence."""
    return RunDetail.model_validate(service.get_run(db, run_id))


@detections.post(
    "/run",
    response_model=RunDetail,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(400),
)
def run_detection(payload: RunRequest, admin: AdminUser, db: DbSession) -> RunDetail:
    """Run every enabled rule over `from`–`to` (at most 31 days). Audited."""
    return RunDetail.model_validate(service.run_manual(db, payload.start, payload.end, admin))


Days = Annotated[int, Query(ge=1, le=365)]


def _period(days: int) -> tuple[datetime, datetime]:
    end = datetime.now(UTC)
    return end - timedelta(days=days), end


@detections.get("/metrics", response_model=DetectionMetrics, responses=error_responses(422))
def detection_metrics(_user: CurrentUser, db: DbSession, days: Days = 30) -> DetectionMetrics:
    """Per rule, for the alerts it created in the last `days` (1–365, default 30): how many,
    how analysts closed them (confirmed, benign, false positive), the false-positive rate,
    and the median time to triage and to close. Counted from the alerts, never estimated."""
    start, end = _period(days)
    measured = insights.rule_metrics(db, start, end)
    items = []
    for row in db.scalars(select(DetectionRule).order_by(DetectionRule.rule_id)):
        m = measured.get(row.rule_id, insights.RuleMetrics(row.rule_id))
        items.append(
            RuleMetricsPublic(
                rule_id=row.rule_id,
                name=row.name,
                category=row.category,
                severity=str(effective(row).severity),
                enabled=row.enabled,
                in_library=row.in_library,
                alerts=m.alerts,
                open=m.open,
                confirmed=m.confirmed,
                benign=m.benign,
                false_positives=m.false_positives,
                closed=m.closed,
                false_positive_rate=m.false_positive_rate,
                median_triage_seconds=m.median_triage_seconds,
                median_resolve_seconds=m.median_resolve_seconds,
                match_count=row.match_count,
                last_match_at=row.last_match_at,
            )
        )
    return DetectionMetrics(days=days, start=start, end=end, items=items)


@detections.get("", response_model=list[RuleSummary])
def list_rules(_user: CurrentUser, db: DbSession) -> list[RuleSummary]:
    rows = db.scalars(select(DetectionRule).order_by(DetectionRule.rule_id))
    return [_summary(row) for row in rows]


@detections.get("/{rule_id}", response_model=RuleDetail, responses=error_responses(404))
def get_detection_rule(rule_id: RuleId, _user: CurrentUser, db: DbSession) -> RuleDetail:
    """The effective definition, what admins changed, what may be changed, and ATT&CK."""
    return _detail(db, get_rule(db, rule_id))


@detections.get(
    "/{rule_id}/versions",
    response_model=list[RuleVersionPublic],
    responses=error_responses(404),
)
def list_versions(
    rule_id: RuleId, _user: CurrentUser, db: DbSession, limit: Limit = 100
) -> list[RuleVersionPublic]:
    """Newest first, at most `limit` (every tuning adds a version with its full definition)."""
    get_rule(db, rule_id)
    rows = db.scalars(
        select(DetectionRuleVersion)
        .where(DetectionRuleVersion.rule_id == rule_id)
        .order_by(DetectionRuleVersion.version.desc())
        .limit(limit)
    )
    return [RuleVersionPublic.model_validate(r) for r in rows]


def _playground_line(line: playground.LineResult, evidence: bool) -> PlaygroundLine:
    event = line.event
    return PlaygroundLine(
        line=line.line,
        status=line.status,
        code=line.code,
        timestamp=event.timestamp if event else None,
        event=(
            f"{event.event_category}/{event.event_action} {event.event_outcome}" if event else None
        ),
        host=event.host if event else None,
        username=event.username if event else None,
        target_username=event.target_username if event else None,
        source_ip=event.source_ip if event else None,
        process_name=event.process_name if event else None,
        excluded=line.excluded,
        matched=line.matched,
        steps=line.steps,
        evidence=evidence,
    )


@detections.post(
    "/{rule_id}/test",
    response_model=PlaygroundResult,
    responses=error_responses(400, 404, 409, 422),
)
def test_rule(
    rule_id: RuleId,
    payload: playground.PlaygroundRequest,
    _user: AnalystUser,
    db: DbSession,
    settings: SettingsDep,
) -> PlaygroundResult:
    """Detection testing playground: runs the rule on sample log lines (at most 500, 256 KiB)
    through the real parser, enrichment and evaluator, optionally with what-if tuning values
    (`changes`, checked against the rule's bounds). Stores nothing: no events, alerts or runs.
    The rule sees only the sample (a new-value rule builds its history from earlier lines)."""
    result = playground.run(db, rule_id, payload, settings)
    evidence: dict[int, list[int]] = {}
    for number, detection in enumerate(result.detections):
        evidence[number] = sorted(int(e.split("-", 1)[1]) for e in detection.evidence_event_ids)
    cited = {line for lines in evidence.values() for line in lines}
    rule = result.rule
    lines = [_playground_line(line, line.line in cited) for line in result.lines]
    parsed = [line for line in result.lines if line.event is not None]
    return PlaygroundResult(
        triggered=bool(result.detections),
        rule=PlaygroundRule(
            rule_id=rule.id,
            name=rule.name,
            kind=rule.kind,
            version=result.version,
            severity=str(rule.severity),
            confidence=str(rule.confidence),
            threshold=rule.threshold,
            time_window=format_duration(rule.time_window) if rule.time_window else None,
            tried=result.tried,
        ),
        summary=PlaygroundSummary(
            lines=len(result.lines),
            parsed=len(parsed),
            skipped=sum(line.status == "skipped" for line in result.lines),
            failed=sum(line.status == "failed" for line in result.lines),
            excluded=sum(line.excluded for line in parsed),
            matched=sum(bool(line.matched) or bool(line.steps) for line in parsed),
            detections=len(result.detections),
        ),
        detections=[
            PlaygroundDetection(
                explanation=d.explanation,
                severity=str(d.severity),
                confidence=str(d.confidence),
                indicator=d.indicator,
                event_count=d.event_count,
                first_seen=d.first_seen,
                last_seen=d.last_seen,
                evidence_lines=evidence[number],
                group=d.group,
                mitre=[m.technique for m in d.mitre],
                investigation=d.investigation,
                response=d.response,
            )
            for number, d in enumerate(result.detections)
        ],
        lines=lines,
    )


@detections.patch("/{rule_id}", response_model=RuleDetail, responses=error_responses(400, 404, 409))
def tune_rule(rule_id: RuleId, payload: RuleChanges, admin: AdminUser, db: DbSession) -> RuleDetail:
    """Change tunable values only (threshold, time window, severity, confidence, enabled,
    exclusions), within the rule's bounds, with a reason. Creates a version; audited."""
    return _detail(db, update_rule(db, rule_id, payload, admin))


@mitre.get("/coverage", response_model=Coverage, responses=error_responses(422))
def implemented_coverage(_user: CurrentUser, db: DbSession, days: Days = 30) -> Coverage:
    """Implemented coverage: the ATT&CK techniques SentinelX's own rules map to, under every
    Enterprise tactic (covered or not), with each rule's state, severity, alerts in the last
    `days` and last trigger. Not a claim of complete ATT&CK coverage."""
    attack = get_library().attack
    start, end = _period(days)
    found = insights.coverage(db, attack, start, end)
    techniques = [
        CoverageTechnique(
            technique_id=t.technique_id,
            name=t.name,
            url=_technique_url(t.technique_id),
            tactics=t.tactics,
            active=t.active,
            alerts=sum(r.alerts for r in t.rules),
            last_triggered_at=max(
                (r.last_triggered_at for r in t.rules if r.last_triggered_at), default=None
            ),
            rules=[CoverageRule(**vars(r)) for r in t.rules],
        )
        for t in found
    ]
    tactics = []
    for tactic in attack.tactics:
        under = [t for t in techniques if tactic.name in t.tactics]
        tactics.append(
            CoverageTactic(
                id=tactic.id,
                name=tactic.name,
                url=tactic.url,
                techniques=[t.technique_id for t in under],
                active=any(t.active for t in under),
            )
        )
    rules = list(db.scalars(select(DetectionRule).where(DetectionRule.in_library.is_(True))))
    enabled = [r for r in rules if r.enabled]
    return Coverage(
        label="Implemented coverage",
        attack_version=attack.attack_version,
        checked_on=attack.checked_on,
        days=days,
        start=start,
        end=end,
        summary=CoverageSummary(
            tactics_total=len(attack.tactics),
            tactics_covered=sum(1 for t in tactics if t.active),
            techniques_covered=sum(1 for t in techniques if t.active),
            rules_in_library=len(rules),
            rules_enabled=len(enabled),
            categories=dict(sorted(Counter(r.category for r in enabled).items())),
        ),
        tactics=tactics,
        techniques=techniques,
    )


@mitre.get("/techniques", response_model=list[TechniquePublic])
def list_techniques(_user: CurrentUser, db: DbSession) -> list[TechniquePublic]:
    """The ATT&CK techniques SentinelX's rules map to (implemented coverage only)."""
    mapped: dict[str, set[str]] = {}
    for rule_id, technique_id in db.execute(
        select(DetectionRuleTechnique.rule_id, DetectionRuleTechnique.technique_id)
    ):
        mapped.setdefault(technique_id, set()).add(rule_id)
    return [
        TechniquePublic(
            technique_id=t.technique_id,
            name=t.name,
            tactics=t.tactics,
            attack_version=t.attack_version,
            url=_technique_url(t.technique_id),
            rules=sorted(mapped.get(t.technique_id, set())),
        )
        for t in db.scalars(select(MitreTechnique).order_by(MitreTechnique.technique_id))
    ]
