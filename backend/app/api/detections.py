"""Detection rules (read, tune), detection runs (history, manual runs) and ATT&CK reference."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Path, Query, status
from sqlalchemy import select

from app.api.deps import DbSession
from app.auth.deps import AdminUser, CurrentUser
from app.detection import service
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
    RuleDetail,
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
def list_versions(rule_id: RuleId, _user: CurrentUser, db: DbSession) -> list[RuleVersionPublic]:
    get_rule(db, rule_id)
    rows = db.scalars(
        select(DetectionRuleVersion)
        .where(DetectionRuleVersion.rule_id == rule_id)
        .order_by(DetectionRuleVersion.version.desc())
    )
    return [RuleVersionPublic.model_validate(r) for r in rows]


@detections.patch("/{rule_id}", response_model=RuleDetail, responses=error_responses(400, 404, 409))
def tune_rule(rule_id: RuleId, payload: RuleChanges, admin: AdminUser, db: DbSession) -> RuleDetail:
    """Change tunable values only (threshold, time window, severity, confidence, enabled,
    exclusions), within the rule's bounds, with a reason. Creates a version; audited."""
    return _detail(db, update_rule(db, rule_id, payload, admin))


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
