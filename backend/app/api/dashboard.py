"""The SOC dashboard: counts, distributions, top lists, trends and recent items, all computed
from the database on request (brief §19)."""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import DbSession
from app.api.incidents import incident_summary
from app.auth.deps import CurrentUser
from app.dashboard import queries
from app.schemas.alert import AlertSummary
from app.schemas.common import error_responses
from app.schemas.dashboard import DashboardSummary, Trends

dashboard = APIRouter(prefix="/dashboard", tags=["dashboard"], responses=error_responses(401, 403))


@dashboard.get("/summary", response_model=DashboardSummary)
def get_summary(_user: CurrentUser, db: DbSession) -> DashboardSummary:
    """Records processed, events (total and today), alerts (today, open by severity), incidents
    (open, under investigation), monitored hosts, active rules, the top rules and source
    addresses of the last 7 days, and the latest alerts and incidents. Times are UTC."""
    return DashboardSummary(
        **queries.summary(db, datetime.now(UTC)),
        recent_alerts=[AlertSummary.model_validate(a) for a in queries.recent_alerts(db)],
        recent_incidents=[incident_summary(db, i) for i in queries.recent_incidents(db)],
    )


@dashboard.get("/trends", response_model=Trends)
def get_trends(
    _user: CurrentUser, db: DbSession, days: Annotated[int, Query(ge=1, le=90)] = 14
) -> Trends:
    """Per UTC day, oldest first, with every day present: alerts created (by severity),
    incidents created, and events (by their own time)."""
    items = queries.trends(db, days, datetime.now(UTC))
    return Trends.model_validate({"days": days, "items": items})
