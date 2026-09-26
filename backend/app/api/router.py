from fastapi import APIRouter

from app.api import (
    alerts,
    audit,
    auth,
    context,
    detections,
    health,
    incidents,
    ingestion,
    users,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(audit.router)
api_router.include_router(context.assets)
api_router.include_router(context.identities)
api_router.include_router(ingestion.sources)
api_router.include_router(ingestion.ingestion)
api_router.include_router(ingestion.events)
api_router.include_router(detections.detections)
api_router.include_router(detections.mitre)
api_router.include_router(alerts.alerts)
api_router.include_router(incidents.escalation)
api_router.include_router(incidents.incidents)
api_router.include_router(incidents.settings)
