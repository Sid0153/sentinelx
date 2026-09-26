from fastapi import APIRouter

from app.api import audit, auth, context, health, ingestion, users

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
