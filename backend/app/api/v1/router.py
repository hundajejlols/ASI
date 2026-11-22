from fastapi import APIRouter

from app.api.v1 import (
    ai_agent,
    auth,
    changes,
    dashboard,
    groups,
    health,
    hosts,
    integrations,
    overrides,
    scans,
    schedules,
    signatures,
    targets,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(targets.router)
api_router.include_router(groups.router)
api_router.include_router(scans.router)
api_router.include_router(schedules.router)
api_router.include_router(hosts.router)
api_router.include_router(changes.router)
api_router.include_router(overrides.router)
api_router.include_router(signatures.router)
api_router.include_router(ai_agent.router)
api_router.include_router(integrations.router)
