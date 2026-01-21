"""API v1 router assembly."""

from fastapi import APIRouter

from clusterpulse.api.v1.endpoints import (
    auth,
    clusters,
    custom_resources,
    health,
    public,
    registries,
)
from clusterpulse.config import settings

api_router = APIRouter()

# Health checks (no prefix)
api_router.include_router(health.router, tags=["health"])

# Auth endpoints
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])

# Cluster endpoints
api_router.include_router(clusters.router, prefix="/clusters", tags=["clusters"])

# Registry endpoints
api_router.include_router(registries.router, tags=["registries"])

# Custom resource endpoints (MetricSources and custom types)
api_router.include_router(
    custom_resources.router,
    tags=["custom-resources"],
)

# Public endpoints (if enabled)
if settings.allow_anonymous_access:
    public_router = APIRouter()
    public_router.include_router(public.router, tags=["public"])
    # Note: Public router is included separately in main.py with different prefix
