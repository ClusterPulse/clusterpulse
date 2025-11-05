"""OpenShift Cluster Monitor API."""

from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from clusterpulse.api.middleware.auth import AuthMiddleware
from clusterpulse.api.middleware.logging import LoggingMiddleware
from clusterpulse.api.routes import auth, clusters, health, public, registries
from clusterpulse.core.config import settings
from clusterpulse.core.logging import get_logger, setup_logging
from clusterpulse.core.redis_client import close_redis_connection, get_redis_client

setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle."""
    logger.info(
        f"Starting {settings.app_name} v{settings.app_version}",
        extra={
            "environment": settings.environment,
            "rbac_enabled": settings.rbac_enabled,
        },
    )

    # Validate Redis connection
    try:
        redis = get_redis_client()

        cluster_count = redis.scard("clusters:all")
        policy_count = redis.scard("policies:all")
        registry_count = redis.scard("registries:all")

        logger.info(
            f"Initialized: {cluster_count} clusters, "
            f"{policy_count} policies, {registry_count} registries"
        )
    except Exception as e:
        logger.error(f"Redis initialization failed: {e}")
        if settings.environment == "production":
            raise

    yield

    logger.info("Shutting down")
    close_redis_connection()


app = FastAPI(
    title=f"{settings.app_name} API",
    version=settings.app_version,
    description="Multi-cluster OpenShift monitoring with RBAC",
    docs_url=f"{settings.api_prefix}/docs",
    redoc_url=f"{settings.api_prefix}/redoc",
    openapi_url=f"{settings.api_prefix}/openapi.json",
    lifespan=lifespan,
)

# Configure middleware
app.add_middleware(LoggingMiddleware)
app.add_middleware(AuthMiddleware)

if settings.allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

if settings.environment == "production":
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)

# Register routes
app.include_router(health.router, tags=["health"])
app.include_router(auth.router, prefix=f"{settings.api_prefix}/auth", tags=["auth"])
app.include_router(
    clusters.router, prefix=f"{settings.api_prefix}/clusters", tags=["clusters"]
)
app.include_router(
    registries.router, prefix=f"{settings.api_prefix}", tags=["registries"]
)

# Register public routes (if anonymous access enabled)
if settings.allow_anonymous_access:
    app.include_router(
        public.router, prefix=settings.public_api_prefix, tags=["public"]
    )
    logger.info("Public API endpoints enabled")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        log_level=settings.log_level.value.lower(),
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
