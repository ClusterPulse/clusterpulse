"""Health check endpoints for Kubernetes probes."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Response, status
from pydantic import BaseModel, Field

from clusterpulse.config.settings import settings
from clusterpulse.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter()

# Track application start time
APP_START_TIME = datetime.now(timezone.utc)


class HealthStatus(BaseModel):
    """Health check response model."""

    status: str = Field(..., description="Overall health status")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    uptime_seconds: float = Field(..., description="Application uptime in seconds")
    version: str = Field(..., description="Application version")
    environment: str = Field(..., description="Application environment")
    checks: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict, description="Individual component health checks"
    )


class ReadinessStatus(BaseModel):
    """Readiness check response model."""

    ready: bool = Field(..., description="Whether the application is ready")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    checks: Dict[str, bool] = Field(
        default_factory=dict, description="Individual readiness checks"
    )
    message: Optional[str] = Field(None, description="Additional status message")


def check_component_health(component: str) -> Dict[str, Any]:
    """Check health of a specific component."""
    try:
        if component == "logging":
            # Check if logging is working
            logger.debug("Health check test log")
            return {"status": "healthy", "message": "Logging operational"}

        elif component == "config":
            # Check if configuration is loaded
            if settings.secret_key and settings.secret_key != "changeme":
                return {"status": "healthy", "message": "Configuration loaded"}
            else:
                return {"status": "unhealthy", "message": "Invalid configuration"}

        elif component == "auth":
            # Check if auth is configured
            if settings.oauth_proxy_enabled or settings.environment == "development":
                return {"status": "healthy", "message": "Authentication configured"}
            else:
                return {
                    "status": "degraded",
                    "message": "Authentication not fully configured",
                }

        # Add more component checks as needed (database, cache, external services)

        return {"status": "unknown", "message": f"No health check for {component}"}

    except Exception as e:
        logger.error(f"Health check failed for {component}: {str(e)}")
        return {"status": "unhealthy", "message": str(e)}


@router.get(
    settings.health_check_path,
    response_model=HealthStatus,
    responses={
        200: {"description": "Application is healthy"},
        503: {"description": "Application is unhealthy"},
    },
    summary="Health Check",
    description="Kubernetes liveness probe endpoint",
)
async def health_check(response: Response) -> HealthStatus:
    """
    Health check endpoint for Kubernetes liveness probe.

    Returns overall application health status and individual component checks.
    """
    # Calculate uptime
    uptime = (datetime.now(timezone.utc) - APP_START_TIME).total_seconds()

    # Check various components
    checks = {
        "logging": check_component_health("logging"),
        "config": check_component_health("config"),
        "auth": check_component_health("auth"),
    }

    # Determine overall status
    unhealthy_count = sum(
        1 for check in checks.values() if check["status"] == "unhealthy"
    )
    degraded_count = sum(
        1 for check in checks.values() if check["status"] == "degraded"
    )

    if unhealthy_count > 0:
        overall_status = "unhealthy"
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    elif degraded_count > 0:
        overall_status = "degraded"
    else:
        overall_status = "healthy"

    health_status = HealthStatus(
        status=overall_status,
        uptime_seconds=uptime,
        version=settings.app_version,
        environment=settings.environment,
        checks=checks,
    )

    # Log health check result (only if unhealthy)
    if overall_status != "healthy":
        logger.warning(
            "Health check failed", extra={"status": overall_status, "checks": checks}
        )

    return health_status


@router.get(
    settings.readiness_check_path,
    response_model=ReadinessStatus,
    responses={
        200: {"description": "Application is ready"},
        503: {"description": "Application is not ready"},
    },
    summary="Readiness Check",
    description="Kubernetes readiness probe endpoint",
)
async def readiness_check(response: Response) -> ReadinessStatus:
    """
    Readiness check endpoint for Kubernetes readiness probe.

    Checks if the application is ready to receive traffic.
    """
    checks = {}

    # Check if authentication is ready
    if settings.oauth_proxy_enabled:
        checks["auth"] = True  # OAuth proxy handles auth
    else:
        checks["auth"] = settings.environment == "development"  # Dev mode

    # Determine if ready
    is_ready = all(checks.values())

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        message = "Application not ready"
        logger.warning("Readiness check failed", extra={"checks": checks})
    else:
        message = "Application ready to receive traffic"

    return ReadinessStatus(ready=is_ready, checks=checks, message=message)
