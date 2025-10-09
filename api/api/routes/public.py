"""
Public API routes - No authentication required (when enabled).
Returns minimal cluster information for anonymous users.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from src.api.dependencies.auth import get_optional_current_user, rbac_engine
from src.core.config import settings
from src.core.logging import get_logger
from src.core.rbac_engine import Action, Principal
from src.core.rbac_engine import Request as RBACRequest
from src.core.rbac_engine import Resource, ResourceType
from src.core.redis_client import get_redis_client
from src.models.auth import User

logger = get_logger(__name__)
redis_client = get_redis_client()
router = APIRouter()


def check_anonymous_access_enabled():
    """Verify that anonymous access is enabled."""
    if not settings.allow_anonymous_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Anonymous access is not enabled on this instance",
        )


def get_cluster_health_data(cluster_name: str) -> dict:
    """Get minimal cluster data for public view."""
    import json

    # Get basic cluster info
    spec_data = redis_client.get(f"cluster:{cluster_name}:spec")
    status_data = redis_client.get(f"cluster:{cluster_name}:status")

    if not spec_data:
        return None

    spec = json.loads(spec_data)
    status = (
        json.loads(status_data)
        if status_data
        else {"health": "unknown", "message": "Status unavailable", "last_check": None}
    )

    return {
        "name": cluster_name,
        "displayName": spec.get("displayName", spec.get("display_name", cluster_name)),
        "status": {
            "health": status.get("health", "unknown"),
            "message": status.get("message", ""),
            "last_check": status.get("last_check"),
        },
        "anonymous_view": True,
    }


@router.get(
    "/clusters/health",
    summary="Public Cluster Health",
    description="Get basic cluster health status (no authentication required)",
)
async def get_public_cluster_health(
    user: User | None = Depends(get_optional_current_user),
) -> List[dict]:
    """
    Get basic health information for all clusters.

    **No authentication required** when anonymous access is enabled.

    Returns:
    - Cluster name and display name
    - Health status (healthy/degraded/unhealthy/unknown)
    - Last check timestamp

    Does NOT return:
    - Metrics, resource counts, or detailed information
    - Node information
    - Operator information
    - Any sensitive data
    """
    check_anonymous_access_enabled()

    # Get all cluster names
    cluster_names = redis_client.smembers("clusters:all")

    if not cluster_names:
        return []

    # If user is authenticated, check their permissions
    # If not authenticated, use anonymous principal
    if user:
        principal = Principal(
            username=user.username,
            email=user.email,
            groups=user.groups if user.groups else [],
        )
        logger.info(f"Authenticated user {user.username} accessing public endpoint")
    else:
        principal = rbac_engine.create_anonymous_principal()
        logger.info("Anonymous user accessing public endpoint")

    # Collect accessible clusters
    accessible_clusters = []

    for cluster_name in cluster_names:
        # Create resource
        resource = Resource(
            type=ResourceType.CLUSTER, name=cluster_name, cluster=cluster_name
        )

        # Check authorization
        if user:
            # Authenticated user - use normal RBAC
            rbac_request = RBACRequest(
                principal=principal, action=Action.VIEW, resource=resource
            )
            decision = rbac_engine.authorize(rbac_request)
        else:
            # Anonymous user - use anonymous authorization
            decision = rbac_engine.authorize_anonymous(Action.VIEW, resource)

        if decision.allowed:
            cluster_data = get_cluster_health_data(cluster_name)
            if cluster_data:
                accessible_clusters.append(cluster_data)

    logger.info(
        f"{'Anonymous' if not user else user.username} accessed "
        f"{len(accessible_clusters)} clusters via public endpoint"
    )

    return accessible_clusters


@router.get(
    "/health",
    summary="Public API Health",
    description="Check if public API is available",
)
async def public_health_check():
    """
    Health check for public API.
    Returns whether anonymous access is enabled.
    """
    return {
        "status": "healthy",
        "anonymous_access_enabled": settings.allow_anonymous_access,
        "public_api_version": "v1",
    }
