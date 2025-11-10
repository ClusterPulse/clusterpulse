"""
Public API routes
Returns minimal cluster information for anonymous users.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status

from clusterpulse.api.dependencies.auth import get_optional_current_user
from clusterpulse.api.dependencies.rbac import get_rbac_context, user_to_principal
from clusterpulse.config.settings import settings
from clusterpulse.core.logging import get_logger
from clusterpulse.db.redis import get_redis_client
from clusterpulse.models.auth import User
from clusterpulse.repositories.redis_base import ClusterDataRepository
from clusterpulse.services.rbac import Action, Resource, ResourceType

# Import RBAC engine
from clusterpulse.api.dependencies.rbac import get_rbac_engine

logger = get_logger(__name__)
redis_client = get_redis_client()
repo = ClusterDataRepository(redis_client)
rbac_engine = get_rbac_engine()

router = APIRouter()


def check_anonymous_access_enabled():
    """Verify that anonymous access is enabled."""
    if not settings.allow_anonymous_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Anonymous access is not enabled on this instance",
        )


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

    # Determine principal
    if user:
        principal = user_to_principal(user)
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
            from clusterpulse.services.rbac import Request as RBACRequest

            rbac_request = RBACRequest(
                principal=principal, action=Action.VIEW, resource=resource
            )
            decision = rbac_engine.authorize(rbac_request)
        else:
            # Anonymous user - use anonymous authorization
            decision = rbac_engine.authorize_anonymous(Action.VIEW, resource)

        if decision.allowed:
            # Get minimal cluster data
            bundle = repo.get_cluster_bundle(cluster_name)
            spec = bundle.get("spec")
            status_data = bundle.get("status")

            # Build minimal response
            display_name = cluster_name
            if spec:
                display_name = (
                    spec.get("displayName")
                    or spec.get("display_name")
                    or cluster_name
                )

            cluster_health = {
                "name": cluster_name,
                "displayName": display_name,
                "status": status_data
                or {
                    "health": "unknown",
                    "message": "Status unavailable",
                    "last_check": None,
                },
                "anonymous_view": not user,
            }

            accessible_clusters.append(cluster_health)

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
