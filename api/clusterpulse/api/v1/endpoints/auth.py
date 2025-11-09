"""
Authentication routes
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Response, status
from fastapi.responses import RedirectResponse

from clusterpulse.api.dependencies.auth import (get_current_user,
                                                get_optional_current_user,
                                                get_user_with_groups)
from clusterpulse.api.dependencies.rbac import (RBACContext, get_rbac_context,
                                                get_rbac_engine)
from clusterpulse.config.settings import settings
from clusterpulse.core.logging import get_logger
from clusterpulse.db.redis import get_redis_client
from clusterpulse.models.auth import AuthStatus, User
from clusterpulse.services.rbac import Resource, ResourceType

logger = get_logger(__name__)
redis_client = get_redis_client()
router = APIRouter()


@router.get(
    "/status",
    response_model=AuthStatus,
    summary="Authentication Status",
    description="Check current authentication status",
)
async def auth_status(
    user: Optional[User] = Depends(get_optional_current_user),
) -> AuthStatus:
    """Get current authentication status."""
    if user:
        # Ensure groups are populated
        if not user.groups:
            user = await get_user_with_groups(user)

        return AuthStatus(
            authenticated=True, user=user, message="User is authenticated"
        )
    else:
        return AuthStatus(
            authenticated=False, user=None, message="User is not authenticated"
        )


@router.get(
    "/me",
    response_model=User,
    summary="Current User",
    description="Get current authenticated user information",
)
async def get_me(user: User = Depends(get_user_with_groups)) -> User:
    """Get current user information with groups."""
    logger.info(
        "User information requested",
        extra={"user_id": user.id, "groups_count": len(user.groups)},
    )
    return user


@router.get(
    "/permissions",
    summary="User Permissions Summary",
    description="Get current user's effective permissions",
)
async def get_user_permissions(
    rbac: RBACContext = Depends(get_rbac_context),
) -> Dict[str, Any]:
    """Get current user's permissions using the RBAC engine."""

    # Get accessible clusters
    accessible_clusters = rbac.get_accessible_clusters()

    # Build detailed permissions for each cluster
    cluster_permissions = {}

    for cluster_name in accessible_clusters:
        # Create resource for this cluster
        resource = Resource(
            type=ResourceType.CLUSTER, name=cluster_name, cluster=cluster_name
        )

        # Get all permissions for this cluster using RBAC engine
        permissions = get_rbac_engine().get_permissions(rbac.principal, resource)

        cluster_permissions[cluster_name] = {
            "permissions": [action.value for action in permissions],
            "access_level": "full" if len(permissions) > 5 else "limited",
        }

    response = {
        "user": {
            "username": rbac.user.username,
            "email": rbac.user.email,
            "groups": rbac.user.groups,
        },
        "summary": {
            "total_clusters": len(accessible_clusters),
            "accessible_clusters": len(accessible_clusters),
        },
        "clusters": cluster_permissions,
        "accessible_cluster_names": sorted(accessible_clusters),
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }

    logger.info(
        "User permissions retrieved",
        extra={
            "user_id": rbac.user.id,
            "accessible_clusters": len(accessible_clusters),
        },
    )

    return response


@router.get(
    "/policies",
    summary="Applied Policies",
    description="Get all policies that apply to the current user",
)
async def get_applied_policies(
    user: User = Depends(get_user_with_groups),
) -> Dict[str, Any]:
    """Get detailed information about all policies that apply to the user."""

    applicable_policies = []

    # Get user-specific policies
    user_policies = redis_client.zrevrange(
        f"policy:user:{user.username}:sorted", 0, -1, withscores=True
    )

    for policy_key, priority in user_policies:
        policy_data = redis_client.hget(policy_key, "data")
        if policy_data:
            policy = json.loads(policy_data)
            applicable_policies.append(
                {"source": "user", "policy": policy, "priority": int(priority)}
            )

    # Get group policies
    for group in user.groups:
        group_policies = redis_client.zrevrange(
            f"policy:group:{group}:sorted", 0, -1, withscores=True
        )

        for policy_key, priority in group_policies:
            policy_data = redis_client.hget(policy_key, "data")
            if policy_data:
                policy = json.loads(policy_data)
                applicable_policies.append(
                    {
                        "source": f"group:{group}",
                        "policy": policy,
                        "priority": int(priority),
                    }
                )

    # Sort by priority
    applicable_policies.sort(key=lambda x: x["priority"], reverse=True)

    return {
        "user": {"username": user.username, "groups": user.groups},
        "total_policies": len(applicable_policies),
        "policies": applicable_policies,
        "evaluation_order": [p["policy"]["policy_name"] for p in applicable_policies],
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/logout", summary="Logout", description="Logout the current user")
async def logout(
    response: Response,
    rbac: RBACContext = Depends(get_rbac_context),
) -> dict:
    """
    Logout endpoint.

    With OAuth proxy, this typically redirects to the OAuth provider's logout URL.
    """

    # Clear RBAC cache for this user
    get_rbac_engine().clear_cache(rbac.principal)

    # Clear group cache
    redis_client.delete(f"user:groups:{rbac.user.username}")
    redis_client.delete(f"user:permissions:{rbac.user.username}")

    logger.info("User logout", extra={"user_id": rbac.user.id})

    # In production with OAuth proxy, redirect to OAuth logout
    if settings.oauth_proxy_enabled and settings.environment == "production":
        return {
            "message": "Logout successful",
            "redirect": "/oauth2/sign_out",  # OAuth proxy logout path
        }

    return {"message": "Logout successful"}


@router.get("/login", summary="Login Redirect", description="Redirect to OAuth login")
async def login_redirect():
    """
    Redirect to OAuth login.

    This is typically handled by the OAuth proxy automatically,
    but we provide this endpoint for explicit login requests.
    """
    if settings.oauth_proxy_enabled:
        # OAuth proxy handles this
        return RedirectResponse(
            url="/oauth2/start",  # OAuth proxy login path
            status_code=status.HTTP_302_FOUND,
        )
    else:
        # Development mode
        return {
            "message": "OAuth proxy disabled in development mode",
            "development": True,
        }


@router.post(
    "/cache/clear",
    summary="Clear Cache",
    description="Clear RBAC cache for the current user",
)
async def clear_user_cache(
    rbac: RBACContext = Depends(get_rbac_context),
) -> Dict[str, Any]:
    """Clear RBAC and group cache for the current user."""

    # Clear RBAC cache
    rbac_count = get_rbac_engine().clear_cache(rbac.principal)

    # Clear group cache
    redis_client.delete(f"user:groups:{rbac.user.username}")
    redis_client.delete(f"user:permissions:{rbac.user.username}")

    logger.info(f"Cleared cache for user {rbac.user.username}")

    return {
        "message": "Cache cleared successfully",
        "rbac_entries_cleared": rbac_count,
        "user": rbac.user.username,
    }
