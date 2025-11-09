"""RBAC dependencies and utilities for simplified authorization."""

from typing import List, Optional

from fastapi import Depends

from clusterpulse.api.dependencies.auth import (AuthorizationError,
                                                get_user_with_groups)
from clusterpulse.db.redis import get_redis_client
from clusterpulse.models.auth import User
from clusterpulse.services.rbac import (Action, Principal, RBACDecision,
                                        RBACEngine, Request, Resource,
                                        ResourceType, create_rbac_engine)

# Initialize RBAC engine
_rbac_engine: Optional[RBACEngine] = None


def get_rbac_engine() -> RBACEngine:
    """Get or create RBAC engine singleton."""
    global _rbac_engine
    if _rbac_engine is None:
        _rbac_engine = create_rbac_engine(get_redis_client(), cache_ttl=0)
    return _rbac_engine


def user_to_principal(user: User) -> Principal:
    """Convert User to Principal for RBAC operations."""
    return Principal(
        username=user.username, email=user.email, groups=user.groups or []
    )


class RBACContext:
    """Context object providing RBAC operations for endpoints."""

    def __init__(self, user: User, rbac_engine: RBACEngine):
        self.user = user
        self.principal = user_to_principal(user)
        self.rbac = rbac_engine

    def check_cluster_access(
        self, cluster_name: str, action: Action = Action.VIEW
    ) -> RBACDecision:
        """
        Check access to a cluster and raise if denied.

        Args:
            cluster_name: Name of the cluster
            action: Action to check (default: VIEW)

        Returns:
            RBACDecision if allowed

        Raises:
            AuthorizationError if access denied
        """
        resource = Resource(
            type=ResourceType.CLUSTER, name=cluster_name, cluster=cluster_name
        )
        request = Request(principal=self.principal, action=action, resource=resource)

        decision = self.rbac.authorize(request)

        if decision.denied:
            raise AuthorizationError(
                f"Access denied to cluster {cluster_name}: {decision.reason}"
            )

        return decision

    def filter_resources(
        self,
        resources: List[dict],
        resource_type: ResourceType,
        cluster: Optional[str] = None,
    ) -> List[dict]:
        """
        Filter resources through RBAC engine.

        Args:
            resources: List of resource dictionaries
            resource_type: Type of resources being filtered
            cluster: Optional cluster name for context

        Returns:
            Filtered list of resources
        """
        return self.rbac.filter_resources(
            principal=self.principal,
            resources=resources,
            resource_type=resource_type,
            cluster=cluster,
        )

    def get_accessible_clusters(self) -> List[str]:
        """Get list of all clusters accessible to the user."""
        return self.rbac.get_accessible_clusters(self.principal)

    def has_permission(self, action: Action, resource: Resource) -> bool:
        """Check if user has specific permission on resource."""
        request = Request(principal=self.principal, action=action, resource=resource)
        decision = self.rbac.authorize(request)
        return decision.allowed


def get_rbac_context(
    user: User = Depends(get_user_with_groups),
) -> RBACContext:
    """
    FastAPI dependency to get RBAC context for current user.

    Usage:
        @router.get("/clusters/{cluster_name}")
        async def get_cluster(
            cluster_name: str,
            rbac: RBACContext = Depends(get_rbac_context)
        ):
            rbac.check_cluster_access(cluster_name)
            ...
    """
    return RBACContext(user, get_rbac_engine())
