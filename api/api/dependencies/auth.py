"""Authentication dependencies for FastAPI."""

from typing import List, Optional

from fastapi import Depends, HTTPException, Request, status
from kubernetes import client, config
from kubernetes.dynamic import DynamicClient
from src.core.config import settings
from src.core.logging import get_logger
from src.core.rbac_engine import create_rbac_engine
from src.core.redis_client import get_redis_client
from src.models.auth import User

logger = get_logger(__name__)

# Initialize Kubernetes client
try:
    config.load_incluster_config()
    k8s_client = client.ApiClient()
    k8s_dynamic_client = DynamicClient(k8s_client)
    logger.info("Kubernetes client initialized (in-cluster)")
except Exception:
    try:
        config.load_kube_config()
        k8s_client = client.ApiClient()
        k8s_dynamic_client = DynamicClient(k8s_client)
        logger.info("Kubernetes client initialized (kubeconfig)")
    except Exception:
        k8s_dynamic_client = None
        logger.warning("Kubernetes client unavailable")

# Initialize RBAC engine
rbac_engine = create_rbac_engine(get_redis_client(), cache_ttl=0)


class AuthenticationError(HTTPException):
    """Raised when authentication fails."""

    def __init__(self, detail: str = "Authentication required"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


class AuthorizationError(HTTPException):
    """Raised when authorization fails."""

    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def extract_user_from_headers(request: Request) -> Optional[User]:
    """Extract user from OAuth proxy headers."""
    if not settings.oauth_proxy_enabled:
        if settings.environment == "development":
            return User(
                username="dev-user",
                email="dev@example.com",
                preferred_username="Development User",
                groups=["developers", "cluster-viewers"],
            )
        return None

    username = request.headers.get(settings.oauth_header_user)
    email = request.headers.get(settings.oauth_header_email)

    if not username:
        return None

    return User(username=username, email=email, groups=[], preferred_username=username)


def resolve_groups_realtime(username: str, email: Optional[str] = None) -> List[str]:
    """Resolve user groups from OpenShift in real-time."""
    if not k8s_dynamic_client:
        logger.error(f"No Kubernetes client available for group resolution")
        if settings.environment == "development":
            return ["developers", "cluster-viewers"]
        return []

    groups = []

    # Build list of identifiers to check - email often works better than username
    identifiers = []
    if email:
        identifiers.append(email)
    if username and username != email:
        identifiers.append(username)

    logger.debug(f"Resolving groups for identifiers: {identifiers}")

    try:
        # Method 1: Try User resource directly
        try:
            user_resource = k8s_dynamic_client.resources.get(
                api_version="user.openshift.io/v1", kind="User"
            )

            for identifier in identifiers:
                try:
                    user_obj = user_resource.get(name=identifier)
                    if user_obj and hasattr(user_obj, "groups") and user_obj.groups:
                        groups = user_obj.groups
                        logger.info(
                            f"Found {len(groups)} groups for {identifier} via User API: {groups}"
                        )
                        return groups
                except Exception as e:
                    logger.debug(f"User resource lookup failed for {identifier}: {e}")
                    continue
        except Exception as e:
            logger.warning(f"Could not access User API: {e}")

        # Method 2: Check Group resources for membership
        # This is critical because some OpenShift setups don't populate User.groups
        try:
            group_resource = k8s_dynamic_client.resources.get(
                api_version="user.openshift.io/v1", kind="Group"
            )

            all_groups = group_resource.get()

            for group in all_groups.items:
                if not hasattr(group, "users"):
                    continue

                group_users = group.users or []

                # Check if any identifier matches
                for identifier in identifiers:
                    if identifier in group_users:
                        group_name = group.metadata.name
                        if group_name not in groups:
                            groups.append(group_name)
                            logger.debug(f"Found {identifier} in group {group_name}")
                        break

            if groups:
                logger.info(
                    f"Found {len(groups)} groups for {username} via Group API: {groups}"
                )
            else:
                logger.warning(
                    f"User {username} ({email}) is not a member of any groups"
                )

        except Exception as e:
            logger.error(f"Failed to check Group resources: {e}")

    except Exception as e:
        logger.error(f"Failed to resolve groups for {username}: {e}")

    return groups


async def get_current_user(request: Request) -> User:
    """Get authenticated user from request."""
    user = extract_user_from_headers(request)
    if not user:
        raise AuthenticationError("No valid authentication found")
    return user


async def get_optional_current_user(request: Request) -> Optional[User]:
    """Get user if authenticated, else None."""
    try:
        return await get_current_user(request)
    except AuthenticationError:
        return None


async def get_user_with_groups(user: User = Depends(get_current_user)) -> User:
    """Enhance user with real-time group membership."""
    user.groups = resolve_groups_realtime(user.username, user.email)
    logger.debug(f"Resolved {len(user.groups)} groups for {user.username}")
    return user
