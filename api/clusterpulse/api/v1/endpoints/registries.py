"""
Registry routes - Refactored with repository and response builders.
"""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query

from clusterpulse.api.dependencies.auth import get_current_user
from clusterpulse.api.responses.registry import RegistryStatusBuilder
from clusterpulse.core.logging import get_logger
from clusterpulse.db.redis import get_redis_client
from clusterpulse.models.auth import User
from clusterpulse.repositories.redis_base import RegistryDataRepository

logger = get_logger(__name__)

# Initialize repository
redis_client = get_redis_client()
repo = RegistryDataRepository(redis_client)

router = APIRouter()


# ============================================================================
# API ENDPOINTS
# ============================================================================


@router.get("/registries/status", response_model=List[Dict[str, Any]])
async def list_registries_status(
    user: User = Depends(get_current_user),
    include_response_time: bool = Query(
        False, description="Include response time in ms"
    ),
) -> List[Dict[str, Any]]:
    """
    Get minimal status for all registries - Optimized for speed.

    Returns for each registry:
    - name: Registry name
    - display_name: Display name from spec
    - endpoint: Registry endpoint URL
    - available: Boolean availability status
    - error: Error message if unavailable (null if available)
    - response_time: Last check response time in ms (optional)

    This endpoint is optimized with Redis pipelining for fast lookups.
    """

    # Get all registry names
    registry_names = repo.get_all_registry_names()

    if not registry_names:
        return []

    # Batch fetch all registry data
    bundles = repo.batch_get_registry_bundles(registry_names)

    # Build responses using builder
    registries = []
    for name in registry_names:
        bundle = bundles.get(name, {})

        builder = (
            RegistryStatusBuilder(name)
            .with_spec(bundle.get("spec"))
            .with_status(bundle.get("status"))
            .with_response_time(bundle.get("status"), include_response_time)
        )

        registries.append(builder.build())

    logger.info(f"User {user.username} listed {len(registries)} registries (minimal)")
    return registries
