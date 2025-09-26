"""
Registry routes
"""

import json
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query
from src.api.dependencies.auth import get_current_user
from src.core.logging import get_logger
from src.core.redis_client import get_redis_client
from src.models.auth import User

logger = get_logger(__name__)
redis_client = get_redis_client()
router = APIRouter()


# ============================================================================
# DATA ACCESS FUNCTIONS
# ============================================================================


def get_registry_status_minimal(registry_name: str) -> Dict[str, Any]:
    """
    Get minimal registry status with O(1) Redis lookups.
    Returns: name, display_name, endpoint, available, error
    """
    # Use pipeline for atomic fetch of both status and spec
    pipeline = redis_client.pipeline()
    pipeline.get(f"registry:{registry_name}:status")
    pipeline.get(f"registry:{registry_name}:spec")
    status_data, spec_data = pipeline.execute()

    result = {
        "name": registry_name,
        "display_name": registry_name,  # Default to name
        "endpoint": None,
        "available": False,
        "error": None,
    }

    # Parse spec for display_name and endpoint
    if spec_data:
        try:
            spec = json.loads(spec_data)
            result["display_name"] = spec.get("display_name", registry_name)
            result["endpoint"] = spec.get("endpoint")
        except json.JSONDecodeError:
            pass

    # Parse status for availability and error
    if status_data:
        try:
            status = json.loads(status_data)
            result["available"] = status.get("available", False)
            if not result["available"] and "error" in status:
                result["error"] = status["error"]
        except json.JSONDecodeError:
            result["error"] = "Invalid status data"
    else:
        result["error"] = "Registry not found"

    return result


def get_all_registries_minimal() -> List[Dict[str, Any]]:
    """
    Get minimal info for all registries with optimized Redis pipeline.
    """
    # Get all registry names
    registry_names_set = redis_client.smembers("registries:all")

    if not registry_names_set:
        return []

    # Sort the names FIRST to ensure consistent ordering
    registry_names = sorted(registry_names_set)

    # Use Redis pipeline to batch all GET operations
    pipeline = redis_client.pipeline()

    # Queue operations in the SAME order as registry_names
    for name in registry_names:
        pipeline.get(f"registry:{name}:status")
        pipeline.get(f"registry:{name}:spec")

    # Execute all at once - results will be in the same order as queued
    all_results = pipeline.execute()

    # Build results - process pairs of (status, spec) for each registry
    results = []
    for i, name in enumerate(registry_names):
        # Each registry has 2 results: status at even index, spec at odd index
        status_data = all_results[i * 2]
        spec_data = all_results[i * 2 + 1]

        result = {
            "name": name,
            "display_name": name,  # Default to name
            "endpoint": None,
            "available": False,
            "error": None,
        }

        # Parse spec for display_name and endpoint
        if spec_data:
            try:
                spec = json.loads(spec_data)
                result["display_name"] = spec.get("display_name", name)
                result["endpoint"] = spec.get("endpoint")
            except json.JSONDecodeError:
                pass

        # Parse status for availability and error
        if status_data:
            try:
                status = json.loads(status_data)
                result["available"] = status.get("available", False)
                if not result["available"] and "error" in status:
                    result["error"] = status["error"]
            except json.JSONDecodeError:
                result["error"] = "Invalid status data"

        results.append(result)

    return results


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
    registries = get_all_registries_minimal()

    # If response time is requested, enhance with additional lookup
    if include_response_time:
        # Sort registries to ensure consistent ordering
        registry_names = [reg["name"] for reg in registries]

        pipeline = redis_client.pipeline()
        for name in registry_names:
            pipeline.get(f"registry:{name}:status")

        statuses = pipeline.execute()
        for reg, status_data in zip(registries, statuses):
            if status_data:
                try:
                    status = json.loads(status_data)
                    reg["response_time"] = status.get("response_time", None)
                except:
                    reg["response_time"] = None

    logger.info(f"User {user.username} listed {len(registries)} registries (minimal)")
    return registries
