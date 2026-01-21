"""Custom resource endpoints for MetricSource data access."""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, status

from clusterpulse.api.dependencies.auth import get_current_user
from clusterpulse.api.responses.custom_resource import (
    CustomResourceTypeListBuilder,
    MetricSourceDetailBuilder,
    MetricSourceListItemBuilder,
)
from clusterpulse.core.logging import get_logger
from clusterpulse.db.redis import get_redis_client
from clusterpulse.models.auth import User
from clusterpulse.repositories.custom_resource import CustomResourceRepository

logger = get_logger(__name__)

router = APIRouter()

# Initialize repository
redis_client = get_redis_client()
repo = CustomResourceRepository(redis_client)


@router.get(
    "/metricsources",
    response_model=List[Dict[str, Any]],
    summary="List MetricSources",
    description="Get all MetricSource definitions with their current status",
)
async def list_metricsources(
    user: User = Depends(get_current_user),
    enabled_only: bool = False,
) -> List[Dict[str, Any]]:
    """List all MetricSource definitions.

    Args:
        user: Authenticated user
        enabled_only: If true, only return enabled MetricSources

    Returns:
        List of MetricSource summaries
    """
    if enabled_only:
        source_ids = repo.get_enabled_metricsource_ids()
    else:
        source_ids = repo.get_all_metricsource_ids()

    if not source_ids:
        return []

    # Batch fetch definitions
    definitions = repo.batch_get_metricsources(source_ids)

    metricsources = []
    for source_id in source_ids:
        definition = definitions.get(source_id)

        # Parse source_id for status lookup
        parts = source_id.split("/", 1)
        status_data = None
        if len(parts) == 2:
            status_data = repo.get_metricsource_status(parts[0], parts[1])

        builder = (
            MetricSourceListItemBuilder(source_id)
            .with_definition(definition)
            .with_status(status_data)
        )

        metricsources.append(builder.build())

    logger.info(
        f"User {user.username} listed {len(metricsources)} MetricSources"
    )

    return metricsources


@router.get(
    "/metricsources/{namespace}/{name}",
    response_model=Dict[str, Any],
    summary="Get MetricSource",
    description="Get detailed information about a specific MetricSource",
    responses={
        404: {"description": "MetricSource not found"},
    },
)
async def get_metricsource(
    namespace: str,
    name: str,
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get a specific MetricSource definition.

    Args:
        namespace: MetricSource namespace
        name: MetricSource name
        user: Authenticated user

    Returns:
        Full MetricSource definition with status

    Raises:
        HTTPException: 404 if MetricSource not found
    """
    definition = repo.get_metricsource(namespace, name)

    if not definition:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MetricSource '{namespace}/{name}' not found",
        )

    status_data = repo.get_metricsource_status(namespace, name)
    source_id = f"{namespace}/{name}"

    builder = (
        MetricSourceDetailBuilder(source_id)
        .with_definition(definition)
        .with_status(status_data)
    )

    logger.info(
        f"User {user.username} accessed MetricSource {namespace}/{name}"
    )

    return builder.build()


@router.get(
    "/custom-types",
    response_model=List[Dict[str, Any]],
    summary="List Custom Resource Types",
    description="Get list of available custom resource types from enabled MetricSources",
)
async def list_custom_types(
    user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """List available custom resource types.

    Returns resource types that can be queried via the custom resource endpoints.
    Only includes types from enabled MetricSources.

    Args:
        user: Authenticated user

    Returns:
        List of available resource types with their source information
    """
    available_types = repo.get_available_resource_types()

    builder = CustomResourceTypeListBuilder()
    builder.add_types_from_list(available_types)

    result = builder.build()

    logger.info(
        f"User {user.username} listed {len(result)} custom resource types"
    )

    return result


@router.get(
    "/custom-types/{resource_type}",
    response_model=Dict[str, Any],
    summary="Get Custom Resource Type Info",
    description="Get information about a specific custom resource type",
    responses={
        404: {"description": "Resource type not found"},
    },
)
async def get_custom_type_info(
    resource_type: str,
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get information about a specific custom resource type.

    Args:
        resource_type: The resource type name (from rbac.resourceTypeName)
        user: Authenticated user

    Returns:
        Resource type information including MetricSource details

    Raises:
        HTTPException: 404 if resource type not found
    """
    definition = repo.get_metricsource_by_resource_type(resource_type)

    if not definition:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Custom resource type '{resource_type}' not found or not enabled",
        )

    source = definition.get("source", {})
    rbac = definition.get("rbac", {})
    collection = definition.get("collection", {})

    # Get field names for documentation
    fields = definition.get("fields", [])
    field_names = [f.get("name") for f in fields if f.get("name")]

    # Get aggregation names
    aggregations = definition.get("aggregations", [])
    aggregation_names = [a.get("name") for a in aggregations if a.get("name")]

    result = {
        "resourceTypeName": resource_type,
        "sourceId": f"{definition.get('namespace', '')}/{definition.get('name', '')}",
        "sourceKind": source.get("kind"),
        "sourceApiVersion": source.get("apiVersion"),
        "scope": source.get("scope", "Namespaced"),
        "fields": field_names,
        "filterableFields": rbac.get("filterableFields", []),
        "aggregations": aggregation_names,
        "filterAggregations": rbac.get("filterAggregations", True),
        "collectionInterval": collection.get("intervalSeconds"),
        "identifiers": {
            "namespace": rbac.get("identifiers", {}).get("namespace"),
            "name": rbac.get("identifiers", {}).get("name"),
        },
    }

    logger.info(
        f"User {user.username} accessed custom resource type info: {resource_type}"
    )

    return result
