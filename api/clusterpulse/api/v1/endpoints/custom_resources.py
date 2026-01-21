"""Custom resource type discovery and listing endpoints."""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query

from clusterpulse.api.dependencies.rbac import RBACContext, get_rbac_context
from clusterpulse.api.responses.metricsource import CustomResourceTypeBuilder
from clusterpulse.core.logging import get_logger
from clusterpulse.db.redis import get_redis_client
from clusterpulse.repositories.redis_base import MetricSourceRepository

logger = get_logger(__name__)

redis_client = get_redis_client()
repo = MetricSourceRepository(redis_client)

router = APIRouter()


@router.get("", response_model=List[Dict[str, Any]])
async def list_custom_resource_types(
    rbac: RBACContext = Depends(get_rbac_context),
    include_source_details: bool = Query(
        False, description="Include MetricSource details"
    ),
    include_cluster_availability: bool = Query(
        False, description="Include which clusters have data"
    ),
) -> List[Dict[str, Any]]:
    """
    List all custom resource types the user can access.

    Returns resource types that:
    1. Have an enabled MetricSource definition
    2. User has explicit policy granting access

    Types not explicitly granted in a policy are NOT returned (implicit deny).
    """
    all_sources = repo.get_all_metric_sources()
    type_to_source = {}
    for source in all_sources:
        type_name = source.get("rbac", {}).get("resourceTypeName")
        if type_name:
            type_to_source[type_name] = source

    accessible_types = rbac.get_accessible_custom_types()

    result = []
    for type_name in sorted(accessible_types):
        source = type_to_source.get(type_name)
        if not source:
            continue

        source_id = source.get("_id") or f"{source.get('namespace')}/{source.get('name')}"

        builder = CustomResourceTypeBuilder(type_name).with_source_id(source_id)

        if include_source_details:
            builder.with_source_info(source)

        if include_cluster_availability:
            clusters = repo.get_clusters_with_data(type_name)
            builder.with_cluster_availability(clusters)

        result.append(builder.build())

    logger.info(
        f"User {rbac.user.username} listed {len(result)} custom resource types"
    )
    return result
