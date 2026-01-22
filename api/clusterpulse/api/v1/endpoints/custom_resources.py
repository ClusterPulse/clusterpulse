"""Custom resource type discovery and listing endpoints."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from clusterpulse.api.dependencies.rbac import RBACContext, get_rbac_context
from clusterpulse.api.responses.metricsource import (
    ClusterResourceCountBuilder,
    CustomResourceTypeBuilder,
)
from clusterpulse.api.utils.aggregations import recompute_aggregations
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


def _get_counts_for_resource_type(
    resource_type_name: str,
    accessible_clusters: List[str],
    rbac: RBACContext,
    include_aggregations: bool,
) -> List[Dict[str, Any]]:
    """
    Compute filtered resource counts for a single resource type across clusters.

    Returns list of cluster count entries for the given type.
    """
    source_id = repo.get_source_id_for_type(resource_type_name)
    if not source_id:
        return []

    source = repo.get_metric_source(source_id)
    rbac_config = source.get("rbac", {}) if source else {}
    filter_aggregations = rbac_config.get("filterAggregations", True)

    resources_by_cluster = repo.get_custom_resources_for_clusters(
        source_id, accessible_clusters
    )
    aggregations_by_cluster = {}
    if include_aggregations:
        aggregations_by_cluster = repo.get_custom_aggregations_for_clusters(
            source_id, accessible_clusters
        )

    result = []
    for cluster_name in sorted(accessible_clusters):
        resource_data = resources_by_cluster.get(cluster_name)
        if not resource_data:
            continue

        raw_resources = resource_data.get("resources", [])
        total_count = len(raw_resources)

        filtered_resources = rbac.filter_custom_resources(
            raw_resources, resource_type_name, cluster_name
        )
        filtered_count = len(filtered_resources)

        builder = ClusterResourceCountBuilder(cluster_name, resource_type_name)
        builder.with_counts(filtered_count)
        builder.with_collection_time(resource_data.get("collectedAt"))

        if include_aggregations:
            agg_data = aggregations_by_cluster.get(cluster_name)
            if agg_data:
                values = agg_data.get("values", {})
                if filter_aggregations and filtered_count < total_count:
                    agg_specs = source.get("aggregations", []) if source else []
                    values = recompute_aggregations(filtered_resources, agg_specs)
                values = rbac.filter_aggregations(values, resource_type_name, cluster_name)
                builder.with_aggregations(values)

        result.append(builder.build())

    return result


@router.get("/clusters", response_model=List[Dict[str, Any]])
async def get_custom_resource_counts_by_cluster(
    rbac: RBACContext = Depends(get_rbac_context),
    resource_type_names: List[str] = Query(
        ..., alias="type", description="Resource type names to query"
    ),
    clusters: Optional[List[str]] = Query(
        None, description="Filter to specific clusters"
    ),
    include_aggregations: bool = Query(False, description="Include key aggregations"),
) -> List[Dict[str, Any]]:
    """
    Get resource counts for one or more custom resource types across clusters.

    Returns for each accessible cluster and requested type the total and filtered
    resource counts. Results are returned as a flat list with cluster and
    resourceTypeName in each entry.
    """
    # Validate access to all requested types upfront
    for type_name in resource_type_names:
        rbac.check_custom_resource_access(type_name)

    accessible_clusters = rbac.get_accessible_clusters()
    if clusters:
        accessible_clusters = [c for c in accessible_clusters if c in clusters]

    if not accessible_clusters:
        return []

    result = []
    for type_name in resource_type_names:
        type_counts = _get_counts_for_resource_type(
            type_name, accessible_clusters, rbac, include_aggregations
        )
        result.extend(type_counts)

    logger.info(
        f"User {rbac.user.username} accessed counts for {len(resource_type_names)} "
        f"resource types across {len(accessible_clusters)} clusters"
    )
    return result
