"""
Cluster routes
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from clusterpulse.api.dependencies.rbac import RBACContext, get_rbac_context
from clusterpulse.api.responses.cluster import (ClusterListItemBuilder,
                                                 ClusterResponseBuilder,
                                                 NamespaceDetailBuilder)
from clusterpulse.core.logging import get_logger
from clusterpulse.db.redis import get_redis_client
from clusterpulse.repositories.redis_base import ClusterDataRepository
from clusterpulse.services.metrics import create_metrics_calculator
from clusterpulse.services.rbac import Action, ResourceType

from clusterpulse.api.responses.metricsource import CustomResourceDetailBuilder
from clusterpulse.api.utils.aggregations import recompute_aggregations
from clusterpulse.api.utils.pagination import PaginationParams, paginate
from clusterpulse.repositories.redis_base import MetricSourceRepository


logger = get_logger(__name__)

# Initialize dependencies
redis_client = get_redis_client()
repo = ClusterDataRepository(redis_client)
metric_source_repo = MetricSourceRepository(redis_client)

# Import RBAC engine from dependencies to use the singleton
from clusterpulse.api.dependencies.rbac import get_rbac_engine

rbac_engine = get_rbac_engine()
metrics_calculator = create_metrics_calculator(redis_client, rbac_engine)

router = APIRouter()


# ============================================================================
# ROUTES
# ============================================================================


@router.get("", response_model=List[Dict[str, Any]])
async def list_clusters(
    rbac: RBACContext = Depends(get_rbac_context),
) -> List[Dict[str, Any]]:
    """List all clusters accessible to the user with filtered metrics."""

    accessible_cluster_names = rbac.get_accessible_clusters()

    clusters = []
    for cluster_name in accessible_cluster_names:
        # Get bundle (spec, status, metrics, info) in one batch
        bundle = repo.get_cluster_bundle(cluster_name)

        # Get filtered metrics
        filtered_metrics = metrics_calculator.get_filtered_cluster_metrics(
            cluster_name, rbac.principal, include_resource_details=False
        )

        # Get filtered operator count
        operators = repo.get_cluster_operators(cluster_name)
        filtered_operators = rbac.filter_resources(
            operators, ResourceType.OPERATOR, cluster_name
        )

        # Check if user has metrics permission
        has_metrics_permission = rbac.has_permission(
            Action.VIEW_METRICS,
            # Need to create a resource for permission check
            type("Resource", (), {
                "type": ResourceType.CLUSTER,
                "name": cluster_name,
                "cluster": cluster_name
            })()
        )

        # Build response using builder
        cluster_item = (
            ClusterListItemBuilder(cluster_name)
            .with_spec(bundle["spec"])
            .with_status(bundle["status"])
            .with_info(bundle["info"])
            .with_metrics(filtered_metrics, has_metrics_permission)
            .with_operator_count(len(filtered_operators))
            .build()
        )

        clusters.append(cluster_item)

    logger.info(f"User {rbac.user.username} listed {len(clusters)} clusters")
    return clusters


@router.get("/{cluster_name}")
async def get_cluster(
    cluster_name: str, rbac: RBACContext = Depends(get_rbac_context)
) -> Dict[str, Any]:
    """Get detailed information about a specific cluster with filtered metrics."""

    # Check access and get decision
    decision = rbac.check_cluster_access(cluster_name)

    # Get all data in one batch
    bundle = repo.get_cluster_bundle(cluster_name)

    # Get resource metadata
    resource_metadata = repo.get_json(f"cluster:{cluster_name}:resource_metadata")

    # Build base response
    builder = (
        ClusterResponseBuilder(cluster_name)
        .with_spec(bundle["spec"])
        .with_status(bundle["status"])
        .with_info(bundle["info"])
        .with_resource_collection_metadata(resource_metadata)
    )

    # Add filtered metrics if permitted
    if decision.can(Action.VIEW_METRICS):
        filtered_metrics = metrics_calculator.get_filtered_cluster_metrics(
            cluster_name, rbac.principal, include_resource_details=True
        )

        if filtered_metrics:
            builder.with_metrics(filtered_metrics, decision)
            builder.with_metrics_filtering_info(filtered_metrics)

    # Add operator count
    operators = repo.get_cluster_operators(cluster_name)
    filtered_operators = rbac.filter_resources(
        operators, ResourceType.OPERATOR, cluster_name
    )
    builder.with_operator_count(len(filtered_operators))

    logger.info(f"User {rbac.user.username} accessed cluster {cluster_name}")
    return builder.build()


@router.get("/{cluster_name}/nodes")
async def get_cluster_nodes(
    cluster_name: str,
    rbac: RBACContext = Depends(get_rbac_context),
    role: Optional[str] = Query(None, description="Filter by node role"),
    status_filter: Optional[str] = Query(
        None, description="Filter by node status", alias="status"
    ),
) -> List[Dict[str, Any]]:
    """Get nodes for a specific cluster."""

    # Check cluster access
    rbac.check_cluster_access(cluster_name)

    # Get all nodes
    nodes = repo.get_cluster_nodes(cluster_name)

    # Apply query filters
    if role:
        nodes = [node for node in nodes if role in node.get("roles", [])]
    if status_filter:
        nodes = [node for node in nodes if node.get("status") == status_filter]

    # Filter through RBAC
    filtered_nodes = rbac.filter_resources(nodes, ResourceType.NODE, cluster_name)

    logger.info(
        f"User {rbac.user.username} accessed {len(filtered_nodes)} nodes "
        f"for cluster {cluster_name}"
    )
    return filtered_nodes


@router.get("/{cluster_name}/nodes/{node_name}")
async def get_cluster_node(
    cluster_name: str,
    node_name: str,
    rbac: RBACContext = Depends(get_rbac_context),
    include_metrics: bool = Query(False, description="Include node metrics history"),
) -> Dict[str, Any]:
    """Get detailed information about a specific node."""

    # Check cluster access
    decision = rbac.check_cluster_access(cluster_name)

    # Get node data
    node = repo.get_cluster_node(cluster_name, node_name)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {node_name} not found in cluster {cluster_name}",
        )

    # Filter through RBAC
    filtered_nodes = rbac.filter_resources([node], ResourceType.NODE, cluster_name)

    if not filtered_nodes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access to node {node_name} is not permitted",
        )

    node = filtered_nodes[0]

    # Add metrics history if requested and permitted
    if include_metrics and decision.can(Action.VIEW_METRICS):
        node["metrics_history"] = repo.get_node_metrics_history(
            cluster_name, node_name, limit=100
        )

    # Add conditions
    conditions = repo.get_node_conditions(cluster_name, node_name)
    if conditions:
        node["current_conditions"] = conditions

    return node


@router.get("/{cluster_name}/operators")
async def get_cluster_operators(
    cluster_name: str,
    rbac: RBACContext = Depends(get_rbac_context),
    namespace: Optional[str] = Query(None, description="Filter by namespace"),
    status_filter: Optional[str] = Query(
        None, description="Filter by status", alias="status"
    ),
) -> List[Dict[str, Any]]:
    """Get operators for a specific cluster."""

    # Check cluster access
    rbac.check_cluster_access(cluster_name)

    # Get operators
    operators = repo.get_cluster_operators(cluster_name)

    # Apply query filters
    if namespace:
        operators = [
            op
            for op in operators
            if op.get("available_in_namespaces") == ["*"]
            or namespace in op.get("available_in_namespaces", [])
        ]

    if status_filter:
        operators = [op for op in operators if op.get("status") == status_filter]

    # Filter through RBAC
    filtered_operators = rbac.filter_resources(
        operators, ResourceType.OPERATOR, cluster_name
    )

    logger.info(
        f"User {rbac.user.username} accessed {len(filtered_operators)} operators "
        f"for cluster {cluster_name}"
    )
    return filtered_operators


@router.get("/{cluster_name}/namespaces")
async def get_cluster_namespaces(
    cluster_name: str,
    rbac: RBACContext = Depends(get_rbac_context),
    with_operator_count: bool = Query(
        False, description="Include operator count per namespace"
    ),
    with_resource_counts: bool = Query(
        False, description="Include resource counts per namespace"
    ),
) -> List[Any]:
    """Get namespaces for a specific cluster - ONLY those the user can access."""

    # Check cluster access
    rbac.check_cluster_access(cluster_name)

    # Get allowed namespaces directly from metrics calculator
    allowed_namespaces = metrics_calculator.get_allowed_namespaces(
        cluster_name, rbac.principal
    )

    # Convert to sorted list
    namespace_list = sorted(allowed_namespaces)

    # If no additional details requested, return simple list
    if not with_operator_count and not with_resource_counts:
        logger.info(
            f"User {rbac.user.username} accessed {len(namespace_list)} namespaces "
            f"for cluster {cluster_name}"
        )
        return namespace_list

    # Build detailed response
    namespace_details = []

    for ns in namespace_list:
        builder = NamespaceDetailBuilder(ns)

        # Add operator count if requested
        if with_operator_count:
            operators = repo.get_cluster_operators(cluster_name)
            filtered_operators = rbac.filter_resources(
                operators, ResourceType.OPERATOR, cluster_name
            )

            # Count operators available in this namespace
            operator_count = 0
            available_operators = []

            for op in filtered_operators:
                available_ns = op.get("available_in_namespaces", [])
                if available_ns == ["*"] or ns in available_ns:
                    operator_count += 1
                    available_operators.append(
                        op.get("display_name", op.get("name", "Unknown"))
                    )

            builder.with_operator_count(
                operator_count, available_operators[:5], operator_count > 5
            )

        # Add resource counts if requested
        if with_resource_counts:
            counts = {
                "pods": 0,
                "deployments": 0,
                "services": 0,
                "statefulsets": 0,
                "daemonsets": 0,
            }

            # Count each resource type
            for resource_type in counts.keys():
                resources = repo.get_cluster_resource_list(cluster_name, resource_type)
                counts[resource_type] = sum(
                    1 for r in resources if r.get("namespace") == ns
                )

            builder.with_resource_counts(counts)

        namespace_details.append(builder.build())

    # Sort by total resources if we have counts
    if with_resource_counts:
        namespace_details.sort(key=lambda x: x.get("total_resources", 0), reverse=True)

    logger.info(
        f"User {rbac.user.username} accessed {len(namespace_details)} namespaces "
        f"for cluster {cluster_name}"
    )
    return namespace_details


@router.get("/{cluster_name}/metrics")
async def get_cluster_metrics(
    cluster_name: str,
    rbac: RBACContext = Depends(get_rbac_context),
    include_costs: bool = Query(False, description="Include cost metrics"),
    detailed: bool = Query(False, description="Include detailed breakdown"),
) -> Dict[str, Any]:
    """Get FILTERED metrics for a specific cluster based on namespace permissions."""

    # Check cluster access with metrics permission
    decision = rbac.check_cluster_access(cluster_name, Action.VIEW_METRICS)

    # Additional check for cost metrics
    if include_costs and not decision.can(Action.VIEW_COSTS):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access to cost metrics is not permitted",
        )

    # Get filtered metrics
    filtered_metrics = metrics_calculator.get_filtered_cluster_metrics(
        cluster_name, rbac.principal, include_resource_details=detailed
    )

    if not filtered_metrics:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Metrics not found for cluster {cluster_name}",
        )

    # Remove cost data if not permitted
    if not include_costs:
        for field in ["cost", "costs", "estimated_cost", "monthly_cost"]:
            filtered_metrics.pop(field, None)

    # Add filtering information
    response = {
        **filtered_metrics,
        "filtering_applied": filtered_metrics.get("filtered", False),
    }

    if filtered_metrics.get("filtered"):
        response["filtering_summary"] = {
            "type": "namespace-based",
            "allowed_namespaces": filtered_metrics.get("allowed_namespaces_count", 0),
            "note": "Metrics reflect only resources in allowed namespaces",
        }

    logger.info(
        f"User {rbac.user.username} accessed "
        f"{'filtered' if filtered_metrics.get('filtered') else 'full'} "
        f"metrics for cluster {cluster_name}"
    )

    return response


@router.get("/{cluster_name}/alerts")
async def get_cluster_alerts(
    cluster_name: str,
    rbac: RBACContext = Depends(get_rbac_context),
    severity: Optional[str] = Query(None, description="Filter by severity"),
) -> List[Dict[str, Any]]:
    """Get alerts for a specific cluster."""

    # Check cluster access
    rbac.check_cluster_access(cluster_name)

    # Get alerts
    alerts = repo.get_cluster_alerts(cluster_name)

    # Apply severity filter
    if severity:
        alerts = [alert for alert in alerts if alert.get("severity") == severity]

    # Filter through RBAC
    filtered_alerts = rbac.filter_resources(alerts, ResourceType.ALERT, cluster_name)

    logger.info(
        f"User {rbac.user.username} accessed {len(filtered_alerts)} alerts "
        f"for cluster {cluster_name}"
    )
    return filtered_alerts


@router.get("/{cluster_name}/events")
async def get_cluster_events(
    cluster_name: str,
    rbac: RBACContext = Depends(get_rbac_context),
    limit: int = Query(100, description="Maximum number of events"),
) -> List[Dict[str, Any]]:
    """Get recent events for a specific cluster."""

    # Check cluster access
    rbac.check_cluster_access(cluster_name)

    # Get events
    events = repo.get_cluster_events(cluster_name, limit)

    # Filter through RBAC
    filtered_events = rbac.filter_resources(events, ResourceType.EVENT, cluster_name)

    logger.info(
        f"User {rbac.user.username} accessed {len(filtered_events)} events "
        f"for cluster {cluster_name}"
    )
    return filtered_events

@router.get("/{cluster_name}/custom/{resource_type_name}")
async def get_custom_resources(
    cluster_name: str,
    resource_type_name: str,
    rbac: RBACContext = Depends(get_rbac_context),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(100, ge=1, le=1000, description="Items per page"),
    include_aggregations: bool = Query(True, description="Include aggregations"),
    namespace: Optional[str] = Query(None, description="Filter by namespace"),
    sort_by: Optional[str] = Query(None, description="Field to sort by"),
    sort_order: str = Query("asc", regex="^(asc|desc)$", description="Sort order"),
) -> Dict[str, Any]:
    """Get custom resources for a cluster with RBAC filtering and pagination."""
    rbac.check_cluster_access(cluster_name)
    decision = rbac.check_custom_resource_access(resource_type_name, cluster_name)

    source_id = metric_source_repo.get_source_id_for_type(resource_type_name)
    if not source_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Custom resource type '{resource_type_name}' not found",
        )

    source = metric_source_repo.get_metric_source(source_id)
    rbac_config = source.get("rbac", {}) if source else {}
    identifiers = rbac_config.get("identifiers", {})
    namespace_field = identifiers.get("namespace", "namespace")
    name_field = identifiers.get("name", "name")
    filter_aggregations = rbac_config.get("filterAggregations", True)

    resource_data = metric_source_repo.get_custom_resources(source_id, cluster_name)
    if not resource_data:
        return CustomResourceDetailBuilder(resource_type_name, cluster_name).with_resources(
            [], False
        ).with_pagination({"total": 0, "page": 1, "pageSize": page_size, "totalPages": 1, "hasNext": False, "hasPrevious": False}).build()

    raw_resources = resource_data.get("resources", [])
    total_before_filter = len(raw_resources)

    filtered_resources = rbac.filter_custom_resources(
        raw_resources, resource_type_name, cluster_name, namespace_field, name_field
    )

    if namespace:
        filtered_resources = [
            r for r in filtered_resources if r.get(namespace_field) == namespace
        ]

    if sort_by:
        valid_fields = {f.get("name") for f in source.get("fields", [])} if source else set()
        valid_fields.update({c.get("name") for c in source.get("computed", [])} if source else set())
        if sort_by not in valid_fields and sort_by not in ("name", "namespace", "_id"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid sort field: {sort_by}",
            )
        reverse = sort_order == "desc"
        filtered_resources.sort(key=lambda x: x.get(sort_by) or "", reverse=reverse)

    params = PaginationParams(page=page, page_size=page_size)
    paginated = paginate(filtered_resources, params)

    builder = CustomResourceDetailBuilder(resource_type_name, cluster_name)
    builder.with_collection_metadata({
        "collectedAt": resource_data.get("collectedAt"),
        "truncated": resource_data.get("truncated", False),
    })
    builder.with_resources(paginated.items, total_before_filter != len(filtered_resources))
    builder.with_pagination(paginated.to_dict()["pagination"])

    if include_aggregations:
        agg_data = metric_source_repo.get_custom_aggregations(source_id, cluster_name)
        if agg_data:
            values = agg_data.get("values", {})
            if filter_aggregations and len(filtered_resources) < total_before_filter:
                agg_specs = source.get("aggregations", []) if source else []
                values = recompute_aggregations(filtered_resources, agg_specs)
            values = rbac.filter_aggregations(values, resource_type_name, cluster_name)
            builder.with_aggregations(values)

    logger.info(
        f"User {rbac.user.username} accessed {resource_type_name} in {cluster_name}: "
        f"{total_before_filter} total, {len(filtered_resources)} after RBAC, page {page}"
    )
    return builder.build()
