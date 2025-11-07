"""
Cluster routes with direct RBAC engine integration.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from clusterpulse.api.dependencies.auth import (AuthorizationError,
                                                get_user_with_groups,
                                                rbac_engine)
from clusterpulse.core.logging import get_logger
from clusterpulse.db.redis import get_redis_client
from clusterpulse.models.auth import User
from clusterpulse.services.metrics import create_metrics_calculator
from clusterpulse.services.rbac import Action, Principal, RBACDecision
from clusterpulse.services.rbac import Request as RBACRequest
from clusterpulse.services.rbac import Resource, ResourceType

logger = get_logger(__name__)
redis_client = get_redis_client()
metrics_calculator = create_metrics_calculator(redis_client, rbac_engine)
router = APIRouter()


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def get_cluster_data(cluster_name: str, data_type: str) -> Optional[Dict]:
    """Get cluster data from Redis."""
    key = f"cluster:{cluster_name}:{data_type}"

    # Check if this is a hash type
    if data_type in ["meta", "nodes:summary"]:
        try:
            data = redis_client.hgetall(key)
            if data and "data" in data:
                return json.loads(data["data"])
            return data if data else None
        except Exception as e:
            logger.error(f"Error getting hash data for {key}: {e}")
            return None

    # Otherwise try as string
    try:
        data = redis_client.get(key)
        if data:
            return json.loads(data)
    except Exception as e:
        logger.error(f"Error getting string data for {key}: {e}")

    return None


def get_cluster_data_batch(
    cluster_name: str, data_types: List[str]
) -> Dict[str, Optional[Dict]]:
    """Get multiple cluster data types in a single pipeline."""
    pipeline = redis_client.pipeline()

    for data_type in data_types:
        key = f"cluster:{cluster_name}:{data_type}"
        if data_type in ["meta", "nodes:summary"]:
            pipeline.hgetall(key)
        else:
            pipeline.get(key)

    results = pipeline.execute()

    data = {}
    for i, data_type in enumerate(data_types):
        result = results[i]
        if result:
            try:
                if data_type in ["meta", "nodes:summary"]:
                    if isinstance(result, dict) and "data" in result:
                        data[data_type] = json.loads(result["data"])
                    else:
                        data[data_type] = result
                else:
                    data[data_type] = json.loads(result) if result else None
            except (json.JSONDecodeError, TypeError):
                data[data_type] = None
        else:
            data[data_type] = None

    return data


async def check_cluster_access(
    cluster_name: str, user: User, action: Action = Action.VIEW
) -> RBACDecision:
    """Check if user has access to a cluster."""
    principal = Principal(
        username=user.username,
        email=user.email,
        groups=user.groups if user.groups else [],
    )

    resource = Resource(
        type=ResourceType.CLUSTER, name=cluster_name, cluster=cluster_name
    )

    rbac_request = RBACRequest(principal=principal, action=action, resource=resource)

    decision = rbac_engine.authorize(rbac_request)

    if decision.denied:
        raise AuthorizationError(
            f"Access denied to cluster {cluster_name}: {decision.reason}"
        )

    return decision


# ============================================================================
# ROUTES
# ============================================================================


@router.get("", response_model=List[Dict[str, Any]])
async def list_clusters(
    user: User = Depends(get_user_with_groups),
    include_status: bool = Query(
        True, description="Include cluster status"
    ),  # Default to True for frontend
    include_metrics: bool = Query(
        True, description="Include cluster metrics"
    ),  # Default to True for frontend
) -> List[Dict[str, Any]]:
    """List all clusters accessible to the user with filtered metrics."""

    # Get accessible clusters from RBAC engine
    principal = Principal(username=user.username, email=user.email, groups=user.groups)
    accessible_cluster_names = rbac_engine.get_accessible_clusters(principal)

    # Build response for each accessible cluster
    clusters = []
    for cluster_name in accessible_cluster_names:
        # Get permissions for this cluster
        resource = Resource(
            type=ResourceType.CLUSTER, name=cluster_name, cluster=cluster_name
        )
        permissions = rbac_engine.get_permissions(principal, resource)

        # Build cluster info
        cluster_info = {"name": cluster_name, "accessible": True}

        # Get basic data
        spec = get_cluster_data(cluster_name, "spec")
        if spec:
            cluster_info["labels"] = spec.get("labels", {})
            # Use consistent displayName (not display_name) for frontend
            cluster_info["displayName"] = spec.get(
                "displayName", spec.get("display_name", cluster_name)
            )
        else:
            cluster_info["displayName"] = cluster_name
            cluster_info["labels"] = {}

        # Get cluster info (version, channel, console_url, etc.)
        info = get_cluster_data(cluster_name, "info")
        if info:
            cluster_info["console_url"] = info.get("console_url")
            cluster_info["api_url"] = info.get("api_url")
            cluster_info["platform"] = info.get("platform", "OpenShift")
            if Action.VIEW_METADATA in permissions:
                cluster_info["version"] = info.get("version")
                cluster_info["channel"] = info.get("channel")

        # Add status (always include for frontend)
        status_data = get_cluster_data(cluster_name, "status")
        if status_data:
            cluster_info["status"] = status_data
        else:
            # Provide default status if not available
            cluster_info["status"] = {
                "health": "unknown",
                "message": "Status unavailable",
                "last_check": datetime.now(timezone.utc).isoformat(),
            }

        # Get operator count for display
        operators_data = get_cluster_data(cluster_name, "operators")
        if operators_data and isinstance(operators_data, list):
            # Filter operators through RBAC engine
            filtered_operators = rbac_engine.filter_resources(
                principal=principal,
                resources=operators_data,
                resource_type=ResourceType.OPERATOR,
                cluster=cluster_name,
            )
            cluster_info["operator_count"] = len(filtered_operators)
        else:
            cluster_info["operator_count"] = 0

        # Add FILTERED metrics (always include for frontend, but respect permissions)
        if Action.VIEW_METRICS in permissions:
            # Use filtered metrics calculator
            filtered_metrics = metrics_calculator.get_filtered_cluster_metrics(
                cluster_name,
                principal,
                include_resource_details=False,  # Keep it light for list view
            )

            if filtered_metrics:
                # Include all metrics needed by the frontend
                cluster_info["metrics"] = {
                    "filtered": filtered_metrics.get("filtered", False),
                    "timestamp": filtered_metrics.get("timestamp"),
                    # Node metrics
                    "nodes": filtered_metrics.get("nodes", 0),
                    "nodes_ready": filtered_metrics.get("nodes_ready", 0),
                    "nodes_not_ready": filtered_metrics.get("nodes_not_ready", 0),
                    # Namespace and pod metrics
                    "namespaces": filtered_metrics.get("namespaces", 0),
                    "pods": filtered_metrics.get("pods", 0),
                    "pods_running": filtered_metrics.get("pods_running", 0),
                    "pods_pending": filtered_metrics.get("pods_pending", 0),
                    "pods_failed": filtered_metrics.get("pods_failed", 0),
                    # Workload metrics
                    "deployments": filtered_metrics.get("deployments", 0),
                    "services": filtered_metrics.get("services", 0),
                    "statefulsets": filtered_metrics.get("statefulsets", 0),
                    "daemonsets": filtered_metrics.get("daemonsets", 0),
                    "pvcs": filtered_metrics.get("pvcs", 0),
                    # Resource usage metrics
                    "cpu_capacity": filtered_metrics.get("cpu_capacity", 0),
                    "cpu_allocatable": filtered_metrics.get("cpu_allocatable", 0),
                    "cpu_requested": filtered_metrics.get("cpu_requested", 0),
                    "cpu_usage_percent": filtered_metrics.get("cpu_usage_percent", 0),
                    "memory_capacity": filtered_metrics.get("memory_capacity", 0),
                    "memory_allocatable": filtered_metrics.get("memory_allocatable", 0),
                    "memory_requested": filtered_metrics.get("memory_requested", 0),
                    "memory_usage_percent": filtered_metrics.get(
                        "memory_usage_percent", 0
                    ),
                    "storage_capacity": filtered_metrics.get("storage_capacity", 0),
                    "storage_used": filtered_metrics.get("storage_used", 0),
                }

                # Add filter note if applicable
                if filtered_metrics.get("filtered"):
                    cluster_info["metrics"][
                        "filter_note"
                    ] = "Counts reflect namespace permissions"
            else:
                # Provide empty metrics structure if not available
                cluster_info["metrics"] = {
                    "filtered": False,
                    "nodes": 0,
                    "nodes_ready": 0,
                    "nodes_not_ready": 0,
                    "namespaces": 0,
                    "pods": 0,
                    "pods_running": 0,
                    "pods_pending": 0,
                    "pods_failed": 0,
                    "deployments": 0,
                    "services": 0,
                    "statefulsets": 0,
                    "daemonsets": 0,
                    "pvcs": 0,
                    "cpu_capacity": 0,
                    "cpu_allocatable": 0,
                    "cpu_requested": 0,
                    "cpu_usage_percent": 0,
                    "memory_capacity": 0,
                    "memory_allocatable": 0,
                    "memory_requested": 0,
                    "memory_usage_percent": 0,
                    "storage_capacity": 0,
                    "storage_used": 0,
                }
        else:
            # User doesn't have metrics permission - provide minimal structure
            cluster_info["metrics"] = None

        clusters.append(cluster_info)

    logger.info(f"User {user.username} listed {len(clusters)} clusters")
    return clusters


@router.get("/{cluster_name}")
async def get_cluster(
    cluster_name: str, user: User = Depends(get_user_with_groups)
) -> Dict[str, Any]:
    """Get detailed information about a specific cluster with filtered metrics."""

    # Check access
    decision = await check_cluster_access(cluster_name, user)

    principal = Principal(username=user.username, email=user.email, groups=user.groups)

    # Batch fetch all data
    data_types = ["info", "spec", "status"]
    cluster_data_raw = get_cluster_data_batch(cluster_name, data_types)

    # Build response
    cluster_data = {"name": cluster_name}

    # Add spec with consistent displayName
    if spec := cluster_data_raw.get("spec"):
        # Ensure displayName is consistent
        spec["displayName"] = spec.get(
            "displayName", spec.get("display_name", cluster_name)
        )
        cluster_data["spec"] = spec
        cluster_data["displayName"] = spec["displayName"]
        cluster_data["labels"] = spec.get("labels", {})
    else:
        cluster_data["displayName"] = cluster_name
        cluster_data["labels"] = {}

    # Add info data
    if info := cluster_data_raw.get("info"):
        cluster_data["info"] = info
        # Also add top-level fields for frontend convenience
        cluster_data["version"] = info.get("version")
        cluster_data["channel"] = info.get("channel")
        cluster_data["console_url"] = info.get("console_url")
        cluster_data["api_url"] = info.get("api_url")
        cluster_data["platform"] = info.get("platform", "OpenShift")

    # Add status
    if status := cluster_data_raw.get("status"):
        cluster_data["status"] = status
    else:
        cluster_data["status"] = {
            "health": "unknown",
            "message": "Status unavailable",
            "last_check": datetime.now(timezone.utc).isoformat(),
        }

    # Get operator count
    operators_data = get_cluster_data(cluster_name, "operators")
    if operators_data and isinstance(operators_data, list):
        filtered_operators = rbac_engine.filter_resources(
            principal=principal,
            resources=operators_data,
            resource_type=ResourceType.OPERATOR,
            cluster=cluster_name,
        )
        cluster_data["operator_count"] = len(filtered_operators)
    else:
        cluster_data["operator_count"] = 0

    # Add FILTERED metrics if permitted
    if decision.can(Action.VIEW_METRICS):
        # Get filtered metrics with details
        filtered_metrics = metrics_calculator.get_filtered_cluster_metrics(
            cluster_name,
            principal,
            include_resource_details=True,  # Include details for single cluster view
        )

        if filtered_metrics:
            cluster_data["metrics"] = filtered_metrics

            # Add summary of filtering
            if filtered_metrics.get("filtered"):
                cluster_data["metrics_filtering"] = {
                    "applied": True,
                    "allowed_namespaces": filtered_metrics.get(
                        "allowed_namespaces_count", 0
                    ),
                    "filter_metadata": filtered_metrics.get("filter_metadata", {}),
                }

    # Add resource collection metadata if available
    resource_metadata = get_cluster_data(cluster_name, "resource_metadata")
    if resource_metadata:
        cluster_data["resource_collection"] = {
            "enabled": True,
            "last_collection": resource_metadata.get("timestamp"),
            "collection_time_ms": resource_metadata.get("collection_time_ms"),
            "truncated": resource_metadata.get("truncated", False),
        }

    logger.info(f"User {user.username} accessed cluster {cluster_name}")
    return cluster_data


@router.get("/{cluster_name}/nodes")
async def get_cluster_nodes(
    cluster_name: str,
    user: User = Depends(get_user_with_groups),
    role: Optional[str] = Query(None, description="Filter by node role"),
    status: Optional[str] = Query(None, description="Filter by node status"),
) -> List[Dict[str, Any]]:
    """Get nodes for a specific cluster."""

    # Check cluster access
    await check_cluster_access(cluster_name, user)

    principal = Principal(username=user.username, email=user.email, groups=user.groups)

    # Get all nodes
    node_names = redis_client.smembers(f"cluster:{cluster_name}:nodes")
    nodes = []

    for node_name in node_names:
        node_data = redis_client.hgetall(f"cluster:{cluster_name}:node:{node_name}")
        if node_data and "current" in node_data:
            node = json.loads(node_data["current"])

            # Apply query filters
            if role and role not in node.get("roles", []):
                continue
            if status and node.get("status") != status:
                continue

            nodes.append(node)

    # Let RBAC engine filter the nodes
    filtered_nodes = rbac_engine.filter_resources(
        principal=principal,
        resources=nodes,
        resource_type=ResourceType.NODE,
        cluster=cluster_name,
    )

    logger.info(
        f"User {user.username} accessed {len(filtered_nodes)} nodes for cluster {cluster_name}"
    )
    return filtered_nodes


@router.get("/{cluster_name}/nodes/{node_name}")
async def get_cluster_node(
    cluster_name: str,
    node_name: str,
    user: User = Depends(get_user_with_groups),
    include_metrics: bool = Query(False, description="Include node metrics history"),
) -> Dict[str, Any]:
    """Get detailed information about a specific node."""

    # Check cluster access
    decision = await check_cluster_access(cluster_name, user)

    principal = Principal(username=user.username, email=user.email, groups=user.groups)

    # Get node data
    node_data = redis_client.hgetall(f"cluster:{cluster_name}:node:{node_name}")
    if not node_data or "current" not in node_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {node_name} not found in cluster {cluster_name}",
        )

    node = json.loads(node_data["current"])

    # Let RBAC engine filter the node
    filtered_nodes = rbac_engine.filter_resources(
        principal=principal,
        resources=[node],
        resource_type=ResourceType.NODE,
        cluster=cluster_name,
    )

    if not filtered_nodes:
        raise AuthorizationError(f"Access to node {node_name} is not permitted")

    node = filtered_nodes[0]

    # Add metrics history if requested
    if include_metrics and decision.can(Action.VIEW_METRICS):
        metrics_key = f"cluster:{cluster_name}:node:{node_name}:metrics"
        # Get last 100 metrics points
        metrics = redis_client.zrevrange(metrics_key, 0, 99)
        node["metrics_history"] = [json.loads(m) for m in metrics]

    # Add conditions
    conditions_key = f"cluster:{cluster_name}:node:{node_name}:conditions"
    conditions = redis_client.hgetall(conditions_key)
    if conditions:
        node["current_conditions"] = {k: json.loads(v) for k, v in conditions.items()}

    return node


@router.get("/{cluster_name}/operators")
async def get_cluster_operators(
    cluster_name: str,
    user: User = Depends(get_user_with_groups),
    namespace: Optional[str] = Query(None, description="Filter by namespace"),
    status_filter: Optional[str] = Query(
        None, description="Filter by status", alias="status"
    ),
) -> List[Dict[str, Any]]:
    """Get operators for a specific cluster."""

    # Check cluster access
    await check_cluster_access(cluster_name, user)

    principal = Principal(username=user.username, email=user.email, groups=user.groups)

    # Get operators data
    operators_data = get_cluster_data(cluster_name, "operators")
    if not operators_data:
        return []

    operators = operators_data if isinstance(operators_data, list) else []

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

    # Let RBAC engine filter the operators
    filtered_operators = rbac_engine.filter_resources(
        principal=principal,
        resources=operators,
        resource_type=ResourceType.OPERATOR,
        cluster=cluster_name,
    )

    logger.info(
        f"User {user.username} accessed {len(filtered_operators)} operators for cluster {cluster_name}"
    )
    return filtered_operators


@router.get("/{cluster_name}/namespaces")
async def get_cluster_namespaces(
    cluster_name: str,
    user: User = Depends(get_user_with_groups),
    with_operator_count: bool = Query(
        False, description="Include operator count per namespace"
    ),
    with_resource_counts: bool = Query(
        False, description="Include resource counts per namespace"
    ),
) -> List[Any]:
    """Get namespaces for a specific cluster - ONLY those the user can access."""

    # Check cluster access
    await check_cluster_access(cluster_name, user)

    principal = Principal(username=user.username, email=user.email, groups=user.groups)

    # Get allowed namespaces directly from the metrics calculator
    allowed_namespaces = metrics_calculator.get_allowed_namespaces(
        cluster_name, principal
    )

    # Convert to sorted list
    namespace_list = sorted(allowed_namespaces)

    # If no additional details requested, return simple list
    if not with_operator_count and not with_resource_counts:
        logger.info(
            f"User {user.username} accessed {len(namespace_list)} namespaces for cluster {cluster_name}"
        )
        return namespace_list

    # Build detailed response
    namespace_details = []

    for ns in namespace_list:
        detail = {"namespace": ns}

        # Add operator count if requested
        if with_operator_count:
            operators_data = get_cluster_data(cluster_name, "operators")
            if operators_data:
                # Filter operators for this namespace
                filtered_operators = rbac_engine.filter_resources(
                    principal=principal,
                    resources=(
                        operators_data if isinstance(operators_data, list) else []
                    ),
                    resource_type=ResourceType.OPERATOR,
                    cluster=cluster_name,
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

                detail["operator_count"] = operator_count
                detail["available_operators"] = available_operators[
                    :5
                ]  # First 5 for preview
                detail["has_more_operators"] = operator_count > 5

        # Add resource counts if requested
        if with_resource_counts:
            counts = {
                "pods": 0,
                "deployments": 0,
                "services": 0,
                "statefulsets": 0,
                "daemonsets": 0,
            }

            # Count pods
            pods_data = redis_client.get(f"cluster:{cluster_name}:pods")
            if pods_data:
                try:
                    pods = json.loads(pods_data)
                    counts["pods"] = sum(1 for p in pods if p.get("namespace") == ns)
                except:
                    pass

            # Count deployments
            deps_data = redis_client.get(f"cluster:{cluster_name}:deployments")
            if deps_data:
                try:
                    deps = json.loads(deps_data)
                    counts["deployments"] = sum(
                        1 for d in deps if d.get("namespace") == ns
                    )
                except:
                    pass

            # Count services
            svcs_data = redis_client.get(f"cluster:{cluster_name}:services")
            if svcs_data:
                try:
                    svcs = json.loads(svcs_data)
                    counts["services"] = sum(
                        1 for s in svcs if s.get("namespace") == ns
                    )
                except:
                    pass

            # Count statefulsets
            sts_data = redis_client.get(f"cluster:{cluster_name}:statefulsets")
            if sts_data:
                try:
                    sts = json.loads(sts_data)
                    counts["statefulsets"] = sum(
                        1 for s in sts if s.get("namespace") == ns
                    )
                except:
                    pass

            # Count daemonsets
            ds_data = redis_client.get(f"cluster:{cluster_name}:daemonsets")
            if ds_data:
                try:
                    ds = json.loads(ds_data)
                    counts["daemonsets"] = sum(
                        1 for d in ds if d.get("namespace") == ns
                    )
                except:
                    pass

            detail["resource_counts"] = counts
            detail["total_resources"] = sum(counts.values())

        namespace_details.append(detail)

    # Sort by total resources if we have counts, otherwise by name
    if with_resource_counts:
        namespace_details.sort(key=lambda x: x.get("total_resources", 0), reverse=True)

    logger.info(
        f"User {user.username} accessed {len(namespace_details)} namespaces for cluster {cluster_name}"
    )
    return namespace_details


@router.get("/{cluster_name}/metrics")
async def get_cluster_metrics(
    cluster_name: str,
    user: User = Depends(get_user_with_groups),
    include_costs: bool = Query(False, description="Include cost metrics"),
    detailed: bool = Query(False, description="Include detailed breakdown"),
) -> Dict[str, Any]:
    """Get FILTERED metrics for a specific cluster based on namespace permissions."""

    # Check cluster access
    decision = await check_cluster_access(cluster_name, user, Action.VIEW_METRICS)

    # Additional check for cost metrics
    if include_costs and not decision.can(Action.VIEW_COSTS):
        raise AuthorizationError("Access to cost metrics is not permitted")

    principal = Principal(username=user.username, email=user.email, groups=user.groups)

    # Get filtered metrics
    filtered_metrics = metrics_calculator.get_filtered_cluster_metrics(
        cluster_name, principal, include_resource_details=detailed
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

    # Add explicit filtering information
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
        f"User {user.username} accessed {'filtered' if filtered_metrics.get('filtered') else 'full'} "
        f"metrics for cluster {cluster_name}"
    )

    return response


@router.get("/{cluster_name}/alerts")
async def get_cluster_alerts(
    cluster_name: str,
    user: User = Depends(get_user_with_groups),
    severity: Optional[str] = Query(None, description="Filter by severity"),
) -> List[Dict[str, Any]]:
    """Get alerts for a specific cluster."""

    # Check cluster access
    await check_cluster_access(cluster_name, user)

    principal = Principal(username=user.username, email=user.email, groups=user.groups)

    # Get alerts from Redis
    alerts = []
    alert_pattern = f"alerts:{cluster_name}:*"

    for key in redis_client.scan_iter(match=alert_pattern):
        alert_data = redis_client.hgetall(key)
        if alert_data:
            # Apply severity filter
            if severity and alert_data.get("severity") != severity:
                continue
            alerts.append(alert_data)

    # Let RBAC engine filter the alerts
    filtered_alerts = rbac_engine.filter_resources(
        principal=principal,
        resources=alerts,
        resource_type=ResourceType.ALERT,
        cluster=cluster_name,
    )

    # Sort by timestamp
    filtered_alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    logger.info(
        f"User {user.username} accessed {len(filtered_alerts)} alerts for cluster {cluster_name}"
    )
    return filtered_alerts


@router.get("/{cluster_name}/events")
async def get_cluster_events(
    cluster_name: str,
    user: User = Depends(get_user_with_groups),
    limit: int = Query(100, description="Maximum number of events"),
) -> List[Dict[str, Any]]:
    """Get recent events for a specific cluster."""

    # Check cluster access
    await check_cluster_access(cluster_name, user)

    principal = Principal(username=user.username, email=user.email, groups=user.groups)

    # Get events from Redis
    events_key = f"events:{cluster_name}"
    raw_events = redis_client.lrange(events_key, 0, limit - 1)

    events = []
    for event_str in raw_events:
        try:
            events.append(json.loads(event_str))
        except json.JSONDecodeError:
            continue

    # Let RBAC engine filter the events
    filtered_events = rbac_engine.filter_resources(
        principal=principal,
        resources=events,
        resource_type=ResourceType.EVENT,
        cluster=cluster_name,
    )

    logger.info(
        f"User {user.username} accessed {len(filtered_events)} events for cluster {cluster_name}"
    )
    return filtered_events
