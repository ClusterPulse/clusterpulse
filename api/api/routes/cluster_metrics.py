"""
Helper functions for calculating filtered metrics based on RBAC permissions.
ALL filtering goes through the centralized RBAC engine.
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import redis
from src.core.logging import get_logger
from src.core.rbac_engine import Principal, RBACEngine, ResourceType

logger = get_logger(__name__)


class FilteredMetricsCalculator:
    """
    Calculate metrics filtered by RBAC permissions.
    ALL filtering is delegated to the RBAC engine.
    """

    def __init__(self, redis_client: redis.Redis, rbac_engine: RBACEngine):
        self.redis = redis_client
        self.rbac = rbac_engine

    def get_filtered_cluster_metrics(
        self,
        cluster_name: str,
        principal: Principal,
        include_resource_details: bool = False,
    ) -> Dict[str, Any]:
        """
        Get cluster metrics filtered by user's permissions.
        All filtering goes through the RBAC engine.
        """
        # Get the base metrics (unfiltered)
        base_metrics = self._get_base_metrics(cluster_name)
        if not base_metrics:
            return {}

        # Check if detailed resource data
        has_detailed = self._has_detailed_resources(cluster_name)

        if not has_detailed:
            # No detailed data - return base metrics with a note
            base_metrics["filtered"] = False
            base_metrics["filter_note"] = (
                "Detailed filtering not available - showing total counts"
            )
            return base_metrics

        # Calculate filtered metrics using RBAC engine
        filtered_metrics = self._calculate_filtered_metrics_via_rbac(
            cluster_name, principal, base_metrics, include_resource_details
        )

        return filtered_metrics

    def _get_base_metrics(self, cluster_name: str) -> Optional[Dict[str, Any]]:
        """Get base metrics from Redis."""
        try:
            data = self.redis.get(f"cluster:{cluster_name}:metrics")
            if data:
                return json.loads(data)
        except Exception as e:
            logger.error(f"Error getting base metrics for {cluster_name}: {e}")
        return None

    def _has_detailed_resources(self, cluster_name: str) -> bool:
        """Check if detailed resource data is available."""
        metadata_key = f"cluster:{cluster_name}:resource_metadata"
        return self.redis.exists(metadata_key) > 0

    def _get_all_cluster_namespaces(self, cluster_name: str) -> List[str]:
        """Get all actual namespaces in the cluster from the new storage format."""
        # First, try the new dedicated namespace storage
        ns_data = self.redis.get(f"cluster:{cluster_name}:namespaces")
        if ns_data:
            try:
                namespace_info = json.loads(ns_data)
                if isinstance(namespace_info, dict):
                    # New format: {"namespaces": [...], "count": N, "timestamp": "..."}
                    namespaces = namespace_info.get("namespaces", [])
                    if namespaces:
                        logger.debug(
                            f"Retrieved {len(namespaces)} namespaces from dedicated storage "
                            f"for cluster {cluster_name}"
                        )
                        return namespaces
                elif isinstance(namespace_info, list):
                    # Backward compatibility: direct list
                    return namespace_info
            except json.JSONDecodeError:
                logger.error(
                    f"Failed to decode namespace data for cluster {cluster_name}"
                )

        # Fallback: Try to get from namespace set (more efficient for membership checks)
        ns_set_key = f"cluster:{cluster_name}:namespaces:set"
        namespaces_set = self.redis.smembers(ns_set_key)
        if namespaces_set:
            namespaces = sorted(namespaces_set)
            logger.debug(
                f"Retrieved {len(namespaces)} namespaces from set storage "
                f"for cluster {cluster_name}"
            )
            return namespaces

        return []

    def _get_all_cluster_nodes(self, cluster_name: str) -> List[Dict[str, Any]]:
        """Get all nodes in the cluster."""
        nodes = []
        node_names = self.redis.smembers(f"cluster:{cluster_name}:nodes")

        for node_name in node_names:
            node_data = self.redis.hget(
                f"cluster:{cluster_name}:node:{node_name}", "current"
            )
            if node_data:
                try:
                    node = json.loads(node_data)
                    nodes.append(node)
                except json.JSONDecodeError:
                    logger.error(f"Failed to decode node data for {node_name}")

        return nodes

    def _calculate_filtered_metrics_via_rbac(
        self,
        cluster_name: str,
        principal: Principal,
        base_metrics: Dict[str, Any],
        include_details: bool,
    ) -> Dict[str, Any]:
        """
        Calculate metrics by using RBAC engine to filter each resource type.
        This ensures all filtering logic goes through the centralized engine.

        IMPORTANT: Both nodes AND namespace-scoped resources are filtered through RBAC.
        """

        # Start with base metrics structure
        filtered = base_metrics.copy()

        # Track if any filtering was applied
        any_filtering_applied = False

        # ========================================================================
        # FILTER NODES THROUGH RBAC ENGINE
        # ========================================================================
        all_nodes = self._get_all_cluster_nodes(cluster_name)

        if all_nodes:
            # Filter nodes through RBAC engine
            filtered_nodes = self.rbac.filter_resources(
                principal=principal,
                resources=all_nodes,
                resource_type=ResourceType.NODE,
                cluster=cluster_name,
            )

            # Check if node filtering was applied
            if len(filtered_nodes) != len(all_nodes):
                any_filtering_applied = True
                logger.debug(
                    f"Node filtering for {principal.username}: "
                    f"{len(filtered_nodes)}/{len(all_nodes)} nodes allowed"
                )

            # Update node counts based on filtered results
            filtered["nodes"] = len(filtered_nodes)
            filtered["nodes_ready"] = sum(
                1 for node in filtered_nodes if node.get("status") == "Ready"
            )
            filtered["nodes_not_ready"] = filtered["nodes"] - filtered["nodes_ready"]

            # Recalculate node capacity/usage based on filtered nodes
            if filtered_nodes:
                # CPU metrics
                filtered["cpu_capacity"] = sum(
                    node.get("cpu_capacity", 0) for node in filtered_nodes
                )
                filtered["cpu_allocatable"] = sum(
                    node.get("cpu_allocatable", 0) for node in filtered_nodes
                )
                filtered["cpu_requested"] = sum(
                    node.get("cpu_requested", 0) for node in filtered_nodes
                )
                if filtered["cpu_capacity"] > 0:
                    filtered["cpu_usage_percent"] = (
                        filtered["cpu_requested"] / filtered["cpu_capacity"] * 100
                    )
                else:
                    filtered["cpu_usage_percent"] = 0

                # Memory metrics
                filtered["memory_capacity"] = sum(
                    node.get("memory_capacity", 0) for node in filtered_nodes
                )
                filtered["memory_allocatable"] = sum(
                    node.get("memory_allocatable", 0) for node in filtered_nodes
                )
                filtered["memory_requested"] = sum(
                    node.get("memory_requested", 0) for node in filtered_nodes
                )
                if filtered["memory_capacity"] > 0:
                    filtered["memory_usage_percent"] = (
                        filtered["memory_requested"] / filtered["memory_capacity"] * 100
                    )
                else:
                    filtered["memory_usage_percent"] = 0

                # Storage metrics
                filtered["storage_capacity"] = sum(
                    node.get("storage_capacity", 0) for node in filtered_nodes
                )
                filtered["storage_used"] = sum(
                    node.get("storage_used", 0) for node in filtered_nodes
                )
            else:
                # No nodes visible - zero out all node metrics
                filtered["cpu_capacity"] = 0
                filtered["cpu_allocatable"] = 0
                filtered["cpu_requested"] = 0
                filtered["cpu_usage_percent"] = 0
                filtered["memory_capacity"] = 0
                filtered["memory_allocatable"] = 0
                filtered["memory_requested"] = 0
                filtered["memory_usage_percent"] = 0
                filtered["storage_capacity"] = 0
                filtered["storage_used"] = 0

            # Add node details if requested
            if include_details and filtered_nodes:
                node_roles = {}
                for node in filtered_nodes:
                    for role in node.get("roles", []):
                        node_roles[role] = node_roles.get(role, 0) + 1
                filtered["node_roles"] = node_roles
                filtered["node_names"] = [
                    n.get("name") for n in filtered_nodes[:10]
                ]  # First 10

        # ========================================================================
        # FILTER NAMESPACES THROUGH RBAC ENGINE
        # ========================================================================
        all_namespaces = self._get_all_cluster_namespaces(cluster_name)
        namespace_resources = [{"name": ns, "namespace": ns} for ns in all_namespaces]

        # Filter namespaces through RBAC engine
        filtered_namespace_resources = self.rbac.filter_resources(
            principal=principal,
            resources=namespace_resources,
            resource_type=ResourceType.NAMESPACE,
            cluster=cluster_name,
        )

        # Extract allowed namespace names
        allowed_namespaces = set(ns["name"] for ns in filtered_namespace_resources)

        # Check if namespace filtering is applied
        if len(allowed_namespaces) < len(all_namespaces):
            any_filtering_applied = True

        # Update namespace count with ACTUAL filtered namespace count
        filtered["namespaces"] = len(allowed_namespaces)
        original_namespace_count = base_metrics.get("namespaces", len(all_namespaces))

        logger.debug(
            f"Namespace filtering for {principal.username}: "
            f"{len(allowed_namespaces)}/{len(all_namespaces)} namespaces allowed"
        )

        # ========================================================================
        # FILTER NAMESPACE-SCOPED RESOURCES
        # ========================================================================
        namespace_scoped_resources = [
            ("pods", ResourceType.POD),
            ("deployments", ResourceType.POD),  # Use POD type for namespace filtering
            ("services", ResourceType.POD),  # Use POD type for namespace filtering
            ("statefulsets", ResourceType.POD),  # Use POD type for namespace filtering
            ("daemonsets", ResourceType.POD),  # Use POD type for namespace filtering
            ("pvcs", ResourceType.POD),  # PVCs are also namespace-scoped
        ]

        for resource_key, resource_type in namespace_scoped_resources:
            # Skip if this resource type doesn't exist
            if resource_key == "pvcs":
                # PVCs might not have detailed data, just set to 0 if filtered
                if any_filtering_applied:
                    filtered["pvcs"] = 0  # We can't filter PVCs without detailed data
                continue

            # Get raw data from Redis
            data = self.redis.get(f"cluster:{cluster_name}:{resource_key}")
            if not data:
                filtered[resource_key] = 0
                continue

            try:
                resources = json.loads(data)
                if not isinstance(resources, list):
                    filtered[resource_key] = 0
                    continue

                # Use RBAC engine to filter resources
                filtered_resources = self.rbac.filter_resources(
                    principal=principal,
                    resources=resources,
                    resource_type=resource_type,
                    cluster=cluster_name,
                )

                # Check if filtering was applied
                if len(filtered_resources) != len(resources):
                    any_filtering_applied = True

                # Update counts
                filtered[resource_key] = len(filtered_resources)

                # Process by status for pods
                if resource_key == "pods":
                    filtered["pods_running"] = sum(
                        1
                        for p in filtered_resources
                        if p.get("status", "").lower() == "running"
                    )
                    filtered["pods_pending"] = sum(
                        1
                        for p in filtered_resources
                        if p.get("status", "").lower() == "pending"
                    )
                    filtered["pods_failed"] = sum(
                        1
                        for p in filtered_resources
                        if p.get("status", "").lower() == "failed"
                    )

                    if include_details:
                        # Show which namespaces have pods
                        pod_namespaces = set(
                            p.get("namespace")
                            for p in filtered_resources
                            if p.get("namespace")
                        )
                        filtered["pod_namespaces"] = sorted(pod_namespaces)
                        filtered["pod_namespace_count"] = len(pod_namespaces)

                # Add deployment summary if requested
                if resource_key == "deployments" and include_details:
                    filtered["deployment_summary"] = {
                        "total": len(filtered_resources),
                        "ready": sum(
                            1
                            for d in filtered_resources
                            if d.get("ready", 0) == d.get("replicas", 1)
                        ),
                    }

                # Add service type breakdown if requested
                if resource_key == "services" and include_details:
                    svc_types = {}
                    for svc in filtered_resources:
                        svc_type = svc.get("type", "Unknown")
                        svc_types[svc_type] = svc_types.get(svc_type, 0) + 1
                    filtered["services_by_type"] = svc_types

            except Exception as e:
                logger.error(f"Error filtering {resource_key}: {e}")
                filtered[resource_key] = 0

        # ========================================================================
        # FILTER OPERATORS
        # ========================================================================
        operators_data = self.redis.get(f"cluster:{cluster_name}:operators")
        if operators_data:
            try:
                operators = json.loads(operators_data)
                filtered_operators = self.rbac.filter_resources(
                    principal=principal,
                    resources=operators,
                    resource_type=ResourceType.OPERATOR,
                    cluster=cluster_name,
                )

                if len(filtered_operators) != len(operators):
                    any_filtering_applied = True

                # Operators count is not in standard metrics, but we can add it
                if include_details:
                    filtered["operators"] = len(filtered_operators)
                    filtered["operators_total"] = len(operators)

            except Exception as e:
                logger.error(f"Error filtering operators: {e}")

        # ========================================================================
        # SET FILTERING METADATA
        # ========================================================================
        filtered["filtered"] = any_filtering_applied

        if any_filtering_applied:
            # Add filtering metadata
            filtered["filter_metadata"] = {
                "applied": True,
                "type": "rbac-based",
                "allowed_namespaces": len(allowed_namespaces),
                "total_namespaces": original_namespace_count,
                "allowed_nodes": filtered["nodes"],
                "total_nodes": (
                    len(all_nodes) if all_nodes else base_metrics.get("nodes", 0)
                ),
                "timestamp": datetime.utcnow().isoformat(),
            }

            if include_details:
                filtered["filter_details"] = {
                    "allowed_namespaces": sorted(allowed_namespaces)[:20],  # First 20
                    "total_allowed_namespaces": len(allowed_namespaces),
                    "allowed_nodes": filtered["nodes"],
                    "total_nodes": (
                        len(all_nodes) if all_nodes else base_metrics.get("nodes", 0)
                    ),
                    "note": "All counts reflect RBAC permissions for both nodes and namespaces.",
                }

        # Log returning
        logger.debug(
            f"Returning filtered metrics for {cluster_name}: "
            f"filtered={any_filtering_applied}, "
            f"nodes={filtered.get('nodes')}/{len(all_nodes) if all_nodes else 'N/A'}, "
            f"namespaces={filtered.get('namespaces')}/{len(all_namespaces)}, "
            f"pods={filtered.get('pods')}, "
            f"cpu_capacity={filtered.get('cpu_capacity')}, "
            f"memory_capacity={filtered.get('memory_capacity')}"
        )

        return filtered

    def get_namespace_filtered_counts(
        self, cluster_name: str, principal: Principal
    ) -> Dict[str, int]:
        """
        Get simple counts filtered by RBAC engine.
        Lighter weight than full metrics calculation.
        """
        # Get actual namespace list and filter it
        all_namespaces = self._get_all_cluster_namespaces(cluster_name)
        namespace_resources = [{"name": ns, "namespace": ns} for ns in all_namespaces]

        filtered_namespace_resources = self.rbac.filter_resources(
            principal=principal,
            resources=namespace_resources,
            resource_type=ResourceType.NAMESPACE,
            cluster=cluster_name,
        )

        allowed_namespaces = set(ns["name"] for ns in filtered_namespace_resources)

        # Also get node counts
        all_nodes = self._get_all_cluster_nodes(cluster_name)
        filtered_nodes = self.rbac.filter_resources(
            principal=principal,
            resources=all_nodes,
            resource_type=ResourceType.NODE,
            cluster=cluster_name,
        )

        counts = {
            "filtered": len(allowed_namespaces) < len(all_namespaces)
            or len(filtered_nodes) < len(all_nodes),
            "namespaces": len(allowed_namespaces),
            "total_namespaces": len(all_namespaces),
            "nodes": len(filtered_nodes),
            "total_nodes": len(all_nodes),
            "pods": 0,
            "deployments": 0,
            "services": 0,
            "statefulsets": 0,
            "daemonsets": 0,
        }

        # Process each resource type through RBAC engine
        for resource_type in [
            "pods",
            "deployments",
            "services",
            "statefulsets",
            "daemonsets",
        ]:
            data = self.redis.get(f"cluster:{cluster_name}:{resource_type}")
            if data:
                try:
                    resources = json.loads(data)

                    # Use RBAC engine to filter
                    filtered = self.rbac.filter_resources(
                        principal=principal,
                        resources=resources,
                        resource_type=ResourceType.POD,  # Use POD for namespace filtering
                        cluster=cluster_name,
                    )

                    counts[resource_type] = len(filtered)

                except Exception as e:
                    logger.error(f"Error counting {resource_type}: {e}")

        return counts

    def get_allowed_namespaces(
        self, cluster_name: str, principal: Principal
    ) -> Set[str]:
        """
        Get allowed namespaces by filtering actual namespace list through RBAC engine.
        Returns a set of namespace names the user can access.
        """
        # Get all actual namespaces using the updated method
        all_namespaces = self._get_all_cluster_namespaces(cluster_name)

        # Create namespace resources
        namespace_resources = [{"name": ns, "namespace": ns} for ns in all_namespaces]

        # Filter through RBAC engine
        filtered_namespace_resources = self.rbac.filter_resources(
            principal=principal,
            resources=namespace_resources,
            resource_type=ResourceType.NAMESPACE,
            cluster=cluster_name,
        )

        # Extract allowed namespace names
        allowed_namespaces = set(ns["name"] for ns in filtered_namespace_resources)

        logger.debug(
            f"Allowed namespaces for {principal.username} in {cluster_name}: "
            f"{len(allowed_namespaces)}/{len(all_namespaces)}"
        )

        return allowed_namespaces


# Create singleton instance
def create_metrics_calculator(
    redis_client: redis.Redis, rbac_engine: RBACEngine
) -> FilteredMetricsCalculator:
    """Factory function to create metrics calculator."""
    return FilteredMetricsCalculator(redis_client, rbac_engine)
