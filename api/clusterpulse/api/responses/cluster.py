"""Response builders for cluster endpoints."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from clusterpulse.services.rbac import Action, RBACDecision


class ClusterResponseBuilder:
    """Builder for cluster detail response objects."""

    def __init__(self, cluster_name: str):
        self.cluster_name = cluster_name
        self.data = {"name": cluster_name}

    def with_spec(self, spec: Optional[Dict]) -> "ClusterResponseBuilder":
        """Add spec data with normalized displayName."""
        if spec:
            # Normalize displayName - ensure consistency
            display_name = (
                spec.get("displayName")
                or spec.get("display_name")
                or self.cluster_name
            )
            spec["displayName"] = display_name

            self.data["spec"] = spec
            self.data["displayName"] = display_name
            self.data["labels"] = spec.get("labels", {})
        else:
            self.data["displayName"] = self.cluster_name
            self.data["labels"] = {}

        return self

    def with_status(self, status: Optional[Dict]) -> "ClusterResponseBuilder":
        """Add status with fallback for missing data."""
        self.data["status"] = status or {
            "health": "unknown",
            "message": "Status unavailable",
            "last_check": datetime.now(timezone.utc).isoformat(),
        }
        return self

    def with_info(
        self, info: Optional[Dict], include_version: bool = True
    ) -> "ClusterResponseBuilder":
        """Add cluster info (console, API URL, version, etc)."""
        if info:
            self.data["info"] = info
            self.data["console_url"] = info.get("console_url")
            self.data["api_url"] = info.get("api_url")
            self.data["platform"] = info.get("platform", "OpenShift")

            if include_version:
                self.data["version"] = info.get("version")
                self.data["channel"] = info.get("channel")

        return self

    def with_metrics(
        self, metrics: Optional[Dict], decision: RBACDecision
    ) -> "ClusterResponseBuilder":
        """Add metrics if user has VIEW_METRICS permission."""
        if decision.can(Action.VIEW_METRICS) and metrics:
            self.data["metrics"] = metrics
        else:
            self.data["metrics"] = None

        return self

    def with_operator_count(self, count: int) -> "ClusterResponseBuilder":
        """Add operator count."""
        self.data["operator_count"] = count
        return self

    def with_resource_collection_metadata(
        self, metadata: Optional[Dict]
    ) -> "ClusterResponseBuilder":
        """Add resource collection metadata if available."""
        if metadata:
            self.data["resource_collection"] = {
                "enabled": True,
                "last_collection": metadata.get("timestamp"),
                "collection_time_ms": metadata.get("collection_time_ms"),
                "truncated": metadata.get("truncated", False),
            }
        return self

    def with_metrics_filtering_info(
        self, filtered_metrics: Dict
    ) -> "ClusterResponseBuilder":
        """Add filtering summary if metrics were filtered."""
        if filtered_metrics.get("filtered"):
            self.data["metrics_filtering"] = {
                "applied": True,
                "allowed_namespaces": filtered_metrics.get(
                    "allowed_namespaces_count", 0
                ),
                "filter_metadata": filtered_metrics.get("filter_metadata", {}),
            }
        return self

    def build(self) -> Dict[str, Any]:
        """Build and return the final response dictionary."""
        return self.data


class ClusterListItemBuilder:
    """Builder for cluster items in list responses."""

    def __init__(self, cluster_name: str):
        self.cluster_name = cluster_name
        self.data = {"name": cluster_name, "accessible": True}

    def with_spec(self, spec: Optional[Dict]) -> "ClusterListItemBuilder":
        """Add spec data with normalized displayName."""
        if spec:
            display_name = (
                spec.get("displayName")
                or spec.get("display_name")
                or self.cluster_name
            )
            self.data["displayName"] = display_name
            self.data["labels"] = spec.get("labels", {})
        else:
            self.data["displayName"] = self.cluster_name
            self.data["labels"] = {}

        return self

    def with_status(self, status: Optional[Dict]) -> "ClusterListItemBuilder":
        """Add status with fallback."""
        self.data["status"] = status or {
            "health": "unknown",
            "message": "Status unavailable",
            "last_check": datetime.now(timezone.utc).isoformat(),
        }
        return self

    def with_info(self, info: Optional[Dict]) -> "ClusterListItemBuilder":
        """Add basic cluster info."""
        if info:
            self.data["console_url"] = info.get("console_url")
            self.data["api_url"] = info.get("api_url")
            self.data["platform"] = info.get("platform", "OpenShift")
            self.data["version"] = info.get("version")
            self.data["channel"] = info.get("channel")
        return self

    def with_metrics(
        self, metrics: Optional[Dict], has_permission: bool
    ) -> "ClusterListItemBuilder":
        """Add filtered metrics if user has permission."""
        if has_permission and metrics:
            # Include all metrics needed by frontend
            self.data["metrics"] = {
                "filtered": metrics.get("filtered", False),
                "timestamp": metrics.get("timestamp"),
                # Node metrics
                "nodes": metrics.get("nodes", 0),
                "nodes_ready": metrics.get("nodes_ready", 0),
                "nodes_not_ready": metrics.get("nodes_not_ready", 0),
                # Namespace and pod metrics
                "namespaces": metrics.get("namespaces", 0),
                "pods": metrics.get("pods", 0),
                "pods_running": metrics.get("pods_running", 0),
                "pods_pending": metrics.get("pods_pending", 0),
                "pods_failed": metrics.get("pods_failed", 0),
                # Workload metrics
                "deployments": metrics.get("deployments", 0),
                "services": metrics.get("services", 0),
                "statefulsets": metrics.get("statefulsets", 0),
                "daemonsets": metrics.get("daemonsets", 0),
                "pvcs": metrics.get("pvcs", 0),
                # Resource usage
                "cpu_capacity": metrics.get("cpu_capacity", 0),
                "cpu_allocatable": metrics.get("cpu_allocatable", 0),
                "cpu_requested": metrics.get("cpu_requested", 0),
                "cpu_usage_percent": metrics.get("cpu_usage_percent", 0),
                "memory_capacity": metrics.get("memory_capacity", 0),
                "memory_allocatable": metrics.get("memory_allocatable", 0),
                "memory_requested": metrics.get("memory_requested", 0),
                "memory_usage_percent": metrics.get("memory_usage_percent", 0),
                "storage_capacity": metrics.get("storage_capacity", 0),
                "storage_used": metrics.get("storage_used", 0),
            }

            if metrics.get("filtered"):
                self.data["metrics"]["filter_note"] = (
                    "Counts reflect namespace permissions"
                )
        else:
            self.data["metrics"] = None

        return self

    def with_operator_count(self, count: int) -> "ClusterListItemBuilder":
        """Add operator count."""
        self.data["operator_count"] = count
        return self

    def build(self) -> Dict[str, Any]:
        """Build and return the final item dictionary."""
        return self.data


class NamespaceDetailBuilder:
    """Builder for namespace detail responses."""

    def __init__(self, namespace: str):
        self.data = {"namespace": namespace}

    def with_operator_count(
        self, count: int, operators: List[str], has_more: bool = False
    ) -> "NamespaceDetailBuilder":
        """Add operator information."""
        self.data["operator_count"] = count
        self.data["available_operators"] = operators
        self.data["has_more_operators"] = has_more
        return self

    def with_resource_counts(self, counts: Dict[str, int]) -> "NamespaceDetailBuilder":
        """Add resource counts."""
        self.data["resource_counts"] = counts
        self.data["total_resources"] = sum(counts.values())
        return self

    def build(self) -> Dict[str, Any]:
        """Build and return the final namespace detail."""
        return self.data
