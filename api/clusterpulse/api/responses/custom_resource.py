"""Response builders for custom resource endpoints."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class MetricSourceListItemBuilder:
    """Builder for MetricSource list item responses."""

    def __init__(self, source_id: str):
        """Initialize builder with source identifier.

        Args:
            source_id: MetricSource identifier (namespace/name)
        """
        parts = source_id.split("/", 1)
        if len(parts) == 2:
            namespace, name = parts
        else:
            namespace, name = "", source_id

        self.data = {
            "id": source_id,
            "name": name,
            "namespace": namespace,
            "resourceTypeName": None,
            "sourceKind": None,
            "sourceApiVersion": None,
            "phase": "Unknown",
            "lastCollectionTime": None,
            "resourcesCollected": 0,
        }

    def with_definition(
        self, definition: Optional[Dict[str, Any]]
    ) -> "MetricSourceListItemBuilder":
        """Add MetricSource definition data.

        Args:
            definition: Compiled MetricSource definition

        Returns:
            Self for chaining
        """
        if definition:
            self.data["name"] = definition.get("name", self.data["name"])

            rbac = definition.get("rbac", {})
            self.data["resourceTypeName"] = rbac.get("resourceTypeName")

            source = definition.get("source", {})
            self.data["sourceKind"] = source.get("kind")
            self.data["sourceApiVersion"] = source.get("apiVersion")

            # Collection settings
            collection = definition.get("collection", {})
            self.data["intervalSeconds"] = collection.get("intervalSeconds")
            self.data["maxResources"] = collection.get("maxResources")

        return self

    def with_status(
        self, status: Optional[Dict[str, Any]]
    ) -> "MetricSourceListItemBuilder":
        """Add MetricSource status data.

        Args:
            status: MetricSource status information

        Returns:
            Self for chaining
        """
        if status:
            self.data["phase"] = status.get("phase", "Unknown")
            self.data["lastCollectionTime"] = status.get("lastCollectionTime")
            self.data["resourcesCollected"] = status.get("resourcesCollected", 0)
            self.data["clustersCollected"] = status.get("clustersCollected", 0)
            self.data["errorsLastRun"] = status.get("errorsLastRun", 0)

            if status.get("message"):
                self.data["statusMessage"] = status["message"]

        return self

    def build(self) -> Dict[str, Any]:
        """Build and return the final response dictionary."""
        return self.data


class MetricSourceDetailBuilder:
    """Builder for detailed MetricSource responses."""

    def __init__(self, source_id: str):
        """Initialize builder with source identifier.

        Args:
            source_id: MetricSource identifier (namespace/name)
        """
        parts = source_id.split("/", 1)
        if len(parts) == 2:
            namespace, name = parts
        else:
            namespace, name = "", source_id

        self.data = {
            "id": source_id,
            "name": name,
            "namespace": namespace,
        }

    def with_definition(
        self, definition: Optional[Dict[str, Any]]
    ) -> "MetricSourceDetailBuilder":
        """Add complete MetricSource definition.

        Args:
            definition: Compiled MetricSource definition

        Returns:
            Self for chaining
        """
        if definition:
            self.data["name"] = definition.get("name", self.data["name"])
            self.data["source"] = definition.get("source", {})
            self.data["fields"] = definition.get("fields", [])
            self.data["computed"] = definition.get("computed", [])
            self.data["aggregations"] = definition.get("aggregations", [])
            self.data["collection"] = definition.get("collection", {})
            self.data["rbac"] = definition.get("rbac", {})
            self.data["compiledAt"] = definition.get("compiledAt")

        return self

    def with_status(
        self, status: Optional[Dict[str, Any]]
    ) -> "MetricSourceDetailBuilder":
        """Add MetricSource status.

        Args:
            status: Status information

        Returns:
            Self for chaining
        """
        if status:
            self.data["status"] = status
        else:
            self.data["status"] = {
                "phase": "Unknown",
                "message": "Status not available",
            }

        return self

    def build(self) -> Dict[str, Any]:
        """Build and return the final response dictionary."""
        return self.data


class CustomResourceListBuilder:
    """Builder for custom resource list responses."""

    def __init__(self, resource_type_name: str, cluster_name: str):
        """Initialize builder.

        Args:
            resource_type_name: The RBAC resource type identifier
            cluster_name: Name of the cluster
        """
        self.data = {
            "resourceType": resource_type_name,
            "cluster": cluster_name,
            "resources": [],
            "resourceCount": 0,
            "aggregations": {},
            "filtered": False,
            "originalCount": None,
            "collectedAt": None,
            "collectionDuration": None,
        }

    def with_resources(
        self, resources: List[Dict[str, Any]]
    ) -> "CustomResourceListBuilder":
        """Add filtered resources.

        Args:
            resources: List of resource dictionaries

        Returns:
            Self for chaining
        """
        self.data["resources"] = resources
        self.data["resourceCount"] = len(resources)
        return self

    def with_aggregations(
        self,
        aggregations: Optional[Dict[str, Any]],
        visible_names: Optional[List[str]] = None,
    ) -> "CustomResourceListBuilder":
        """Add aggregation results filtered by visibility.

        Args:
            aggregations: Full aggregation results
            visible_names: List of aggregation names user can see (None means all)

        Returns:
            Self for chaining
        """
        if not aggregations:
            self.data["aggregations"] = {}
            return self

        values = aggregations.get("values", aggregations)

        if visible_names is None:
            self.data["aggregations"] = values
        else:
            self.data["aggregations"] = {
                name: value
                for name, value in values.items()
                if name in visible_names
            }

        if aggregations.get("computedAt"):
            self.data["aggregationsComputedAt"] = aggregations["computedAt"]

        return self

    def with_collection_meta(
        self, meta: Optional[Dict[str, Any]]
    ) -> "CustomResourceListBuilder":
        """Add collection metadata.

        Args:
            meta: Collection metadata

        Returns:
            Self for chaining
        """
        if meta:
            self.data["collectedAt"] = meta.get("collectedAt")
            self.data["collectionDuration"] = meta.get("collectionDuration")
            self.data["sourceId"] = meta.get("sourceId")

        return self

    def with_filtering_info(
        self, filtered: bool, original_count: Optional[int] = None
    ) -> "CustomResourceListBuilder":
        """Add RBAC filtering information.

        Args:
            filtered: Whether RBAC filtering was applied
            original_count: Count before filtering (if filtered)

        Returns:
            Self for chaining
        """
        self.data["filtered"] = filtered
        if filtered and original_count is not None:
            self.data["originalCount"] = original_count
            self.data["filterNote"] = "Results filtered based on RBAC permissions"

        return self

    def with_recomputed_aggregations_flag(
        self, recomputed: bool
    ) -> "CustomResourceListBuilder":
        """Indicate if aggregations were recomputed from filtered data.

        Args:
            recomputed: Whether aggregations were recomputed

        Returns:
            Self for chaining
        """
        if recomputed:
            self.data["aggregationsRecomputed"] = True
            self.data["aggregationsNote"] = (
                "Aggregations computed from filtered resource set"
            )

        return self

    def build(self) -> Dict[str, Any]:
        """Build and return the final response dictionary."""
        return self.data


class CustomResourceTypeListBuilder:
    """Builder for available custom resource types list."""

    def __init__(self):
        """Initialize builder."""
        self._types: List[Dict[str, Any]] = []

    def add_type(
        self,
        resource_type_name: str,
        source_id: str,
        source_kind: str,
        source_api_version: str,
        display_name: Optional[str] = None,
        namespace: Optional[str] = None,
    ) -> "CustomResourceTypeListBuilder":
        """Add a custom resource type to the list.

        Args:
            resource_type_name: The RBAC identifier
            source_id: The MetricSource that defines it
            source_kind: The Kubernetes kind being collected
            source_api_version: The API version
            display_name: Human-readable name
            namespace: MetricSource namespace

        Returns:
            Self for chaining
        """
        self._types.append({
            "resourceTypeName": resource_type_name,
            "sourceId": source_id,
            "sourceKind": source_kind,
            "sourceApiVersion": source_api_version,
            "displayName": display_name or resource_type_name,
            "namespace": namespace,
        })
        return self

    def add_types_from_list(
        self, type_list: List[Dict[str, Any]]
    ) -> "CustomResourceTypeListBuilder":
        """Add multiple types from repository result.

        Args:
            type_list: List from CustomResourceRepository.get_available_resource_types()

        Returns:
            Self for chaining
        """
        for item in type_list:
            self.add_type(
                resource_type_name=item.get("resource_type_name", ""),
                source_id=item.get("source_id", ""),
                source_kind=item.get("source_kind", "Unknown"),
                source_api_version=item.get("source_api_version", ""),
                display_name=item.get("display_name"),
                namespace=item.get("namespace"),
            )
        return self

    def build(self) -> List[Dict[str, Any]]:
        """Build and return the final list."""
        return sorted(self._types, key=lambda x: x["resourceTypeName"])


class AggregationsResponseBuilder:
    """Builder for aggregations-only responses."""

    def __init__(self, resource_type: str, cluster: str):
        """Initialize builder.

        Args:
            resource_type: The resource type name
            cluster: Cluster name
        """
        self.data = {
            "resourceType": resource_type,
            "cluster": cluster,
            "aggregations": {},
            "recomputed": False,
            "filtered": False,
            "computedAt": datetime.now(timezone.utc).isoformat(),
        }

    def with_aggregations(
        self, aggregations: Dict[str, Any]
    ) -> "AggregationsResponseBuilder":
        """Add aggregation values.

        Args:
            aggregations: Aggregation results

        Returns:
            Self for chaining
        """
        self.data["aggregations"] = aggregations
        return self

    def with_computation_info(
        self, recomputed: bool, filtered: bool
    ) -> "AggregationsResponseBuilder":
        """Add computation metadata.

        Args:
            recomputed: Whether aggregations were recomputed
            filtered: Whether RBAC filtering was applied

        Returns:
            Self for chaining
        """
        self.data["recomputed"] = recomputed
        self.data["filtered"] = filtered

        if recomputed:
            self.data["note"] = "Aggregations recomputed from filtered resource set"

        return self

    def with_timestamp(self, computed_at: str) -> "AggregationsResponseBuilder":
        """Set computation timestamp.

        Args:
            computed_at: ISO format timestamp

        Returns:
            Self for chaining
        """
        self.data["computedAt"] = computed_at
        return self

    def build(self) -> Dict[str, Any]:
        """Build and return the final response dictionary."""
        return self.data
