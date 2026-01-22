"""Response builders for MetricSource and custom resource endpoints."""

from typing import Any, Dict, List, Optional


class CustomResourceTypeBuilder:
    """Builder for custom resource type list items."""

    def __init__(self, resource_type_name: str):
        self.data = {"resourceTypeName": resource_type_name}

    def with_source_id(self, source_id: str) -> "CustomResourceTypeBuilder":
        """Add MetricSource identifier."""
        self.data["sourceId"] = source_id
        return self

    def with_source_info(self, source: Optional[Dict]) -> "CustomResourceTypeBuilder":
        """Add MetricSource details."""
        if not source:
            return self

        source_spec = source.get("source", {})
        self.data["source"] = {
            "apiVersion": source_spec.get("apiVersion"),
            "kind": source_spec.get("kind"),
            "scope": source_spec.get("scope", "Namespaced"),
        }

        fields = source.get("fields", [])
        self.data["fields"] = [f.get("name") for f in fields if f.get("name")]

        computed = source.get("computed", [])
        self.data["computedFields"] = [c.get("name") for c in computed if c.get("name")]

        aggregations = source.get("aggregations", [])
        self.data["aggregations"] = [a.get("name") for a in aggregations if a.get("name")]

        return self

    def with_cluster_availability(self, clusters: List[str]) -> "CustomResourceTypeBuilder":
        """Add list of clusters where data exists."""
        self.data["clustersWithData"] = clusters
        return self

    def build(self) -> Dict[str, Any]:
        """Build and return the final response."""
        return self.data


class ClusterResourceCountBuilder:
    """Builder for cluster resource count responses."""

    def __init__(self, cluster: str, resource_type_name: str):
        self.data = {
            "cluster": cluster,
            "resourceTypeName": resource_type_name,
        }

    def with_counts(self, filtered: int) -> "ClusterResourceCountBuilder":
        """Add filtered count."""
        self.data["count"] = filtered
        return self

    def with_aggregations(self, aggregations: Dict[str, Any]) -> "ClusterResourceCountBuilder":
        """Add aggregation values."""
        if aggregations:
            self.data["aggregations"] = aggregations
        return self

    def with_collection_time(self, timestamp: Optional[str]) -> "ClusterResourceCountBuilder":
        """Add last collection timestamp."""
        if timestamp:
            self.data["lastCollection"] = timestamp
        return self

    def build(self) -> Dict[str, Any]:
        """Build and return the final response."""
        return self.data


class CustomResourceDetailBuilder:
    """Builder for custom resource detail responses."""

    def __init__(self, resource_type_name: str, cluster: str):
        self.data = {
            "resourceTypeName": resource_type_name,
            "cluster": cluster,
        }

    def with_collection_metadata(self, metadata: Optional[Dict]) -> "CustomResourceDetailBuilder":
        """Add collection timestamp and truncation info."""
        if metadata:
            self.data["collectedAt"] = metadata.get("collectedAt")
            if metadata.get("truncated"):
                self.data["truncated"] = True
        return self

    def with_resources(
        self, resources: List[Dict], filtered: bool
    ) -> "CustomResourceDetailBuilder":
        """Add resource list with filtering indicator."""
        self.data["items"] = resources
        self.data["filtered"] = filtered
        if filtered:
            self.data["filterNote"] = "Results filtered based on access policies"
        return self

    def with_aggregations(self, aggregations: Dict[str, Any]) -> "CustomResourceDetailBuilder":
        """Add aggregation values."""
        if aggregations:
            self.data["aggregations"] = aggregations
        return self

    def with_pagination(self, pagination: Dict) -> "CustomResourceDetailBuilder":
        """Add pagination metadata."""
        self.data["pagination"] = pagination
        return self

    def build(self) -> Dict[str, Any]:
        """Build and return the final response."""
        return self.data
