"""Repository for custom MetricSource resource data access."""

from typing import Any, Dict, List, Optional

from clusterpulse.core.logging import get_logger
from clusterpulse.repositories.redis_base import RedisRepository

logger = get_logger(__name__)


class CustomResourceRepository(RedisRepository):
    """Repository for MetricSource definitions and collected custom resource data."""

    def get_all_metricsource_ids(self) -> List[str]:
        """Get all MetricSource identifiers.

        Returns:
            List of MetricSource keys in format '{namespace}/{name}'
        """
        try:
            return sorted(self.redis.smembers("metricsources:all"))
        except Exception as e:
            logger.error(f"Error getting all MetricSource IDs: {e}")
            return []

    def get_enabled_metricsource_ids(self) -> List[str]:
        """Get enabled MetricSource identifiers.

        Returns:
            List of enabled MetricSource keys in format '{namespace}/{name}'
        """
        try:
            return sorted(self.redis.smembers("metricsources:enabled"))
        except Exception as e:
            logger.error(f"Error getting enabled MetricSource IDs: {e}")
            return []

    def get_metricsource(self, namespace: str, name: str) -> Optional[Dict[str, Any]]:
        """Get a compiled MetricSource definition.

        Args:
            namespace: MetricSource namespace
            name: MetricSource name

        Returns:
            Compiled MetricSource definition or None if not found
        """
        key = f"metricsource:{namespace}:{name}"
        return self.get_json(key)

    def get_metricsource_by_resource_type(
        self, resource_type_name: str
    ) -> Optional[Dict[str, Any]]:
        """Get MetricSource definition by its RBAC resource type name.
    
        Args:
            resource_type_name: The resourceTypeName from rbac configuration
    
        Returns:
            Compiled MetricSource definition or None if not found
        """
        # First get the source ID from the index
        index_key = f"metricsources:by:resourcetype:{resource_type_name}"
        source_ids = self.redis.smembers(index_key)
    
        if not source_ids:
            return None
    
        # Get the first source_id from the set (typically there should be only one)
        source_id = next(iter(source_ids))
    
        # Parse source_id (format: namespace/name)
        parts = source_id.split("/", 1)
        if len(parts) != 2:
            logger.error(f"Invalid source_id format in index: {source_id}")
            return None
    
        namespace, name = parts
        return self.get_metricsource(namespace, name)

    def get_custom_resources(
        self, cluster_name: str, source_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get collected custom resources for a cluster and source.

        Args:
            cluster_name: Name of the cluster
            source_id: MetricSource identifier (namespace/name)

        Returns:
            Collected resources data structure including metadata and resource list
        """
        # Normalize source_id for key (replace / with :)
        normalized_id = source_id.replace("/", ":")
        key = f"cluster:{cluster_name}:custom:{normalized_id}:resources"
        return self.get_json(key)

    def get_custom_aggregations(
        self, cluster_name: str, source_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get aggregation results for a cluster and source.

        Args:
            cluster_name: Name of the cluster
            source_id: MetricSource identifier (namespace/name)

        Returns:
            Aggregation results dictionary
        """
        normalized_id = source_id.replace("/", ":")
        key = f"cluster:{cluster_name}:custom:{normalized_id}:aggregations"
        return self.get_json(key)

    def get_custom_collection_meta(
        self, cluster_name: str, source_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get collection metadata for a cluster and source.

        Args:
            cluster_name: Name of the cluster
            source_id: MetricSource identifier (namespace/name)

        Returns:
            Collection metadata (timing, errors, etc.)
        """
        normalized_id = source_id.replace("/", ":")
        key = f"cluster:{cluster_name}:custom:{normalized_id}:meta"
        return self.get_json(key)

    def get_available_resource_types(self) -> List[Dict[str, Any]]:
        """Get list of available custom resource types from enabled MetricSources.

        Returns:
            List of dicts with resource_type_name, source_id, source_kind, etc.
        """
        enabled_ids = self.get_enabled_metricsource_ids()
        resource_types = []

        for source_id in enabled_ids:
            parts = source_id.split("/", 1)
            if len(parts) != 2:
                continue

            namespace, name = parts
            definition = self.get_metricsource(namespace, name)

            if not definition:
                continue

            rbac_config = definition.get("rbac", {})
            source_config = definition.get("source", {})

            resource_type_name = rbac_config.get("resourceTypeName")
            if not resource_type_name:
                continue

            resource_types.append({
                "resource_type_name": resource_type_name,
                "source_id": source_id,
                "source_kind": source_config.get("kind", "Unknown"),
                "source_api_version": source_config.get("apiVersion", ""),
                "display_name": definition.get("name", name),
                "namespace": namespace,
            })

        return resource_types

    def batch_get_custom_resources(
        self, cluster_name: str, source_ids: List[str]
    ) -> Dict[str, Optional[Dict[str, Any]]]:
        """Batch fetch custom resources for multiple sources.

        Args:
            cluster_name: Name of the cluster
            source_ids: List of MetricSource identifiers

        Returns:
            Dict mapping source_id to resource data
        """
        if not source_ids:
            return {}

        keys = []
        for source_id in source_ids:
            normalized_id = source_id.replace("/", ":")
            keys.append(f"cluster:{cluster_name}:custom:{normalized_id}:resources")

        results = self.batch_get_json(keys)

        output = {}
        for source_id, key in zip(source_ids, keys):
            output[source_id] = results.get(key)

        return output

    def batch_get_metricsources(
        self, source_ids: List[str]
    ) -> Dict[str, Optional[Dict[str, Any]]]:
        """Batch fetch multiple MetricSource definitions.

        Args:
            source_ids: List of MetricSource identifiers (namespace/name)

        Returns:
            Dict mapping source_id to definition
        """
        if not source_ids:
            return {}

        keys = []
        for source_id in source_ids:
            parts = source_id.split("/", 1)
            if len(parts) == 2:
                keys.append(f"metricsource:{parts[0]}:{parts[1]}")
            else:
                keys.append(f"metricsource:{source_id}")

        results = self.batch_get_json(keys)

        output = {}
        for source_id, key in zip(source_ids, keys):
            output[source_id] = results.get(key)

        return output

    def get_metricsource_status(
        self, namespace: str, name: str
    ) -> Optional[Dict[str, Any]]:
        """Get MetricSource status information.

        Args:
            namespace: MetricSource namespace
            name: MetricSource name

        Returns:
            Status information or None
        """
        key = f"metricsource:{namespace}:{name}:status"
        return self.get_json(key)
