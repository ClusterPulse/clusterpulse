"""Base repository with common Redis patterns and type-safe operations."""

import json
from typing import Any, Dict, List, Optional

from redis import Redis

from clusterpulse.core.logging import get_logger

logger = get_logger(__name__)


class RedisRepository:
    """Base repository with common Redis operations."""

    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    def get_json(self, key: str) -> Optional[Dict[str, Any]]:
        """Get and parse JSON from Redis key."""
        try:
            data = self.redis.get(key)
            return json.loads(data) if data else None
        except (json.JSONDecodeError, Exception) as e:
            logger.error(f"Error getting JSON from {key}: {e}")
            return None

    def get_json_list(self, key: str) -> List[Dict[str, Any]]:
        """Get and parse JSON list from Redis key."""
        data = self.get_json(key)
        return data if isinstance(data, list) else []

    def get_hash_json(self, key: str, field: str) -> Optional[Dict[str, Any]]:
        """Get and parse JSON from Redis hash field."""
        try:
            data = self.redis.hget(key, field)
            return json.loads(data) if data else None
        except (json.JSONDecodeError, Exception) as e:
            logger.error(f"Error getting hash JSON from {key}:{field}: {e}")
            return None

    def batch_get_json(self, keys: List[str]) -> Dict[str, Optional[Dict]]:
        """Batch get multiple JSON keys using pipeline."""
        pipeline = self.redis.pipeline()
        for key in keys:
            pipeline.get(key)

        results = pipeline.execute()

        output = {}
        for key, result in zip(keys, results):
            try:
                output[key] = json.loads(result) if result else None
            except json.JSONDecodeError:
                output[key] = None

        return output


class ClusterDataRepository(RedisRepository):
    """Repository for cluster-specific data access with optimized operations."""

    def get_cluster_spec(self, cluster_name: str) -> Optional[Dict]:
        """Get cluster specification."""
        return self.get_json(f"cluster:{cluster_name}:spec")

    def get_cluster_status(self, cluster_name: str) -> Optional[Dict]:
        """Get cluster status."""
        return self.get_json(f"cluster:{cluster_name}:status")

    def get_cluster_metrics(self, cluster_name: str) -> Optional[Dict]:
        """Get cluster metrics."""
        return self.get_json(f"cluster:{cluster_name}:metrics")

    def get_cluster_info(self, cluster_name: str) -> Optional[Dict]:
        """Get cluster info (version, console URL, etc)."""
        return self.get_json(f"cluster:{cluster_name}:info")

    def get_cluster_operators(self, cluster_name: str) -> List[Dict]:
        """Get operators for cluster."""
        return self.get_json_list(f"cluster:{cluster_name}:operators")

    def get_cluster_namespaces(self, cluster_name: str) -> List[str]:
        """Get namespaces from dedicated storage."""
        data = self.get_json(f"cluster:{cluster_name}:namespaces")
        if isinstance(data, dict):
            return data.get("namespaces", [])
        elif isinstance(data, list):
            return data

        # Fallback to set storage
        return sorted(self.redis.smembers(f"cluster:{cluster_name}:namespaces:set"))

    def get_cluster_bundle(self, cluster_name: str) -> Dict[str, Optional[Dict]]:
        """
        Get all cluster data in one optimized batch operation.

        Returns dict with keys: spec, status, metrics, info
        """
        keys = [
            f"cluster:{cluster_name}:spec",
            f"cluster:{cluster_name}:status",
            f"cluster:{cluster_name}:metrics",
            f"cluster:{cluster_name}:info",
        ]

        results = self.batch_get_json(keys)

        return {
            "spec": results.get(keys[0]),
            "status": results.get(keys[1]),
            "metrics": results.get(keys[2]),
            "info": results.get(keys[3]),
        }

    def get_cluster_nodes(self, cluster_name: str) -> List[Dict]:
        """Get all nodes for a cluster."""
        node_names = self.redis.smembers(f"cluster:{cluster_name}:nodes")
        nodes = []

        for node_name in node_names:
            node_data = self.get_hash_json(
                f"cluster:{cluster_name}:node:{node_name}", "current"
            )
            if node_data:
                nodes.append(node_data)

        return nodes

    def get_cluster_node(self, cluster_name: str, node_name: str) -> Optional[Dict]:
        """Get specific node data."""
        return self.get_hash_json(
            f"cluster:{cluster_name}:node:{node_name}", "current"
        )

    def get_node_conditions(self, cluster_name: str, node_name: str) -> Dict[str, Any]:
        """Get node conditions."""
        key = f"cluster:{cluster_name}:node:{node_name}:conditions"
        try:
            conditions = self.redis.hgetall(key)
            result = {}
            for condition_type, data in conditions.items():
                try:
                    result[condition_type] = json.loads(data)
                except json.JSONDecodeError:
                    continue
            return result
        except Exception as e:
            logger.error(f"Error getting conditions for node {node_name}: {e}")
            return {}

    def get_node_metrics_history(
        self, cluster_name: str, node_name: str, limit: int = 100
    ) -> List[Dict]:
        """Get node metrics history."""
        metrics_key = f"cluster:{cluster_name}:node:{node_name}:metrics"
        metrics = self.redis.zrevrange(metrics_key, 0, limit - 1)
        return [json.loads(m) for m in metrics]

    def get_cluster_resource_list(
        self, cluster_name: str, resource_type: str
    ) -> List[Dict]:
        """Get list of resources (pods, deployments, services, etc)."""
        return self.get_json_list(f"cluster:{cluster_name}:{resource_type}")

    def get_cluster_alerts(self, cluster_name: str) -> List[Dict[str, Any]]:
        """Get active alerts for a cluster."""
        pattern = f"alerts:{cluster_name}:*"
        alerts = []

        try:
            for key in self.redis.scan_iter(match=pattern):
                alert_data = self.redis.hgetall(key)
                if alert_data:
                    alerts.append(alert_data)

            alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            return alerts
        except Exception as e:
            logger.error(f"Error getting alerts for cluster {cluster_name}: {e}")
            return []

    def get_cluster_events(self, cluster_name: str, limit: int = 100) -> List[Dict]:
        """Get recent events for a cluster."""
        key = f"events:{cluster_name}"
        try:
            events = self.redis.lrange(key, 0, limit - 1)
            result = []
            for event in events:
                try:
                    result.append(json.loads(event))
                except json.JSONDecodeError:
                    continue
            return result
        except Exception as e:
            logger.error(f"Error getting events for cluster {cluster_name}: {e}")
            return []


class RegistryDataRepository(RedisRepository):
    """Repository for registry-specific data access."""

    def get_all_registry_names(self) -> List[str]:
        """Get all registry names."""
        return sorted(self.redis.smembers("registries:all"))

    def get_registry_status(self, registry_name: str) -> Optional[Dict]:
        """Get registry status."""
        return self.get_json(f"registry:{registry_name}:status")

    def get_registry_spec(self, registry_name: str) -> Optional[Dict]:
        """Get registry specification."""
        return self.get_json(f"registry:{registry_name}:spec")

    def get_registry_bundle(self, registry_name: str) -> Dict[str, Optional[Dict]]:
        """Get registry status and spec in one batch operation."""
        keys = [
            f"registry:{registry_name}:status",
            f"registry:{registry_name}:spec",
        ]

        results = self.batch_get_json(keys)

        return {
            "status": results.get(keys[0]),
            "spec": results.get(keys[1]),
        }

    def batch_get_registry_bundles(
        self, registry_names: List[str]
    ) -> Dict[str, Dict[str, Optional[Dict]]]:
        """Get multiple registry bundles in one optimized batch."""
        if not registry_names:
            return {}

        # Build all keys
        keys = []
        for name in registry_names:
            keys.append(f"registry:{name}:status")
            keys.append(f"registry:{name}:spec")

        # Batch fetch
        results = self.batch_get_json(keys)

        # Organize by registry
        output = {}
        for i, name in enumerate(registry_names):
            status_key = keys[i * 2]
            spec_key = keys[i * 2 + 1]

            output[name] = {
                "status": results.get(status_key),
                "spec": results.get(spec_key),
            }

        return output

class MetricSourceRepository(RedisRepository):
    """Repository for MetricSource data access."""

    def get_all_metric_source_ids(self) -> List[str]:
        """Get all enabled MetricSource identifiers."""
        try:
            return sorted(self.redis.smembers("metricsources:enabled"))
        except Exception as e:
            logger.error(f"Error getting MetricSource IDs: {e}")
            return []

    def get_metric_source(self, source_id: str) -> Optional[Dict[str, Any]]:
        """Get compiled MetricSource definition by ID."""
        if "/" not in source_id:
            return None
        namespace, name = source_id.split("/", 1)
        return self.get_json(f"metricsource:{namespace}:{name}")

    def get_all_metric_sources(self) -> List[Dict[str, Any]]:
        """Get all enabled MetricSource definitions."""
        source_ids = self.get_all_metric_source_ids()
        if not source_ids:
            return []

        sources = []
        for source_id in source_ids:
            source = self.get_metric_source(source_id)
            if source:
                source["_id"] = source_id
                sources.append(source)
        return sources

    def get_resource_type_mapping(self) -> Dict[str, str]:
        """Map resourceTypeName to sourceId."""
        sources = self.get_all_metric_sources()
        mapping = {}
        for source in sources:
            type_name = source.get("rbac", {}).get("resourceTypeName")
            if type_name:
                mapping[type_name] = source.get("_id", f"{source.get('namespace')}/{source.get('name')}")
        return mapping

    def get_source_id_for_type(self, resource_type_name: str) -> Optional[str]:
            """Get sourceId for a resource type name."""
            key = f"metricsources:by:resourcetype:{resource_type_name}"
            try:
                # Key is stored as a set, get first member
                members = self.redis.smembers(key)
                if members:
                    return next(iter(members))
            except Exception as e:
                logger.debug(f"Error getting source ID for {resource_type_name}: {e}")
    
            # Fallback to iterating sources
            mapping = self.get_resource_type_mapping()
            return mapping.get(resource_type_name)

    def get_clusters_with_data(self, resource_type_name: str) -> List[str]:
        """Get cluster names that have collected data for this type."""
        source_id = self.get_source_id_for_type(resource_type_name)
        if not source_id:
            return []

        clusters = set()
        pattern = f"cluster:*:custom:{source_id}:resources"
        try:
            for key in self.redis.scan_iter(match=pattern, count=100):
                parts = key.split(":")
                if len(parts) >= 2:
                    clusters.add(parts[1])
        except Exception as e:
            logger.error(f"Error scanning for clusters with data: {e}")
        return sorted(clusters)

    def get_custom_resources(
        self, source_id: str, cluster: str
    ) -> Optional[Dict[str, Any]]:
        """Get collected custom resources for a cluster."""
        return self.get_json(f"cluster:{cluster}:custom:{source_id}:resources")

    def get_custom_aggregations(
        self, source_id: str, cluster: str
    ) -> Optional[Dict[str, Any]]:
        """Get computed aggregations for a cluster."""
        return self.get_json(f"cluster:{cluster}:custom:{source_id}:aggregations")

    def get_custom_resources_for_clusters(
        self, source_id: str, clusters: List[str]
    ) -> Dict[str, Optional[Dict[str, Any]]]:
        """Batch fetch custom resources for multiple clusters."""
        keys = [f"cluster:{c}:custom:{source_id}:resources" for c in clusters]
        results = self.batch_get_json(keys)
        return {c: results.get(keys[i]) for i, c in enumerate(clusters)}

    def get_custom_aggregations_for_clusters(
        self, source_id: str, clusters: List[str]
    ) -> Dict[str, Optional[Dict[str, Any]]]:
        """Batch fetch aggregations for multiple clusters."""
        keys = [f"cluster:{c}:custom:{source_id}:aggregations" for c in clusters]
        results = self.batch_get_json(keys)
        return {c: results.get(keys[i]) for i, c in enumerate(clusters)}
