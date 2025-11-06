"""Cluster repository for Redis data access."""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import redis
from redis.exceptions import RedisError
from clusterpulse.core.config import settings

logger = logging.getLogger(__name__)


class ClusterRepository:
    """Repository for cluster data access from Redis."""

    def __init__(self):
        self.pool = redis.ConnectionPool(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password,
            db=settings.redis_db,
            decode_responses=True,
            max_connections=50,
            socket_connect_timeout=5,
            socket_keepalive=True,
        )
        self.redis = redis.Redis(connection_pool=self.pool)
        self._test_connection()

    def _test_connection(self):
        """Test Redis connection on initialization."""
        try:
            self.redis.ping()
            logger.info("Redis connection established")
        except RedisError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    def _get_json(self, key: str) -> Optional[Dict[str, Any]]:
        """Get and parse JSON data from Redis."""
        try:
            data = self.redis.get(key)
            return json.loads(data) if data else None
        except (RedisError, json.JSONDecodeError) as e:
            logger.error(f"Error getting data from key {key}: {e}")
            return None

    def _hget_json(self, key: str, field: str) -> Optional[Dict[str, Any]]:
        """Get and parse JSON data from Redis hash."""
        try:
            data = self.redis.hget(key, field)
            return json.loads(data) if data else None
        except (RedisError, json.JSONDecodeError) as e:
            logger.error(f"Error getting hash field {field} from key {key}: {e}")
            return None

    def list_clusters(self) -> List[str]:
        """List all cluster names."""
        try:
            return list(self.redis.smembers("clusters:all"))
        except RedisError as e:
            logger.error(f"Error listing clusters: {e}")
            return []

    def get_cluster(self, name: str) -> Optional[Dict[str, Any]]:
        """Get cluster details."""
        try:
            # Get spec, status, and metrics
            spec = self._get_json(f"cluster:{name}:spec")
            status = self._get_json(f"cluster:{name}:status")
            metrics = self._get_json(f"cluster:{name}:metrics")

            if not spec:
                return None

            return {
                "name": name,
                "spec": spec,
                "status": status
                or {"health": "unknown", "message": "No status available"},
                "metrics": metrics,
            }
        except Exception as e:
            logger.error(f"Error getting cluster {name}: {e}")
            return None

    def get_cluster_status(self, name: str) -> Optional[Dict[str, Any]]:
        """Get cluster status."""
        return self._get_json(f"cluster:{name}:status")

    def get_cluster_metrics(self, name: str) -> Optional[Dict[str, Any]]:
        """Get cluster metrics."""
        return self._get_json(f"cluster:{name}:metrics")

    def get_cluster_operators(self, name: str) -> Optional[List[Dict[str, Any]]]:
        """Get cluster operators."""
        data = self._get_json(f"cluster:{name}:operators")
        return data if isinstance(data, list) else None

    def get_cluster_operators_summary(self, name: str) -> Optional[Dict[str, Any]]:
        """Get cluster operators summary."""
        return self._get_json(f"cluster:{name}:operators_summary")

    def list_cluster_nodes(self, name: str) -> List[str]:
        """List all nodes in a cluster."""
        try:
            return list(self.redis.smembers(f"cluster:{name}:nodes"))
        except RedisError as e:
            logger.error(f"Error listing nodes for cluster {name}: {e}")
            return []

    def get_node(self, cluster: str, node: str) -> Optional[Dict[str, Any]]:
        """Get node details."""
        key = f"cluster:{cluster}:node:{node}"
        try:
            # Get current state
            current = self.redis.hget(key, "current")
            if not current:
                return None

            node_data = json.loads(current)

            # Add metadata
            metadata = self.redis.hgetall(key)
            node_data["_metadata"] = {
                k: v for k, v in metadata.items() if k != "current"
            }

            return node_data
        except Exception as e:
            logger.error(f"Error getting node {node} from cluster {cluster}: {e}")
            return None

    def get_node_metrics_history(
        self,
        cluster: str,
        node: str,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Get node metrics history from time-series data."""
        key = f"cluster:{cluster}:node:{node}:metrics"
        try:
            # Default to last hour if not specified
            if end_time is None:
                end_time = datetime.now(timezone.utc).timestamp()
            if start_time is None:
                start_time = end_time - 3600  # Last hour

            # Get metrics from sorted set
            metrics = self.redis.zrangebyscore(
                key, start_time, end_time, withscores=True
            )

            result = []
            for data, score in metrics:
                try:
                    metric = json.loads(data)
                    metric["_timestamp"] = score
                    result.append(metric)
                except json.JSONDecodeError:
                    continue

            return result
        except RedisError as e:
            logger.error(f"Error getting metrics history for node {node}: {e}")
            return []

    def get_nodes_summary(self, cluster: str) -> Optional[Dict[str, Any]]:
        """Get nodes summary for a cluster."""
        return self._hget_json(f"cluster:{cluster}:nodes:summary", "data")

    def get_node_conditions(self, cluster: str, node: str) -> Dict[str, Any]:
        """Get node conditions."""
        key = f"cluster:{cluster}:node:{node}:conditions"
        try:
            conditions = self.redis.hgetall(key)
            result = {}
            for condition_type, data in conditions.items():
                try:
                    result[condition_type] = json.loads(data)
                except json.JSONDecodeError:
                    continue
            return result
        except RedisError as e:
            logger.error(f"Error getting conditions for node {node}: {e}")
            return {}

    def get_cluster_alerts(self, cluster: str) -> List[Dict[str, Any]]:
        """Get active alerts for a cluster."""
        pattern = f"alerts:{cluster}:*"
        alerts = []

        try:
            for key in self.redis.scan_iter(match=pattern):
                alert_data = self.redis.hgetall(key)
                if alert_data:
                    alert_data["id"] = key.split(":")[-1]
                    alerts.append(alert_data)

            # Sort by timestamp
            alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            return alerts
        except RedisError as e:
            logger.error(f"Error getting alerts for cluster {cluster}: {e}")
            return []

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        """Get all active alerts across all clusters."""
        pattern = "alerts:*"
        alerts = []

        try:
            for key in self.redis.scan_iter(match=pattern):
                alert_data = self.redis.hgetall(key)
                if alert_data:
                    # Extract cluster name from key
                    parts = key.split(":")
                    if len(parts) >= 2:
                        alert_data["cluster"] = parts[1]
                    alert_data["id"] = key
                    alerts.append(alert_data)

            # Sort by severity then timestamp
            severity_order = {"critical": 0, "warning": 1, "info": 2}
            alerts.sort(
                key=lambda x: (
                    severity_order.get(x.get("severity", "info"), 3),
                    x.get("timestamp", ""),
                )
            )
            return alerts
        except RedisError as e:
            logger.error(f"Error getting all alerts: {e}")
            return []

    def get_cluster_events(
        self, cluster: str, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get recent events for a cluster."""
        key = f"events:{cluster}"
        try:
            events = self.redis.lrange(key, 0, limit - 1)
            result = []
            for event in events:
                try:
                    result.append(json.loads(event))
                except json.JSONDecodeError:
                    continue
            return result
        except RedisError as e:
            logger.error(f"Error getting events for cluster {cluster}: {e}")
            return []

    def subscribe_to_events(self):
        """Subscribe to cluster events (for websocket streaming)."""
        pubsub = self.redis.pubsub()
        pubsub.subscribe("cluster-events")
        return pubsub

    def get_aggregated_metrics(self) -> Dict[str, Any]:
        """Get aggregated metrics across all clusters."""
        clusters = self.list_clusters()

        total_nodes = 0
        total_nodes_ready = 0
        total_namespaces = 0
        total_pods = 0
        total_pods_running = 0
        clusters_healthy = 0
        clusters_degraded = 0
        clusters_unhealthy = 0

        for cluster_name in clusters:
            metrics = self.get_cluster_metrics(cluster_name)
            status = self.get_cluster_status(cluster_name)

            if metrics:
                total_nodes += metrics.get("nodes", 0)
                total_nodes_ready += metrics.get("nodes_ready", 0)
                total_namespaces += metrics.get("namespaces", 0)
                total_pods += metrics.get("pods", 0)
                total_pods_running += metrics.get("pods_running", 0)

            if status:
                health = status.get("health", "unknown")
                if health == "healthy":
                    clusters_healthy += 1
                elif health == "degraded":
                    clusters_degraded += 1
                elif health == "unhealthy":
                    clusters_unhealthy += 1

        return {
            "clusters": {
                "total": len(clusters),
                "healthy": clusters_healthy,
                "degraded": clusters_degraded,
                "unhealthy": clusters_unhealthy,
            },
            "nodes": {
                "total": total_nodes,
                "ready": total_nodes_ready,
                "not_ready": total_nodes - total_nodes_ready,
            },
            "workloads": {
                "namespaces": total_namespaces,
                "pods": total_pods,
                "pods_running": total_pods_running,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def search_nodes(self, query: str) -> List[Dict[str, Any]]:
        """Search nodes across all clusters."""
        results = []
        clusters = self.list_clusters()

        for cluster_name in clusters:
            nodes = self.list_cluster_nodes(cluster_name)
            for node_name in nodes:
                if query.lower() in node_name.lower():
                    node_data = self.get_node(cluster_name, node_name)
                    if node_data:
                        node_data["cluster"] = cluster_name
                        results.append(node_data)

        return results

    def health_check(self) -> bool:
        """Check Redis connection health."""
        try:
            return self.redis.ping()
        except RedisError:
            return False
