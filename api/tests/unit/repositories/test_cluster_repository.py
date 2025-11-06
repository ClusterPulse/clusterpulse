"""Unit tests for ClusterRepository."""

import json
from datetime import datetime, timezone

import pytest

from clusterpulse.repositories.cluster import ClusterRepository


@pytest.mark.unit
class TestClusterRepository:
    """Test ClusterRepository data access methods."""

    @pytest.fixture
    def repository(self, fake_redis, monkeypatch):
        """Create repository with fake Redis."""
        # Mock settings
        monkeypatch.setenv("REDIS_HOST", "localhost")
        monkeypatch.setenv("REDIS_PORT", "6379")

        # Patch the redis client creation to use fake
        import clusterpulse.repositories.cluster as repo_module

        original_init = repo_module.ClusterRepository.__init__

        def mock_init(self):
            self.redis = fake_redis
            self.pool = None

        monkeypatch.setattr(repo_module.ClusterRepository, "__init__", mock_init)

        repo = ClusterRepository()
        repo.redis = fake_redis  # Ensure it's set
        return repo

    def test_list_clusters_empty(self, repository):
        """Test listing clusters when none exist."""
        clusters = repository.list_clusters()
        assert clusters == []

    def test_list_clusters(self, repository, fake_redis):
        """Test listing clusters."""
        # Add clusters to Redis
        fake_redis.sadd("clusters:all", "cluster-1", "cluster-2", "cluster-3")

        clusters = repository.list_clusters()
        assert len(clusters) == 3
        assert "cluster-1" in clusters
        assert "cluster-2" in clusters
        assert "cluster-3" in clusters

    def test_get_cluster_exists(
        self,
        repository,
        fake_redis,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test getting cluster data."""
        cluster_name = "test-cluster"

        # Store cluster data
        fake_redis.set(f"cluster:{cluster_name}:spec", json.dumps(sample_cluster_spec))
        fake_redis.set(
            f"cluster:{cluster_name}:status", json.dumps(sample_cluster_status)
        )
        fake_redis.set(
            f"cluster:{cluster_name}:metrics", json.dumps(sample_cluster_metrics)
        )

        cluster = repository.get_cluster(cluster_name)

        assert cluster is not None
        assert cluster["name"] == cluster_name
        assert cluster["spec"] == sample_cluster_spec
        assert cluster["status"] == sample_cluster_status
        assert cluster["metrics"] == sample_cluster_metrics

    def test_get_cluster_not_found(self, repository):
        """Test getting non-existent cluster."""
        cluster = repository.get_cluster("nonexistent")
        assert cluster is None

    def test_get_cluster_status(
        self, repository, fake_redis, sample_cluster_status
    ):
        """Test getting cluster status."""
        cluster_name = "test-cluster"
        fake_redis.set(
            f"cluster:{cluster_name}:status", json.dumps(sample_cluster_status)
        )

        status = repository.get_cluster_status(cluster_name)
        assert status == sample_cluster_status

    def test_get_cluster_metrics(
        self, repository, fake_redis, sample_cluster_metrics
    ):
        """Test getting cluster metrics."""
        cluster_name = "test-cluster"
        fake_redis.set(
            f"cluster:{cluster_name}:metrics", json.dumps(sample_cluster_metrics)
        )

        metrics = repository.get_cluster_metrics(cluster_name)
        assert metrics == sample_cluster_metrics

    def test_list_cluster_nodes(self, repository, fake_redis, sample_nodes):
        """Test listing cluster nodes."""
        cluster_name = "test-cluster"

        # Add nodes to set
        for node in sample_nodes:
            fake_redis.sadd(f"cluster:{cluster_name}:nodes", node["name"])

        nodes = repository.list_cluster_nodes(cluster_name)
        assert len(nodes) == len(sample_nodes)
        for node in sample_nodes:
            assert node["name"] in nodes

    def test_get_node(self, repository, fake_redis, sample_nodes):
        """Test getting node details."""
        cluster_name = "test-cluster"
        node = sample_nodes[0]
        node_name = node["name"]

        # Store node data
        fake_redis.hset(
            f"cluster:{cluster_name}:node:{node_name}",
            "current",
            json.dumps(node),
        )

        retrieved_node = repository.get_node(cluster_name, node_name)

        assert retrieved_node is not None
        assert retrieved_node["name"] == node_name
        assert retrieved_node["status"] == node["status"]

    def test_get_node_not_found(self, repository):
        """Test getting non-existent node."""
        node = repository.get_node("test-cluster", "nonexistent-node")
        assert node is None

    def test_get_aggregated_metrics(
        self,
        repository,
        fake_redis,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test getting aggregated metrics across clusters."""
        # Setup multiple clusters
        clusters = ["cluster-1", "cluster-2"]
        for cluster_name in clusters:
            fake_redis.sadd("clusters:all", cluster_name)
            fake_redis.set(
                f"cluster:{cluster_name}:spec", json.dumps(sample_cluster_spec)
            )
            fake_redis.set(
                f"cluster:{cluster_name}:status", json.dumps(sample_cluster_status)
            )
            fake_redis.set(
                f"cluster:{cluster_name}:metrics", json.dumps(sample_cluster_metrics)
            )

        aggregated = repository.get_aggregated_metrics()

        assert "clusters" in aggregated
        assert aggregated["clusters"]["total"] == 2
        assert aggregated["clusters"]["healthy"] == 2

        assert "nodes" in aggregated
        # Each cluster has 5 nodes according to sample data
        assert aggregated["nodes"]["total"] == 10

        assert "workloads" in aggregated

    def test_get_cluster_alerts(self, repository, fake_redis):
        """Test getting cluster alerts."""
        cluster_name = "test-cluster"

        # Create some alerts
        alerts = [
            {
                "severity": "critical",
                "message": "Node down",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            {
                "severity": "warning",
                "message": "High CPU usage",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        ]

        for i, alert in enumerate(alerts):
            alert_key = f"alerts:{cluster_name}:alert-{i}"
            for key, value in alert.items():
                fake_redis.hset(alert_key, key, value)

        retrieved_alerts = repository.get_cluster_alerts(cluster_name)

        assert len(retrieved_alerts) == 2
        assert any(a.get("severity") == "critical" for a in retrieved_alerts)
        assert any(a.get("severity") == "warning" for a in retrieved_alerts)

    def test_get_all_alerts(self, repository, fake_redis):
        """Test getting all alerts across clusters."""
        # Create alerts for multiple clusters
        clusters = ["cluster-1", "cluster-2"]
        for cluster in clusters:
            alert_key = f"alerts:{cluster}:alert-1"
            fake_redis.hset(alert_key, "severity", "critical")
            fake_redis.hset(alert_key, "message", f"Issue in {cluster}")

        all_alerts = repository.get_all_alerts()

        assert len(all_alerts) >= 2
        assert any(a.get("cluster") == "cluster-1" for a in all_alerts)
        assert any(a.get("cluster") == "cluster-2" for a in all_alerts)

    def test_get_cluster_events(self, repository, fake_redis):
        """Test getting cluster events."""
        cluster_name = "test-cluster"

        # Create events
        events = [
            {
                "type": "NodeReady",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "message": "Node became ready",
            },
            {
                "type": "PodScheduled",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "message": "Pod scheduled",
            },
        ]

        events_key = f"events:{cluster_name}"
        for event in events:
            fake_redis.lpush(events_key, json.dumps(event))

        retrieved_events = repository.get_cluster_events(cluster_name, limit=10)

        assert len(retrieved_events) == 2
        # Events are in reverse order (LIFO)
        assert retrieved_events[0]["type"] == "PodScheduled"
        assert retrieved_events[1]["type"] == "NodeReady"

    def test_health_check_success(self, repository, fake_redis):
        """Test health check with working Redis."""
        # Fake Redis always responds to ping
        is_healthy = repository.health_check()
        assert is_healthy is True

    def test_search_nodes(self, repository, fake_redis, sample_nodes):
        """Test searching nodes across clusters."""
        cluster_name = "test-cluster"

        # Add clusters and nodes
        fake_redis.sadd("clusters:all", cluster_name)

        for node in sample_nodes:
            node_name = node["name"]
            fake_redis.sadd(f"cluster:{cluster_name}:nodes", node_name)
            fake_redis.hset(
                f"cluster:{cluster_name}:node:{node_name}",
                "current",
                json.dumps(node),
            )

        # Search for "worker" nodes
        results = repository.search_nodes("worker")

        assert len(results) >= 2  # worker-1 and worker-2
        assert all("worker" in r["name"] for r in results)

        # Search for specific node
        results = repository.search_nodes("master-1")
        assert len(results) == 1
        assert results[0]["name"] == "master-1"

    def test_get_cluster_operators(self, repository, fake_redis, sample_operators):
        """Test getting cluster operators."""
        cluster_name = "test-cluster"

        fake_redis.set(
            f"cluster:{cluster_name}:operators", json.dumps(sample_operators)
        )

        operators = repository.get_cluster_operators(cluster_name)

        assert operators is not None
        assert len(operators) == len(sample_operators)
        assert operators[0]["name"] == sample_operators[0]["name"]

    def test_get_cluster_operators_summary(self, repository, fake_redis):
        """Test getting operators summary."""
        cluster_name = "test-cluster"
        summary = {
            "total": 5,
            "by_status": {"Succeeded": 4, "Failed": 1},
            "by_namespace": {"openshift-operators": 3, "custom": 2},
        }

        fake_redis.set(
            f"cluster:{cluster_name}:operators_summary", json.dumps(summary)
        )

        retrieved_summary = repository.get_cluster_operators_summary(cluster_name)

        assert retrieved_summary == summary

    def test_get_nodes_summary(self, repository, fake_redis):
        """Test getting nodes summary."""
        cluster_name = "test-cluster"
        summary = {
            "total": 5,
            "ready": 4,
            "not_ready": 1,
            "by_role": {"worker": 3, "master": 2},
        }

        fake_redis.hset(
            f"cluster:{cluster_name}:nodes:summary", "data", json.dumps(summary)
        )

        retrieved_summary = repository.get_nodes_summary(cluster_name)

        assert retrieved_summary == summary


@pytest.mark.unit
class TestRepositoryErrorHandling:
    """Test error handling in repository."""

    @pytest.fixture
    def repository_with_errors(self, monkeypatch):
        """Create repository that simulates errors."""
        # Create a mock Redis that raises errors
        class ErrorRedis:
            def get(self, key):
                from redis.exceptions import RedisError
                raise RedisError("Redis connection failed")

            def smembers(self, key):
                from redis.exceptions import RedisError
                raise RedisError("Redis connection failed")

            def ping(self):
                from redis.exceptions import RedisError
                raise RedisError("Redis connection failed")

        error_redis = ErrorRedis()

        import clusterpulse.repositories.cluster as repo_module

        def mock_init(self):
            self.redis = error_redis
            self.pool = None

        monkeypatch.setattr(repo_module.ClusterRepository, "__init__", mock_init)
        monkeypatch.setattr(
            repo_module.ClusterRepository, "_test_connection", lambda self: None
        )

        return ClusterRepository()

    def test_list_clusters_error(self, repository_with_errors):
        """Test that list_clusters handles Redis errors gracefully."""
        clusters = repository_with_errors.list_clusters()
        # Should return empty list on error
        assert clusters == []

    def test_health_check_failure(self, repository_with_errors):
        """Test health check with failing Redis."""
        is_healthy = repository_with_errors.health_check()
        assert is_healthy is False
