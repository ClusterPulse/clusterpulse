"""Unit tests for MetricSourceRepository."""

import json

import pytest

from clusterpulse.repositories.redis_base import MetricSourceRepository


@pytest.fixture
def metric_source_repo(fake_redis):
    """Create MetricSourceRepository with fake Redis."""
    return MetricSourceRepository(fake_redis)


@pytest.fixture
def sample_metric_source():
    """Sample MetricSource definition."""
    return {
        "name": "pvc-metrics",
        "namespace": "clusterpulse",
        "source": {
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "scope": "Namespaced",
        },
        "rbac": {
            "resourceTypeName": "pvc",
            "filterAggregations": True,
        },
        "fields": [
            {"name": "capacity", "path": "spec.resources.requests.storage"},
            {"name": "status", "path": "status.phase"},
        ],
        "computed": [
            {"name": "utilization", "expression": "used / capacity * 100"},
        ],
        "aggregations": [
            {"name": "total_count", "function": "count"},
            {"name": "sum_capacity", "function": "sum", "field": "capacity"},
        ],
    }


@pytest.fixture
def sample_custom_resources():
    """Sample collected custom resources."""
    return {
        "resources": [
            {"_name": "pvc-1", "_namespace": "ns-a", "values": {"capacity": 100, "status": "Bound"}},
            {"_name": "pvc-2", "_namespace": "ns-b", "values": {"capacity": 200, "status": "Bound"}},
        ],
        "collectedAt": "2024-01-15T10:30:00Z",
        "truncated": False,
    }


@pytest.fixture
def sample_aggregations():
    """Sample computed aggregations."""
    return {
        "values": {
            "total_count": 2,
            "sum_capacity": 300,
        },
        "computedAt": "2024-01-15T10:30:00Z",
    }


@pytest.mark.unit
class TestMetricSourceRepository:
    """Test MetricSourceRepository data access methods."""

    def test_get_all_metric_source_ids_empty(self, metric_source_repo):
        """Test getting IDs when none exist."""
        ids = metric_source_repo.get_all_metric_source_ids()
        assert ids == []

    def test_get_all_metric_source_ids(self, metric_source_repo, fake_redis):
        """Test getting all enabled MetricSource IDs."""
        fake_redis.sadd(
            "metricsources:enabled",
            "clusterpulse/pvc-metrics",
            "clusterpulse/cert-metrics",
        )
        
        ids = metric_source_repo.get_all_metric_source_ids()
        
        assert len(ids) == 2
        assert "clusterpulse/cert-metrics" in ids
        assert "clusterpulse/pvc-metrics" in ids

    def test_get_metric_source(self, metric_source_repo, fake_redis, sample_metric_source):
        """Test getting a MetricSource definition."""
        source_id = "clusterpulse/pvc-metrics"
        fake_redis.set(
            f"metricsource:clusterpulse:pvc-metrics",
            json.dumps(sample_metric_source),
        )
        
        source = metric_source_repo.get_metric_source(source_id)
        
        assert source is not None
        assert source["name"] == "pvc-metrics"
        assert source["rbac"]["resourceTypeName"] == "pvc"

    def test_get_metric_source_not_found(self, metric_source_repo):
        """Test getting non-existent MetricSource."""
        source = metric_source_repo.get_metric_source("nonexistent/source")
        assert source is None

    def test_get_metric_source_invalid_id(self, metric_source_repo):
        """Test getting MetricSource with invalid ID format."""
        source = metric_source_repo.get_metric_source("invalid-no-slash")
        assert source is None

    def test_get_all_metric_sources(self, metric_source_repo, fake_redis, sample_metric_source):
        """Test getting all enabled MetricSource definitions."""
        fake_redis.sadd("metricsources:enabled", "clusterpulse/pvc-metrics")
        fake_redis.set(
            "metricsource:clusterpulse:pvc-metrics",
            json.dumps(sample_metric_source),
        )
        
        sources = metric_source_repo.get_all_metric_sources()
        
        assert len(sources) == 1
        assert sources[0]["name"] == "pvc-metrics"
        assert sources[0]["_id"] == "clusterpulse/pvc-metrics"

    def test_get_resource_type_mapping(self, metric_source_repo, fake_redis, sample_metric_source):
        """Test getting resourceTypeName to sourceId mapping."""
        fake_redis.sadd("metricsources:enabled", "clusterpulse/pvc-metrics")
        fake_redis.set(
            "metricsource:clusterpulse:pvc-metrics",
            json.dumps(sample_metric_source),
        )
        
        mapping = metric_source_repo.get_resource_type_mapping()
        
        assert "pvc" in mapping
        assert mapping["pvc"] == "clusterpulse/pvc-metrics"

    def test_get_source_id_for_type_from_index(self, metric_source_repo, fake_redis):
        """Test getting sourceId using the indexed lookup."""
        fake_redis.sadd(
            "metricsources:by:resourcetype:pvc",
            "clusterpulse/pvc-metrics",
        )
        
        source_id = metric_source_repo.get_source_id_for_type("pvc")
        
        assert source_id == "clusterpulse/pvc-metrics"

    def test_get_source_id_for_type_fallback(
        self, metric_source_repo, fake_redis, sample_metric_source
    ):
        """Test getting sourceId using fallback iteration."""
        # No index, but source exists
        fake_redis.sadd("metricsources:enabled", "clusterpulse/pvc-metrics")
        fake_redis.set(
            "metricsource:clusterpulse:pvc-metrics",
            json.dumps(sample_metric_source),
        )
        
        source_id = metric_source_repo.get_source_id_for_type("pvc")
        
        assert source_id == "clusterpulse/pvc-metrics"

    def test_get_source_id_for_type_not_found(self, metric_source_repo):
        """Test getting sourceId for unknown type."""
        source_id = metric_source_repo.get_source_id_for_type("unknown")
        assert source_id is None

    def test_get_clusters_with_data(self, metric_source_repo, fake_redis, sample_custom_resources):
        """Test getting clusters that have collected data."""
        source_id = "clusterpulse/pvc-metrics"
        fake_redis.sadd("metricsources:by:resourcetype:pvc", source_id)
        
        # Store data for two clusters
        fake_redis.set(
            f"cluster:cluster-a:custom:{source_id}:resources",
            json.dumps(sample_custom_resources),
        )
        fake_redis.set(
            f"cluster:cluster-b:custom:{source_id}:resources",
            json.dumps(sample_custom_resources),
        )
        
        clusters = metric_source_repo.get_clusters_with_data("pvc")
        
        assert len(clusters) == 2
        assert "cluster-a" in clusters
        assert "cluster-b" in clusters

    def test_get_clusters_with_data_none(self, metric_source_repo, fake_redis):
        """Test getting clusters when none have data."""
        fake_redis.sadd("metricsources:by:resourcetype:pvc", "clusterpulse/pvc-metrics")
        
        clusters = metric_source_repo.get_clusters_with_data("pvc")
        
        assert clusters == []

    def test_get_custom_resources(
        self, metric_source_repo, fake_redis, sample_custom_resources
    ):
        """Test getting custom resources for a cluster."""
        source_id = "clusterpulse/pvc-metrics"
        fake_redis.set(
            f"cluster:test-cluster:custom:{source_id}:resources",
            json.dumps(sample_custom_resources),
        )
        
        data = metric_source_repo.get_custom_resources(source_id, "test-cluster")
        
        assert data is not None
        assert len(data["resources"]) == 2
        assert data["collectedAt"] == "2024-01-15T10:30:00Z"

    def test_get_custom_resources_not_found(self, metric_source_repo):
        """Test getting custom resources when none exist."""
        data = metric_source_repo.get_custom_resources("ns/source", "cluster")
        assert data is None

    def test_get_custom_aggregations(
        self, metric_source_repo, fake_redis, sample_aggregations
    ):
        """Test getting aggregations for a cluster."""
        source_id = "clusterpulse/pvc-metrics"
        fake_redis.set(
            f"cluster:test-cluster:custom:{source_id}:aggregations",
            json.dumps(sample_aggregations),
        )
        
        data = metric_source_repo.get_custom_aggregations(source_id, "test-cluster")
        
        assert data is not None
        assert data["values"]["total_count"] == 2
        assert data["values"]["sum_capacity"] == 300

    def test_get_custom_resources_for_clusters(
        self, metric_source_repo, fake_redis, sample_custom_resources
    ):
        """Test batch fetching resources for multiple clusters."""
        source_id = "clusterpulse/pvc-metrics"
        
        # Store for two clusters
        fake_redis.set(
            f"cluster:cluster-a:custom:{source_id}:resources",
            json.dumps(sample_custom_resources),
        )
        fake_redis.set(
            f"cluster:cluster-b:custom:{source_id}:resources",
            json.dumps(sample_custom_resources),
        )
        
        results = metric_source_repo.get_custom_resources_for_clusters(
            source_id, ["cluster-a", "cluster-b", "cluster-c"]
        )
        
        assert results["cluster-a"] is not None
        assert results["cluster-b"] is not None
        assert results["cluster-c"] is None

    def test_get_custom_aggregations_for_clusters(
        self, metric_source_repo, fake_redis, sample_aggregations
    ):
        """Test batch fetching aggregations for multiple clusters."""
        source_id = "clusterpulse/pvc-metrics"
        
        fake_redis.set(
            f"cluster:cluster-a:custom:{source_id}:aggregations",
            json.dumps(sample_aggregations),
        )
        
        results = metric_source_repo.get_custom_aggregations_for_clusters(
            source_id, ["cluster-a", "cluster-b"]
        )
        
        assert results["cluster-a"] is not None
        assert results["cluster-a"]["values"]["total_count"] == 2
        assert results["cluster-b"] is None


@pytest.mark.unit
class TestMetricSourceRepositoryEdgeCases:
    """Test edge cases and error handling."""

    def test_handles_malformed_json(self, metric_source_repo, fake_redis):
        """Test handling of malformed JSON in Redis."""
        fake_redis.set("metricsource:ns:name", "not-valid-json")
        
        source = metric_source_repo.get_metric_source("ns/name")
        assert source is None

    def test_handles_empty_source_id_list(self, metric_source_repo):
        """Test getting sources with empty ID list."""
        sources = metric_source_repo.get_all_metric_sources()
        assert sources == []

    def test_batch_get_empty_clusters(self, metric_source_repo):
        """Test batch get with empty cluster list."""
        results = metric_source_repo.get_custom_resources_for_clusters(
            "ns/source", []
        )
        assert results == {}

    def test_get_resource_type_mapping_empty(self, metric_source_repo):
        """Test mapping with no sources."""
        mapping = metric_source_repo.get_resource_type_mapping()
        assert mapping == {}
