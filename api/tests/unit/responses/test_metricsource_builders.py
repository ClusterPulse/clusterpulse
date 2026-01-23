"""Unit tests for MetricSource response builders."""

import pytest

from clusterpulse.api.responses.metricsource import (
    ClusterResourceCountBuilder,
    CustomResourceDetailBuilder,
    CustomResourceTypeBuilder,
)


class TestCustomResourceTypeBuilder:
    """Test CustomResourceTypeBuilder."""

    def test_basic_build(self):
        """Test building basic response."""
        builder = CustomResourceTypeBuilder("pvc")
        result = builder.build()
        
        assert result["resourceTypeName"] == "pvc"

    def test_with_source_id(self):
        """Test adding source ID."""
        builder = CustomResourceTypeBuilder("pvc").with_source_id("ns/pvc-metrics")
        result = builder.build()
        
        assert result["sourceId"] == "ns/pvc-metrics"

    def test_with_source_info(self):
        """Test adding source details."""
        source = {
            "source": {
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "scope": "Namespaced",
            },
            "fields": [
                {"name": "capacity"},
                {"name": "status"},
            ],
            "computed": [
                {"name": "utilization"},
            ],
            "aggregations": [
                {"name": "total_count"},
                {"name": "sum_capacity"},
            ],
        }
        
        builder = CustomResourceTypeBuilder("pvc").with_source_info(source)
        result = builder.build()
        
        assert result["source"]["apiVersion"] == "v1"
        assert result["source"]["kind"] == "PersistentVolumeClaim"
        assert result["source"]["scope"] == "Namespaced"
        assert "capacity" in result["fields"]
        assert "utilization" in result["computedFields"]
        assert "total_count" in result["aggregations"]

    def test_with_source_info_none(self):
        """Test with_source_info handles None."""
        builder = CustomResourceTypeBuilder("pvc").with_source_info(None)
        result = builder.build()
        
        assert "source" not in result

    def test_with_cluster_availability(self):
        """Test adding cluster availability."""
        clusters = ["cluster-a", "cluster-b"]
        
        builder = CustomResourceTypeBuilder("pvc").with_cluster_availability(clusters)
        result = builder.build()
        
        assert result["clustersWithData"] == clusters

    def test_full_builder_chain(self):
        """Test full builder chain."""
        source = {
            "source": {"apiVersion": "v1", "kind": "PVC", "scope": "Namespaced"},
            "fields": [{"name": "capacity"}],
            "computed": [],
            "aggregations": [{"name": "count"}],
        }
        
        result = (
            CustomResourceTypeBuilder("pvc")
            .with_source_id("ns/pvc-metrics")
            .with_source_info(source)
            .with_cluster_availability(["c1", "c2"])
            .build()
        )
        
        assert result["resourceTypeName"] == "pvc"
        assert result["sourceId"] == "ns/pvc-metrics"
        assert result["source"]["kind"] == "PVC"
        assert result["clustersWithData"] == ["c1", "c2"]


class TestClusterResourceCountBuilder:
    """Test ClusterResourceCountBuilder."""

    def test_basic_build(self):
        """Test building basic count response."""
        builder = ClusterResourceCountBuilder("cluster-a", "pvc")
        result = builder.build()
        
        assert result["cluster"] == "cluster-a"
        assert result["resourceTypeName"] == "pvc"

    def test_with_counts(self):
        """Test adding counts."""
        builder = ClusterResourceCountBuilder("cluster-a", "pvc").with_counts(42)
        result = builder.build()
        
        assert result["count"] == 42

    def test_with_aggregations(self):
        """Test adding aggregations."""
        aggs = {"total": 100, "sum_capacity": 500}
        
        builder = ClusterResourceCountBuilder("cluster-a", "pvc").with_aggregations(aggs)
        result = builder.build()
        
        assert result["aggregations"] == aggs

    def test_with_aggregations_empty(self):
        """Test with_aggregations handles empty dict."""
        builder = ClusterResourceCountBuilder("cluster-a", "pvc").with_aggregations({})
        result = builder.build()
        
        assert "aggregations" not in result

    def test_with_collection_time(self):
        """Test adding collection timestamp."""
        builder = ClusterResourceCountBuilder("cluster-a", "pvc").with_collection_time(
            "2024-01-15T10:30:00Z"
        )
        result = builder.build()
        
        assert result["lastCollection"] == "2024-01-15T10:30:00Z"

    def test_with_collection_time_none(self):
        """Test with_collection_time handles None."""
        builder = ClusterResourceCountBuilder("cluster-a", "pvc").with_collection_time(None)
        result = builder.build()
        
        assert "lastCollection" not in result

    def test_full_builder_chain(self):
        """Test full builder chain."""
        result = (
            ClusterResourceCountBuilder("cluster-a", "pvc")
            .with_counts(50)
            .with_aggregations({"total": 50})
            .with_collection_time("2024-01-15T10:30:00Z")
            .build()
        )
        
        assert result["cluster"] == "cluster-a"
        assert result["resourceTypeName"] == "pvc"
        assert result["count"] == 50
        assert result["aggregations"]["total"] == 50
        assert result["lastCollection"] == "2024-01-15T10:30:00Z"


class TestCustomResourceDetailBuilder:
    """Test CustomResourceDetailBuilder."""

    def test_basic_build(self):
        """Test building basic detail response."""
        builder = CustomResourceDetailBuilder("pvc", "cluster-a")
        result = builder.build()
        
        assert result["resourceTypeName"] == "pvc"
        assert result["cluster"] == "cluster-a"

    def test_with_collection_metadata(self):
        """Test adding collection metadata."""
        metadata = {"collectedAt": "2024-01-15T10:30:00Z", "truncated": True}
        
        builder = CustomResourceDetailBuilder("pvc", "cluster-a").with_collection_metadata(
            metadata
        )
        result = builder.build()
        
        assert result["collectedAt"] == "2024-01-15T10:30:00Z"
        assert result["truncated"] is True

    def test_with_collection_metadata_not_truncated(self):
        """Test collection metadata without truncation."""
        metadata = {"collectedAt": "2024-01-15T10:30:00Z"}
        
        builder = CustomResourceDetailBuilder("pvc", "cluster-a").with_collection_metadata(
            metadata
        )
        result = builder.build()
        
        assert result["collectedAt"] == "2024-01-15T10:30:00Z"
        assert "truncated" not in result

    def test_with_collection_metadata_none(self):
        """Test with_collection_metadata handles None."""
        builder = CustomResourceDetailBuilder("pvc", "cluster-a").with_collection_metadata(
            None
        )
        result = builder.build()
        
        assert "collectedAt" not in result

    def test_with_resources_not_filtered(self):
        """Test adding resources without filtering."""
        resources = [{"_name": "pvc-1"}, {"_name": "pvc-2"}]
        
        builder = CustomResourceDetailBuilder("pvc", "cluster-a").with_resources(
            resources, filtered=False
        )
        result = builder.build()
        
        assert result["items"] == resources
        assert result["filtered"] is False
        assert "filterNote" not in result

    def test_with_resources_filtered(self):
        """Test adding resources with filtering."""
        resources = [{"_name": "pvc-1"}]
        
        builder = CustomResourceDetailBuilder("pvc", "cluster-a").with_resources(
            resources, filtered=True
        )
        result = builder.build()
        
        assert result["items"] == resources
        assert result["filtered"] is True
        assert "filterNote" in result

    def test_with_aggregations(self):
        """Test adding aggregations."""
        aggs = {"total_count": 10, "sum_capacity": 100}
        
        builder = CustomResourceDetailBuilder("pvc", "cluster-a").with_aggregations(aggs)
        result = builder.build()
        
        assert result["aggregations"] == aggs

    def test_with_aggregations_empty(self):
        """Test with_aggregations handles empty dict."""
        builder = CustomResourceDetailBuilder("pvc", "cluster-a").with_aggregations({})
        result = builder.build()
        
        assert "aggregations" not in result

    def test_with_pagination(self):
        """Test adding pagination metadata."""
        pagination = {
            "total": 100,
            "page": 2,
            "pageSize": 25,
            "totalPages": 4,
            "hasNext": True,
            "hasPrevious": True,
        }
        
        builder = CustomResourceDetailBuilder("pvc", "cluster-a").with_pagination(
            pagination
        )
        result = builder.build()
        
        assert result["pagination"] == pagination

    def test_full_builder_chain(self):
        """Test full builder chain."""
        resources = [{"_name": "pvc-1"}]
        
        result = (
            CustomResourceDetailBuilder("pvc", "cluster-a")
            .with_collection_metadata({"collectedAt": "2024-01-15T10:30:00Z"})
            .with_resources(resources, filtered=True)
            .with_aggregations({"total": 1})
            .with_pagination({"total": 1, "page": 1, "pageSize": 100, "totalPages": 1, "hasNext": False, "hasPrevious": False})
            .build()
        )
        
        assert result["resourceTypeName"] == "pvc"
        assert result["cluster"] == "cluster-a"
        assert result["collectedAt"] == "2024-01-15T10:30:00Z"
        assert result["items"] == resources
        assert result["filtered"] is True
        assert result["aggregations"]["total"] == 1
        assert result["pagination"]["total"] == 1
