"""Unit tests for aggregation computation utilities."""

import pytest

from clusterpulse.api.utils.aggregations import (
    _get_field_value,
    _matches_filter,
    recompute_aggregations,
)


class TestGetFieldValue:
    """Test field value extraction."""

    def test_extract_from_values_dict(self):
        """Extract field from values wrapper."""
        resource = {"values": {"status": "Bound", "capacity": 100}}
        
        assert _get_field_value(resource, "status") == "Bound"
        assert _get_field_value(resource, "capacity") == 100

    def test_extract_from_root(self):
        """Extract field from root level."""
        resource = {"name": "pvc-1", "namespace": "default"}
        
        assert _get_field_value(resource, "name") == "pvc-1"
        assert _get_field_value(resource, "namespace") == "default"

    def test_extract_prefixed_fields(self):
        """Extract underscore-prefixed metadata fields."""
        resource = {"_namespace": "default", "_name": "pvc-1", "_id": "abc123"}
        
        assert _get_field_value(resource, "namespace") == "default"
        assert _get_field_value(resource, "name") == "pvc-1"
        assert _get_field_value(resource, "id") == "abc123"

    def test_extract_nested_path(self):
        """Extract field using dot notation."""
        resource = {"spec": {"capacity": {"storage": "10Gi"}}}
        
        assert _get_field_value(resource, "spec.capacity.storage") == "10Gi"

    def test_extract_missing_field(self):
        """Return None for missing fields."""
        resource = {"name": "pvc-1"}
        
        assert _get_field_value(resource, "missing") is None
        assert _get_field_value(resource, "nested.missing") is None

    def test_values_takes_priority(self):
        """Values dict should take priority over root."""
        resource = {"status": "root", "values": {"status": "values"}}
        
        assert _get_field_value(resource, "status") == "values"


class TestMatchesFilter:
    """Test filter matching logic."""

    def test_no_filter(self):
        """No filter should match everything."""
        resource = {"values": {"status": "Bound"}}
        
        assert _matches_filter(resource, None)
        assert _matches_filter(resource, {})

    def test_equals_operator(self):
        """Test equals operator."""
        resource = {"values": {"status": "Bound"}}
        
        assert _matches_filter(resource, {"field": "status", "operator": "equals", "value": "Bound"})
        assert not _matches_filter(resource, {"field": "status", "operator": "equals", "value": "Pending"})

    def test_not_equals_operator(self):
        """Test notEquals operator."""
        resource = {"values": {"status": "Bound"}}
        
        assert _matches_filter(resource, {"field": "status", "operator": "notEquals", "value": "Pending"})
        assert not _matches_filter(resource, {"field": "status", "operator": "notEquals", "value": "Bound"})

    def test_greater_than_operator(self):
        """Test greaterThan operator."""
        resource = {"values": {"capacity": 100}}
        
        assert _matches_filter(resource, {"field": "capacity", "operator": "greaterThan", "value": 50})
        assert not _matches_filter(resource, {"field": "capacity", "operator": "greaterThan", "value": 150})

    def test_less_than_operator(self):
        """Test lessThan operator."""
        resource = {"values": {"capacity": 100}}
        
        assert _matches_filter(resource, {"field": "capacity", "operator": "lessThan", "value": 150})
        assert not _matches_filter(resource, {"field": "capacity", "operator": "lessThan", "value": 50})

    def test_contains_operator(self):
        """Test contains operator."""
        resource = {"values": {"name": "my-pvc-data"}}
        
        assert _matches_filter(resource, {"field": "name", "operator": "contains", "value": "pvc"})
        assert not _matches_filter(resource, {"field": "name", "operator": "contains", "value": "secret"})

    def test_in_operator(self):
        """Test in operator."""
        resource = {"values": {"status": "Bound"}}
        
        assert _matches_filter(resource, {"field": "status", "operator": "in", "value": ["Bound", "Available"]})
        assert not _matches_filter(resource, {"field": "status", "operator": "in", "value": ["Pending", "Failed"]})

    def test_default_equals_operator(self):
        """Test that equals is default operator."""
        resource = {"values": {"status": "Bound"}}
        
        assert _matches_filter(resource, {"field": "status", "value": "Bound"})


class TestRecomputeAggregations:
    """Test aggregation recomputation."""

    @pytest.fixture
    def sample_resources(self):
        """Sample resources for aggregation tests."""
        return [
            {"_name": "pvc-1", "_namespace": "ns-a", "values": {"capacity": 100, "status": "Bound"}},
            {"_name": "pvc-2", "_namespace": "ns-a", "values": {"capacity": 200, "status": "Bound"}},
            {"_name": "pvc-3", "_namespace": "ns-b", "values": {"capacity": 150, "status": "Pending"}},
            {"_name": "pvc-4", "_namespace": "ns-b", "values": {"capacity": 50, "status": "Failed"}},
        ]

    def test_count_aggregation(self, sample_resources):
        """Test count aggregation."""
        specs = [{"name": "total", "function": "count"}]
        
        result = recompute_aggregations(sample_resources, specs)
        
        assert result["total"] == 4

    def test_count_with_filter(self, sample_resources):
        """Test count with filter."""
        specs = [
            {
                "name": "bound_count",
                "function": "count",
                "filter": {"field": "status", "operator": "equals", "value": "Bound"},
            }
        ]
        
        result = recompute_aggregations(sample_resources, specs)
        
        assert result["bound_count"] == 2

    def test_sum_aggregation(self, sample_resources):
        """Test sum aggregation."""
        specs = [{"name": "total_capacity", "function": "sum", "field": "capacity"}]
        
        result = recompute_aggregations(sample_resources, specs)
        
        assert result["total_capacity"] == 500

    def test_avg_aggregation(self, sample_resources):
        """Test average aggregation."""
        specs = [{"name": "avg_capacity", "function": "avg", "field": "capacity"}]
        
        result = recompute_aggregations(sample_resources, specs)
        
        assert result["avg_capacity"] == 125.0

    def test_min_aggregation(self, sample_resources):
        """Test min aggregation."""
        specs = [{"name": "min_capacity", "function": "min", "field": "capacity"}]
        
        result = recompute_aggregations(sample_resources, specs)
        
        assert result["min_capacity"] == 50

    def test_max_aggregation(self, sample_resources):
        """Test max aggregation."""
        specs = [{"name": "max_capacity", "function": "max", "field": "capacity"}]
        
        result = recompute_aggregations(sample_resources, specs)
        
        assert result["max_capacity"] == 200

    def test_distinct_aggregation(self, sample_resources):
        """Test distinct count aggregation."""
        specs = [{"name": "unique_statuses", "function": "distinct", "field": "status"}]
        
        result = recompute_aggregations(sample_resources, specs)
        
        assert result["unique_statuses"] == 3  # Bound, Pending, Failed

    def test_percentile_aggregation(self, sample_resources):
        """Test percentile aggregation."""
        specs = [
            {"name": "p95_capacity", "function": "percentile", "field": "capacity", "percentile": 95}
        ]
        
        result = recompute_aggregations(sample_resources, specs)
        
        # With 4 values [50, 100, 150, 200], 95th percentile should be near 200
        assert result["p95_capacity"] == 200

    def test_grouped_aggregation(self, sample_resources):
        """Test grouped aggregation."""
        specs = [
            {"name": "count_by_namespace", "function": "count", "groupBy": "namespace"}
        ]
        
        result = recompute_aggregations(sample_resources, specs)
        
        assert result["count_by_namespace"]["ns-a"] == 2
        assert result["count_by_namespace"]["ns-b"] == 2

    def test_grouped_sum_aggregation(self, sample_resources):
        """Test grouped sum aggregation."""
        specs = [
            {"name": "capacity_by_status", "function": "sum", "field": "capacity", "groupBy": "status"}
        ]
        
        result = recompute_aggregations(sample_resources, specs)
        
        assert result["capacity_by_status"]["Bound"] == 300
        assert result["capacity_by_status"]["Pending"] == 150
        assert result["capacity_by_status"]["Failed"] == 50

    def test_multiple_aggregations(self, sample_resources):
        """Test multiple aggregations at once."""
        specs = [
            {"name": "total", "function": "count"},
            {"name": "sum_capacity", "function": "sum", "field": "capacity"},
            {"name": "avg_capacity", "function": "avg", "field": "capacity"},
        ]
        
        result = recompute_aggregations(sample_resources, specs)
        
        assert result["total"] == 4
        assert result["sum_capacity"] == 500
        assert result["avg_capacity"] == 125.0

    def test_empty_resources(self):
        """Test aggregations with empty resource list."""
        specs = [
            {"name": "total", "function": "count"},
            {"name": "sum_capacity", "function": "sum", "field": "capacity"},
        ]
        
        result = recompute_aggregations([], specs)
        
        assert result["total"] == 0
        assert result["sum_capacity"] == 0

    def test_missing_field_values(self):
        """Test aggregation when some resources lack the field."""
        resources = [
            {"values": {"capacity": 100}},
            {"values": {}},  # Missing capacity
            {"values": {"capacity": 200}},
        ]
        specs = [
            {"name": "sum_capacity", "function": "sum", "field": "capacity"},
            {"name": "avg_capacity", "function": "avg", "field": "capacity"},
        ]
        
        result = recompute_aggregations(resources, specs)
        
        assert result["sum_capacity"] == 300
        assert result["avg_capacity"] == 150.0  # Only counts 2 values

    def test_aggregation_with_combined_filter(self, sample_resources):
        """Test aggregation with filter on grouped results."""
        specs = [
            {
                "name": "bound_capacity",
                "function": "sum",
                "field": "capacity",
                "filter": {"field": "status", "operator": "equals", "value": "Bound"},
            }
        ]
        
        result = recompute_aggregations(sample_resources, specs)
        
        assert result["bound_capacity"] == 300
