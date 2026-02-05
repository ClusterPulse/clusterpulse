"""Integration tests for custom resources API routes."""

import json

import pytest
from fastapi import status


@pytest.fixture
def custom_resource_policy():
    """Policy granting access to custom resources."""
    return {
        "policy_name": "custom-resource-access",
        "priority": 100,
        "effect": "Allow",
        "enabled": True,
        "subjects": [{"type": "Group", "name": "developers"}],
        "cluster_rules": [
            {
                "cluster_selector": {"matchPattern": ".*"},
                "permissions": {"view": True, "viewMetrics": True},
                "namespace_filter": {"visibility": "all"},
                "node_filter": {"visibility": "all"},
                "custom_resources": {
                    "pvc": {
                        "visibility": "all",
                        "permissions": {"view": True, "viewMetrics": True},
                    },
                    "certificate": {
                        "visibility": "filtered",
                        "permissions": {"view": True},
                        "namespace_filter": {
                            "allowed_literals": ["team-a"],
                            "allowed_patterns": [["dev-.*", "^dev-.*$"]],
                        },
                    },
                },
            }
        ],
    }


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
            {"name": "capacity"},
            {"name": "status"},
        ],
        "computed": [],
        "aggregations": [
            {"name": "total_count", "function": "count"},
            {"name": "sum_capacity", "function": "sum", "field": "capacity"},
        ],
    }


@pytest.fixture
def sample_custom_resources_data():
    """Sample collected custom resources."""
    return {
        "resources": [
            {"_name": "pvc-1", "_namespace": "team-a", "values": {"capacity": 100, "status": "Bound"}},
            {"_name": "pvc-2", "_namespace": "team-a", "values": {"capacity": 200, "status": "Bound"}},
            {"_name": "pvc-3", "_namespace": "team-b", "values": {"capacity": 150, "status": "Pending"}},
        ],
        "collectedAt": "2024-01-15T10:30:00Z",
        "truncated": False,
    }


@pytest.fixture
def sample_aggregations_data():
    """Sample computed aggregations."""
    return {
        "values": {
            "total_count": 3,
            "sum_capacity": 450,
        },
        "computedAt": "2024-01-15T10:30:00Z",
    }


def setup_metric_source(fake_redis, metric_source):
    """Helper to set up MetricSource in Redis."""
    source_id = f"{metric_source['namespace']}/{metric_source['name']}"
    resource_type = metric_source["rbac"]["resourceTypeName"]
    
    fake_redis.sadd("metricsources:enabled", source_id)
    fake_redis.set(
        f"metricsource:{metric_source['namespace']}:{metric_source['name']}",
        json.dumps(metric_source),
    )
    fake_redis.sadd(f"metricsources:by:resourcetype:{resource_type}", source_id)
    
    return source_id


def setup_custom_resources(fake_redis, source_id, cluster, resources, aggregations=None):
    """Helper to set up custom resources in Redis."""
    fake_redis.set(
        f"cluster:{cluster}:custom:{source_id}:resources",
        json.dumps(resources),
    )
    if aggregations:
        fake_redis.set(
            f"cluster:{cluster}:custom:{source_id}:aggregations",
            json.dumps(aggregations),
        )


@pytest.mark.integration
class TestListCustomResourceTypes:
    """Test GET /api/v1/custom-types endpoint."""

    def test_list_types_authenticated(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_policies,
        custom_resource_policy,
        sample_metric_source,
    ):
        """Test listing custom resource types as authenticated user."""
        populate_redis_with_policies([custom_resource_policy])
        setup_metric_source(fake_redis, sample_metric_source)
        
        def mock_resolve_groups(username, email=None):
            return ["developers"]
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_resolve_groups
        
        response = authenticated_client.get("/api/v1/custom-types")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        
        # Should see pvc (has MetricSource and policy access)
        type_names = [t["resourceTypeName"] for t in data]
        assert "pvc" in type_names

    def test_list_types_no_access(self, test_client, fake_redis, sample_metric_source):
        """Test listing types with no policy access returns empty."""
        setup_metric_source(fake_redis, sample_metric_source)
        
        test_client.headers.update({
            "X-Forwarded-User": "noone",
            "X-Forwarded-Email": "noone@example.com",
        })
        
        def mock_resolve_groups(username, email=None):
            return []
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_resolve_groups
        
        response = test_client.get("/api/v1/custom-types")
        
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == []

    def test_list_types_with_source_details(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_policies,
        custom_resource_policy,
        sample_metric_source,
    ):
        """Test listing types with source details included."""
        populate_redis_with_policies([custom_resource_policy])
        setup_metric_source(fake_redis, sample_metric_source)
        
        def mock_resolve_groups(username, email=None):
            return ["developers"]
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_resolve_groups
        
        response = authenticated_client.get(
            "/api/v1/custom-types?include_source_details=true"
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        pvc_type = next((t for t in data if t["resourceTypeName"] == "pvc"), None)
        assert pvc_type is not None
        assert "source" in pvc_type
        assert pvc_type["source"]["kind"] == "PersistentVolumeClaim"

    def test_list_types_with_cluster_availability(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_policies,
        custom_resource_policy,
        sample_metric_source,
        sample_custom_resources_data,
    ):
        """Test listing types with cluster availability."""
        populate_redis_with_policies([custom_resource_policy])
        source_id = setup_metric_source(fake_redis, sample_metric_source)
        setup_custom_resources(fake_redis, source_id, "dev-cluster", sample_custom_resources_data)
        
        def mock_resolve_groups(username, email=None):
            return ["developers"]
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_resolve_groups
        
        response = authenticated_client.get(
            "/api/v1/custom-types?include_cluster_availability=true"
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        pvc_type = next((t for t in data if t["resourceTypeName"] == "pvc"), None)
        assert pvc_type is not None
        assert "clustersWithData" in pvc_type


@pytest.mark.integration
class TestGetCustomResourceCounts:
    """Test GET /api/v1/custom-types/clusters endpoint."""

    def test_get_counts_single_type(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        custom_resource_policy,
        sample_metric_source,
        sample_custom_resources_data,
        sample_aggregations_data,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test getting resource counts for a single type."""
        populate_redis_with_policies([custom_resource_policy])
        populate_redis_with_cluster(
            "dev-cluster",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
        )
        source_id = setup_metric_source(fake_redis, sample_metric_source)
        setup_custom_resources(
            fake_redis, source_id, "dev-cluster",
            sample_custom_resources_data, sample_aggregations_data
        )
        
        def mock_resolve_groups(username, email=None):
            return ["developers"]
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_resolve_groups
        
        response = authenticated_client.get("/api/v1/custom-types/clusters?type=pvc")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        
        count_entry = data[0]
        assert count_entry["cluster"] == "dev-cluster"
        assert count_entry["resourceTypeName"] == "pvc"
        assert "count" in count_entry

    def test_get_counts_with_aggregations(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        custom_resource_policy,
        sample_metric_source,
        sample_custom_resources_data,
        sample_aggregations_data,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test getting counts with aggregations."""
        populate_redis_with_policies([custom_resource_policy])
        populate_redis_with_cluster(
            "dev-cluster",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
        )
        source_id = setup_metric_source(fake_redis, sample_metric_source)
        setup_custom_resources(
            fake_redis, source_id, "dev-cluster",
            sample_custom_resources_data, sample_aggregations_data
        )
        
        def mock_resolve_groups(username, email=None):
            return ["developers"]
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_resolve_groups
        
        response = authenticated_client.get(
            "/api/v1/custom-types/clusters?type=pvc&include_aggregations=true"
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        count_entry = data[0]
        assert "aggregations" in count_entry

    def test_get_counts_no_access(
        self,
        test_client,
        fake_redis,
        sample_metric_source,
    ):
        """Test getting counts without policy access."""
        setup_metric_source(fake_redis, sample_metric_source)
        
        test_client.headers.update({
            "X-Forwarded-User": "noone",
            "X-Forwarded-Email": "noone@example.com",
        })
        
        def mock_resolve_groups(username, email=None):
            return []
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_resolve_groups
        
        response = test_client.get("/api/v1/custom-types/clusters?type=pvc")
        
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.integration
class TestGetClusterCustomResources:
    """Test GET /api/v1/clusters/{cluster}/custom/{type} endpoint."""

    def test_get_custom_resources(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        custom_resource_policy,
        sample_metric_source,
        sample_custom_resources_data,
        sample_aggregations_data,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test getting custom resources for a cluster."""
        populate_redis_with_policies([custom_resource_policy])
        populate_redis_with_cluster(
            "dev-cluster",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
        )
        source_id = setup_metric_source(fake_redis, sample_metric_source)
        setup_custom_resources(
            fake_redis, source_id, "dev-cluster",
            sample_custom_resources_data, sample_aggregations_data
        )
        
        def mock_resolve_groups(username, email=None):
            return ["developers"]
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_resolve_groups
        
        response = authenticated_client.get("/api/v1/clusters/dev-cluster/custom/pvc")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        assert data["resourceTypeName"] == "pvc"
        assert data["cluster"] == "dev-cluster"
        assert "items" in data
        assert "pagination" in data

    def test_get_custom_resources_with_pagination(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        custom_resource_policy,
        sample_metric_source,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test pagination of custom resources."""
        populate_redis_with_policies([custom_resource_policy])
        populate_redis_with_cluster(
            "dev-cluster",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
        )
        source_id = setup_metric_source(fake_redis, sample_metric_source)
        
        # Create many resources
        resources = {
            "resources": [
                {"_name": f"pvc-{i}", "_namespace": "team-a", "values": {"capacity": i * 10}}
                for i in range(50)
            ],
            "collectedAt": "2024-01-15T10:30:00Z",
        }
        setup_custom_resources(fake_redis, source_id, "dev-cluster", resources)
        
        def mock_resolve_groups(username, email=None):
            return ["developers"]
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_resolve_groups
        
        # Get first page
        response = authenticated_client.get(
            "/api/v1/clusters/dev-cluster/custom/pvc?page=1&page_size=10"
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        assert len(data["items"]) == 10
        assert data["pagination"]["total"] == 50
        assert data["pagination"]["page"] == 1
        assert data["pagination"]["totalPages"] == 5
        assert data["pagination"]["hasNext"] is True
        assert data["pagination"]["hasPrevious"] is False

    def test_get_custom_resources_namespace_filter(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        custom_resource_policy,
        sample_metric_source,
        sample_custom_resources_data,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test filtering custom resources by namespace."""
        populate_redis_with_policies([custom_resource_policy])
        populate_redis_with_cluster(
            "dev-cluster",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
        )
        source_id = setup_metric_source(fake_redis, sample_metric_source)
        setup_custom_resources(fake_redis, source_id, "dev-cluster", sample_custom_resources_data)
        
        def mock_resolve_groups(username, email=None):
            return ["developers"]
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_resolve_groups
        
        response = authenticated_client.get(
            "/api/v1/clusters/dev-cluster/custom/pvc?namespace=team-a"
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        # Should only have team-a resources
        for item in data["items"]:
            assert item["_namespace"] == "team-a"

    def test_get_custom_resources_sorting(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        custom_resource_policy,
        sample_metric_source,
        sample_custom_resources_data,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test sorting custom resources."""
        populate_redis_with_policies([custom_resource_policy])
        populate_redis_with_cluster(
            "dev-cluster",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
        )
        source_id = setup_metric_source(fake_redis, sample_metric_source)
        setup_custom_resources(fake_redis, source_id, "dev-cluster", sample_custom_resources_data)
        
        def mock_resolve_groups(username, email=None):
            return ["developers"]
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_resolve_groups
        
        response = authenticated_client.get(
            "/api/v1/clusters/dev-cluster/custom/pvc?sort_by=capacity&sort_order=desc"
        )
        
        assert response.status_code == status.HTTP_200_OK

    def test_get_custom_resources_not_found(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        custom_resource_policy,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test getting custom resources for unknown type."""
        populate_redis_with_policies([custom_resource_policy])
        populate_redis_with_cluster(
            "dev-cluster",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
        )
        
        def mock_resolve_groups(username, email=None):
            return ["developers"]
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_resolve_groups
        
        response = authenticated_client.get(
            "/api/v1/clusters/dev-cluster/custom/unknown-type"
        )
        
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_get_custom_resources_no_cluster_access(
        self,
        test_client,
        fake_redis,
        populate_redis_with_cluster,
        sample_metric_source,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test getting custom resources without cluster access."""
        populate_redis_with_cluster(
            "dev-cluster",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
        )
        setup_metric_source(fake_redis, sample_metric_source)
        
        test_client.headers.update({
            "X-Forwarded-User": "noone",
            "X-Forwarded-Email": "noone@example.com",
        })
        
        def mock_resolve_groups(username, email=None):
            return []
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_resolve_groups
        
        response = test_client.get("/api/v1/clusters/dev-cluster/custom/pvc")
        
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_get_custom_resources_with_aggregations(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        custom_resource_policy,
        sample_metric_source,
        sample_custom_resources_data,
        sample_aggregations_data,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test getting custom resources with aggregations."""
        populate_redis_with_policies([custom_resource_policy])
        populate_redis_with_cluster(
            "dev-cluster",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
        )
        source_id = setup_metric_source(fake_redis, sample_metric_source)
        setup_custom_resources(
            fake_redis, source_id, "dev-cluster",
            sample_custom_resources_data, sample_aggregations_data
        )
        
        def mock_resolve_groups(username, email=None):
            return ["developers"]
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_resolve_groups
        
        response = authenticated_client.get(
            "/api/v1/clusters/dev-cluster/custom/pvc?include_aggregations=true"
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        assert "aggregations" in data

    def test_get_custom_resources_empty(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        custom_resource_policy,
        sample_metric_source,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test getting custom resources when none exist."""
        populate_redis_with_policies([custom_resource_policy])
        populate_redis_with_cluster(
            "dev-cluster",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
        )
        setup_metric_source(fake_redis, sample_metric_source)
        # Don't set up any resources
        
        def mock_resolve_groups(username, email=None):
            return ["developers"]
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_resolve_groups
        
        response = authenticated_client.get("/api/v1/clusters/dev-cluster/custom/pvc")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        assert data["items"] == []
        assert data["pagination"]["total"] == 0


@pytest.mark.integration
class TestCustomResourceRBACFiltering:
    """Test RBAC filtering of custom resources."""

    def test_namespace_filtered_access(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test that namespace filtering is applied."""
        # Policy with namespace restrictions
        filtered_policy = {
            "policy_name": "filtered-access",
            "priority": 100,
            "effect": "Allow",
            "enabled": True,
            "subjects": [{"type": "Group", "name": "developers"}],
            "cluster_rules": [
                {
                    "cluster_selector": {"matchPattern": ".*"},
                    "permissions": {"view": True},
                    "namespace_filter": {"visibility": "all"},
                    "custom_resources": {
                        "pvc": {
                            "visibility": "filtered",
                            "permissions": {"view": True},
                            "namespace_filter": {
                                "allowed_literals": ["allowed-ns"],
                            },
                        },
                    },
                }
            ],
        }
        
        populate_redis_with_policies([filtered_policy])
        populate_redis_with_cluster(
            "dev-cluster",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
        )
        
        metric_source = {
            "name": "pvc-metrics",
            "namespace": "clusterpulse",
            "source": {"apiVersion": "v1", "kind": "PVC", "scope": "Namespaced"},
            "rbac": {"resourceTypeName": "pvc", "filterAggregations": True},
            "fields": [{"name": "capacity"}],
            "computed": [],
            "aggregations": [],
        }
        source_id = setup_metric_source(fake_redis, metric_source)
        
        resources = {
            "resources": [
                {"_name": "pvc-1", "_namespace": "allowed-ns", "values": {"capacity": 100}},
                {"_name": "pvc-2", "_namespace": "denied-ns", "values": {"capacity": 200}},
            ],
            "collectedAt": "2024-01-15T10:30:00Z",
        }
        setup_custom_resources(fake_redis, source_id, "dev-cluster", resources)
        
        def mock_resolve_groups(username, email=None):
            return ["developers"]
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_resolve_groups
        
        response = authenticated_client.get("/api/v1/clusters/dev-cluster/custom/pvc")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        # Should only see allowed-ns resources
        assert len(data["items"]) == 1
        assert data["items"][0]["_namespace"] == "allowed-ns"
        assert data["filtered"] is True
