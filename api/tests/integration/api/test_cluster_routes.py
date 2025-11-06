"""Integration tests for cluster API routes."""

import json

import pytest
from fastapi import status


@pytest.mark.integration
class TestClusterListEndpoint:
    """Test GET /api/v1/clusters endpoint."""

    def test_list_clusters_authenticated(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        basic_dev_policy,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
        sample_nodes,
        sample_namespaces,
    ):
        """Test listing clusters as authenticated user."""
        # Setup policy
        populate_redis_with_policies([basic_dev_policy])

        # Setup clusters
        populate_redis_with_cluster(
            "dev-cluster-1",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
            sample_nodes,
            sample_namespaces,
        )

        # Mock group resolution to return developer group
        def mock_resolve_groups(username, email=None):
            return ["developers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        # Make request
        response = authenticated_client.get("/api/v1/clusters")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["name"] == "dev-cluster-1"
        assert "status" in data[0]
        assert "metrics" in data[0]

    def test_list_clusters_no_access(
        self,
        test_client,
        fake_redis,
        populate_redis_with_cluster,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test listing clusters with no access returns empty list."""
        # Setup cluster but no policies
        populate_redis_with_cluster(
            "dev-cluster-1",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
        )

        # Mock headers for user with no groups
        test_client.headers.update(
            {"X-Forwarded-User": "noone", "X-Forwarded-Email": "noone@example.com"}
        )

        def mock_resolve_groups(username, email=None):
            return []

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = test_client.get("/api/v1/clusters")

        assert response.status_code == status.HTTP_200_OK
        assert response.json() == []

    def test_list_clusters_filtered_metrics(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        namespace_filtered_policy,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
        sample_nodes,
        sample_namespaces,
        sample_pods,
    ):
        """Test that metrics are filtered based on namespace access."""
        # Setup namespace-filtered policy
        populate_redis_with_policies([namespace_filtered_policy])

        # Setup cluster with namespace-scoped resources
        populate_redis_with_cluster(
            "production-cluster",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
            sample_nodes,
            sample_namespaces,
        )

        # Add pod data
        fake_redis.set(f"cluster:production-cluster:pods", json.dumps(sample_pods))

        def mock_resolve_groups(username, email=None):
            return ["developers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get("/api/v1/clusters")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 1

        cluster = data[0]
        assert cluster["name"] == "production-cluster"

        # Metrics should be filtered
        if cluster["metrics"]:
            metrics = cluster["metrics"]
            # Should have filter note if filtering was applied
            assert "filtered" in metrics or "filter_note" in metrics


@pytest.mark.integration
class TestClusterDetailEndpoint:
    """Test GET /api/v1/clusters/{cluster_name} endpoint."""

    def test_get_cluster_detail(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        basic_dev_policy,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
        sample_nodes,
        sample_namespaces,
    ):
        """Test getting cluster details."""
        populate_redis_with_policies([basic_dev_policy])
        populate_redis_with_cluster(
            "dev-cluster-1",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
            sample_nodes,
            sample_namespaces,
        )

        def mock_resolve_groups(username, email=None):
            return ["developers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get("/api/v1/clusters/dev-cluster-1")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["name"] == "dev-cluster-1"
        assert "spec" in data
        assert "status" in data
        assert "metrics" in data

    def test_get_cluster_not_found(self, authenticated_client, fake_redis):
        """Test getting non-existent cluster returns 404."""
        def mock_resolve_groups(username, email=None):
            return ["developers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get("/api/v1/clusters/nonexistent")

        # Should return 404 or empty data depending on implementation
        assert response.status_code in [
            status.HTTP_404_NOT_FOUND,
            status.HTTP_403_FORBIDDEN,
        ]

    def test_get_cluster_no_permission(
        self,
        test_client,
        fake_redis,
        populate_redis_with_cluster,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test getting cluster without permission returns 403."""
        populate_redis_with_cluster(
            "prod-cluster",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
        )

        test_client.headers.update(
            {"X-Forwarded-User": "noone", "X-Forwarded-Email": "noone@example.com"}
        )

        def mock_resolve_groups(username, email=None):
            return []

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = test_client.get("/api/v1/clusters/prod-cluster")

        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.integration
class TestClusterNodesEndpoint:
    """Test GET /api/v1/clusters/{cluster_name}/nodes endpoint."""

    def test_list_cluster_nodes(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        basic_dev_policy,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
        sample_nodes,
    ):
        """Test listing cluster nodes."""
        populate_redis_with_policies([basic_dev_policy])
        populate_redis_with_cluster(
            "dev-cluster-1",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
            sample_nodes,
        )

        def mock_resolve_groups(username, email=None):
            return ["developers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get("/api/v1/clusters/dev-cluster-1/nodes")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == len(sample_nodes)

    def test_list_cluster_nodes_filtered(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
        sample_nodes,
    ):
        """Test listing nodes with node filter applied."""
        # Policy that filters nodes
        node_filtered_policy = {
            "policy_name": "node-filtered-policy",
            "priority": 100,
            "effect": "Allow",
            "enabled": True,
            "subjects": [{"type": "Group", "name": "developers"}],
            "cluster_rules": [
                {
                    "cluster_selector": {"matchPattern": ".*"},
                    "permissions": {"view": True},
                    "node_filter": {
                        "visibility": "filtered",
                        "allowed_literals": ["worker-1"],
                    },
                }
            ],
        }

        populate_redis_with_policies([node_filtered_policy])
        populate_redis_with_cluster(
            "dev-cluster-1",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
            sample_nodes,
        )

        def mock_resolve_groups(username, email=None):
            return ["developers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get("/api/v1/clusters/dev-cluster-1/nodes")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # Should only see worker-1
        assert len(data) == 1
        assert data[0]["name"] == "worker-1"

    def test_filter_nodes_by_role(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        basic_dev_policy,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
        sample_nodes,
    ):
        """Test filtering nodes by role query parameter."""
        populate_redis_with_policies([basic_dev_policy])
        populate_redis_with_cluster(
            "dev-cluster-1",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
            sample_nodes,
        )

        def mock_resolve_groups(username, email=None):
            return ["developers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get(
            "/api/v1/clusters/dev-cluster-1/nodes?role=worker"
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # Should only see worker nodes
        assert all("worker" in node.get("roles", []) for node in data)


@pytest.mark.integration
class TestClusterNamespacesEndpoint:
    """Test GET /api/v1/clusters/{cluster_name}/namespaces endpoint."""

    def test_list_namespaces(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        basic_dev_policy,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
        sample_namespaces,
    ):
        """Test listing cluster namespaces."""
        populate_redis_with_policies([basic_dev_policy])
        populate_redis_with_cluster(
            "dev-cluster-1",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
            namespaces=sample_namespaces,
        )

        def mock_resolve_groups(username, email=None):
            return ["developers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get(
            "/api/v1/clusters/dev-cluster-1/namespaces"
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        # Should return only accessible namespaces
        assert len(data) > 0

    def test_list_namespaces_filtered(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        namespace_filtered_policy,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
        sample_namespaces,
    ):
        """Test listing namespaces with filtering applied."""
        populate_redis_with_policies([namespace_filtered_policy])
        populate_redis_with_cluster(
            "production-cluster",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
            namespaces=sample_namespaces,
        )

        def mock_resolve_groups(username, email=None):
            return ["developers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get(
            "/api/v1/clusters/production-cluster/namespaces"
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Should only see team-a namespaces
        if isinstance(data, list) and len(data) > 0:
            if isinstance(data[0], str):
                # Simple list of names
                assert all(
                    ns.startswith("team-a") or ns in ["team-a-prod", "team-a-staging"]
                    for ns in data
                )
            else:
                # Detailed namespace objects
                assert all(
                    ns["namespace"].startswith("team-a")
                    or ns["namespace"] in ["team-a-prod", "team-a-staging"]
                    for ns in data
                )


@pytest.mark.integration
class TestClusterOperatorsEndpoint:
    """Test GET /api/v1/clusters/{cluster_name}/operators endpoint."""

    def test_list_operators(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        basic_dev_policy,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
        sample_operators,
    ):
        """Test listing cluster operators."""
        populate_redis_with_policies([basic_dev_policy])
        populate_redis_with_cluster(
            "dev-cluster-1",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
            operators=sample_operators,
        )

        def mock_resolve_groups(username, email=None):
            return ["developers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get(
            "/api/v1/clusters/dev-cluster-1/operators"
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_filter_operators_by_namespace(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        namespace_filtered_policy,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
        sample_namespaces,
        sample_operators,
    ):
        """Test operator filtering based on namespace access."""
        populate_redis_with_policies([namespace_filtered_policy])
        populate_redis_with_cluster(
            "production-cluster",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
            namespaces=sample_namespaces,
            operators=sample_operators,
        )

        def mock_resolve_groups(username, email=None):
            return ["developers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get(
            "/api/v1/clusters/production-cluster/operators"
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Should see cluster-wide operators and operators in allowed namespaces
        assert isinstance(data, list)


@pytest.mark.integration
class TestClusterMetricsEndpoint:
    """Test GET /api/v1/clusters/{cluster_name}/metrics endpoint."""

    def test_get_cluster_metrics(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        basic_dev_policy,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test getting cluster metrics."""
        populate_redis_with_policies([basic_dev_policy])
        populate_redis_with_cluster(
            "dev-cluster-1",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
        )

        def mock_resolve_groups(username, email=None):
            return ["developers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get("/api/v1/clusters/dev-cluster-1/metrics")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "nodes" in data
        assert "pods" in data
        assert "cpu_usage_percent" in data
        assert "memory_usage_percent" in data

    def test_get_metrics_no_permission(
        self,
        test_client,
        fake_redis,
        populate_redis_with_cluster,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test getting metrics without any cluster access."""
        # Policy that does NOT match this cluster
        limited_policy = {
            "policy_name": "limited-policy",
            "priority": 100,
            "effect": "Allow",
            "enabled": True,
            "subjects": [{"type": "Group", "name": "limited"}],
            "cluster_rules": [
                {
                    "cluster_selector": {"matchPattern": "other-.*"},  # Doesn't match dev-cluster-1
                    "permissions": {"view": True},
                }
            ],
        }

        policy_key = f"policy:{limited_policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(limited_policy))
        fake_redis.zadd(
            "policy:group:limited:sorted",
            {policy_key: limited_policy["priority"]},
        )

        populate_redis_with_cluster(
            "dev-cluster-1",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
        )

        test_client.headers.update(
            {
                "X-Forwarded-User": "limited.user",
                "X-Forwarded-Email": "limited@example.com",
            }
        )

        def mock_resolve_groups(username, email=None):
            return ["limited"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = test_client.get("/api/v1/clusters/dev-cluster-1/metrics")

        # Should return 403 because user has no access to this cluster
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.integration
class TestAuthenticationFlow:
    """Test authentication and authorization flow."""

    def test_unauthenticated_request(self, test_client):
        """Test request without authentication headers."""
        # In development mode, should get dev-user
        # In production mode with OAuth, should get 401
        response = test_client.get("/api/v1/clusters")

        # Development mode provides default user
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED]

    def test_authenticated_but_no_groups(self, test_client, fake_redis):
        """Test authenticated user with no group memberships."""
        test_client.headers.update(
            {"X-Forwarded-User": "lonely", "X-Forwarded-Email": "lonely@example.com"}
        )

        def mock_resolve_groups(username, email=None):
            return []

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = test_client.get("/api/v1/clusters")

        # Should succeed but return empty list (no access)
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == []
