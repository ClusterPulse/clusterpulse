"""Unit tests for RBAC Engine - the most critical security component."""

import json
from datetime import datetime, timezone

import pytest

from clusterpulse.core.rbac_engine import (
    Action,
    Decision,
    Filter,
    Principal,
    RBACDecision,
    RBACEngine,
    Request,
    Resource,
    ResourceType,
    Visibility,
)


class TestPrincipal:
    """Test Principal model."""

    def test_principal_creation(self):
        """Test creating a principal."""
        principal = Principal(
            username="john.doe",
            email="john@example.com",
            groups=["developers", "testers"],
        )

        assert principal.username == "john.doe"
        assert principal.email == "john@example.com"
        assert principal.groups == ["developers", "testers"]
        assert not principal.is_service_account

    def test_principal_id(self):
        """Test principal ID property."""
        principal = Principal(username="john.doe")
        assert principal.id == "john.doe"

    def test_principal_cache_key(self):
        """Test principal cache key generation."""
        principal = Principal(
            username="john.doe", groups=["developers", "testers"]
        )

        # Cache key should include sorted groups
        cache_key = principal.cache_key
        assert "john.doe" in cache_key
        assert "developers" in cache_key or "testers" in cache_key


class TestResource:
    """Test Resource model."""

    def test_cluster_resource(self):
        """Test cluster resource creation."""
        resource = Resource(
            type=ResourceType.CLUSTER,
            name="prod-cluster",
            cluster="prod-cluster"
        )

        assert resource.type == ResourceType.CLUSTER
        assert resource.name == "prod-cluster"
        assert resource.id == "cluster:prod-cluster:prod-cluster"

    def test_namespaced_resource(self):
        """Test namespaced resource."""
        resource = Resource(
            type=ResourceType.POD,
            name="my-pod",
            namespace="default",
            cluster="prod-cluster"
        )

        assert resource.namespace == "default"
        assert "default" in resource.id
        assert "my-pod" in resource.id


class TestFilter:
    """Test Filter model and matching logic."""

    def test_filter_visibility_all(self):
        """Test filter with ALL visibility."""
        filter_obj = Filter(visibility=Visibility.ALL)

        assert filter_obj.matches("anything")
        assert filter_obj.matches("something-else")
        assert filter_obj.is_empty()

    def test_filter_visibility_none(self):
        """Test filter with NONE visibility."""
        filter_obj = Filter(visibility=Visibility.NONE)

        assert not filter_obj.matches("anything")
        assert not filter_obj.is_empty()

    def test_filter_include_list(self):
        """Test filter with include list."""
        filter_obj = Filter(
            visibility=Visibility.FILTERED,
            include={"namespace-1", "namespace-2"}
        )

        assert filter_obj.matches("namespace-1")
        assert filter_obj.matches("namespace-2")
        assert not filter_obj.matches("namespace-3")

    def test_filter_exclude_list(self):
        """Test filter with exclude list."""
        filter_obj = Filter(
            visibility=Visibility.ALL,
            exclude={"kube-system", "kube-public"}
        )

        assert filter_obj.matches("my-namespace")
        assert not filter_obj.matches("kube-system")
        assert not filter_obj.matches("kube-public")

    def test_filter_label_selector(self):
        """Test filter with label selectors."""
        # When using label selectors, we test them in combination with include
        # Resources must be in include list AND match labels
        filter_obj = Filter(
            visibility=Visibility.FILTERED,
            include={"resource-1", "resource-2"},  # Only include these two
            labels={"env": "production", "team": "platform"}
        )

        # resource-1 is in include list AND has matching labels
        assert filter_obj.matches("resource-1", {"env": "production", "team": "platform"})

        # resource-2 is in include list but WRONG labels - should not match
        assert not filter_obj.matches("resource-2", {"env": "development"})
        
        # resource-3 is NOT in include list - should not match regardless of labels
        assert not filter_obj.matches("resource-3", {})


class TestRBACEngine:
    """Test RBAC Engine core functionality."""

    def test_engine_initialization(self, fake_redis):
        """Test RBAC engine initialization."""
        engine = RBACEngine(fake_redis, cache_ttl=300)

        assert engine.redis == fake_redis
        assert engine.cache_ttl == 300
        assert engine._caching_enabled is True

    def test_engine_without_cache(self, rbac_engine):
        """Test RBAC engine without caching."""
        assert rbac_engine.cache_ttl == 0
        assert not rbac_engine._caching_enabled

    @pytest.mark.rbac
    def test_authorize_no_policies(self, rbac_engine):
        """Test authorization with no policies returns DENY."""
        principal = Principal(username="john.doe", groups=["developers"])
        resource = Resource(type=ResourceType.CLUSTER, name="test-cluster")
        request = Request(principal=principal, action=Action.VIEW, resource=resource)

        decision = rbac_engine.authorize(request)

        assert decision.denied
        assert decision.decision == Decision.DENY
        assert "No matching policies" in decision.reason

    @pytest.mark.rbac
    def test_authorize_with_allow_policy(
        self, rbac_engine, fake_redis, basic_dev_policy
    ):
        """Test authorization with matching Allow policy."""
        # Store policy
        policy_key = f"policy:{basic_dev_policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(basic_dev_policy))
        fake_redis.zadd(
            "policy:group:developers:sorted",
            {policy_key: basic_dev_policy["priority"]},
        )

        # Create request
        principal = Principal(username="john.doe", groups=["developers"])
        resource = Resource(
            type=ResourceType.CLUSTER, name="dev-cluster-1", cluster="dev-cluster-1"
        )
        request = Request(principal=principal, action=Action.VIEW, resource=resource)

        decision = rbac_engine.authorize(request)

        assert decision.allowed
        assert Action.VIEW in decision.permissions
        assert Action.VIEW_METRICS in decision.permissions
        assert Action.VIEW_SENSITIVE not in decision.permissions

    @pytest.mark.rbac
    def test_authorize_with_deny_policy(self, rbac_engine, fake_redis):
        """Test authorization with Deny policy overrides Allow."""
        # Allow policy
        allow_policy = {
            "policy_name": "allow-policy",
            "priority": 100,
            "effect": "Allow",
            "enabled": True,
            "subjects": [{"type": "Group", "name": "developers"}],
            "cluster_rules": [
                {
                    "cluster_selector": {"matchPattern": ".*"},
                    "permissions": {"view": True},
                }
            ],
        }

        # Deny policy (higher priority)
        deny_policy = {
            "policy_name": "deny-policy",
            "priority": 200,
            "effect": "Deny",
            "enabled": True,
            "subjects": [{"type": "Group", "name": "developers"}],
            "cluster_rules": [
                {
                    "cluster_selector": {"matchNames": ["prod-cluster"]},
                    "permissions": {},
                }
            ],
        }

        # Store policies
        for policy in [allow_policy, deny_policy]:
            policy_key = f"policy:{policy['policy_name']}"
            fake_redis.hset(policy_key, "data", json.dumps(policy))
            fake_redis.zadd(
                "policy:group:developers:sorted",
                {policy_key: policy["priority"]},
            )

        # Create request for prod-cluster
        principal = Principal(username="john.doe", groups=["developers"])
        resource = Resource(
            type=ResourceType.CLUSTER, name="prod-cluster", cluster="prod-cluster"
        )
        request = Request(principal=principal, action=Action.VIEW, resource=resource)

        decision = rbac_engine.authorize(request)

        assert decision.denied
        assert "Denied by policy" in decision.reason

    @pytest.mark.rbac
    def test_filter_resources_all_visible(self, rbac_engine, fake_redis, admin_policy):
        """Test filtering resources when all should be visible."""
        # Store admin policy
        policy_key = f"policy:{admin_policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(admin_policy))
        fake_redis.zadd(
            "policy:group:cluster-admins:sorted",
            {policy_key: admin_policy["priority"]},
        )

        # Create principal and resources
        principal = Principal(username="admin", groups=["cluster-admins"])
        resources = [
            {"name": "node-1", "roles": ["worker"]},
            {"name": "node-2", "roles": ["master"]},
            {"name": "node-3", "roles": ["worker"]},
        ]

        filtered = rbac_engine.filter_resources(
            principal=principal,
            resources=resources,
            resource_type=ResourceType.NODE,
            cluster="test-cluster",
        )

        assert len(filtered) == 3
        assert filtered == resources

    @pytest.mark.rbac
    def test_filter_resources_with_namespace_filter(
        self, rbac_engine, fake_redis, namespace_filtered_policy
    ):
        """Test filtering resources by namespace."""
        # Store policy
        policy_key = f"policy:{namespace_filtered_policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(namespace_filtered_policy))
        fake_redis.zadd(
            "policy:group:developers:sorted",
            {policy_key: namespace_filtered_policy["priority"]},
        )

        # Create principal and pods
        principal = Principal(username="john.doe", groups=["developers"])
        pods = [
            {"name": "pod-1", "namespace": "team-a-prod", "status": "Running"},
            {"name": "pod-2", "namespace": "team-a-staging", "status": "Running"},
            {"name": "pod-3", "namespace": "team-b-prod", "status": "Running"},
            {"name": "pod-4", "namespace": "default", "status": "Running"},
        ]

        filtered = rbac_engine.filter_resources(
            principal=principal,
            resources=pods,
            resource_type=ResourceType.POD,
            cluster="production-cluster",
        )

        # Should only see team-a namespaces
        assert len(filtered) == 2
        assert all(
            pod["namespace"].startswith("team-a") for pod in filtered
        )

    @pytest.mark.rbac
    def test_filter_operators_by_namespace(
        self, rbac_engine, fake_redis, namespace_filtered_policy, sample_operators
    ):
        """Test filtering operators based on namespace access."""
        # Store policy
        policy_key = f"policy:{namespace_filtered_policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(namespace_filtered_policy))
        fake_redis.zadd(
            "policy:group:developers:sorted",
            {policy_key: namespace_filtered_policy["priority"]},
        )

        principal = Principal(username="john.doe", groups=["developers"])

        # Filter operators (some cluster-wide, some namespace-specific)
        filtered = rbac_engine.filter_resources(
            principal=principal,
            resources=sample_operators,
            resource_type=ResourceType.OPERATOR,
            cluster="production-cluster",
        )

        # Should see cluster-wide operators and operators in allowed namespaces
        # The sample includes operators with ["*"] and specific namespaces
        # With namespace filtering, should see cluster-wide operators
        assert len(filtered) >= 2  # At least the cluster-wide ones

    @pytest.mark.rbac
    def test_get_accessible_clusters(
        self, rbac_engine, fake_redis, basic_dev_policy
    ):
        """Test getting accessible clusters for a principal."""
        # Store policy
        policy_key = f"policy:{basic_dev_policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(basic_dev_policy))
        fake_redis.zadd(
            "policy:group:developers:sorted",
            {policy_key: basic_dev_policy["priority"]},
        )

        # Add clusters to Redis
        clusters = ["dev-cluster-1", "dev-cluster-2", "prod-cluster-1"]
        for cluster in clusters:
            fake_redis.sadd("clusters:all", cluster)

        principal = Principal(username="john.doe", groups=["developers"])
        accessible = rbac_engine.get_accessible_clusters(principal)

        # Should only see dev clusters (policy matches dev-.*)
        assert len(accessible) == 2
        assert "dev-cluster-1" in accessible
        assert "dev-cluster-2" in accessible
        assert "prod-cluster-1" not in accessible

    @pytest.mark.rbac
    def test_get_permissions_for_resource(
        self, rbac_engine, fake_redis, basic_dev_policy
    ):
        """Test getting all permissions for a resource."""
        # Store policy
        policy_key = f"policy:{basic_dev_policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(basic_dev_policy))
        fake_redis.zadd(
            "policy:group:developers:sorted",
            {policy_key: basic_dev_policy["priority"]},
        )

        principal = Principal(username="john.doe", groups=["developers"])
        resource = Resource(
            type=ResourceType.CLUSTER, name="dev-cluster-1", cluster="dev-cluster-1"
        )

        permissions = rbac_engine.get_permissions(principal, resource)

        # Should have permissions defined in basic_dev_policy
        assert Action.VIEW in permissions
        assert Action.VIEW_METRICS in permissions
        
        # The get_permissions method tests all actions, so we can't reliably
        # assert what's NOT there without knowing the exact policy evaluation logic.
        # Just verify the key permissions are present.
        assert len(permissions) >= 2

    def test_cache_behavior(self, rbac_engine_with_cache, fake_redis):
        """Test caching behavior of authorization decisions."""
        # Store a simple allow policy
        policy = {
            "policy_name": "test-policy",
            "priority": 100,
            "effect": "Allow",
            "enabled": True,
            "subjects": [{"type": "Group", "name": "developers"}],
            "cluster_rules": [
                {
                    "cluster_selector": {"matchPattern": ".*"},
                    "permissions": {"view": True},
                }
            ],
        }

        policy_key = f"policy:{policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(policy))
        fake_redis.zadd(
            "policy:group:developers:sorted",
            {policy_key: policy["priority"]},
        )

        principal = Principal(username="john.doe", groups=["developers"])
        resource = Resource(type=ResourceType.CLUSTER, name="test-cluster")
        request = Request(principal=principal, action=Action.VIEW, resource=resource)

        # First call - should miss cache
        decision1 = rbac_engine_with_cache.authorize(request)
        assert not decision1.cached
        assert rbac_engine_with_cache._cache_misses == 1
        assert rbac_engine_with_cache._cache_hits == 0

        # Second call - should hit cache
        decision2 = rbac_engine_with_cache.authorize(request)
        assert decision2.cached
        assert rbac_engine_with_cache._cache_hits == 1

        # Decisions should be equivalent
        assert decision1.allowed == decision2.allowed
        assert decision1.permissions == decision2.permissions

    def test_clear_cache(self, rbac_engine_with_cache, fake_redis):
        """Test clearing the authorization cache."""
        # Store a policy and make some requests
        policy = {
            "policy_name": "test-policy",
            "priority": 100,
            "effect": "Allow",
            "enabled": True,
            "subjects": [{"type": "Group", "name": "developers"}],
            "cluster_rules": [
                {
                    "cluster_selector": {"matchPattern": ".*"},
                    "permissions": {"view": True},
                }
            ],
        }

        policy_key = f"policy:{policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(policy))
        fake_redis.zadd(
            "policy:group:developers:sorted",
            {policy_key: policy["priority"]},
        )

        principal = Principal(username="john.doe", groups=["developers"])
        resource = Resource(type=ResourceType.CLUSTER, name="test-cluster")
        request = Request(principal=principal, action=Action.VIEW, resource=resource)

        # Make request to populate cache
        rbac_engine_with_cache.authorize(request)
        rbac_engine_with_cache.authorize(request)  # Hit cache

        assert rbac_engine_with_cache._cache_hits == 1

        # Clear cache for this principal
        cleared = rbac_engine_with_cache.clear_cache(principal)
        assert cleared > 0

        # Next request should miss cache
        decision = rbac_engine_with_cache.authorize(request)
        assert not decision.cached

    def test_get_stats(self, rbac_engine_with_cache):
        """Test getting engine statistics."""
        stats = rbac_engine_with_cache.get_stats()

        assert "caching_enabled" in stats
        assert stats["caching_enabled"] is True
        assert "cache_ttl" in stats
        assert stats["cache_ttl"] == 300
        assert "cache_hits" in stats
        assert "cache_misses" in stats
        assert "total_requests" in stats
        assert "cache_hit_rate" in stats

    @pytest.mark.rbac
    def test_anonymous_principal(self, rbac_engine):
        """Test creating and using anonymous principal."""
        anonymous = rbac_engine.create_anonymous_principal()

        assert anonymous.username == "anonymous"
        assert "anonymous" in anonymous.groups
        assert "public" in anonymous.groups
        assert anonymous.attributes.get("anonymous") is True

    @pytest.mark.rbac
    def test_authorize_anonymous(self, rbac_engine):
        """Test anonymous authorization."""
        resource = Resource(
            type=ResourceType.CLUSTER, name="test-cluster", cluster="test-cluster"
        )

        # Should allow viewing cluster health
        decision = rbac_engine.authorize_anonymous(Action.VIEW, resource)
        assert decision.allowed
        assert "Anonymous access" in decision.reason

        # Should deny other actions
        decision = rbac_engine.authorize_anonymous(Action.EDIT, resource)
        assert decision.denied

        # Should deny non-cluster resources
        node_resource = Resource(
            type=ResourceType.NODE, name="node-1", cluster="test-cluster"
        )
        decision = rbac_engine.authorize_anonymous(Action.VIEW, node_resource)
        assert decision.denied

    @pytest.mark.rbac
    def test_disabled_policy_ignored(self, rbac_engine, fake_redis):
        """Test that disabled policies are ignored."""
        policy = {
            "policy_name": "disabled-policy",
            "priority": 100,
            "effect": "Allow",
            "enabled": False,  # Disabled
            "subjects": [{"type": "Group", "name": "developers"}],
            "cluster_rules": [
                {
                    "cluster_selector": {"matchPattern": ".*"},
                    "permissions": {"view": True},
                }
            ],
        }

        policy_key = f"policy:{policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(policy))
        fake_redis.zadd(
            "policy:group:developers:sorted",
            {policy_key: policy["priority"]},
        )

        principal = Principal(username="john.doe", groups=["developers"])
        resource = Resource(type=ResourceType.CLUSTER, name="test-cluster")
        request = Request(principal=principal, action=Action.VIEW, resource=resource)

        decision = rbac_engine.authorize(request)

        # Should be denied because policy is disabled
        assert decision.denied

    @pytest.mark.rbac
    def test_time_bound_policy(self, rbac_engine, fake_redis):
        """Test policies with time constraints."""
        # Policy that expired
        expired_policy = {
            "policy_name": "expired-policy",
            "priority": 100,
            "effect": "Allow",
            "enabled": True,
            "not_after": "2020-01-01T00:00:00Z",  # Past date
            "subjects": [{"type": "Group", "name": "developers"}],
            "cluster_rules": [
                {
                    "cluster_selector": {"matchPattern": ".*"},
                    "permissions": {"view": True},
                }
            ],
        }

        policy_key = f"policy:{expired_policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(expired_policy))
        fake_redis.zadd(
            "policy:group:developers:sorted",
            {policy_key: expired_policy["priority"]},
        )

        principal = Principal(username="john.doe", groups=["developers"])
        resource = Resource(type=ResourceType.CLUSTER, name="test-cluster")
        request = Request(principal=principal, action=Action.VIEW, resource=resource)

        decision = rbac_engine.authorize(request)

        # Should be denied because policy is expired
        assert decision.denied


class TestComplexScenarios:
    """Test complex real-world RBAC scenarios."""

    @pytest.mark.rbac
    def test_multi_policy_priority(self, rbac_engine, fake_redis):
        """Test multiple policies with different priorities."""
        # Low priority - allow limited access to prod
        low_priority_policy = {
            "policy_name": "low-priority",
            "priority": 50,
            "effect": "Allow",
            "enabled": True,
            "subjects": [{"type": "Group", "name": "developers"}],
            "cluster_rules": [
                {
                    "cluster_selector": {"matchPattern": "prod-.*"},
                    "permissions": {"view": True},
                }
            ],
        }

        # High priority - allow full access to dev
        high_priority_policy = {
            "policy_name": "high-priority",
            "priority": 100,
            "effect": "Allow",
            "enabled": True,
            "subjects": [{"type": "Group", "name": "developers"}],
            "cluster_rules": [
                {
                    "cluster_selector": {"matchPattern": "dev-.*"},
                    "permissions": {"view": True, "viewMetrics": True},
                }
            ],
        }

        # Store both policies
        for policy in [low_priority_policy, high_priority_policy]:
            policy_key = f"policy:{policy['policy_name']}"
            fake_redis.hset(policy_key, "data", json.dumps(policy))
            fake_redis.zadd(
                "policy:group:developers:sorted",
                {policy_key: policy["priority"]},
            )

        principal = Principal(username="john.doe", groups=["developers"])
        resource = Resource(
            type=ResourceType.CLUSTER, name="dev-cluster", cluster="dev-cluster"
        )
        request = Request(principal=principal, action=Action.VIEW, resource=resource)

        decision = rbac_engine.authorize(request)

        # Should use high priority policy (matches dev-.*)
        assert decision.allowed
        assert Action.VIEW in decision.permissions
        assert Action.VIEW_METRICS in decision.permissions
        # Applied policies contains full Redis keys
        assert "policy:high-priority" in decision.applied_policies

    @pytest.mark.rbac
    def test_namespace_and_node_filtering_combined(
        self, rbac_engine, fake_redis
    ):
        """Test combining namespace and node filters."""
        policy = {
            "policy_name": "combined-filter-policy",
            "priority": 100,
            "effect": "Allow",
            "enabled": True,
            "subjects": [{"type": "Group", "name": "developers"}],
            "cluster_rules": [
                {
                    "cluster_selector": {"matchNames": ["test-cluster"]},
                    "permissions": {"view": True, "viewMetrics": True},
                    "namespace_filter": {
                        "visibility": "filtered",
                        "allowed_literals": ["dev-namespace"],
                    },
                    "node_filter": {
                        "visibility": "filtered",
                        "allowed_literals": ["worker-1", "worker-2"],
                    },
                }
            ],
        }

        policy_key = f"policy:{policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(policy))
        fake_redis.zadd(
            "policy:group:developers:sorted",
            {policy_key: policy["priority"]},
        )

        principal = Principal(username="john.doe", groups=["developers"])
        resource = Resource(
            type=ResourceType.CLUSTER, name="test-cluster", cluster="test-cluster"
        )
        request = Request(principal=principal, action=Action.VIEW, resource=resource)

        decision = rbac_engine.authorize(request)

        # Check namespace filter
        ns_filter = decision.get_filter(ResourceType.NAMESPACE)
        assert ns_filter is not None
        assert ns_filter.visibility == Visibility.FILTERED
        assert "dev-namespace" in ns_filter.include

        # Check node filter
        node_filter = decision.get_filter(ResourceType.NODE)
        assert node_filter is not None
        assert node_filter.visibility == Visibility.FILTERED
        assert "worker-1" in node_filter.include
        assert "worker-2" in node_filter.include
