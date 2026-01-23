"""Unit tests for RBAC custom resource authorization."""

import json
import re

import pytest

from clusterpulse.services.rbac import (
    Action,
    CustomResourceDecision,
    CustomResourceFilter,
    Decision,
    Principal,
    RBACEngine,
    Visibility,
)


@pytest.fixture
def custom_resource_policy():
    """Policy with custom resource rules."""
    return {
        "policy_name": "custom-resource-policy",
        "priority": 100,
        "effect": "Allow",
        "enabled": True,
        "subjects": [{"type": "Group", "name": "developers"}],
        "cluster_rules": [
            {
                "cluster_selector": {"matchPattern": ".*"},
                "permissions": {"view": True, "viewMetrics": True},
                "custom_resources": {
                    "pvc": {
                        "visibility": "all",
                        "permissions": {"view": True, "viewMetrics": True},
                    },
                    "certificate": {
                        "visibility": "filtered",
                        "permissions": {"view": True},
                        "namespace_filter": {
                            "allowed_literals": ["team-a", "team-b"],
                            "allowed_patterns": [["dev-.*", "^dev-.*$"]],
                        },
                    },
                    "secret-store": {
                        "visibility": "none",
                    },
                },
            }
        ],
    }


@pytest.fixture
def custom_resource_deny_policy():
    """Deny policy for custom resources."""
    return {
        "policy_name": "deny-custom-resource",
        "priority": 200,
        "effect": "Deny",
        "enabled": True,
        "subjects": [{"type": "Group", "name": "developers"}],
        "cluster_rules": [
            {
                "cluster_selector": {"matchPattern": ".*"},
                "custom_resources": {
                    "pvc": {},
                },
            }
        ],
    }


class TestCustomResourceFilter:
    """Test CustomResourceFilter functionality."""

    def test_unrestricted_filter(self):
        """Filter with no restrictions should match everything."""
        f = CustomResourceFilter(visibility=Visibility.ALL)
        
        assert f.is_unrestricted()
        assert f.matches_namespace("any-namespace")
        assert f.matches_namespace(None)
        assert f.matches_name("any-name")

    def test_visibility_none(self):
        """NONE visibility should deny all."""
        f = CustomResourceFilter(visibility=Visibility.NONE)
        
        assert not f.is_unrestricted()
        assert not f.matches_namespace("any-namespace")
        assert not f.matches_name("any-name")

    def test_namespace_literal_filter(self):
        """Test namespace filtering with literal values."""
        f = CustomResourceFilter(
            visibility=Visibility.FILTERED,
            namespace_literals={"team-a", "team-b"},
        )
        
        assert f.matches_namespace("team-a")
        assert f.matches_namespace("team-b")
        assert not f.matches_namespace("team-c")
        assert f.matches_namespace(None)  # Cluster-scoped passes

    def test_namespace_pattern_filter(self):
        """Test namespace filtering with patterns."""
        f = CustomResourceFilter(
            visibility=Visibility.FILTERED,
            namespace_patterns=[("dev-.*", re.compile("^dev-.*$"))],
        )
        
        assert f.matches_namespace("dev-app")
        assert f.matches_namespace("dev-staging")
        assert not f.matches_namespace("prod-app")

    def test_namespace_exclude_filter(self):
        """Test namespace exclusions."""
        f = CustomResourceFilter(
            visibility=Visibility.ALL,
            namespace_exclude_literals={"kube-system", "kube-public"},
        )
        
        assert f.matches_namespace("my-app")
        assert not f.matches_namespace("kube-system")
        assert not f.matches_namespace("kube-public")

    def test_name_literal_filter(self):
        """Test name filtering with literal values."""
        f = CustomResourceFilter(
            visibility=Visibility.FILTERED,
            name_literals={"pvc-1", "pvc-2"},
        )
        
        assert f.matches_name("pvc-1")
        assert f.matches_name("pvc-2")
        assert not f.matches_name("pvc-3")

    def test_name_pattern_filter(self):
        """Test name filtering with patterns."""
        f = CustomResourceFilter(
            visibility=Visibility.FILTERED,
            name_patterns=[("app-.*", re.compile("^app-.*$"))],
        )
        
        assert f.matches_name("app-web")
        assert f.matches_name("app-api")
        assert not f.matches_name("db-main")

    def test_name_exclude_filter(self):
        """Test name exclusions."""
        f = CustomResourceFilter(
            visibility=Visibility.ALL,
            name_exclude_literals={"secret-config"},
        )
        
        assert f.matches_name("normal-pvc")
        assert not f.matches_name("secret-config")

    def test_field_filter(self):
        """Test field-based filtering."""
        f = CustomResourceFilter(
            visibility=Visibility.FILTERED,
            field_filters={
                "status": (
                    {"Bound", "Available"},  # allowed literals
                    [],  # allowed patterns
                    set(),  # denied literals
                    [],  # denied patterns
                )
            },
        )
        
        assert f.matches_field("status", "Bound")
        assert f.matches_field("status", "Available")
        assert not f.matches_field("status", "Pending")
        assert f.matches_field("other_field", "anything")  # Unfiltered field

    def test_field_exclusion(self):
        """Test field value exclusions."""
        f = CustomResourceFilter(
            visibility=Visibility.ALL,
            field_filters={
                "status": (
                    set(),  # allowed literals (empty = all)
                    [],  # allowed patterns
                    {"Failed", "Error"},  # denied literals
                    [],  # denied patterns
                )
            },
        )
        
        assert f.matches_field("status", "Running")
        assert not f.matches_field("status", "Failed")
        assert not f.matches_field("status", "Error")

    def test_combined_filters(self):
        """Test multiple filter criteria together."""
        f = CustomResourceFilter(
            visibility=Visibility.FILTERED,
            namespace_literals={"team-a"},
            name_patterns=[("pvc-.*", re.compile("^pvc-.*$"))],
            namespace_exclude_literals={"team-a-secret"},
        )
        
        assert not f.is_unrestricted()
        assert f.matches_namespace("team-a")
        assert not f.matches_namespace("team-a-secret")
        assert f.matches_name("pvc-data")
        assert not f.matches_name("configmap-data")


class TestCustomResourceDecision:
    """Test CustomResourceDecision functionality."""

    def test_decision_allowed(self):
        """Test allowed decision properties."""
        decision = CustomResourceDecision(
            decision=Decision.ALLOW,
            resource_type_name="pvc",
            permissions={Action.VIEW, Action.VIEW_METRICS},
        )
        
        assert decision.allowed
        assert not decision.denied
        assert decision.can(Action.VIEW)
        assert decision.can(Action.VIEW_METRICS)
        assert not decision.can(Action.VIEW_SENSITIVE)

    def test_decision_denied(self):
        """Test denied decision properties."""
        decision = CustomResourceDecision(
            decision=Decision.DENY,
            resource_type_name="pvc",
            reason="No policy grants access",
        )
        
        assert not decision.allowed
        assert decision.denied

    def test_aggregation_visibility_all(self):
        """Test aggregation visibility with no restrictions."""
        decision = CustomResourceDecision(
            decision=Decision.ALLOW,
            resource_type_name="pvc",
            allowed_aggregations=None,  # All allowed
        )
        
        assert decision.is_aggregation_allowed("total_count")
        assert decision.is_aggregation_allowed("sum_capacity")
        assert decision.is_aggregation_allowed("anything")

    def test_aggregation_visibility_allowed_list(self):
        """Test aggregation visibility with allowed list."""
        decision = CustomResourceDecision(
            decision=Decision.ALLOW,
            resource_type_name="pvc",
            allowed_aggregations={"total_count", "sum_capacity"},
        )
        
        assert decision.is_aggregation_allowed("total_count")
        assert decision.is_aggregation_allowed("sum_capacity")
        assert not decision.is_aggregation_allowed("avg_usage")

    def test_aggregation_visibility_denied_list(self):
        """Test aggregation visibility with denied list."""
        decision = CustomResourceDecision(
            decision=Decision.ALLOW,
            resource_type_name="pvc",
            denied_aggregations={"sensitive_metric"},
        )
        
        assert decision.is_aggregation_allowed("total_count")
        assert not decision.is_aggregation_allowed("sensitive_metric")


@pytest.mark.rbac
class TestRBACEngineCustomResources:
    """Test RBAC engine custom resource authorization."""

    def test_authorize_custom_resource_no_policy(self, rbac_engine):
        """Test authorization with no policies returns DENY."""
        principal = Principal(username="john.doe", groups=["developers"])
        
        # Test without cluster - directly tests custom resource policy logic
        decision = rbac_engine.authorize_custom_resource(
            principal, "pvc", cluster=None
        )
        
        assert decision.denied
        assert "No policy grants access" in decision.reason

    def test_authorize_custom_resource_allowed(
        self, rbac_engine, fake_redis, custom_resource_policy
    ):
        """Test authorization with matching Allow policy."""
        # Store policy
        policy_key = f"policy:{custom_resource_policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(custom_resource_policy))
        fake_redis.zadd(
            "policy:group:developers:sorted",
            {policy_key: custom_resource_policy["priority"]},
        )
        
        principal = Principal(username="john.doe", groups=["developers"])
        
        decision = rbac_engine.authorize_custom_resource(
            principal, "pvc", "test-cluster"
        )
        
        assert decision.allowed
        assert Action.VIEW in decision.permissions
        assert Action.VIEW_METRICS in decision.permissions

    def test_authorize_custom_resource_filtered(
        self, rbac_engine, fake_redis, custom_resource_policy
    ):
        """Test authorization returns filtered decision with namespace restrictions."""
        policy_key = f"policy:{custom_resource_policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(custom_resource_policy))
        fake_redis.zadd(
            "policy:group:developers:sorted",
            {policy_key: custom_resource_policy["priority"]},
        )
        
        principal = Principal(username="john.doe", groups=["developers"])
        
        decision = rbac_engine.authorize_custom_resource(
            principal, "certificate", "test-cluster"
        )
        
        assert decision.allowed
        assert decision.decision == Decision.PARTIAL
        assert not decision.filters.is_unrestricted()
        assert decision.filters.matches_namespace("team-a")
        assert decision.filters.matches_namespace("dev-app")
        assert not decision.filters.matches_namespace("prod-app")

    def test_authorize_custom_resource_visibility_none(
        self, rbac_engine, fake_redis, custom_resource_policy
    ):
        """Test authorization with visibility: none returns DENY."""
        policy_key = f"policy:{custom_resource_policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(custom_resource_policy))
        fake_redis.zadd(
            "policy:group:developers:sorted",
            {policy_key: custom_resource_policy["priority"]},
        )
        
        principal = Principal(username="john.doe", groups=["developers"])
        
        decision = rbac_engine.authorize_custom_resource(
            principal, "secret-store", "test-cluster"
        )
        
        # visibility: none means no access granted by this policy
        assert decision.denied

    def test_authorize_custom_resource_deny_overrides(
        self, rbac_engine, fake_redis, custom_resource_policy, custom_resource_deny_policy
    ):
        """Test that Deny policy overrides Allow policy for custom resources."""
        # Store both policies
        for policy in [custom_resource_policy, custom_resource_deny_policy]:
            policy_key = f"policy:{policy['policy_name']}"
            fake_redis.hset(policy_key, "data", json.dumps(policy))
            fake_redis.zadd(
                "policy:group:developers:sorted",
                {policy_key: policy["priority"]},
            )
        
        principal = Principal(username="john.doe", groups=["developers"])
        
        # Test without cluster to bypass cluster access check and test
        # custom resource deny logic directly
        decision = rbac_engine.authorize_custom_resource(
            principal, "pvc", cluster=None
        )
        
        assert decision.denied
        assert "Denied by policy" in decision.reason

    def test_filter_custom_resources(
        self, rbac_engine, fake_redis, custom_resource_policy
    ):
        """Test filtering custom resources through RBAC."""
        policy_key = f"policy:{custom_resource_policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(custom_resource_policy))
        fake_redis.zadd(
            "policy:group:developers:sorted",
            {policy_key: custom_resource_policy["priority"]},
        )
        
        principal = Principal(username="john.doe", groups=["developers"])
        
        resources = [
            {"_name": "cert-1", "_namespace": "team-a", "values": {}},
            {"_name": "cert-2", "_namespace": "team-b", "values": {}},
            {"_name": "cert-3", "_namespace": "dev-app", "values": {}},
            {"_name": "cert-4", "_namespace": "prod-app", "values": {}},
        ]
        
        filtered = rbac_engine.filter_custom_resources(
            principal, resources, "certificate", "test-cluster"
        )
        
        assert len(filtered) == 3
        namespaces = {r["_namespace"] for r in filtered}
        assert "team-a" in namespaces
        assert "team-b" in namespaces
        assert "dev-app" in namespaces
        assert "prod-app" not in namespaces

    def test_filter_custom_resources_no_access(self, rbac_engine):
        """Test filtering returns empty when no access."""
        principal = Principal(username="john.doe", groups=["developers"])
        
        resources = [
            {"_name": "cert-1", "_namespace": "team-a", "values": {}},
        ]
        
        filtered = rbac_engine.filter_custom_resources(
            principal, resources, "certificate", "test-cluster"
        )
        
        assert len(filtered) == 0

    def test_filter_aggregations(
        self, rbac_engine, fake_redis, custom_resource_policy
    ):
        """Test filtering aggregations based on permissions."""
        policy_key = f"policy:{custom_resource_policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(custom_resource_policy))
        fake_redis.zadd(
            "policy:group:developers:sorted",
            {policy_key: custom_resource_policy["priority"]},
        )
        
        principal = Principal(username="john.doe", groups=["developers"])
        
        aggregations = {
            "total_count": 100,
            "sum_capacity": 500,
            "avg_usage": 45.5,
        }
        
        filtered = rbac_engine.filter_aggregations(
            principal, aggregations, "pvc", "test-cluster"
        )
        
        # With VIEW_METRICS permission, should see all
        assert "total_count" in filtered
        assert "sum_capacity" in filtered

    def test_get_accessible_custom_resource_types(
        self, rbac_engine, fake_redis, custom_resource_policy
    ):
        """Test getting accessible custom resource types."""
        policy_key = f"policy:{custom_resource_policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(custom_resource_policy))
        fake_redis.zadd(
            "policy:group:developers:sorted",
            {policy_key: custom_resource_policy["priority"]},
        )
        
        principal = Principal(username="john.doe", groups=["developers"])
        
        types = rbac_engine.get_accessible_custom_resource_types(principal)
        
        assert "pvc" in types
        assert "certificate" in types
        assert "secret-store" not in types  # visibility: none

    def test_custom_resource_cache(self, rbac_engine_with_cache, fake_redis, custom_resource_policy):
        """Test caching of custom resource decisions."""
        policy_key = f"policy:{custom_resource_policy['policy_name']}"
        fake_redis.hset(policy_key, "data", json.dumps(custom_resource_policy))
        fake_redis.zadd(
            "policy:group:developers:sorted",
            {policy_key: custom_resource_policy["priority"]},
        )
        
        principal = Principal(username="john.doe", groups=["developers"])
        
        # First call - cache miss
        decision1 = rbac_engine_with_cache.authorize_custom_resource(
            principal, "pvc", "test-cluster"
        )
        assert not decision1.cached
        
        # Second call - cache hit
        decision2 = rbac_engine_with_cache.authorize_custom_resource(
            principal, "pvc", "test-cluster"
        )
        assert decision2.cached
        
        # Decisions should be equivalent
        assert decision1.allowed == decision2.allowed
        assert decision1.permissions == decision2.permissions
