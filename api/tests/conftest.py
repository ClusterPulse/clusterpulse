"""Pytest configuration and shared fixtures for ClusterPulse tests."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest
from fakeredis import FakeStrictRedis
from fastapi.testclient import TestClient

from clusterpulse.models.auth import User
from clusterpulse.services.rbac import RBACEngine

# ============================================================================
# Redis Fixtures
# ============================================================================


@pytest.fixture(scope="session")
def fake_redis_session():
    """Single FakeRedis instance for entire test session."""
    return FakeStrictRedis(decode_responses=True)


@pytest.fixture(autouse=True)
def fake_redis(fake_redis_session):
    """
    Function-scoped fixture that clears session redis before each test.
    This ensures test isolation while using a single redis instance.
    """
    fake_redis_session.flushdb()
    yield fake_redis_session


@pytest.fixture
def rbac_engine(fake_redis):
    """Provide an RBAC engine with fake Redis."""
    return RBACEngine(fake_redis, cache_ttl=0)


@pytest.fixture
def rbac_engine_with_cache(fake_redis):
    """Provide an RBAC engine with caching enabled."""
    return RBACEngine(fake_redis, cache_ttl=300)


# ============================================================================
# User Fixtures
# ============================================================================


@pytest.fixture
def dev_user():
    """Standard developer user."""
    return User(
        username="john.doe",
        email="john.doe@example.com",
        groups=["developers", "cluster-viewers"],
        preferred_username="John Doe",
    )


@pytest.fixture
def admin_user():
    """Administrator user."""
    return User(
        username="admin",
        email="admin@example.com",
        groups=["cluster-admins", "system:masters"],
        preferred_username="Admin User",
    )


@pytest.fixture
def readonly_user():
    """Read-only user."""
    return User(
        username="viewer",
        email="viewer@example.com",
        groups=["cluster-viewers"],
        preferred_username="View Only User",
    )


@pytest.fixture
def no_access_user():
    """User with no access."""
    return User(
        username="noone",
        email="noone@example.com",
        groups=[],
        preferred_username="No Access User",
    )


# ============================================================================
# Policy Fixtures
# ============================================================================


@pytest.fixture
def basic_dev_policy():
    """Basic developer policy - access to dev clusters."""
    return {
        "policy_name": "developers-policy",
        "priority": 100,
        "effect": "Allow",
        "enabled": True,
        "subjects": [{"type": "Group", "name": "developers"}],
        "cluster_rules": [
            {
                "cluster_selector": {"matchPattern": "dev-.*"},
                "permissions": {
                    "view": True,
                    "viewMetrics": True,
                    "viewSensitive": False,
                },
                "namespace_filter": {
                    "visibility": "filtered",
                    "allowed_patterns": [["dev-.*", "dev-.*"]],
                },
                "node_filter": {"visibility": "all"},
            }
        ],
    }


@pytest.fixture
def admin_policy():
    """Admin policy - full access to all clusters."""
    return {
        "policy_name": "admin-policy",
        "priority": 200,
        "effect": "Allow",
        "enabled": True,
        "subjects": [
            {"type": "Group", "name": "cluster-admins"},
            {"type": "Group", "name": "system:masters"},
        ],
        "cluster_rules": [
            {
                "cluster_selector": {"matchPattern": ".*"},
                "permissions": {
                    "view": True,
                    "viewMetrics": True,
                    "viewSensitive": True,
                    "viewCosts": True,
                    "viewSecrets": True,
                    "viewMetadata": True,
                },
                "namespace_filter": {"visibility": "all"},
                "node_filter": {"visibility": "all"},
                "operator_filter": {"visibility": "all"},
            }
        ],
    }


@pytest.fixture
def readonly_policy():
    """Read-only policy - view only, no sensitive data."""
    return {
        "policy_name": "readonly-policy",
        "priority": 50,
        "effect": "Allow",
        "enabled": True,
        "subjects": [{"type": "Group", "name": "cluster-viewers"}],
        "cluster_rules": [
            {
                "cluster_selector": {"matchPattern": ".*"},
                "permissions": {"view": True, "viewMetrics": True},
                "namespace_filter": {"visibility": "all"},
                "node_filter": {"visibility": "all"},
            }
        ],
    }


@pytest.fixture
def namespace_filtered_policy():
    """Policy with strict namespace filtering."""
    return {
        "policy_name": "namespace-filtered-policy",
        "priority": 100,
        "effect": "Allow",
        "enabled": True,
        "subjects": [{"type": "Group", "name": "developers"}],
        "cluster_rules": [
            {
                "cluster_selector": {"matchNames": ["production-cluster"]},
                "permissions": {"view": True, "viewMetrics": True},
                "namespace_filter": {
                    "visibility": "filtered",
                    "allowed_literals": ["team-a-prod", "team-a-staging"],
                    "allowed_patterns": [["team-a-.*", "team-a-.*"]],
                },
                "node_filter": {"visibility": "none"},
            }
        ],
    }


# ============================================================================
# Cluster Data Fixtures
# ============================================================================


@pytest.fixture
def sample_cluster_spec():
    """Sample cluster specification."""
    return {
        "displayName": "Development Cluster",
        "endpoint": "https://api.dev-cluster.example.com:6443",
        "credentialsRef": {"name": "dev-cluster-creds", "namespace": "default"},
        "labels": {"environment": "dev", "team": "platform"},
    }


@pytest.fixture
def sample_cluster_status():
    """Sample cluster status."""
    return {
        "health": "healthy",
        "message": "All systems operational",
        "last_check": datetime.now(timezone.utc).isoformat(),
    }


@pytest.fixture
def sample_cluster_metrics():
    """Sample cluster metrics."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nodes": 5,
        "nodes_ready": 5,
        "nodes_not_ready": 0,
        "namespaces": 25,
        "pods": 150,
        "pods_running": 145,
        "pods_pending": 3,
        "pods_failed": 2,
        "cpu_capacity": 40.0,
        "cpu_allocatable": 38.0,
        "cpu_requested": 25.5,
        "cpu_usage_percent": 67.1,
        "memory_capacity": 160000000000,
        "memory_allocatable": 155000000000,
        "memory_requested": 95000000000,
        "memory_usage_percent": 61.3,
        "storage_capacity": 500000000000,
        "storage_used": 250000000000,
        "deployments": 45,
        "services": 60,
        "statefulsets": 8,
        "daemonsets": 12,
        "pvcs": 35,
    }


@pytest.fixture
def sample_nodes():
    """Sample node data."""
    return [
        {
            "name": "worker-1",
            "status": "Ready",
            "roles": ["worker"],
            "cpu_capacity": 8.0,
            "cpu_allocatable": 7.5,
            "cpu_requested": 5.2,
            "cpu_usage_percent": 69.3,
            "memory_capacity": 32000000000,
            "memory_allocatable": 30000000000,
            "memory_requested": 20000000000,
            "memory_usage_percent": 66.7,
            "pods_running": 30,
            "pods_total": 35,
            "labels": {"node-role.kubernetes.io/worker": ""},
        },
        {
            "name": "master-1",
            "status": "Ready",
            "roles": ["master", "control-plane"],
            "cpu_capacity": 8.0,
            "cpu_allocatable": 7.5,
            "cpu_requested": 4.5,
            "cpu_usage_percent": 60.0,
            "memory_capacity": 32000000000,
            "memory_allocatable": 30000000000,
            "memory_requested": 18000000000,
            "memory_usage_percent": 60.0,
            "pods_running": 25,
            "pods_total": 30,
            "labels": {"node-role.kubernetes.io/master": ""},
        },
        {
            "name": "worker-2",
            "status": "Ready",
            "roles": ["worker"],
            "cpu_capacity": 8.0,
            "cpu_allocatable": 7.5,
            "cpu_requested": 6.0,
            "cpu_usage_percent": 80.0,
            "memory_capacity": 32000000000,
            "memory_allocatable": 30000000000,
            "memory_requested": 22000000000,
            "memory_usage_percent": 73.3,
            "pods_running": 35,
            "pods_total": 35,
            "labels": {"node-role.kubernetes.io/worker": ""},
        },
    ]


@pytest.fixture
def sample_namespaces():
    """Sample namespace list."""
    return [
        "default",
        "kube-system",
        "kube-public",
        "openshift-console",
        "openshift-monitoring",
        "dev-namespace-1",
        "dev-namespace-2",
        "prod-namespace-1",
        "team-a-prod",
        "team-a-staging",
        "team-b-prod",
    ]


@pytest.fixture
def sample_operators():
    """Sample operator data."""
    return [
        {
            "name": "elasticsearch-operator",
            "display_name": "Elasticsearch Operator",
            "version": "5.8.0",
            "status": "Succeeded",
            "namespace": "openshift-operators-redhat",
            "available_in_namespaces": ["*"],
            "install_mode": "AllNamespaces",
        },
        {
            "name": "prometheus-operator",
            "display_name": "Prometheus Operator",
            "version": "0.56.0",
            "status": "Succeeded",
            "namespace": "openshift-operators",
            "available_in_namespaces": ["*"],
            "install_mode": "AllNamespaces",
        },
        {
            "name": "custom-dev-operator",
            "display_name": "Custom Dev Operator",
            "version": "1.0.0",
            "status": "Succeeded",
            "namespace": "dev-operators",
            "available_in_namespaces": ["dev-namespace-1", "dev-namespace-2"],
            "install_mode": "OwnNamespace",
        },
    ]


@pytest.fixture
def sample_pods():
    """Sample pod data."""
    return [
        {
            "name": "app-1-pod-abc123",
            "namespace": "dev-namespace-1",
            "status": "Running",
            "node": "worker-1",
        },
        {
            "name": "app-2-pod-def456",
            "namespace": "dev-namespace-2",
            "status": "Running",
            "node": "worker-2",
        },
        {
            "name": "prod-app-pod-xyz789",
            "namespace": "prod-namespace-1",
            "status": "Running",
            "node": "worker-1",
        },
        {
            "name": "failing-pod-123",
            "namespace": "dev-namespace-1",
            "status": "Failed",
            "node": "worker-2",
        },
    ]


# ============================================================================
# Redis Helper Fixtures
# ============================================================================


@pytest.fixture
def populate_redis_with_policies(fake_redis):
    """Helper to populate Redis with policies."""

    def _populate(policies: List[Dict[str, Any]]):
        """Populate policies into the test's fake_redis instance."""
        for policy in policies:
            policy_key = f"policy:{policy['policy_name']}"

            # Store policy data
            fake_redis.hset(policy_key, "data", json.dumps(policy))
            fake_redis.sadd("policies:all", policy["policy_name"])

            # Index by subjects
            for subject in policy.get("subjects", []):
                subject_type = subject["type"].lower()
                subject_name = subject["name"]
                priority = policy.get("priority", 0)

                if subject_type == "group":
                    fake_redis.zadd(
                        f"policy:group:{subject_name}:sorted",
                        {policy_key: priority},
                    )
                elif subject_type == "user":
                    fake_redis.zadd(
                        f"policy:user:{subject_name}:sorted",
                        {policy_key: priority},
                    )

    return _populate


@pytest.fixture
def populate_redis_with_cluster(fake_redis):
    """Helper to populate Redis with cluster data."""

    def _populate(
        cluster_name: str,
        spec: Dict,
        status: Dict,
        metrics: Dict,
        nodes: List[Dict] = None,
        namespaces: List[str] = None,
        operators: List[Dict] = None,
    ):
        """Populate cluster data into the test's fake_redis instance."""
        # Store cluster in set
        fake_redis.sadd("clusters:all", cluster_name)

        # Store spec, status, metrics
        fake_redis.set(f"cluster:{cluster_name}:spec", json.dumps(spec))
        fake_redis.set(f"cluster:{cluster_name}:status", json.dumps(status))
        fake_redis.set(f"cluster:{cluster_name}:metrics", json.dumps(metrics))

        # Store nodes
        if nodes:
            for node in nodes:
                node_name = node["name"]
                fake_redis.sadd(f"cluster:{cluster_name}:nodes", node_name)
                fake_redis.hset(
                    f"cluster:{cluster_name}:node:{node_name}",
                    "current",
                    json.dumps(node),
                )

        # Store namespaces
        if namespaces:
            namespace_data = {
                "namespaces": namespaces,
                "count": len(namespaces),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            fake_redis.set(
                f"cluster:{cluster_name}:namespaces", json.dumps(namespace_data)
            )
            for ns in namespaces:
                fake_redis.sadd(f"cluster:{cluster_name}:namespaces:set", ns)

        # Store operators
        if operators:
            fake_redis.set(f"cluster:{cluster_name}:operators", json.dumps(operators))

    return _populate


# ============================================================================
# API Test Client Fixtures
# ============================================================================


@pytest.fixture
def test_client(monkeypatch, fake_redis, rbac_engine):
    """Provide a test client with mocked dependencies."""
    # Clear LRU caches FIRST
    from clusterpulse.config.settings import get_settings
    from clusterpulse.db.redis import get_redis_client as _get_redis
    from clusterpulse.db.redis import get_redis_pool

    get_settings.cache_clear()
    _get_redis.cache_clear()
    get_redis_pool.cache_clear()

    # Patch Redis everywhere to use fake_redis
    monkeypatch.setattr("clusterpulse.db.redis.get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(
        "clusterpulse.api.dependencies.auth.get_redis_client", lambda: fake_redis
    )

    # Mock the RBAC engine
    monkeypatch.setattr(
        "clusterpulse.api.dependencies.rbac.get_rbac_engine", lambda: rbac_engine
    )

    from clusterpulse.repositories.redis_base import ClusterDataRepository, MetricSourceRepository

    test_repo = ClusterDataRepository(fake_redis)
    metric_source_repo = MetricSourceRepository(fake_redis)

    monkeypatch.setattr("clusterpulse.api.v1.endpoints.clusters.repo", test_repo)
    monkeypatch.setattr("clusterpulse.api.v1.endpoints.clusters.metric_source_repo", metric_source_repo)

    monkeypatch.setattr(
        "clusterpulse.repositories.redis_base.ClusterDataRepository",
        lambda redis_client=None: test_repo,
    )

    from clusterpulse.services.metrics import FilteredMetricsCalculator

    metrics_calc = FilteredMetricsCalculator(fake_redis, rbac_engine)

    monkeypatch.setattr(
        "clusterpulse.api.v1.endpoints.clusters.metrics_calculator", metrics_calc
    )

    monkeypatch.setattr(
        "clusterpulse.api.v1.endpoints.clusters.redis_client", fake_redis
    )

    monkeypatch.setattr("clusterpulse.api.dependencies.auth.k8s_dynamic_client", None)

    # Import app AFTER all patching
    # Set auth module's redis_client to the same instance
    import clusterpulse.api.v1.endpoints.auth as auth_module
    from clusterpulse.main import app

    auth_module.redis_client = fake_redis

    return TestClient(app)


@pytest.fixture
def authenticated_client(test_client, dev_user, rbac_engine):
    """Provide a test client with authenticated user headers."""
    test_client.headers.update(
        {
            "X-Forwarded-User": dev_user.username,
            "X-Forwarded-Email": dev_user.email,
        }
    )
    return test_client


@pytest.fixture
def admin_client(test_client, admin_user, rbac_engine):
    """Provide a test client with admin user headers."""
    test_client.headers.update(
        {
            "X-Forwarded-User": admin_user.username,
            "X-Forwarded-Email": admin_user.email,
        }
    )
    return test_client


# ============================================================================
# Utility Fixtures
# ============================================================================


@pytest.fixture
def mock_datetime(monkeypatch):
    """Mock datetime for consistent timestamps."""
    fixed_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

    class MockDatetime:
        @classmethod
        def now(cls, tz=None):
            return fixed_time

        @classmethod
        def utcnow(cls):
            return fixed_time

    monkeypatch.setattr("datetime.datetime", MockDatetime)
    return fixed_time


@pytest.fixture(autouse=True)
def reset_lru_caches():
    """Reset LRU caches between tests."""
    from clusterpulse.config.settings import get_settings
    from clusterpulse.db.redis import get_redis_client, get_redis_pool

    get_settings.cache_clear()
    get_redis_client.cache_clear()
    get_redis_pool.cache_clear()

    yield

    get_settings.cache_clear()
    get_redis_client.cache_clear()
    get_redis_pool.cache_clear()


# ============================================================================
# Markers
# ============================================================================

pytest_plugins = []


def pytest_configure(config):
    """Configure custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "e2e: End-to-end tests")
    config.addinivalue_line("markers", "slow: Slow running tests")
    config.addinivalue_line("markers", "rbac: RBAC-specific tests")
    config.addinivalue_line("markers", "redis: Redis-dependent tests")
