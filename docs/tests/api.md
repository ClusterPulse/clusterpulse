# ClusterPulse API Test Guide

## Overview

This test suite covers the ClusterPulse API with a focus on the RBAC engine (our most security-critical component) and API endpoints. Tests use `pytest` with `fakeredis` for isolated, fast execution.

## Quick Start

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=clusterpulse --cov-report=html

# Run specific test categories
uv run pytest -m unit           # Unit tests only
uv run pytest -m integration    # Integration tests only
uv run pytest -m rbac          # RBAC-specific tests

# Run a specific test file
uv run pytest tests/unit/core/test_rbac_engine.py

# Run with verbose output
uv run pytest -v

# Run tests matching a pattern
uv run pytest -k "test_filter"
```

## Test Structure

```
tests/
├── conftest.py                          # Shared fixtures and configuration
├── unit/                                # Fast, isolated unit tests
│   ├── core/
│   │   └── test_rbac_engine.py         # RBAC engine (security critical!)
│   └── repositories/
│       └── test_cluster_repository.py  # Redis data access layer
└── integration/                         # Tests with multiple components
    └── api/
        ├── test_auth_routes.py         # Authentication/authorization flows
        └── test_cluster_routes.py      # Cluster API endpoints
```

## Key Testing Patterns

### 1. Fixture-Based Test Data

We use fixtures in `conftest.py` to create consistent test data:

```python
def test_example(authenticated_client, basic_dev_policy, sample_cluster_metrics):
    # Fixtures provide pre-configured test data
    # No manual setup needed
    pass
```

**Available Fixtures:**

- **Users:** `dev_user`, `admin_user`, `readonly_user`, `no_access_user`
- **Policies:** `basic_dev_policy`, `admin_policy`, `readonly_policy`, `namespace_filtered_policy`
- **Data:** `sample_cluster_spec`, `sample_cluster_metrics`, `sample_nodes`, `sample_operators`
- **Clients:** `test_client`, `authenticated_client`, `admin_client`
- **Infrastructure:** `fake_redis`, `rbac_engine`

### 2. FakeRedis for Isolation

All tests use `fakeredis` instead of a real Redis instance:

```python
def test_something(fake_redis):
    # fake_redis behaves like real Redis but is in-memory
    fake_redis.set("key", "value")
    assert fake_redis.get("key") == "value"
```

**Benefits:**

- No external dependencies
- Fast execution (in-memory)
- Isolated - tests don't interfere with each other
- Deterministic - no timing issues

### 3. Policy-Based Authorization Testing

The RBAC engine is complex, so we test it thoroughly:

```python
def test_authorize_with_policy(rbac_engine, fake_redis, basic_dev_policy):
    # 1. Store policy in fake Redis
    populate_redis_with_policies([basic_dev_policy])
    
    # 2. Create authorization request
    principal = Principal(username="john.doe", groups=["developers"])
    resource = Resource(type=ResourceType.CLUSTER, name="dev-cluster-1")
    request = Request(principal=principal, action=Action.VIEW, resource=resource)
    
    # 3. Test authorization
    decision = rbac_engine.authorize(request)
    
    assert decision.allowed
    assert Action.VIEW in decision.permissions
```

### 4. Mocking External Dependencies

We mock Kubernetes API calls and group resolution:

```python
def test_with_mock_groups(authenticated_client):
    def mock_resolve_groups(username, email=None):
        return ["developers", "platform-team"]
    
    import clusterpulse.api.dependencies.auth as auth_module
    auth_module.resolve_groups_realtime = mock_resolve_groups
    
    # Now requests will use mocked group data
    response = authenticated_client.get("/api/v1/auth/me")
```

## Critical Test Areas

### RBAC Engine (`test_rbac_engine.py`)

**Why it matters:** This is our security boundary. A bug here could expose unauthorized data.

**What we test:**

- Policy matching and evaluation
- Permission calculation
- Resource filtering (namespaces, nodes, operators)
- Deny overrides Allow (security critical)
- Time-bound policies
- Disabled policies are ignored
- Cache behavior
- Anonymous access

**Example test:**
```python
def test_authorize_with_deny_policy(rbac_engine, fake_redis):
    """Ensure Deny policies override Allow policies."""
    # Setup Allow + Deny policies (Deny has higher priority)
    # ...
    decision = rbac_engine.authorize(request)
    assert decision.denied  # Deny must win!
```

### Cluster Repository (`test_cluster_repository.py`)

**Why it matters:** All cluster data flows through this layer.

**What we test:**

- CRUD operations on cluster data
- Node management
- Metrics retrieval
- Alert and event handling
- Error handling (Redis failures)
- Health checks

### Auth Routes (`test_auth_routes.py`)

**Why it matters:** Authentication is the entry point for all API access.

**What we test:**

- Authentication status
- User information with groups
- Permission calculation
- Policy retrieval
- Cache clearing
- Logout flow
- Group resolution (real-time from K8s)

### Cluster Routes (`test_cluster_routes.py`)

**Why it matters:** Main API surface - this is what users interact with.

**What we test:**

- Listing clusters with RBAC filtering
- Getting cluster details
- Node listing and filtering
- Namespace access control
- Operator visibility
- Metrics with permission checks
- Query parameter filtering

## Writing New Tests

### Unit Test Template

```python
@pytest.mark.unit
class TestNewFeature:
    """Test description."""
    
    def test_basic_functionality(self, fake_redis):
        """Test the happy path."""
        # Arrange
        # ... setup test data
        
        # Act
        result = function_under_test()
        
        # Assert
        assert result == expected
    
    def test_error_handling(self, fake_redis):
        """Test error conditions."""
        # Test what happens when things go wrong
        pass
```

### Integration Test Template

```python
@pytest.mark.integration
class TestNewEndpoint:
    """Test API endpoint with full stack."""
    
    def test_endpoint_success(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_policies,
        basic_dev_policy
    ):
        """Test successful request."""
        # Setup policies and data
        populate_redis_with_policies([basic_dev_policy])
        
        # Mock group resolution
        def mock_resolve_groups(username, email=None):
            return ["developers"]
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_resolve_groups
        
        # Make request
        response = authenticated_client.get("/api/v1/your/endpoint")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "expected_field" in data
    
    def test_endpoint_no_permission(self, test_client, fake_redis):
        """Test authorization failure."""
        response = test_client.get("/api/v1/your/endpoint")
        assert response.status_code == 403
```

## Test Data Management

### Populating Redis

Use helper fixtures to populate Redis with test data:

```python
def test_with_cluster_data(
    fake_redis,
    populate_redis_with_cluster,
    sample_cluster_spec,
    sample_cluster_metrics
):
    # Populate Redis with a complete cluster
    populate_redis_with_cluster(
        "test-cluster",
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
        nodes=sample_nodes,
        namespaces=sample_namespaces
    )
    
    # Now Redis has complete cluster data
    assert fake_redis.exists("cluster:test-cluster:spec")
```

### Populating Policies

```python
def test_with_policies(fake_redis, populate_redis_with_policies, basic_dev_policy):
    populate_redis_with_policies([basic_dev_policy])
    
    # Policy is now indexed and ready
    # You can make authorization decisions
```

## Common Testing Scenarios

### Testing Namespace Filtering

```python
def test_namespace_filtering(authenticated_client, fake_redis, namespace_filtered_policy):
    """User should only see pods in their allowed namespaces."""
    # 1. Setup policy with namespace restrictions
    populate_redis_with_policies([namespace_filtered_policy])
    
    # 2. Create pods in various namespaces
    pods = [
        {"name": "pod-1", "namespace": "team-a-prod"},   # Allowed
        {"name": "pod-2", "namespace": "team-b-prod"},   # Not allowed
    ]
    
    # 3. Make request
    response = authenticated_client.get("/api/v1/clusters/test/pods")
    
    # 4. Verify filtering
    data = response.json()
    assert len(data) == 1
    assert data[0]["namespace"] == "team-a-prod"
```

### Testing Node Filtering

```python
def test_node_filtering(authenticated_client, fake_redis):
    """User should only see allowed nodes."""
    # Setup policy that restricts node visibility
    node_filter_policy = {
        "policy_name": "node-filter",
        # ... policy with node_filter
    }
    populate_redis_with_policies([node_filter_policy])
    
    response = authenticated_client.get("/api/v1/clusters/test/nodes")
    data = response.json()
    
    # Should only see filtered nodes
    assert all(node["name"] in ["worker-1", "worker-2"] for node in data)
```

### Testing Permission Levels

```python
def test_view_metrics_permission(authenticated_client, fake_redis):
    """User with viewMetrics permission can see metrics."""
    policy_with_metrics = {
        # ... policy with viewMetrics: true
    }
    
    response = authenticated_client.get("/api/v1/clusters/test/metrics")
    assert response.status_code == 200
    assert "cpu_usage_percent" in response.json()

def test_no_metrics_permission(authenticated_client, fake_redis):
    """User without viewMetrics permission cannot see metrics."""
    policy_without_metrics = {
        # ... policy with viewMetrics: false
    }
    
    response = authenticated_client.get("/api/v1/clusters/test/metrics")
    assert response.status_code == 403
```

## Debugging Tests

### Running a Single Test

```bash
# Run one specific test
uv run pytest tests/unit/core/test_rbac_engine.py::TestRBACEngine::test_authorize_no_policies -v

# Run with print statements visible
uv run pytest tests/unit/core/test_rbac_engine.py::TestRBACEngine::test_authorize_no_policies -v -s
```

### Inspecting Failures

```bash
# Show local variables on failure
uv run pytest --showlocals

# Enter debugger on failure
uv run pytest --pdb

# Show full diff on assertion failures
uv run pytest -vv
```

### Common Issues

**Issue: "No module named 'clusterpulse'"**
```bash
# Solution: Sync dependencies with uv
uv sync
```

**Issue: Redis client not mocked properly**
```python
# Make sure to use the fake_redis fixture
def test_something(fake_redis):  # ← Include this fixture
    # Test code here
```

**Issue: Group resolution failing**
```python
# Always mock group resolution in integration tests
def mock_resolve_groups(username, email=None):
    return ["developers"]

import clusterpulse.api.dependencies.auth as auth_module
auth_module.resolve_groups_realtime = mock_resolve_groups
```

## Test Markers

We use pytest markers to categorize tests:

```python
@pytest.mark.unit           # Fast, isolated unit tests
@pytest.mark.integration    # Integration tests with multiple components
@pytest.mark.rbac          # RBAC-specific tests
@pytest.mark.redis         # Tests that depend on Redis behavior
@pytest.mark.slow          # Long-running tests
```

Run tests by marker:
```bash
uv run pytest -m "unit and not slow"
uv run pytest -m "integration or rbac"
```

## Coverage Goals

Current coverage focuses on:

- ✅ RBAC engine (security critical)
- ✅ Repository layer (data access)
- ✅ Main API endpoints
- ✅ Authentication flows
- ✅ Middleware configs

**Next priorities:**

- ⚠️ Health endpoints
- ⚠️ Public API routes
- ⚠️ Metrics calculator
- ⚠️ Registry routes
- ⚠️ Error scenarios

## Best Practices

1. **Use descriptive test names:** `test_authorize_with_deny_policy` not `test_1`
2. **One assertion per test (usually):** Makes failures easier to debug
3. **Use fixtures over setup/teardown:** More flexible and readable
4. **Test error paths:** Don't just test happy paths
5. **Keep tests independent:** Tests should not depend on each other
6. **Mock external dependencies:** Don't make real API calls or connect to real Redis
7. **Use meaningful test data:** `"dev-cluster-1"` is better than `"cluster1"`

## Contributing Tests

When adding new features:

1. **Write tests first** (TDD when possible)
2. **Add fixtures** for reusable test data
3. **Use appropriate markers** (`@pytest.mark.unit`, etc.)
4. **Document complex test scenarios** with comments
5. **Run the full suite** before submitting PR

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [fakeredis documentation](https://github.com/cunla/fakeredis-py)
- [FastAPI testing guide](https://fastapi.tiangolo.com/tutorial/testing/)
