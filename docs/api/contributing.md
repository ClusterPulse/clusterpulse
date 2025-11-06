# Contributing to ClusterPulse API

## Getting Started

### Local Setup

```bash
# Install dependencies
pip install -r requirements.txt
pip install -e .  # Install in dev mode

# Set up environment
cp .env.example .env
# Edit .env - set ENVIRONMENT=development, DEBUG=True

# Start Redis
docker run -d -p 6379:6379 redis:latest

# Run the API
python -m uvicorn clusterpulse.main:app --reload --host 0.0.0.0 --port 8080
```

API docs available at `http://localhost:8080/api/v1/docs`

### Development Dependencies

```bash
pip install pytest pytest-cov pytest-asyncio black ruff mypy
```

## Architecture Overview

```
Request → OAuth Headers → Auth Middleware → Route Handler
                                                ↓
                                         Check RBAC Engine
                                                ↓
                                         Get Data from Redis
                                                ↓
                                         Filter Through RBAC
                                                ↓
                                         Return Filtered Response
```

**Key Components:**
- **RBAC Engine** (`core/rbac_engine.py`): Authorization decisions
- **Redis Client** (`core/redis_client.py`): Connection management
- **Auth Dependencies** (`api/dependencies/auth.py`): User extraction and group resolution
- **Routes** (`api/routes/`): API endpoints
- **Repositories** (`repositories/`): Data access layer

## Understanding RBAC

This is the most important part of the system. Every data access goes through RBAC filtering.

### Core Concepts

**Principal**: Who is making the request
```python
Principal(username="john.doe", email="john@example.com", groups=["developers"])
```

**Resource**: What they're trying to access
```python
Resource(type=ResourceType.CLUSTER, name="prod-cluster", cluster="prod-cluster")
```

**Request**: Combines principal + action + resource
```python
Request(principal=principal, action=Action.VIEW, resource=resource)
```

**Decision**: Result of authorization
```python
decision = rbac_engine.authorize(request)
if decision.allowed:
    # Proceed
```

### Filtering Resources

**Always filter resources through the engine:**

```python
# DON'T do this:
all_nodes = get_all_nodes()
return all_nodes  # ❌ Bypasses RBAC

# DO this:
all_nodes = get_all_nodes()
filtered_nodes = rbac_engine.filter_resources(
    principal=principal,
    resources=all_nodes,
    resource_type=ResourceType.NODE,
    cluster=cluster_name
)
return filtered_nodes  # ✅ RBAC enforced
```

The engine applies filters from policies (namespace patterns, node selectors, etc.) and removes resources the user shouldn't see.

## Common Tasks

### Adding a New Endpoint

1. **Create the route handler:**

```python
# api/routes/clusters.py

@router.get("/{cluster_name}/workloads")
async def get_cluster_workloads(
    cluster_name: str,
    user: User = Depends(get_user_with_groups)  # Gets user + groups
) -> List[Dict[str, Any]]:
    """Get workloads for a cluster."""
    
    # 1. Check cluster access
    await check_cluster_access(cluster_name, user, Action.VIEW)
    
    # 2. Create principal for RBAC
    principal = Principal(
        username=user.username,
        email=user.email,
        groups=user.groups
    )
    
    # 3. Get raw data from Redis
    workloads_data = redis_client.get(f"cluster:{cluster_name}:workloads")
    workloads = json.loads(workloads_data) if workloads_data else []
    
    # 4. Filter through RBAC
    filtered_workloads = rbac_engine.filter_resources(
        principal=principal,
        resources=workloads,
        resource_type=ResourceType.POD,  # Use POD for namespace-scoped resources
        cluster=cluster_name
    )
    
    return filtered_workloads
```

2. **Register the route** (if new router file):

```python
# main.py
from clusterpulse.api.routes import workloads

app.include_router(
    workloads.router,
    prefix=f"{settings.api_prefix}/workloads",
    tags=["workloads"]
)
```

### Adding a New Resource Type

If you need a new resource type (e.g., `ConfigMap`):

1. **Add to `ResourceType` enum:**

```python
# core/rbac_engine.py
class ResourceType(str, Enum):
    CLUSTER = "cluster"
    NODE = "node"
    # ... existing types
    CONFIGMAP = "configmap"  # Add this
```

2. **Add filter support in policies** (if needed):

```python
# In policy structure, add configmap_filter support
# Update _extract_permissions_and_filters() if needed
```

3. **Use in routes:**

```python
filtered_configmaps = rbac_engine.filter_resources(
    principal=principal,
    resources=configmaps,
    resource_type=ResourceType.CONFIGMAP,
    cluster=cluster_name
)
```

### Modifying RBAC Filtering Logic

The filtering happens in `_should_show_resource()` in `rbac_engine.py`. 

**Example: Add label-based filtering:**

```python
# rbac_engine.py

def _should_show_resource(self, resource, resource_type, primary_filter, namespace_filter):
    # Existing checks...
    
    # Add label filtering
    if primary_filter and primary_filter.labels:
        resource_labels = resource.get("labels", {})
        for key, value in primary_filter.labels.items():
            if resource_labels.get(key) != value:
                return False  # Label mismatch
    
    return True
```

### Adding Metrics Calculations

Metrics are calculated in `api/routes/cluster_metrics.py`. The `FilteredMetricsCalculator` class handles this.

**Example: Add new metric:**

```python
# cluster_metrics.py

def _calculate_filtered_metrics_via_rbac(self, cluster_name, principal, base_metrics, include_details):
    filtered = base_metrics.copy()
    
    # Add your new metric calculation
    jobs_data = self.redis.get(f"cluster:{cluster_name}:jobs")
    if jobs_data:
        jobs = json.loads(jobs_data)
        filtered_jobs = self.rbac.filter_resources(
            principal=principal,
            resources=jobs,
            resource_type=ResourceType.POD,  # Use POD for namespace filtering
            cluster=cluster_name
        )
        
        filtered["jobs"] = len(filtered_jobs)
        filtered["jobs_succeeded"] = sum(1 for j in filtered_jobs if j.get("status") == "Succeeded")
    
    return filtered
```

### Working with Redis

Use the repository pattern in `repositories/cluster.py`:

```python
# repositories/cluster.py

def get_cluster_workloads(self, cluster_name: str) -> List[Dict[str, Any]]:
    """Get workloads for a cluster."""
    try:
        data = self.redis.get(f"cluster:{cluster_name}:workloads")
        return json.loads(data) if data else []
    except Exception as e:
        logger.error(f"Error getting workloads: {e}")
        return []
```

Then use in routes:

```python
from clusterpulse.repositories.cluster import ClusterRepository

repo = ClusterRepository()
workloads = repo.get_cluster_workloads(cluster_name)
```

## Testing

### Write Tests First

For new endpoints, create a test file:

```python
# tests/integration/api/test_workloads.py

import pytest
from clusterpulse.core.rbac_engine import Principal

@pytest.mark.integration
class TestWorkloadsEndpoint:
    def test_get_workloads_success(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_policies,
        basic_dev_policy
    ):
        """User can see workloads they have access to."""
        # Setup policy
        populate_redis_with_policies([basic_dev_policy])
        
        # Mock group resolution
        def mock_groups(username, email=None):
            return ["developers"]
        
        import clusterpulse.api.dependencies.auth as auth_module
        auth_module.resolve_groups_realtime = mock_groups
        
        # Add test data
        workloads = [
            {"name": "app-1", "namespace": "team-a"},
            {"name": "app-2", "namespace": "team-b"},
        ]
        fake_redis.set(f"cluster:test-cluster:workloads", json.dumps(workloads))
        
        # Make request
        response = authenticated_client.get("/api/v1/clusters/test-cluster/workloads")
        
        # Verify
        assert response.status_code == 200
        data = response.json()
        assert len(data) > 0  # Should see some workloads based on policy
```

### Running Tests

```bash
# All tests
pytest

# Specific category
pytest -m unit
pytest -m integration

# With coverage
pytest --cov=clusterpulse --cov-report=html

# Single test
pytest tests/integration/api/test_workloads.py::TestWorkloadsEndpoint::test_get_workloads_success -v
```

## Code Patterns

### Error Handling

```python
from fastapi import HTTPException, status
from clusterpulse.api.dependencies.auth import AuthorizationError

# Not found
raise HTTPException(
    status_code=status.HTTP_404_NOT_FOUND,
    detail="Resource not found"
)

# Authorization failed
raise AuthorizationError(f"Access denied to {resource_name}")
```

### Logging

```python
from clusterpulse.core.logging import get_logger, log_event

logger = get_logger(__name__)

# Simple log
logger.info(f"User {user.username} accessed {cluster_name}")

# Structured log
log_event(
    logger,
    "info",
    "resource_accessed",
    user_id=user.id,
    resource_type="cluster",
    resource_name=cluster_name,
    action="view"
)
```

### Redis Operations

Use pipelines for batch operations:

```python
# DON'T do this (N separate round trips):
for item in items:
    data = redis_client.get(f"key:{item}")

# DO this (1 round trip):
pipeline = redis_client.pipeline()
for item in items:
    pipeline.get(f"key:{item}")
results = pipeline.execute()
```

## Code Style

We use `black` for formatting and `ruff` for linting:

```bash
# Format code
black <path>
autoflake --remove-all-unused-imports --remove-unused-variables --recursive --in-place <path>
isort <path>

# Check linting
pylint check <path>

# Type checking
mypy <path>
```

**Import order:**
1. Standard library
2. Third-party packages
3. Local application imports

```python
import json
from datetime import datetime
from typing import List, Dict

from fastapi import APIRouter, Depends
from redis import Redis

from clusterpulse.core.rbac_engine import RBACEngine
from clusterpulse.models.cluster import ClusterMetrics
```

## Pull Request Process

1. **Branch naming:** `feature/add-workloads-endpoint` or `fix/rbac-namespace-filter`

2. **Commits:** Keep them focused and descriptive
   - ✅ "Add workloads endpoint with RBAC filtering"
   - ❌ "WIP" or "Fix stuff"

3. **Before submitting:**
   ```bash
   # Format and lint
   black <path>
   autoflake --remove-all-unused-imports --remove-unused-variables --recursive --in-place <path>
   isort <path>

   ruff check . --fix
   
   # Run tests
   pytest
   
   # Check coverage
   pytest --cov=clusterpulse --cov-report=term-missing
   ```

4. **PR description should include:**
   - What changed and why
   - How to test it
   - Any security implications
   - Related issues

5. **Things reviewers look for:**
   - RBAC filtering is applied correctly
   - No data leaks (all resources filtered)
   - Tests cover new functionality
   - Error handling is appropriate
   - Logging added for important operations

## Security Considerations

### Always Filter Resources

```python
# ❌ NEVER return raw data without filtering
@router.get("/nodes")
async def get_nodes():
    nodes = get_all_nodes()
    return nodes  # Security issue!

# ✅ ALWAYS filter through RBAC
@router.get("/nodes")
async def get_nodes(user: User = Depends(get_user_with_groups)):
    nodes = get_all_nodes()
    principal = Principal(username=user.username, email=user.email, groups=user.groups)
    filtered = rbac_engine.filter_resources(principal, nodes, ResourceType.NODE, cluster)
    return filtered  # Safe
```

### Check Permissions for Sensitive Actions

```python
# Check specific permissions
decision = await check_cluster_access(cluster_name, user, Action.VIEW_SENSITIVE)

if not decision.can(Action.VIEW_SENSITIVE):
    raise AuthorizationError("Cannot view sensitive data")
```

### Input Validation

```python
from pydantic import BaseModel, validator

class WorkloadFilter(BaseModel):
    namespace: Optional[str]
    status: Optional[str]
    
    @validator('status')
    def validate_status(cls, v):
        allowed = ['Running', 'Pending', 'Failed']
        if v and v not in allowed:
            raise ValueError(f'Status must be one of {allowed}')
        return v
```

## Common Pitfalls

1. **Forgetting to filter resources:** Always use `rbac_engine.filter_resources()`

2. **Not mocking group resolution in tests:** Tests will fail without it
   ```python
   def mock_resolve_groups(username, email=None):
       return ["developers"]
   
   import clusterpulse.api.dependencies.auth as auth_module
   auth_module.resolve_groups_realtime = mock_resolve_groups
   ```

3. **Using wrong `ResourceType` for filtering:** Namespace-scoped resources should use `ResourceType.POD` for filtering

4. **N+1 Redis queries:** Use pipelines for batch operations

5. **Not handling Redis failures:** Wrap Redis calls in try/except

## Getting Help

- Check existing code in `api/routes/clusters.py` for patterns
- Look at tests in `tests/integration/api/` for examples
- Read the RBAC engine code in `core/rbac_engine.py` to understand filtering
- Review the test guide in `docs/api/tests.md`

## Project-Specific Notes

- **Group resolution is real-time:** Every request queries OpenShift for current group membership
- **Caching is disabled by default:** RBAC decisions are not cached (security over speed)
- **Policies are in Redis:** The Policy Controller manages them, but you can inspect with `redis-cli`
- **Metrics are pre-calculated:** The Cluster Controller writes metrics to Redis, we just filter them
