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

## Project Structure

Here's what goes where and why it's organized this way.

### Directory Layout

```
clusterpulse/
├── config/              Configuration settings
├── core/                Core utilities (logging, etc.)
├── db/                  Database and cache connections
├── models/              Pydantic models for data validation
├── repositories/        Data access layer (talks to Redis)
├── services/            Business logic (RBAC, metrics)
└── api/                 HTTP layer
    ├── dependencies/    FastAPI dependencies
    ├── middleware/      Request/response middleware
    └── v1/              API version 1
        ├── endpoints/   Route handlers
        └── router.py    Router assembly
```

### What Each Directory Does

#### `config/`
Application configuration. Just settings, environment variables, that sort of thing.

**Files:**
- `settings.py` - All configuration (Redis host, OAuth settings, etc.)

**When to edit:**
- Adding a new feature flag
- Adding a new environment variable
- Changing default values

```python
# Example: Adding a new setting
class Settings(BaseSettings):
    new_feature_enabled: bool = Field(False, env="NEW_FEATURE_ENABLED")
```

#### `core/`
Utilities used throughout the app. Keep it minimal - only truly shared utilities go here.

**Files:**
- `logging.py` - Logging setup and helpers

**When to add here:**
- Shared utility functions
- Common helpers
- Framework setup code

**Don't put here:**
- Business logic (goes in `services/`)
- Data access (goes in `repositories/`)
- HTTP handlers (goes in `api/`)

#### `db/`
Database and cache connections. Currently just Redis, but could expand.

**Files:**
- `redis.py` - Redis connection pool and client

**When to edit:**
- Changing Redis connection logic
- Adding connection health checks
- Adding a new database (Postgres, etc.)

```python
# Example: Using the Redis client
from clusterpulse.db.redis import get_redis_client

redis = get_redis_client()
data = redis.get("some:key")
```

#### `models/`
Pydantic models for request/response validation and data structures.

**Files:**
- `auth.py` - User, AuthStatus
- `cluster.py` - Cluster, Node, Metrics, etc.

**When to add here:**
- New API request/response models
- Data structures shared across layers

```python
# Example: Adding a new model
class Workload(BaseModel):
    name: str
    namespace: str
    replicas: int
```

#### `repositories/`
Data access layer. These talk to Redis (or any datastore) and return Python objects.

**Files:**
- `cluster.py` - ClusterRepository with all cluster data operations

**When to add here:**
- New data access patterns
- New CRUD operations
- Complex Redis queries

**Pattern:**
```python
class SomeRepository:
    def __init__(self):
        self.redis = get_redis_client()
    
    def get_something(self, id: str) -> Optional[Dict]:
        data = self.redis.get(f"key:{id}")
        return json.loads(data) if data else None
```

#### `services/`
Business logic goes here. This is where you implement features, algorithms, calculations, etc.

**Files:**
- `rbac.py` - RBACEngine for authorization
- `metrics.py` - FilteredMetricsCalculator for calculating filtered metrics

**When to add here:**
- Authorization logic
- Complex calculations
- Business rules
- Data transformation

**Pattern:**
```python
class MyService:
    def __init__(self, redis_client, other_deps):
        self.redis = redis_client
        self.other = other_deps
    
    def do_complex_thing(self, params):
        # Business logic here
        pass
```

#### `api/v1/endpoints/`
HTTP route handlers. Keep these thin - they should mostly just coordinate between services.

**Files:**
- `auth.py` - Authentication endpoints
- `clusters.py` - Cluster management endpoints
- `health.py` - Health check endpoints
- `public.py` - Public API endpoints
- `registries.py` - Registry endpoints

**When to add here:**
- New API endpoints
- New HTTP handlers

**Pattern:**
```python
@router.get("/{id}")
async def get_something(
    id: str,
    user: User = Depends(get_current_user)
):
    # 1. Check authorization
    await check_access(id, user)
    
    # 2. Get data from service
    result = service.get_filtered_data(id, user)
    
    # 3. Return it
    return result
```

**Keep endpoints thin:**
- Don't put business logic here
- Don't do complex calculations
- Don't directly access Redis
- Delegate to services

#### `api/dependencies/`
FastAPI dependency injection functions.

**Files:**
- `auth.py` - User extraction, group resolution

**When to add here:**
- Reusable dependencies
- Common parameter validation
- Shared authorization checks

#### `api/middleware/`
Request/response middleware.

**Files:**
- `auth.py` - AuthMiddleware
- `logging.py` - LoggingMiddleware

**When to add here:**
- Request preprocessing
- Response post-processing
- Cross-cutting concerns

### Data Flow Example

Here's how a request flows through the layers:

```python
# 1. HTTP Request comes in
GET /api/v1/clusters/prod-cluster/metrics

# 2. Middleware processes it
# - LoggingMiddleware logs the request
# - AuthMiddleware checks OAuth headers

# 3. Endpoint handler (api/v1/endpoints/clusters.py)
@router.get("/{cluster_name}/metrics")
async def get_cluster_metrics(cluster_name: str, user: User = Depends(get_current_user)):
    # Thin handler - just coordinates
    decision = await check_cluster_access(cluster_name, user)
    principal = Principal(username=user.username, groups=user.groups)
    
    # 4. Service layer (services/metrics.py)
    metrics = metrics_calculator.get_filtered_cluster_metrics(
        cluster_name, principal
    )
    
    return metrics

# Inside metrics_calculator (service layer):
def get_filtered_cluster_metrics(self, cluster_name, principal):
    # 5. Repository layer (repositories/cluster.py)
    base_metrics = self.repo.get_metrics(cluster_name)
    
    # Business logic - filtering
    filtered = self.rbac.filter_resources(...)
    
    return self._calculate_metrics(filtered)

# Inside repository:
def get_metrics(self, cluster_name):
    # 6. Database layer (db/redis.py)
    data = self.redis.get(f"cluster:{cluster_name}:metrics")
    return json.loads(data) if data else None
```

## Understanding RBAC

RBAC is the most important part of the system. Every data access goes through RBAC filtering.

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

Always filter resources through the engine:

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

1. **Create the endpoint:**

```python
# api/v1/endpoints/clusters.py

@router.get("/{cluster_name}/workloads")
async def get_cluster_workloads(
    cluster_name: str,
    user: User = Depends(get_user_with_groups)
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

2. **Register the route** (if needed):

The route is already registered since it's in `api/v1/endpoints/clusters.py`. If you create a new router file, add it to `api/v1/router.py`.

### Adding a New Resource Type

If you need a new resource type (e.g., `ConfigMap`):

1. **Add to `ResourceType` enum:**

```python
# services/rbac.py
class ResourceType(str, Enum):
    CLUSTER = "cluster"
    NODE = "node"
    # ... existing types
    CONFIGMAP = "configmap"  # Add this
```

2. **Use in endpoints:**

```python
filtered_configmaps = rbac_engine.filter_resources(
    principal=principal,
    resources=configmaps,
    resource_type=ResourceType.CONFIGMAP,
    cluster=cluster_name
)
```

### Adding Metrics Calculations

Metrics are calculated in `services/metrics.py`. The `FilteredMetricsCalculator` class handles this.

**Example: Add new metric:**

```python
# services/metrics.py

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

Then use in endpoints:

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
from clusterpulse.services.rbac import Principal

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

We use `black` for formatting, `autoflake` for removing unused imports and `pylint` for linting:

```bash
# Format code
black <path>
autoflake --remove-all-unused-imports --remove-unused-variables --recursive --in-place <path>
isort <path>

# Check linting
pylint clusterpulse/
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

from clusterpulse.config.settings import settings
from clusterpulse.services.rbac import RBACEngine
from clusterpulse.models.cluster import Cluster
```

## Pull Request Process

1. **Branch naming:** `feature/add-workloads-endpoint` or `fix/rbac-namespace-filter`

2. **Commits:** Keep them focused and descriptive
   - ✅ "Add workloads endpoint with RBAC filtering"
   - ❌ "WIP" or "Fix stuff"

3. **Before submitting:**
   ```bash
   # Format and lint
   black clusterpulse/
   autoflake...
   isort...
   
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

- Check existing code in `api/v1/endpoints/clusters.py` for patterns
- Look at tests in `tests/integration/api/` for examples
- Read the RBAC engine code in `services/rbac.py` to understand filtering

## Project-Specific Notes

- **Group resolution is real-time:** Every request queries OpenShift for current group membership
- **Caching is disabled by default:** RBAC decisions are not cached (security over speed)
- **Policies are in Redis:** The Policy Controller manages them, but you can inspect with `redis-cli`
- **Metrics are pre-calculated:** The Cluster Controller writes metrics to Redis, we just filter them
