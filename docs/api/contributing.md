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
    ├── responses/       Response builders for consistent API responses
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
- `cluster.py` - Legacy ClusterRepository
- `redis_base.py` - Base repository classes with optimized patterns
  - `RedisRepository` - Base class with common Redis operations
  - `ClusterDataRepository` - Cluster-specific data access
  - `RegistryDataRepository` - Registry-specific data access

**When to add here:**
- New data access patterns
- New CRUD operations
- Complex Redis queries

**Pattern:**
```python
from clusterpulse.repositories.redis_base import ClusterDataRepository

# Use the repository
repo = ClusterDataRepository(redis_client)

# Get all cluster data in one batch operation
bundle = repo.get_cluster_bundle(cluster_name)
spec = bundle['spec']
status = bundle['status']
metrics = bundle['metrics']
info = bundle['info']

# Get specific resources
nodes = repo.get_cluster_nodes(cluster_name)
operators = repo.get_cluster_operators(cluster_name)
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
from clusterpulse.api.dependencies.rbac import RBACContext, get_rbac_context
from clusterpulse.repositories.redis_base import ClusterDataRepository
from clusterpulse.api.responses.cluster import ClusterResponseBuilder

repo = ClusterDataRepository(redis_client)

@router.get("/{id}")
async def get_something(
    id: str,
    rbac: RBACContext = Depends(get_rbac_context)
):
    # 1. Check authorization (1 line)
    rbac.check_cluster_access(id)
    
    # 2. Get data from repository (1 line)
    bundle = repo.get_cluster_bundle(id)
    
    # 3. Build and return response (3-5 lines)
    return (ClusterResponseBuilder(id)
        .with_spec(bundle['spec'])
        .with_status(bundle['status'])
        .build())
```

**Keep endpoints thin:**
- Don't put business logic here
- Don't do complex calculations
- Don't directly access Redis
- Delegate to repositories and services

#### `api/dependencies/`
FastAPI dependency injection functions.

**Files:**
- `auth.py` - User extraction, group resolution
- `rbac.py` - RBAC context and utilities

**When to add here:**
- Reusable dependencies
- Common parameter validation
- Shared authorization checks

**Key Components:**
- `RBACContext` - Provides all RBAC operations for endpoints
- `get_rbac_context()` - FastAPI dependency that injects RBAC context
- `get_rbac_engine()` - Singleton RBAC engine

```python
# Using RBACContext in endpoints
@router.get("/resource")
async def get_resource(rbac: RBACContext = Depends(get_rbac_context)):
    # Check access
    rbac.check_cluster_access(cluster_name)
    
    # Filter resources
    filtered = rbac.filter_resources(items, ResourceType.NODE, cluster_name)
    
    # Get accessible clusters
    clusters = rbac.get_accessible_clusters()
```

#### `api/middleware/`
Request/response middleware.

**Files:**
- `auth.py` - AuthMiddleware
- `logging.py` - LoggingMiddleware

**When to add here:**
- Request preprocessing
- Response post-processing
- Cross-cutting concerns

#### `api/responses/`
Response builder classes for consistent API responses.

**Files:**
- `cluster.py` - Cluster response builders
- `registry.py` - Registry response builders

**When to add here:**
- New response builders for new resource types
- Shared response formatting logic

**Pattern:**
```python
from clusterpulse.api.responses.cluster import ClusterResponseBuilder

# Build a cluster detail response
return (ClusterResponseBuilder(cluster_name)
    .with_spec(spec)
    .with_status(status)
    .with_info(info)
    .with_metrics(metrics, decision)
    .with_operator_count(count)
    .build())
```

**Benefits:**
- Consistent response format across endpoints
- Easy to add new fields
- Handles fallbacks and normalization
- Type-safe and IDE-friendly

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
async def get_cluster_metrics(
    cluster_name: str, 
    rbac: RBACContext = Depends(get_rbac_context)
):
    # Check access (1 line - RBAC context handles everything)
    decision = rbac.check_cluster_access(cluster_name, Action.VIEW_METRICS)
    
    # 4. Service layer (services/metrics.py)
    metrics = metrics_calculator.get_filtered_cluster_metrics(
        cluster_name, rbac.principal
    )
    
    return metrics

# Inside metrics_calculator (service layer):
def get_filtered_cluster_metrics(self, cluster_name, principal):
    # 5. Repository layer (repositories/redis_base.py)
    base_metrics = self.repo.get_cluster_metrics(cluster_name)
    
    # Business logic - filtering
    filtered = self.rbac.filter_resources(...)
    
    return self._calculate_metrics(filtered)

# Inside repository:
def get_cluster_metrics(self, cluster_name):
    # 6. Database layer (db/redis.py)
    return self.get_json(f"cluster:{cluster_name}:metrics")
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

### Using RBACContext

The `RBACContext` class simplifies RBAC operations in endpoints:

```python
from clusterpulse.api.dependencies.rbac import RBACContext, get_rbac_context

@router.get("/{cluster_name}")
async def get_cluster(
    cluster_name: str,
    rbac: RBACContext = Depends(get_rbac_context)
):
    # Check access - raises AuthorizationError if denied
    decision = rbac.check_cluster_access(cluster_name)
    
    # Check specific permissions
    if not decision.can(Action.VIEW_METRICS):
        # Handle case where metrics viewing is not allowed
        pass
    
    # Filter resources
    nodes = get_all_nodes()
    filtered_nodes = rbac.filter_resources(nodes, ResourceType.NODE, cluster_name)
    
    # Get accessible clusters
    accessible = rbac.get_accessible_clusters()
    
    return filtered_nodes
```

**RBACContext provides:**
- `check_cluster_access(cluster_name, action=Action.VIEW)` - Check and raise if denied
- `filter_resources(resources, resource_type, cluster)` - Filter resources through RBAC
- `get_accessible_clusters()` - Get all accessible cluster names
- `has_permission(action, resource)` - Check specific permission
- `principal` - The user's Principal object
- `user` - The authenticated User object
- `rbac` - The RBAC engine instance

### Filtering Resources

Always filter resources through the engine:

```python
# DON'T do this:
all_nodes = get_all_nodes()
return all_nodes  # ❌ Bypasses RBAC

# DO this with RBACContext:
all_nodes = get_all_nodes()
filtered_nodes = rbac.filter_resources(all_nodes, ResourceType.NODE, cluster_name)
return filtered_nodes  # ✅ RBAC enforced

# Or without RBACContext (when not in an endpoint):
from clusterpulse.api.dependencies.rbac import get_rbac_engine

rbac_engine = get_rbac_engine()
filtered_nodes = rbac_engine.filter_resources(
    principal=principal,
    resources=all_nodes,
    resource_type=ResourceType.NODE,
    cluster=cluster_name
)
```

The engine applies filters from policies (namespace patterns, node selectors, etc.) and removes resources the user shouldn't see.

## Common Tasks

### Adding a New Endpoint

1. **Create the endpoint using the new patterns:**

```python
# api/v1/endpoints/clusters.py
from clusterpulse.api.dependencies.rbac import RBACContext, get_rbac_context
from clusterpulse.repositories.redis_base import ClusterDataRepository
from clusterpulse.api.responses.cluster import ClusterResponseBuilder

repo = ClusterDataRepository(redis_client)

@router.get("/{cluster_name}/workloads")
async def get_cluster_workloads(
    cluster_name: str,
    rbac: RBACContext = Depends(get_rbac_context)
) -> List[Dict[str, Any]]:
    """Get workloads for a cluster."""
    
    # 1. Check cluster access (1 line)
    rbac.check_cluster_access(cluster_name)
    
    # 2. Get raw data from repository (1 line)
    workloads = repo.get_cluster_resource_list(cluster_name, "workloads")
    
    # 3. Filter through RBAC (1 line)
    filtered_workloads = rbac.filter_resources(
        workloads, 
        ResourceType.POD,  # Use POD for namespace-scoped resources
        cluster_name
    )
    
    return filtered_workloads
```

**Total: ~10 lines of actual logic**

2. **Register the route** (if needed):

The route is already registered since it's in `api/v1/endpoints/clusters.py`. If you create a new router file, add it to `api/v1/router.py`.

### Using Response Builders

Response builders provide consistent formatting and handle fallbacks:

```python
from clusterpulse.api.responses.cluster import ClusterResponseBuilder

@router.get("/{cluster_name}")
async def get_cluster(
    cluster_name: str,
    rbac: RBACContext = Depends(get_rbac_context)
):
    decision = rbac.check_cluster_access(cluster_name)
    
    # Get data in one batch
    bundle = repo.get_cluster_bundle(cluster_name)
    
    # Build response with builder pattern
    builder = ClusterResponseBuilder(cluster_name)
    builder.with_spec(bundle['spec'])
    builder.with_status(bundle['status'])
    builder.with_info(bundle['info'])
    
    # Conditionally add metrics
    if decision.can(Action.VIEW_METRICS):
        builder.with_metrics(bundle['metrics'], decision)
    
    return builder.build()
```

**Or using method chaining:**

```python
return (ClusterResponseBuilder(cluster_name)
    .with_spec(bundle['spec'])
    .with_status(bundle['status'])
    .with_info(bundle['info'])
    .with_metrics(bundle['metrics'], decision)
    .with_operator_count(operator_count)
    .build())
```

**Benefits:**
- Automatic fallbacks (missing spec/status gets defaults)
- Consistent field naming (displayName normalization)
- Easy to extend (add new methods)
- Type-safe
- Self-documenting code

### Creating a New Response Builder

If you need a builder for a new resource type:

```python
# api/responses/workload.py

class WorkloadResponseBuilder:
    """Builder for workload response objects."""
    
    def __init__(self, workload_name: str):
        self.data = {"name": workload_name}
    
    def with_spec(self, spec: Optional[Dict]) -> "WorkloadResponseBuilder":
        """Add spec data."""
        if spec:
            self.data["spec"] = spec
            self.data["replicas"] = spec.get("replicas", 1)
        return self
    
    def with_status(self, status: Optional[Dict]) -> "WorkloadResponseBuilder":
        """Add status with fallback."""
        self.data["status"] = status or {"state": "unknown"}
        return self
    
    def build(self) -> Dict[str, Any]:
        """Build and return the final response."""
        return self.data
```

### Using Repositories

Repositories provide optimized data access with batch operations:

```python
from clusterpulse.repositories.redis_base import ClusterDataRepository

repo = ClusterDataRepository(redis_client)

# Get all cluster data in one optimized batch operation
bundle = repo.get_cluster_bundle(cluster_name)
# Returns: {'spec': ..., 'status': ..., 'metrics': ..., 'info': ...}

# Get specific resources
nodes = repo.get_cluster_nodes(cluster_name)
operators = repo.get_cluster_operators(cluster_name)
namespaces = repo.get_cluster_namespaces(cluster_name)

# Get specific resource types (pods, deployments, etc.)
pods = repo.get_cluster_resource_list(cluster_name, "pods")
deployments = repo.get_cluster_resource_list(cluster_name, "deployments")

# Get node details
node = repo.get_cluster_node(cluster_name, node_name)
conditions = repo.get_node_conditions(cluster_name, node_name)
```

**Repository Methods:**

**ClusterDataRepository:**
- `get_cluster_bundle(cluster_name)` - Get spec/status/metrics/info in one batch
- `get_cluster_spec(cluster_name)` - Get cluster specification
- `get_cluster_status(cluster_name)` - Get cluster status
- `get_cluster_metrics(cluster_name)` - Get cluster metrics
- `get_cluster_info(cluster_name)` - Get cluster info (version, console URL, etc.)
- `get_cluster_operators(cluster_name)` - Get operators list
- `get_cluster_namespaces(cluster_name)` - Get namespace list
- `get_cluster_nodes(cluster_name)` - Get all nodes
- `get_cluster_node(cluster_name, node_name)` - Get specific node
- `get_cluster_resource_list(cluster_name, resource_type)` - Get pods/deployments/etc.
- `get_cluster_alerts(cluster_name)` - Get alerts
- `get_cluster_events(cluster_name, limit)` - Get events

**RegistryDataRepository:**
- `batch_get_registry_bundles(registry_names)` - Get multiple registry bundles in one batch
- `get_registry_bundle(registry_name)` - Get status and spec
- `get_all_registry_names()` - Get all registry names
- `get_registry_status(registry_name)` - Get registry status
- `get_registry_spec(registry_name)` - Get registry spec

**Why use repositories:**
- Optimized batch operations (1 Redis call instead of N)
- Consistent error handling
- Type hints for return values
- Centralized data access patterns
- Easy to test (mock the repository)

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
filtered_configmaps = rbac.filter_resources(
    configmaps, 
    ResourceType.CONFIGMAP, 
    cluster_name
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

### Adding New Repository Methods

To add a new data access pattern:

```python
# repositories/redis_base.py

class ClusterDataRepository(RedisRepository):
    # ... existing methods
    
    def get_cluster_configmaps(self, cluster_name: str) -> List[Dict]:
        """Get configmaps for cluster."""
        return self.get_json_list(f"cluster:{cluster_name}:configmaps")
    
    def get_cluster_secrets_count(self, cluster_name: str) -> int:
        """Get count of secrets (not actual secret data)."""
        data = self.get_json(f"cluster:{cluster_name}:secrets_summary")
        return data.get("count", 0) if data else 0
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

### Testing with Repositories

Mock repositories for cleaner tests:

```python
from unittest.mock import Mock
from clusterpulse.repositories.redis_base import ClusterDataRepository

def test_endpoint_with_mocked_repo(mocker):
    # Mock the repository
    mock_repo = Mock(spec=ClusterDataRepository)
    mock_repo.get_cluster_bundle.return_value = {
        'spec': {'displayName': 'Test Cluster'},
        'status': {'health': 'healthy'},
        'metrics': {'nodes': 3},
        'info': {'version': '4.12'}
    }
    
    # Inject mock into endpoint
    # ... test logic
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

# Authorization failed (RBACContext.check_cluster_access raises this automatically)
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

Use repositories instead of direct Redis calls:

```python
# DON'T do this:
data = redis_client.get(f"cluster:{name}:spec")
spec = json.loads(data) if data else None

# DO this:
from clusterpulse.repositories.redis_base import ClusterDataRepository

repo = ClusterDataRepository(redis_client)
spec = repo.get_cluster_spec(name)
```

**For batch operations, repositories use pipelines automatically:**

```python
# This uses a single Redis pipeline internally
bundle = repo.get_cluster_bundle(cluster_name)

# This batches all registries in one pipeline
bundles = repo.batch_get_registry_bundles(registry_names)
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
from clusterpulse.api.dependencies.rbac import RBACContext, get_rbac_context
from clusterpulse.repositories.redis_base import ClusterDataRepository
from clusterpulse.api.responses.cluster import ClusterResponseBuilder
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
   - Using repositories instead of direct Redis calls
   - Using RBACContext instead of manual RBAC operations
   - Using response builders for consistency

## Security Considerations

### Always Filter Resources

```python
# ❌ NEVER return raw data without filtering
@router.get("/nodes")
async def get_nodes():
    nodes = get_all_nodes()
    return nodes  # Security issue!

# ✅ ALWAYS filter through RBAC using RBACContext
@router.get("/nodes")
async def get_nodes(rbac: RBACContext = Depends(get_rbac_context)):
    nodes = repo.get_cluster_nodes(cluster_name)
    filtered = rbac.filter_resources(nodes, ResourceType.NODE, cluster_name)
    return filtered  # Safe
```

### Check Permissions for Sensitive Actions

```python
# Check specific permissions using RBACContext
decision = rbac.check_cluster_access(cluster_name, Action.VIEW_SENSITIVE)

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

1. **Forgetting to filter resources:** Always use `rbac.filter_resources()` or `rbac_engine.filter_resources()`

2. **Not mocking group resolution in tests:** Tests will fail without it
   ```python
   def mock_resolve_groups(username, email=None):
       return ["developers"]
   
   import clusterpulse.api.dependencies.auth as auth_module
   auth_module.resolve_groups_realtime = mock_resolve_groups
   ```

3. **Using wrong `ResourceType` for filtering:** Namespace-scoped resources should use `ResourceType.POD` for filtering

4. **Direct Redis access instead of repositories:** Use `ClusterDataRepository` methods for type safety and batching

5. **Manual dict building instead of response builders:** Use builder classes for consistent formatting

6. **Not using RBACContext:** Use `RBACContext` dependency instead of manually creating Principal/Request objects

7. **N+1 queries:** Repositories handle batching automatically, but be aware when making multiple repository calls

## Getting Help

- Check existing code in `api/v1/endpoints/clusters.py` for patterns
- Look at `api/responses/cluster.py` for response builder examples
- Look at `repositories/redis_base.py` for data access patterns
- Check `api/dependencies/rbac.py` for RBAC utilities
- Look at tests in `tests/integration/api/` for examples
- Read the RBAC engine code in `services/rbac.py` to understand filtering

## Project-Specific Notes

- **Group resolution is real-time:** Every request queries OpenShift for current group membership
- **Caching is disabled by default:** RBAC decisions are not cached (security over speed)
- **Policies are in Redis:** The Policy Controller manages them, but you can inspect with `redis-cli`
- **Metrics are pre-calculated:** The Cluster Controller writes metrics to Redis, we just filter them
- **Use repositories for data access:** Don't access Redis directly - use `ClusterDataRepository` or `RegistryDataRepository`
- **Use RBACContext in endpoints:** Simplifies authorization checks and resource filtering
- **Use response builders:** Ensures consistent API responses and handles fallbacks

## Quick Reference

### Typical Endpoint Structure

```python
from clusterpulse.api.dependencies.rbac import RBACContext, get_rbac_context
from clusterpulse.repositories.redis_base import ClusterDataRepository
from clusterpulse.api.responses.cluster import ClusterResponseBuilder

repo = ClusterDataRepository(redis_client)

@router.get("/{cluster_name}/resource")
async def get_resource(
    cluster_name: str,
    rbac: RBACContext = Depends(get_rbac_context)
):
    # 1. Check access
    rbac.check_cluster_access(cluster_name)
    
    # 2. Get data
    data = repo.get_cluster_resource_list(cluster_name, "resource")
    
    # 3. Filter
    filtered = rbac.filter_resources(data, ResourceType.POD, cluster_name)
    
    # 4. Return
    return filtered
```

### Common Imports

```python
# Dependencies
from clusterpulse.api.dependencies.rbac import RBACContext, get_rbac_context

# Repositories
from clusterpulse.repositories.redis_base import ClusterDataRepository, RegistryDataRepository

# Response builders
from clusterpulse.api.responses.cluster import ClusterResponseBuilder, ClusterListItemBuilder
from clusterpulse.api.responses.registry import RegistryStatusBuilder

# RBAC types
from clusterpulse.services.rbac import Action, ResourceType, Principal, Resource
```
