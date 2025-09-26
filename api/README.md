# OpenShift Cluster Monitor API Documentation

## Overview

The OpenShift Cluster Monitor API is a FastAPI-based service that provides multi-cluster OpenShift monitoring capabilities with fine-grained Role-Based Access Control (RBAC). It serves as the controller component in a larger monitoring ecosystem, managing cluster data, enforcing access policies, and providing filtered metrics based on user permissions.

## Table of Contents

- [Architecture](#architecture)
- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [Core Components](#core-components)
- [API Endpoints](#api-endpoints)
- [RBAC System](#rbac-system)
- [Development Guide](#development-guide)
- [Troubleshooting](#troubleshooting)

## Architecture

### High-Level Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   OAuth Proxy   │────▶│    FastAPI App   │────▶│      Redis      │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │                          │
                               ▼                          ▼
                        ┌──────────────────┐     ┌─────────────────┐
                        │   RBAC Engine    │     │  Cluster Data   │
                        └──────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌──────────────────┐
                        │  OpenShift API   │
                        └──────────────────┘
```

### Key Design Principles

1. **Zero-Trust Security**: All requests are authenticated and authorized
2. **Real-Time Authorization**: Groups and permissions resolved dynamically
3. **Filtered Visibility**: Users only see resources they have access to
4. **Performance Optimized**: Redis pipelining and strategic caching
5. **Cloud-Native**: Designed for OpenShift/Kubernetes deployment

## Getting Started

### Prerequisites

- Python 3.11+
- Redis instance (local or remote)
- OpenShift/Kubernetes cluster (for production)
- OAuth proxy (for production authentication)

### Local Development Setup

1. **Clone the repository and install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Set up environment variables:**
```bash
# Create .env file
cat > .env << EOF
ENVIRONMENT=development
DEBUG=True
REDIS_HOST=localhost
REDIS_PORT=6379
OAUTH_PROXY_ENABLED=False
RBAC_ENABLED=True
LOG_LEVEL=DEBUG
EOF
```

3. **Start Redis locally:**
```bash
docker run -d -p 6379:6379 redis:latest
```

4. **Run the application:**
```bash
python -m uvicorn src.main:app --reload --host 0.0.0.0 --port 8080
```

5. **Access the API documentation:**
- Swagger UI: http://localhost:8080/api/v1/docs
- ReDoc: http://localhost:8080/api/v1/redoc

## Project Structure

```
api/
├── __init__.py
├── main.py                 # Application entry point
├── core/                   # Core functionality
│   ├── config.py          # Configuration management
│   ├── logging.py         # Structured logging setup
│   ├── rbac_engine.py     # RBAC authorization engine
│   └── redis_client.py    # Redis connection management
├── api/
│   ├── routes/            # API endpoints
│   │   ├── auth.py       # Authentication endpoints
│   │   ├── clusters.py   # Cluster management
│   │   ├── cluster_metrics.py  # Metrics filtering
│   │   ├── health.py     # Health checks
│   │   └── registries.py # Registry management
│   ├── dependencies/      # FastAPI dependencies
│   │   └── auth.py       # Authentication/authorization deps
│   └── middleware/        # Request/response middleware
│       ├── auth.py       # Authentication middleware
│       └── logging.py    # Request logging
├── models/                # Pydantic models
│   ├── auth.py          # Authentication models
│   └── cluster.py       # Cluster/resource models
└── repositories/          # Data access layer
    └── cluster.py        # Redis data operations
```

## Core Components

### 1. RBAC Engine (`core/rbac_engine.py`)

The RBAC engine is the heart of the authorization system. It evaluates policies to determine what resources a user can access.

**Key Concepts:**
- **Principal**: The entity making the request (user/service account)
- **Resource**: The object being accessed (cluster, node, namespace, etc.)
- **Action**: The operation being performed (view, edit, delete, etc.)
- **Filter**: Restrictions on resource visibility

**Usage Example:**
```python
from src.core.rbac_engine import RBACEngine, Principal, Resource, ResourceType, Action, Request

# Create principal from user
principal = Principal(
    username="john.doe",
    email="john@example.com",
    groups=["developers", "cluster-viewers"]
)

# Define resource
resource = Resource(
    type=ResourceType.CLUSTER,
    name="production-cluster",
    cluster="production-cluster"
)

# Create authorization request
request = Request(
    principal=principal,
    action=Action.VIEW,
    resource=resource
)

# Authorize
decision = rbac_engine.authorize(request)
if decision.allowed:
    # Access granted
    pass
```

### 2. Filtered Metrics Calculator (`api/routes/cluster_metrics.py`)

This component calculates cluster metrics filtered by user permissions. It ensures users only see metrics for resources they can access.

**Key Features:**
- Namespace-based filtering
- Node filtering
- Resource count adjustments
- Performance optimized with Redis pipelining

### 3. Authentication Dependencies (`api/dependencies/auth.py`)

Handles user extraction from OAuth proxy headers and real-time group resolution from OpenShift.

**Group Resolution Flow:**
1. Extract user from OAuth headers
2. Query OpenShift User API
3. Check Group membership
4. Cache results (optional)

### 4. Redis Repository (`repositories/cluster.py`)

Provides data access patterns optimized for Redis, including:
- Batch operations with pipelining
- Sorted set operations for time-series data
- Hash operations for structured data
- Atomic operations for consistency

## API Endpoints

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/status` | GET | Check authentication status |
| `/api/v1/auth/me` | GET | Get current user info with groups |
| `/api/v1/auth/permissions` | GET | Get user's effective permissions |
| `/api/v1/auth/policies` | GET | List policies applied to user |
| `/api/v1/auth/cache/clear` | POST | Clear user's cache |

### Clusters

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/clusters` | GET | List accessible clusters with filtered metrics |
| `/api/v1/clusters/{name}` | GET | Get cluster details |
| `/api/v1/clusters/{name}/nodes` | GET | List cluster nodes (filtered) |
| `/api/v1/clusters/{name}/operators` | GET | List operators (filtered) |
| `/api/v1/clusters/{name}/namespaces` | GET | List accessible namespaces |
| `/api/v1/clusters/{name}/metrics` | GET | Get filtered metrics |
| `/api/v1/clusters/{name}/alerts` | GET | Get cluster alerts |
| `/api/v1/clusters/{name}/events` | GET | Get cluster events |

### Registries

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/registries/status` | GET | Get registry status (optimized) |

### Health

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness probe |
| `/ready` | GET | Readiness probe |

## RBAC System

### Policy Structure

Policies are stored in Redis and follow this structure:

```json
{
  "policy_name": "developers-policy",
  "priority": 100,
  "effect": "Allow",
  "enabled": true,
  "cluster_rules": [
    {
      "cluster_selector": {
        "matchNames": ["dev-cluster"],
        "matchPattern": "dev-.*"
      },
      "permissions": {
        "view": true,
        "viewMetrics": true,
        "viewSensitive": false
      },
      "namespace_filter": {
        "visibility": "filtered",
        "allowed_literals": ["dev-namespace"],
        "allowed_patterns": [["dev-.*", "dev-.*"]]
      },
      "node_filter": {
        "visibility": "all"
      }
    }
  ]
}
```

### Authorization Flow

1. **Request Reception**: User makes API request
2. **Authentication**: OAuth proxy validates user
3. **Group Resolution**: Real-time lookup from OpenShift
4. **Policy Evaluation**: RBAC engine evaluates applicable policies
5. **Resource Filtering**: Apply filters based on permissions
6. **Response Generation**: Return filtered data

### Permission Types

- `view`: Basic read access
- `viewMetrics`: Access to performance metrics
- `viewSensitive`: Access to sensitive data (tokens, secrets) - NOT FUNCTIONAL
- `viewCosts`: Access to cost information - NOT FUNCTIONAL
- `viewSecrets`: Access to secret values - NOT FUNCTIONAL
- `viewMetadata`: Access to metadata (versions, etc.)
- `viewAudit`: Access to audit logs - NOT FUNCTIONAL

## Development Guide

### Adding New Endpoints

1. **Create route in appropriate file:**
```python
# api/routes/your_resource.py
@router.get("/{resource_id}")
async def get_resource(
    resource_id: str,
    user: User = Depends(get_user_with_groups)
) -> Dict[str, Any]:
    # Check authorization
    decision = await check_resource_access(resource_id, user)
    
    # Get and filter data
    data = get_resource_data(resource_id)
    filtered_data = filter_by_permissions(data, decision)
    
    return filtered_data
```

2. **Register route in main.py:**
```python
app.include_router(
    your_resource.router,
    prefix=f"{settings.api_prefix}/resources",
    tags=["resources"]
)
```

### Implementing Resource Filtering

Always filter resources through the RBAC engine:

```python
# Filter resources
filtered_resources = rbac_engine.filter_resources(
    principal=principal,
    resources=raw_resources,
    resource_type=ResourceType.YOUR_TYPE,
    cluster=cluster_name
)
```

### Error Handling

Use appropriate exceptions:

```python
from src.api.dependencies.auth import AuthenticationError, AuthorizationError

# Authentication failed
raise AuthenticationError("Invalid credentials")

# Authorization failed
raise AuthorizationError("Access denied to resource")

# Resource not found
raise HTTPException(
    status_code=status.HTTP_404_NOT_FOUND,
    detail="Resource not found"
)
```

### Logging Best Practices

Use structured logging with context:

```python
from src.core.logging import get_logger, log_event

logger = get_logger(__name__)

# Log with context
log_event(
    logger,
    "info",
    "resource_accessed",
    user_id=user.id,
    resource_id=resource_id,
    action="view"
)
```

### Debug Mode

Enable debug mode for detailed logging:

```bash
DEBUG=True LOG_LEVEL=DEBUG python -m uvicorn src.main:app
```

### Health Check Endpoints

- `/health` - Basic liveness check
- `/ready` - Readiness with dependency checks

### Performance Monitoring

Monitor these key metrics:
- RBAC cache hit rate
- Redis operation latency
- Group resolution time
- Request processing time

## Contributing

### Security Considerations

- Never bypass RBAC checks
- Always validate input
- Use parameterized queries
- Log security-relevant events
- Follow least-privilege principle
