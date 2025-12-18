# Architecture

ClusterPulse consists of three main components that work together to provide
secure multi-cluster monitoring.

## System Overview
![Diagram](../assets/architecture.jpg)

## Components

### Cluster Controller (Go)

The Cluster Controller is a Kubernetes operator that:

- Watches `ClusterConnection` CRDs
- Connects to remote clusters using provided credentials
- Collects metrics (nodes, pods, operators, resources)
- Stores data in Redis for the API to consume

[Learn more →](../contributing/cluster-controller.md)

### Policy Controller (Python)

The Policy Controller compiles RBAC policies:

- Watches `MonitorAccessPolicy` CRDs
- Compiles policies into efficient evaluation structures
- Indexes policies by user/group for fast lookup
- Validates time-bound policies

[Learn more →](../contributing/policy-controller.md)

### API Server (Python/FastAPI)

The API Server handles all user requests:

- Authenticates users via OAuth/OIDC
- Resolves group membership in real-time
- Evaluates RBAC policies for every request
- Filters resources based on user permissions
- Serves the web UI

[Learn more →](../contributing/api.md)

## Data Flow

1. **Cluster Controller** collects metrics every 30 seconds
2. Data is stored in **Redis** with TTL
3. **Policy Controller** indexes policies for fast lookup
4. **API Server** receives user request
5. API authenticates user and resolves groups
6. **RBAC Engine** evaluates policies and filters data
7. Filtered response returned to user
