# Cluster Controller Documentation

## Overview

The Cluster Controller is a Kubernetes operator that manages connections to multiple Kubernetes/OpenShift clusters and container registries, collecting metrics and health information for centralized monitoring and management. It's a core component of the ClusterPulse platform.

## Table of Contents

- [Architecture](#architecture)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Core Components](#core-components)
- [Custom Resource Definitions](#custom-resource-definitions)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

## Architecture

### Design Principles

The controller follows several key design patterns:

- **Operator Pattern**: Uses Kubernetes controller-runtime to manage custom resources
- **Circuit Breaker**: Protects against cascading failures when connecting to unhealthy clusters
- **Connection Pooling**: Reuses cluster clients efficiently with automatic cleanup
- **Parallel Collection**: Gathers metrics concurrently for performance
- **Graceful Degradation**: Continues operation even when some metrics fail

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                     OpenShift Cluster                       │
│                                                             │
│  ┌──────────────────┐        ┌────────────────── ┐          │
│  │ ClusterConnection│        │RegistryConnection │          │
│  │      CRDs        │        │      CRDs         │          │
│  └────────┬─────────┘        └─ ───────┬─────────┘          │
│           │                            │                    │
│  ┌────────▼────────────────────────────▼─────────┐          │
│  │           Cluster Controller                  │          │
│  │  ┌──────────────┐  ┌────────────────────┐     │          │
│  │  │   Cluster    │  │     Registry       │     │          │
│  │  │ Reconciler   │  │    Reconciler      │     │          │
│  │  └──────┬───────┘  └───────── ┬─────────┘     │          │
│  │         │                     │               │          │
│  │  ┌──────▼─────────────────────▼──────────┐    │          │
│  │  │         Client Pool                   │    │          │
│  │  └──────┬────────────────────────────────┘    │          │
│  └─────────┼─────────────────────────────────────┘          │
└────────────┼───────────────────────────────────────────── ──┐
             │                                                │
    ┌────────▼────────┐                         ┌──────────┐  │
    │   Target        │                         │  Redis   │  │
    │   Clusters      │                         │  Store   │  │
    └─────────────────┘                         └──────────┘  │
```

### Data Flow

1. **Resource Creation**: User creates ClusterConnection/RegistryConnection CRs
2. **Reconciliation**: Controller reconciles resources on configured intervals
3. **Connection**: Establishes secure connections to target clusters/registries
4. **Collection**: Gathers metrics, health status, and resource information
5. **Storage**: Persists data to Redis for API consumption

## Development Setup

### Prerequisites

- Go 1.21+
- Docker
- oc
- Access to a Kubernetes cluster (minikube, kind, or real cluster)
- Redis instance

### Local Development

1. **Clone the repository**:
```bash
git clone <repository-url>
cd cluster-controller
```

2. **Install dependencies**:
```bash
go mod download
```

3. **Install CRDs**:
```bash
oc apply -f config/crd/
```

4. **Set up environment variables**:
```bash
export NAMESPACE=clusterpulse
export REDIS_HOST=localhost
export REDIS_PORT=6379
export RECONCILIATION_INTERVAL=30
```

5. **Run locally**:
```bash
go run
```

### Building - TODO

```bash
# Build binary
make build

# Build Docker image
make docker-build IMG=clusterpulse/cluster-controller:dev

# Push to registry
make docker-push IMG=clusterpulse/cluster-controller:dev
```

## Project Structure

```
cluster-controller/
├── api/v1alpha1/           # CRD definitions
│   ├── clusterconnection_types.go
│   ├── registryconnection_types.go
│   └── zz_generated.deepcopy.go
├── cmd/manager/            # Main entry point
│   └── main.go
├── internal/
│   ├── client/            # Client implementations
│   │   ├── cluster/       # Kubernetes cluster clients
│   │   ├── registry/      # Docker registry clients
│   │   └── pool/          # Connection pool management
│   ├── config/            # Configuration management
│   ├── controller/        # Reconciliation logic
│   │   ├── cluster/
│   │   └── registry/
│   └── store/             # Redis storage layer
├── pkg/
│   ├── types/             # Shared type definitions
│   └── utils/             # Utility functions
└── config/                # Kubernetes manifests
    ├── crd/              # Custom Resource Definitions
    ├── rbac/             # RBAC configurations
    └── deployment.yaml   # Controller deployment
```

## Core Components

### Cluster Reconciler

Located in `internal/controller/cluster/cluster_controller.go`

**Responsibilities:**
- Reconciles ClusterConnection resources
- Manages cluster client lifecycle
- Collects comprehensive cluster metrics
- Handles OpenShift-specific features (ClusterOperators)
- Implements retry logic with circuit breaker

**Key Methods:**
```go
// Main reconciliation loop
func (r *ClusterReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error)

// Core reconciliation logic
func (r *ClusterReconciler) reconcileCluster(ctx context.Context, clusterConn *v1alpha1.ClusterConnection) error

// Health calculation
func (r *ClusterReconciler) calculateClusterHealth(metrics *types.ClusterMetrics) types.ClusterHealth
```

### Registry Reconciler

Located in `internal/controller/registry/registry_controller.go`

**Responsibilities:**
- Reconciles RegistryConnection resources
- Performs Docker Registry v2 API health checks
- Monitors registry availability and response times
- Collects repository information (optional)

### Cluster Client

Located in `internal/client/cluster/client.go`

**Features:**
- Multi-cluster connection management
- Metrics collection (nodes, pods, deployments, etc.)
- OpenShift detection and ClusterOperator support
- Resource collection for RBAC filtering
- Operator discovery via OLM subscriptions

**Key Methods:**
```go
// Test cluster connectivity
func (c *ClusterClient) TestConnection(ctx context.Context) error

// Collect node-level metrics
func (c *ClusterClient) GetNodeMetrics(ctx context.Context) ([]types.NodeMetrics, error)

// Collect cluster-wide metrics
func (c *ClusterClient) GetClusterMetrics(ctx context.Context) (*types.ClusterMetrics, error)

// Get installed operators
func (c *ClusterClient) GetOperators(ctx context.Context) ([]types.OperatorInfo, error)

// Collect resources for RBAC
func (c *ClusterClient) GetResourceCollection(ctx context.Context, config types.CollectionConfig) (*types.ResourceCollection, error)
```

### Redis Storage Layer

Located in `internal/store/`

**Capabilities:**
- Structured data storage with TTL
- Time-series metrics storage
- Event publishing for real-time updates
- Python-compatible data format (for API backend)

**Storage Patterns:**
```
cluster:<name>:metrics          # Current cluster metrics
cluster:<name>:nodes            # Node information
cluster:<name>:operators        # Installed operators
cluster:<name>:namespaces       # Namespace list
cluster:<name>:resource_metadata # Resource collection metadata
registry:<name>:status          # Registry health status
```

## Custom Resource Definitions

### ClusterConnection

Defines a connection to a Kubernetes/OpenShift cluster.

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: ClusterConnection
metadata:
  name: production-cluster
  namespace: clusterpulse
spec:
  displayName: "Production Cluster"
  endpoint: "https://api.cluster.example.com:6443"
  credentialsRef:
    name: cluster-credentials
    namespace: clusterpulse
  monitoring:
    interval: 30  # Reconciliation interval in seconds
    timeout: 10   # Connection timeout in seconds
  labels:
    environment: production
    region: us-west
status:
  phase: Connected
  health: healthy
  lastSyncTime: "2024-01-15T10:30:00Z"
  nodes: 10
  namespaces: 50
```

### RegistryConnection

Defines a connection to a Docker Registry v2 compatible registry.

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: RegistryConnection
metadata:
  name: harbor-registry
  namespace: clusterpulse
spec:
  displayName: "Harbor Registry"
  endpoint: "https://registry.example.com"
  type: harbor  # Optional, informational only
  credentialsRef:
    name: registry-credentials
  monitoring:
    interval: 60
    checkCatalog: true
    maxCatalogEntries: 100
  skipTLSVerify: false
status:
  available: true
  health: healthy
  responseTime: 245
  repositoryCount: 150
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NAMESPACE` | clusterpulse | Namespace to watch for resources |
| `REDIS_HOST` | redis | Redis server hostname |
| `REDIS_PORT` | 6379 | Redis server port |
| `REDIS_PASSWORD` | "" | Redis password (optional) |
| `RECONCILIATION_INTERVAL` | 30 | Default reconciliation interval (seconds) |
| `NODE_METRICS_INTERVAL` | 15 | Node metrics collection interval |
| `OPERATOR_SCAN_INTERVAL` | 300 | Operator discovery interval |
| `CACHE_TTL` | 600 | Redis cache TTL (seconds) |
| `METRICS_RETENTION` | 3600 | Metrics retention period |
| `CPU_WARNING_THRESHOLD` | 85 | CPU warning threshold (%) |
| `MEMORY_WARNING_THRESHOLD` | 85 | Memory warning threshold (%) |
| `RESOURCE_COLLECTION_ENABLED` | true | Enable resource collection |
| `MAX_PODS_PER_NAMESPACE` | 100 | Max pods to collect per namespace |
| `MAX_TOTAL_PODS` | 1000 | Max total pods to collect |

### Resource Collection Configuration

The controller can collect detailed resource information for RBAC filtering:

```go
type CollectionConfig struct {
    Enabled          bool   // Enable/disable collection
    MaxPodsPerNS     int    // Limit pods per namespace
    MaxTotalPods     int    // Global pod limit
    MaxDeployments   int    // Max deployments to collect
    MaxServices      int    // Max services to collect
    IncludeLabels    bool   // Include resource labels
    NamespaceFilter  string // Regex to filter namespaces
}
```

## Troubleshooting

### Common Issues

1. **Controller Not Reconciling**:
   - Check controller logs: `oc logs -n clusterpulse deployment/cluster-controller`
   - Verify CRDs are installed: `oc get crd`
   - Check RBAC permissions: `oc auth can-i --list`

2. **Connection Failures**:
   - Verify credentials secret exists and is valid
   - Check network connectivity to target cluster
   - Verify CA certificate if provided
   - Check circuit breaker state in logs

3. **Redis Connection Issues**:
   - Verify Redis is running and accessible
   - Check Redis credentials
   - Monitor Redis memory usage

4. **High Memory Usage**:
   - Reduce resource collection limits
   - Decrease reconciliation frequency
   - Check for memory leaks with pprof

### Performance Tuning

1. **Reconciliation Intervals**: Adjust based on cluster size and requirements
2. **Resource Collection**: Tune limits based on available memory
3. **Connection Pool**: Adjust idle timeout for client reuse
4. **Redis Pipeline**: Batch operations for better performance

### Monitoring

Key metrics to monitor:
- Reconciliation duration
- Error rates per cluster
- Redis memory usage
- API server request rates
- Circuit breaker states

---

For additional help or questions, please open an issue in the repository or contact the maintainers.
