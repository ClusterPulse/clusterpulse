# Contributing to ClusterPulse Cluster Controller

## Getting Started

### Local Setup

```bash
# Install dependencies
# Requires Go 1.21+ and kubebuilder
go mod download

# Install kubebuilder (for CRD generation)
curl -L -o kubebuilder https://go.kubebuilder.io/dl/latest/$(go env GOOS)/$(go env GOARCH)
chmod +x kubebuilder && mv kubebuilder /usr/local/bin/

# Set up environment
export NAMESPACE=clusterpulse
export REDIS_HOST=localhost
export REDIS_PORT=6379

# Start Redis
docker run -d -p 6379:6379 redis:latest

# Generate CRDs and deep copy code
controller-gen object paths="./..."
controller-gen crd paths="./..." output:crd:artifacts:config=config/crd/bases

# Run locally (connects to your current kubeconfig cluster)
go run cmd/manager/main.go --namespace=clusterpulse
```

### Development Dependencies

```bash
# Install development tools
go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Install buf CLI (for proto generation)
# See https://buf.build/docs/installation
```

## Project Structure

Here's what goes where and why it's organized this way.

### Directory Layout

```
├── api/v1alpha1/            Custom Resource Definitions (CRDs)
├── cmd/
│   ├── manager/             Controller manager entry point
│   └── collector/           Collector agent entry point (push mode)
├── proto/
│   ├── collector.proto      gRPC service definition
│   └── collectorpb/         Generated Go code (don't edit)
├── internal/
│   ├── client/              Cluster and registry clients
│   │   ├── cluster/         Kubernetes cluster client
│   │   ├── registry/        Docker registry client
│   │   └── pool/            Client connection pooling
│   ├── collector/           Collector agent (push mode)
│   │   ├── agent.go         Agent lifecycle (connect, collect, push)
│   │   ├── config.go        Agent configuration from env vars
│   │   └── buffer.go        Local buffer for network outages
│   ├── controller/          Reconciliation controllers
│   │   ├── cluster/         ClusterConnection reconciler + collector deploy
│   │   ├── registry/        RegistryConnection reconciler
│   │   └── metricsource/    MetricSource reconciler
│   ├── ingester/            gRPC ingester server (embedded in manager)
│   │   ├── server.go        gRPC server, connection tracking
│   │   ├── handler.go       Batch processing, proto→internal conversion
│   │   └── vmwriter.go      VictoriaMetrics remote-write client
│   ├── metricsource/        MetricSource collection subsystem
│   │   ├── aggregator/      Aggregation computation engine
│   │   ├── collector/       Resource collection from clusters
│   │   ├── compiler/        CRD spec to runtime compilation
│   │   ├── expression/      Expression language implementation
│   │   └── extractor/       Field extraction from resources
│   ├── store/               Redis storage layer
│   └── config/              Configuration management
├── pkg/
│   ├── types/               Shared type definitions
│   │   ├── types.go         Core types (NodeMetrics, ClusterMetrics, etc.)
│   │   ├── resources.go     Resource collection types (PodSummary, etc.)
│   │   └── metricsource.go  MetricSource types (CompiledMetricSource, etc.)
│   └── utils/               Common utilities
│       ├── parser.go        CPU and memory parsing utilities
│       └── circuit_breaker.go Circuit breaker implementation
└── config/                  Kubernetes manifests and CRDs
```

### What Each Directory Does

#### `api/v1alpha1/`
Custom Resource Definitions. These define the API schema for ClusterConnection, RegistryConnection, and MetricSource resources.

**Files:**
- `groupversion_info.go` - API group registration (`clusterpulse.io/v1alpha1`)
- `clusterconnection_types.go` - ClusterConnection CRD schema
- `registryconnection_types.go` - RegistryConnection CRD schema
- `metricsource_types.go` - MetricSource CRD schema
- `zz_generated.deepcopy.go` - Auto-generated deep copy methods (don't edit)

**When to edit:**
- Adding new fields to CRDs
- Changing validation rules
- Adding new status fields
- Modifying kubebuilder markers for oc output columns

**Pattern:**
```go
// Add a new field to ClusterConnectionSpec
type ClusterConnectionSpec struct {
    // Existing fields...
    
    // NewField does something useful
    // +optional
    NewField string `json:"newField,omitempty"`
}

// After editing, regenerate:
// controller-gen object paths="./..."
// controller-gen crd paths="./..." output:crd:artifacts:config=config/crd/bases
```

**Kubebuilder markers you'll use:**
```go
// +kubebuilder:validation:Required
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:Minimum=30
// +kubebuilder:default=30
// +optional
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.phase"
```

#### `cmd/manager/`
Application entry point. Sets up the controller manager, starts all reconcilers, and optionally starts the embedded Ingester gRPC server for push-mode collection.

**Files:**
- `main.go` - Initializes manager, registers controllers, starts ingester server

**When to edit:**
- Adding new controllers
- Changing manager configuration
- Modifying health check endpoints
- Adjusting leader election settings
- Changing ingester startup behavior

**Ingester integration:**
When `INGESTER_ENABLED=true` (default), the manager starts a gRPC server on `INGESTER_PORT` (default 9443) that accepts push-mode collector connections. The ingester server reference is passed to the `ClusterReconciler` so it can check collector connection status.

**Pattern:**
```go
// Register a new controller
if err = (&newcontroller.NewReconciler{
    Client:      mgr.GetClient(),
    Scheme:      mgr.GetScheme(),
    RedisClient: redisClient,
    Config:      cfg,
}).SetupWithManager(mgr); err != nil {
    setupLog.Error(err, "unable to create controller")
    os.Exit(1)
}
```

#### `cmd/collector/`
Collector agent entry point. Runs on managed clusters in push mode.

**Files:**
- `main.go` - Creates in-cluster k8s client, starts collector agent

**When to edit:**
- Changing agent startup behavior
- Adding new agent flags or env vars

**How it works:**
The collector runs as a single-replica Deployment on each managed cluster. It uses an in-cluster ServiceAccount (no remote tokens), connects to the hub ingester via gRPC, and pushes metrics using the same collection packages as the hub controller.

```bash
# Environment variables (set by hub-deployed Deployment)
CLUSTER_NAME=prod-east           # Cluster identifier
INGESTER_ADDRESS=hub:9443        # Hub ingester gRPC endpoint
COLLECTOR_TOKEN=<bearer-token>   # Auth token (from Secret)
COLLECT_INTERVAL=30s             # Collection interval (default 30s)
BUFFER_SIZE=10                   # Local buffer size (default 10 cycles)
```

#### `internal/client/cluster/`
Kubernetes cluster client implementation. Connects to remote clusters, collects metrics, gets resource information.

**Files:**
- `client.go` - Main cluster client, connection management
- `resources.go` - Resource collection (pods, deployments, services)

**When to edit:**
- Adding new resource collection
- Modifying metrics calculation
- Implementing new health checks
- Changing how node metrics are extracted

**Key methods:**
```go
// TestConnection - Verifies cluster is accessible
func (c *ClusterClient) TestConnection(ctx context.Context) error

// GetNodeMetrics - Collects detailed metrics from all nodes
func (c *ClusterClient) GetNodeMetrics(ctx context.Context) ([]types.NodeMetrics, error)

// GetClusterMetrics - Aggregates cluster-wide metrics
func (c *ClusterClient) GetClusterMetrics(ctx context.Context) (*types.ClusterMetrics, error)

// GetOperators - Retrieves OLM operator information
func (c *ClusterClient) GetOperators(ctx context.Context) ([]types.OperatorInfo, error)

// GetResourceCollection - Collects lightweight resource data for RBAC
func (c *ClusterClient) GetResourceCollection(ctx context.Context, config types.CollectionConfig) (*types.ResourceCollection, error)
```

**Important:** All methods use circuit breakers and timeouts to prevent hanging on unhealthy clusters.

#### `internal/client/registry/`
Docker Registry v2 API client for health checking and catalog access.

**Files:**
- `client.go` - Registry client implementation

**When to edit:**
- Adding new registry feature detection
- Modifying health check logic
- Adding authentication methods
- Changing catalog retrieval

**Key pattern:**
```go
// All registries use Docker v2 API
client := registry.NewDockerV2Client(
    endpoint,
    username,
    password,
    insecure,
    skipTLSVerify,
)

// Health check
result, err := client.HealthCheck(ctx)

// Optional catalog access
catalog, err := client.CheckCatalog(ctx, maxEntries)
```

#### `internal/client/pool/`
Connection pool for cluster clients. Reuses connections and cleans up idle clients.

**Files:**
- `pool.go` - Client pool implementation

**Why it exists:** Creating new Kubernetes clients is expensive. The pool reuses existing clients and tests them before returning.

**When to edit:**
- Changing idle timeout
- Modifying connection test logic
- Adding pool metrics

**Usage:**
```go
// Get client from pool (creates if needed, reuses if exists)
client, err := pool.Get(name, endpoint, token, caCert)

// Remove from pool (on cluster deletion)
pool.Remove(name)
```

#### `internal/ingester/`
gRPC ingester server, embedded in the manager process. Accepts metric pushes from collector agents on managed clusters.

**Files:**
- `server.go` - gRPC server lifecycle, connection tracking, keepalive
- `handler.go` - Processes `MetricsBatch` messages, converts proto→internal types, writes to Redis
- `vmwriter.go` - VictoriaMetrics remote-write client (Prometheus text format)

**Key methods:**
```go
// Server manages gRPC connections from collector agents
server.Start(port)                       // Start listening
server.Stop()                            // Graceful shutdown
server.IsConnected(clusterName) bool     // Check if collector is connected
server.GetConnectionInfo(name) ConnInfo  // Get collector version, heartbeat

// VMWriter writes time-series metrics to VictoriaMetrics
vmWriter.WriteClusterMetrics(ctx, cluster, metrics)                // 8 cluster-level gauges
vmWriter.WriteNodeMetrics(ctx, cluster, nodes)                     // 17 per-node gauges
vmWriter.WriteOperatorMetrics(ctx, cluster, ops, cops)             // Operator presence + status gauges
vmWriter.WriteCustomResourceMetrics(ctx, cluster, sourceID, aggs) // Custom resource aggregation values
```

**VictoriaMetrics metrics written:**

| Metric | Labels | Source |
|--------|--------|--------|
| `clusterpulse_cluster_nodes_total` | cluster | ClusterMetrics |
| `clusterpulse_cluster_nodes_ready` | cluster | ClusterMetrics |
| `clusterpulse_cluster_pods_total` | cluster | ClusterMetrics |
| `clusterpulse_cluster_pods_running` | cluster | ClusterMetrics |
| `clusterpulse_cluster_cpu_capacity` | cluster | ClusterMetrics |
| `clusterpulse_cluster_memory_capacity_bytes` | cluster | ClusterMetrics |
| `clusterpulse_cluster_namespaces_total` | cluster | ClusterMetrics |
| `clusterpulse_cluster_deployments_total` | cluster | ClusterMetrics |
| `clusterpulse_node_cpu_usage_percent` | cluster, node | NodeMetrics |
| `clusterpulse_node_memory_usage_percent` | cluster, node | NodeMetrics |
| `clusterpulse_node_cpu_capacity` | cluster, node | NodeMetrics |
| `clusterpulse_node_memory_capacity_bytes` | cluster, node | NodeMetrics |
| `clusterpulse_node_storage_capacity_bytes` | cluster, node | NodeMetrics |
| `clusterpulse_node_pods_capacity` | cluster, node | NodeMetrics |
| `clusterpulse_node_cpu_allocatable` | cluster, node | NodeMetrics |
| `clusterpulse_node_memory_allocatable_bytes` | cluster, node | NodeMetrics |
| `clusterpulse_node_storage_allocatable_bytes` | cluster, node | NodeMetrics |
| `clusterpulse_node_pods_allocatable` | cluster, node | NodeMetrics |
| `clusterpulse_node_cpu_requested` | cluster, node | NodeMetrics |
| `clusterpulse_node_memory_requested_bytes` | cluster, node | NodeMetrics |
| `clusterpulse_node_pods_total` | cluster, node | NodeMetrics |
| `clusterpulse_node_pods_running` | cluster, node | NodeMetrics |
| `clusterpulse_node_pods_pending` | cluster, node | NodeMetrics |
| `clusterpulse_node_pods_failed` | cluster, node | NodeMetrics |
| `clusterpulse_node_pods_succeeded` | cluster, node | NodeMetrics |
| `clusterpulse_operator_installed` | cluster, operator | OperatorInfo |
| `clusterpulse_cluster_operator_available` | cluster, operator | ClusterOperatorInfo |
| `clusterpulse_cluster_operator_progressing` | cluster, operator | ClusterOperatorInfo |
| `clusterpulse_cluster_operator_degraded` | cluster, operator | ClusterOperatorInfo |
| `clusterpulse_cluster_operator_upgradeable` | cluster, operator | ClusterOperatorInfo |
| `clusterpulse_cluster_operators_total` | cluster | len(ops) |
| `clusterpulse_cluster_operators_count` | cluster | len(cops) |
| `clusterpulse_custom_resource_{name}` | cluster, source | Aggregation values |

**Processing pipeline:**
```
gRPC stream → Auth (bearer token) → Register (cluster name)
  → MetricsBatch → Transform (proto → internal types)
  → Dual-write: Redis (current state) + VictoriaMetrics (history)
  → Send Ack back to collector
```

**When to edit:**
- Changing authentication logic
- Adding new message types to the proto
- Modifying the dual-write pipeline
- Adding connection monitoring

#### `internal/collector/`
Collector agent that runs on managed clusters in push mode.

**Files:**
- `agent.go` - Main lifecycle: connect → register → collect loop → push
- `config.go` - Configuration from env vars, reconnect backoff
- `buffer.go` - Bounded FIFO buffer for network outage resilience

**Key behaviors:**
- Reuses `internal/metricsource/collector` for local collection (same code as hub)
- Buffers up to 10 collection cycles during network outages
- Exponential backoff reconnect (1s → 5min cap)
- Receives MetricSource configs from ingester (no hub k8s API access needed)
- gRPC keepalive every 30s

**When to edit:**
- Changing collection logic
- Modifying reconnection behavior
- Adding new message types
- Changing buffer strategy

#### `proto/`
Protocol Buffer definitions for collector↔ingester communication.

**Files:**
- `collector.proto` - Service and message definitions
- `collectorpb/` - Generated Go code (don't edit directly)

**Regenerate after editing proto:**
```bash
buf generate proto
```

**Key messages:**
- `CollectorMessage` - Sent by collector (Register, MetricsBatch, HealthReport)
- `IngesterMessage` - Sent by ingester (ConfigUpdate, Ack)
- `MetricsBatch` - Contains cluster metrics, node metrics, custom resources

#### `internal/controller/cluster/`
ClusterConnection reconciliation controller. This is where the main cluster monitoring logic lives.

**Files:**
- `cluster_controller.go` - Reconciler implementation
- `collector_deploy.go` - Deploys collector agent on managed clusters (push mode)

**When to edit:**
- Changing reconciliation interval logic
- Modifying node metrics or operator collection
- Changing status update logic
- Modifying collector deployment resources or RBAC

**Reconciliation flow:**
```go
func (r *ClusterReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
    // 1. Fetch ClusterConnection resource
    // 2. Handle deletion if needed
    // 3. Check collectionMode:
    //    - "push": check if collector is connected via ingester
    //      - Connected: update CollectorAgentStatus, skip pull collection
    //      - Not connected: deploy collector, fall back to pull
    //    - "pull" (default): proceed with pull collection
    // 4. Get cluster client from pool
    // 5. Test connection
    // 6. Collect data in parallel (errgroup)
    //    - Node metrics
    //    - Cluster info
    //    - Operators (OLM)
    //    - ClusterOperators (OpenShift)
    // 7. Store in Redis (node metrics, cluster info, operators, labels)
    // 8. Update CRD status (health = healthy if reachable)
    // 9. Return with RequeueAfter for periodic reconciliation

    return reconcile.Result{RequeueAfter: time.Duration(interval) * time.Second}, nil
}
```

**Critical points:**
- Always returns `RequeueAfter` to ensure periodic reconciliation
- Uses `errgroup` for parallel data collection
- Cluster-level aggregated metrics and resource collection are handled by MetricSource CRDs
- Health is set to "healthy" when the cluster is reachable; connection failures set "unhealthy"
- Updates status using `Patch` to avoid triggering reconciliation
- Only logs at Info level for significant events
- Push mode: when `collectionMode=push` and collector is connected, the hub skips pull-based collection entirely
- Collector deployment: `collector_deploy.go` creates Namespace, ServiceAccount, ClusterRole, ClusterRoleBinding, Secret, and Deployment on the managed cluster using the dynamic client

#### `internal/controller/registry/`
RegistryConnection reconciliation controller. Monitors Docker registries.

**Files:**
- `registry_controller.go` - Reconciler implementation

**Similar to cluster controller but simpler:**
1. Fetch RegistryConnection resource
2. Create registry client
3. Perform health check
4. Store results in Redis
5. Update status
6. Requeue

**Key difference:** Uses event filtering to avoid status-only update loops:
```go
pred := predicate.Funcs{
    UpdateFunc: func(e event.UpdateEvent) bool {
        oldReg, okOld := e.ObjectOld.(*v1alpha1.RegistryConnection)
        newReg, okNew := e.ObjectNew.(*v1alpha1.RegistryConnection)
        
        // Only reconcile if generation changed (spec change)
        if oldReg.Generation != newReg.Generation {
            return true
        }
        
        // Ignore status-only updates
        return false
    },
}
```

#### `internal/controller/metricsource/`
MetricSource reconciliation controller. Handles custom resource collection based on user-defined MetricSource CRDs.

**Files:**
- `metricsource_controller.go` - Reconciler implementation

**Purpose:** Enables users to define custom resource collection configurations that extract specific fields from any Kubernetes resource type, compute derived values, and aggregate metrics across clusters.

**Reconciliation flow:**
```go
func (r *MetricSourceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
    // 1. Fetch MetricSource resource
    // 2. Handle deletion if needed
    // 3. Compile the MetricSource spec to runtime structure
    // 4. Store compiled definition in Redis
    // 5. Collect from all connected ClusterConnections in parallel
    //    - For each cluster: create dynamic client, collect resources
    //    - Extract fields, compute expressions, run aggregations
    //    - Store results in Redis
    // 6. Update CRD status with collection summary
    // 7. Return with RequeueAfter based on collection interval
    
    return reconcile.Result{RequeueAfter: interval}, nil
}
```

**Key components:**
- `compiler` - Transforms CRD spec to optimized runtime structure
- `collector` - Handles resource collection from clusters
- `compiledCache` - Local cache of compiled MetricSources
- `clusterClients` - Cache of dynamic clients per cluster

**When to edit:**
- Changing how MetricSources are compiled
- Modifying collection parallelism
- Adding new status fields
- Changing error handling or retry logic

**Pattern for collecting from clusters:**
```go
func (r *MetricSourceReconciler) collectFromAllClusters(ctx context.Context, source *types.CompiledMetricSource) (*CollectionSummary, error) {
    // List all ClusterConnections
    clusterConns := &v1alpha1.ClusterConnectionList{}
    r.List(ctx, clusterConns, k8sclient.InNamespace(r.WatchNamespace))
    
    // Collect in parallel using errgroup
    g, gctx := errgroup.WithContext(ctx)
    
    for i := range clusterConns.Items {
        cc := &clusterConns.Items[i]
        if cc.Status.Phase != "Connected" {
            continue
        }
        
        g.Go(func() error {
            result, err := r.collectFromCluster(gctx, cc, source)
            // Handle result...
            return nil
        })
    }
    
    g.Wait()
    return summary, nil
}
```

#### `internal/metricsource/`
The MetricSource collection subsystem. This directory contains all the logic for custom resource collection, field extraction, expression evaluation, and aggregation.

##### `internal/metricsource/compiler/`
Transforms MetricSource CRD specs into optimized runtime structures.

**Files:**
- `compiler.go` - Main compilation logic

**What it does:**
1. Validates the MetricSource spec
2. Parses API version into group/version
3. Derives resource name from kind (pluralization)
4. Compiles field extraction paths into segments
5. Compiles computed field expressions
6. Compiles aggregation definitions
7. Compiles namespace include/exclude patterns to regex
8. Generates a hash for change detection

**Key methods:**
```go
// Compile transforms a MetricSource spec into a CompiledMetricSource
func (c *Compiler) Compile(ms *v1alpha1.MetricSource) (*types.CompiledMetricSource, error)

// Validates the spec
func (c *Compiler) validate(ms *v1alpha1.MetricSource) error

// Parses JSONPath into segments for efficient extraction
func parseJSONPath(path string) []string

// Converts shell-style wildcards to regex
func wildcardToRegex(pattern string) (*regexp.Regexp, error)

// Handles Kubernetes resource pluralization
func pluralize(singular string) string
```

**When to edit:**
- Adding new compilation features
- Changing validation rules
- Supporting new field types
- Modifying expression compilation

**Pattern for adding new spec features:**
```go
// 1. Add to MetricSourceSpec in api/v1alpha1/metricsource_types.go
// 2. Add compiled type in pkg/types/metricsource.go
// 3. Add compilation logic in compiler.go:

func (c *Compiler) Compile(ms *v1alpha1.MetricSource) (*types.CompiledMetricSource, error) {
    // ... existing code ...
    
    // Compile new feature
    compiled.NewFeature = c.compileNewFeature(&ms.Spec.NewFeature)
    
    return compiled, nil
}

func (c *Compiler) compileNewFeature(feature *v1alpha1.NewFeature) types.CompiledNewFeature {
    // Compilation logic
}
```

##### `internal/metricsource/collector/`
Handles resource collection from Kubernetes clusters using the dynamic client.

**Files:**
- `collector.go` - Collection logic

**What it does:**
1. Resolves namespaces to collect from (handling include/exclude patterns)
2. Lists resources using the dynamic client with pagination
3. Extracts configured fields from each resource
4. Evaluates computed expressions
5. Runs aggregations on collected data

**Key methods:**
```go
// Collect gathers resources from a cluster based on MetricSource configuration
func (c *Collector) Collect(
    ctx context.Context,
    dynamicClient dynamic.Interface,
    source *types.CompiledMetricSource,
    clusterName string,
) (*CollectResult, error)

// collectFromScope collects from a single namespace or cluster scope
func (c *Collector) collectFromScope(
    ctx context.Context,
    dynamicClient dynamic.Interface,
    gvr schema.GroupVersionResource,
    namespace string,
    source *types.CompiledMetricSource,
    limit int,
) ([]types.CustomCollectedResource, error)

// extractResource extracts fields and computes expressions for a single resource
func (c *Collector) extractResource(
    resource *unstructured.Unstructured,
    source *types.CompiledMetricSource,
) (*types.CustomCollectedResource, error)
```

**Collection controls:**
- `MaxResources` - Limits total resources collected
- `BatchSize` - API pagination size
- `Parallelism` - Concurrent namespace collection
- `TimeoutSeconds` - Per-cluster timeout

**When to edit:**
- Changing collection parallelism strategy
- Adding new resource filtering
- Modifying pagination behavior
- Adding collection metrics/tracing

##### `internal/metricsource/extractor/`
Field extraction from unstructured Kubernetes resources.

**Files:**
- `extractor.go` - Extraction logic

**What it does:**
1. Navigates object paths using pre-parsed segments
2. Converts values to configured types
3. Handles array index notation
4. Applies default values when paths don't exist

**Key methods:**
```go
// ExtractFields extracts all configured fields from a resource
func (e *Extractor) ExtractFields(
    resource *unstructured.Unstructured,
    fields []types.CompiledField,
) (map[string]interface{}, error)

// navigatePath traverses the object using pre-parsed path segments
func (e *Extractor) navigatePath(obj interface{}, segments []string) (interface{}, bool, error)

// convertValue converts a raw value to the specified type
func (e *Extractor) convertValue(value interface{}, fieldType string) (interface{}, error)
```

**Supported field types:**
- `string` - String value
- `integer` - 64-bit integer
- `float` - 64-bit float
- `boolean` - Boolean value
- `quantity` - Kubernetes quantity (memory/CPU) to bytes
- `timestamp` - RFC3339 timestamp validation
- `arrayLength` - Length of array or map

**When to edit:**
- Adding new field types
- Changing type conversion logic
- Adding extraction error handling

##### `internal/metricsource/expression/`
Expression language implementation for computed fields.

**Files:**
- `types.go` - AST node types and token definitions
- `tokenizer.go` - Lexical analysis (tokenization)
- `parser.go` - Recursive descent parser
- `evaluator.go` - Expression evaluation
- `functions.go` - Built-in function implementations

**Expression language features:**
- Arithmetic: `+`, `-`, `*`, `/`, `%`
- Comparison: `==`, `!=`, `<`, `<=`, `>`, `>=`
- Logical: `&&`, `||`, `!`
- Null coalescing: `??`
- String concatenation: `+` with strings
- Function calls: `round(value, 2)`, `concat(a, b)`

**Built-in functions:**
```go
// String functions
concat(args...)   // Concatenate strings
lower(s)          // Lowercase
upper(s)          // Uppercase
len(s)            // String length
substr(s, start, [length])
contains(s, sub)
startsWith(s, prefix)
endsWith(s, suffix)

// Math functions
round(n, [decimals])
floor(n)
ceil(n)
abs(n)
min(a, b)
max(a, b)

// Utility functions
coalesce(args...) // First non-null value
now()             // Current timestamp
age(timestamp)    // Seconds since timestamp
formatBytes(n)    // Human-readable bytes
toString(v)
toNumber(v)
```

**How parsing works:**
```
Expression: "capacity * 0.8 - used"

1. Tokenizer produces tokens:
   [Ident("capacity"), Star, Number(0.8), Minus, Ident("used")]

2. Parser builds AST:
   BinaryOp(-)
   ├── BinaryOp(*)
   │   ├── Identifier("capacity")
   │   └── Literal(0.8)
   └── Identifier("used")

3. Evaluator traverses AST with context values
```

**When to edit:**
- Adding new operators
- Adding built-in functions
- Changing operator precedence
- Adding expression validation

**Pattern for adding a function:**
```go
// In functions.go
var BuiltinFunctions = map[string]FunctionDef{
    // ... existing functions ...
    
    "newFunc": {MinArgs: 1, MaxArgs: 2, Fn: fnNewFunc},
}

func fnNewFunc(args []interface{}) (interface{}, error) {
    // Implementation
    return result, nil
}
```

##### `internal/metricsource/aggregator/`
Aggregation computation engine.

**Files:**
- `types.go` - Aggregation types and filter operators
- `filter.go` - Filter evaluation logic
- `aggregator.go` - Aggregation computation

**Supported aggregation functions:**
- `count` - Count resources (optionally filtered)
- `sum` - Sum of field values
- `avg` - Average of field values
- `min` - Minimum value
- `max` - Maximum value
- `percentile` - Percentile calculation (e.g., p95)
- `distinct` - Count of unique values

**Filter operators:**
- `equals`, `notEquals`
- `contains`, `startsWith`, `endsWith`
- `greaterThan`, `lessThan`
- `in` - Value in list
- `matches` - Regex match

**Key methods:**
```go
// Compute calculates all aggregations for the given resources
func (a *Aggregator) Compute(input *AggregationInput) *types.AggregationResults

// computeAggregation handles a single aggregation with optional groupBy
func (a *Aggregator) computeAggregation(agg *types.CompiledAggregation, resources []types.CustomCollectedResource) interface{}

// FilterEvaluator.Matches checks if a resource passes the filter condition
func (f *FilterEvaluator) Matches(resource *types.CustomCollectedResource, filter *types.CompiledAggFilter) bool
```

**Grouping:** Aggregations can be grouped by a field value:
```yaml
aggregations:
  - name: pods_by_status
    function: count
    groupBy: status
# Result: {"Running": 45, "Pending": 3, "Failed": 1}
```

**When to edit:**
- Adding new aggregation functions
- Adding new filter operators
- Optimizing aggregation performance

#### `internal/store/`
Redis storage layer. Writes data in Python-compatible format for the API to consume.

**Files:**
- `client.go` - Main Redis client and cluster/operator storage
- `registry_storage.go` - Registry-specific storage
- `resource_storage.go` - Resource collection storage
- `metricsource_storage.go` - MetricSource data storage

**Critical:** All data must be Python-compatible
- Arrays must never be `nil` (use `[]string{}` instead)
- Use snake_case for keys (e.g., `cpu_capacity`, not `cpuCapacity`)
- Store timestamps in RFC3339 format
- Use proper type conversions (JSON numbers become `float64` in Go)

**Pattern:**
```go
// Convert Go struct to Python-compatible map
metricsDict := map[string]interface{}{
    "timestamp":       metrics.Timestamp.Format(time.RFC3339),
    "nodes":           metrics.Nodes,
    "nodes_ready":     metrics.NodesReady,
    "cpu_capacity":    metrics.CPUCapacity,
    "memory_capacity": metrics.MemoryCapacity,
}

// Store with TTL
data, _ := json.Marshal(metricsDict)
pipe.Set(ctx, key, string(data), time.Duration(c.config.CacheTTL)*time.Second)
```

**When to edit:**
- Adding new Redis keys
- Changing data format
- Adding new storage methods
- Modifying TTL strategies

**Important storage methods:**
```go
// Cluster data
StoreClusterSpec(ctx, name, spec)
StoreClusterStatus(ctx, name, status)
StoreClusterMetrics(ctx, name, metrics)
StoreNodeMetrics(ctx, name, nodeMetrics)
StoreOperators(ctx, name, operators)
StoreClusterOperators(ctx, name, clusterOperators)
StoreResourceCollection(ctx, name, collection)

// Registry data
StoreRegistrySpec(ctx, name, spec)
StoreRegistryStatus(ctx, name, status)
StoreRegistryMetrics(ctx, name, metrics)

// MetricSource data
StoreCompiledMetricSource(ctx, source)
GetCompiledMetricSource(ctx, namespace, name)
DeleteMetricSource(ctx, namespace, name)
StoreCustomResourceCollection(ctx, clusterName, collection)
GetCustomResourceCollection(ctx, clusterName, sourceID)
StoreAggregationResults(ctx, clusterName, results)
GetAggregationResults(ctx, clusterName, sourceID)
```

**MetricSource Redis key patterns:**
```go
keyMetricSourceDef          = "metricsource:%s:%s"                // namespace:name
keyMetricSourceResources    = "cluster:%s:custom:%s:resources"    // cluster:sourceId
keyMetricSourceAggregations = "cluster:%s:custom:%s:aggregations" // cluster:sourceId
keyMetricSourceMeta         = "cluster:%s:custom:%s:meta"         // cluster:sourceId
keyMetricSourcesAll         = "metricsources:all"
keyMetricSourcesEnabled     = "metricsources:enabled"
keyMetricSourceByType       = "metricsources:by:resourcetype:%s"  // resourceTypeName
```

#### `internal/config/`
Configuration management from environment variables.

**Files:**
- `config.go` - Configuration struct and loading

**When to edit:**
- Adding new configuration options
- Changing default values
- Adding validation

**Pattern:**
```go
// Add a new config field
type Config struct {
    // Existing fields...
    
    // New configuration
    NewFeatureEnabled bool
    NewFeatureTimeout int
}

// Load from environment
func Load() *Config {
    cfg := &Config{
        // ...
        NewFeatureEnabled: getEnvBool("NEW_FEATURE_ENABLED", false),
        NewFeatureTimeout: getEnvIntWithMin("NEW_FEATURE_TIMEOUT", 30, 5),
    }
    return cfg
}
```

**Available config:**
- `ReconciliationInterval` - How often to reconcile (default 30s)
- `OperatorScanInterval` - How often to scan for operators (default 300s)
- `ConnectTimeout` - Cluster connection timeout (default 10s)
- `CacheTTL` - Redis cache TTL (default 600s)
- `MetricsRetention` - How long to keep time series (default 3600s)
- `IngesterEnabled` - Enable gRPC ingester for push mode (default true, env `INGESTER_ENABLED`)
- `IngesterPort` - gRPC ingester listen port (default 9443, env `INGESTER_PORT`)
- `VMEnabled` - Enable VictoriaMetrics time-series storage (default false, env `VM_ENABLED`)
- `VMEndpoint` - VictoriaMetrics URL (default `http://victoriametrics:8428`, env `VM_ENDPOINT`)

#### `pkg/types/`
**Shared type definitions that are used across the project.** This is the key distinction from `internal/` - types in `pkg/` can be imported by external packages.

**Files:**
- `types.go` - Core cluster and node types
- `resources.go` - Resource collection types for RBAC filtering
- `metricsource.go` - MetricSource types for custom resource collection

**When to use pkg/types/ vs internal/:**
- Use `pkg/types/` for types that define the domain model and might be used by external tools
- Use types in `internal/` for implementation details specific to controllers or clients

**types.go - Core Types:**

```go
// Health status constants
type ClusterHealth string
const (
    HealthHealthy   ClusterHealth = "healthy"
    HealthDegraded  ClusterHealth = "degraded"
    HealthUnhealthy ClusterHealth = "unhealthy"
    HealthUnknown   ClusterHealth = "unknown"
)

// Node status constants
type NodeStatus string
const (
    NodeReady              NodeStatus = "Ready"
    NodeNotReady           NodeStatus = "NotReady"
    NodeUnknown            NodeStatus = "Unknown"
    NodeSchedulingDisabled NodeStatus = "SchedulingDisabled"
)

// NodeMetrics contains detailed metrics for a single node
type NodeMetrics struct {
    Name       string
    Timestamp  time.Time
    Status     string
    Roles      []string
    Conditions []NodeCondition
    
    // Resource capacity and usage
    CPUCapacity        float64
    MemoryCapacity     int64
    CPURequested       float64
    MemoryRequested    int64
    CPUUsagePercent    float64
    MemoryUsagePercent float64
    
    // Pod counts
    PodsRunning   int32
    PodsPending   int32
    PodsFailed    int32
    PodsTotal     int32
    
    // System info
    KernelVersion    string
    OSImage          string
    ContainerRuntime string
    KubeletVersion   string
    
    // Network and labels
    InternalIP  string
    ExternalIP  string
    Labels      map[string]string
    Annotations map[string]string
}

// ClusterMetrics contains cluster-wide aggregated metrics
type ClusterMetrics struct {
    Timestamp      time.Time
    Nodes          int
    NodesReady     int
    Namespaces     int
    NamespaceList  []string
    Pods           int
    PodsRunning    int
    CPUCapacity    float64
    MemoryCapacity int64
    Deployments    int
}

// OperatorInfo for OLM operators
type OperatorInfo struct {
    Name               string
    DisplayName        string
    Version            string
    Status             string
    InstalledNamespace string
    Provider           string
    CreatedAt          time.Time
    IsClusterWide      bool
}

// ClusterOperatorInfo for OpenShift ClusterOperators
type ClusterOperatorInfo struct {
    Name               string
    Version            string
    Available          bool
    Progressing        bool
    Degraded           bool
    Upgradeable        bool
    Message            string
    LastTransitionTime time.Time
    Conditions         []ClusterOperatorCondition
    Versions           []ClusterOperatorVersion
}
```

**When to add types here:**
- Core domain models (nodes, clusters, metrics)
- Types returned by client methods
- Types stored in Redis
- Types that define the system's data model

**resources.go - Resource Collection Types:**

These types are specifically designed for RBAC filtering and are optimized for memory efficiency:

```go
// ResourceCollection holds lightweight resource data for RBAC filtering
// Designed to be memory-efficient and fast to serialize
type ResourceCollection struct {
    Timestamp   time.Time
    Pods        []PodSummary
    Deployments []DeploymentSummary
    Services    []ServiceSummary
    StatefulSets []StatefulSetSummary
    DaemonSets  []DaemonSetSummary
    
    // Metadata for performance monitoring
    CollectionTimeMs int64
    Truncated       bool
    TotalResources  int
}

// PodSummary - minimal pod info for RBAC filtering
type PodSummary struct {
    Name      string
    Namespace string
    Status    string
    Node      string
    Labels    map[string]string `json:"labels,omitempty"` // Only if needed
}

// DeploymentSummary - minimal deployment info
type DeploymentSummary struct {
    Name      string
    Namespace string
    Replicas  int32
    Ready     int32
    Labels    map[string]string `json:"labels,omitempty"`
}

// CollectionConfig controls resource collection behavior
type CollectionConfig struct {
    Enabled          bool
    MaxPodsPerNS     int    // Limit pods per namespace
    MaxTotalPods     int    // Global pod limit
    MaxDeployments   int
    MaxServices      int
    IncludeLabels    bool   // Whether to collect labels
    NamespaceFilter  string // Regex to filter namespaces
}
```

**Why these types are separate:**
- Specifically designed for RBAC filtering use case
- Memory-optimized (minimal fields)
- Fast serialization for Redis storage
- Configurable collection limits

**When to add types here:**
- New resource summary types for RBAC
- Additional resource collection configs
- Metadata for collection performance

**Pattern for adding a new resource summary:**

```go
// ConfigMapSummary - minimal configmap info
type ConfigMapSummary struct {
    Name      string            `json:"name"`
    Namespace string            `json:"namespace"`
    DataCount int               `json:"data_count"`
    Labels    map[string]string `json:"labels,omitempty"`
}

// Then add to ResourceCollection:
type ResourceCollection struct {
    // ... existing fields
    ConfigMaps []ConfigMapSummary `json:"configmaps,omitempty"`
}

// And add to CollectionConfig:
type CollectionConfig struct {
    // ... existing fields
    MaxConfigMaps int `json:"max_configmaps"`
}
```

**metricsource.go - MetricSource Types:**

Types for the custom resource collection feature:

```go
// CompiledMetricSource is the internal representation optimized for collection
type CompiledMetricSource struct {
    Name      string
    Namespace string

    Source            CompiledSourceTarget
    Fields            []CompiledField
    Computed          []CompiledComputation
    Aggregations      []CompiledAggregation
    Collection        CompiledCollectionConf
    RBAC              CompiledRBAC
    CompiledAt        string
    Hash              string
    FieldNameToIndex  map[string]int       // Runtime index for fast lookup
    NamespacePatterns *CompiledPatterns    // Compiled regex patterns
}

// CompiledField represents a field extraction with parsed path
type CompiledField struct {
    Name         string
    Path         string
    PathSegments []string  // Pre-parsed for efficient extraction
    Type         string
    Default      *string
    Index        int
}

// CompiledComputation represents a computed field with parsed expression
type CompiledComputation struct {
    Name       string
    Expression string
    Type       string
    Compiled   interface{}  // *expression.CompiledExpression at runtime
}

// CompiledAggregation represents an aggregation with parsed filter
type CompiledAggregation struct {
    Name       string
    Field      string
    Function   string
    Filter     *CompiledAggFilter
    GroupBy    string
    Percentile int
}

// CustomCollectedResource represents a single resource instance with extracted values
type CustomCollectedResource struct {
    ID        string
    Namespace string
    Name      string
    Labels    map[string]string
    Values    map[string]interface{}
}

// CustomResourceCollection holds all collected resources for a cluster/source combination
type CustomResourceCollection struct {
    CollectedAt   time.Time
    SourceID      string
    ClusterName   string
    ResourceCount int
    Truncated     bool
    DurationMs    int64
    Resources     []CustomCollectedResource
}

// AggregationResults holds computed aggregation values for a cluster/source
type AggregationResults struct {
    ComputedAt time.Time
    SourceID   string
    DurationMs int64
    Values     map[string]interface{}
}
```

**Field type constants:**
```go
const (
    FieldTypeString      = "string"
    FieldTypeInteger     = "integer"
    FieldTypeFloat       = "float"
    FieldTypeBoolean     = "boolean"
    FieldTypeQuantity    = "quantity"
    FieldTypeTimestamp   = "timestamp"
    FieldTypeArrayLength = "arrayLength"
)
```

**Aggregation function constants:**
```go
const (
    AggFunctionCount      = "count"
    AggFunctionSum        = "sum"
    AggFunctionAvg        = "avg"
    AggFunctionMin        = "min"
    AggFunctionMax        = "max"
    AggFunctionPercentile = "percentile"
    AggFunctionDistinct   = "distinct"
)
```

**When to add types here:**
- New compiled structures for MetricSource features
- New collection result types
- New aggregation-related types

#### `pkg/utils/`
**Shared utility functions used throughout the project.** These are pure functions with no dependencies on internal implementation details.

**Files:**
- `parser.go` - CPU and memory parsing utilities
- `circuit_breaker.go` - Circuit breaker implementation

**When to use pkg/utils/ vs internal/:**
- Use `pkg/utils/` for pure utility functions that could be used by external tools
- Use utilities in `internal/` for implementation-specific helpers

**parser.go - Resource Parsing:**

Parses Kubernetes resource strings (CPU and memory) into usable numeric values:

```go
// ParseCPU converts various CPU formats to float64 cores
func ParseCPU(cpu string) float64

// ParseMemory converts various memory formats to int64 bytes  
func ParseMemory(mem string) int64
```

**CPU parsing examples:**
```go
ParseCPU("2")        // 2.0 cores
ParseCPU("500m")     // 0.5 cores (millicores)
ParseCPU("100m")     // 0.1 cores
ParseCPU("1000u")    // 0.001 cores (microcores)
ParseCPU("1000n")    // 0.000001 cores (nanocores)
ParseCPU("")         // 0.0 (empty/invalid)
```

**Memory parsing examples:**
```go
ParseMemory("1024")     // 1024 bytes
ParseMemory("1Ki")      // 1024 bytes (binary)
ParseMemory("1Mi")      // 1048576 bytes (1024*1024)
ParseMemory("1Gi")      // 1073741824 bytes
ParseMemory("1K")       // 1000 bytes (decimal)
ParseMemory("1M")       // 1000000 bytes
ParseMemory("1G")       // 1000000000 bytes
ParseMemory("500Mi")    // 524288000 bytes
ParseMemory("")         // 0 (empty/invalid)
```

**Usage in code:**
```go
import "github.com/clusterpulse/cluster-controller/pkg/utils"

// Parse container resource requests
cpuRequest := container.Resources.Requests.Cpu().String()
cpuCores := utils.ParseCPU(cpuRequest)

memRequest := container.Resources.Requests.Memory().String()
memBytes := utils.ParseMemory(memRequest)

// Calculate percentages
cpuPercent := (cpuCores / nodeCPUCapacity) * 100
memPercent := float64(memBytes) / float64(nodeMemCapacity) * 100
```

**When to use:**
- Converting Kubernetes resource quantities to numbers
- Calculating resource usage percentages
- Aggregating resource requests across pods
- Any time you need to work with CPU or memory values numerically

**circuit_breaker.go - Circuit Breaker Pattern:**

Implements the circuit breaker pattern to prevent cascading failures when calling unreliable services:

```go
type CircuitBreaker struct {
    failureThreshold int           // Number of failures before opening
    recoveryTimeout  time.Duration // How long to wait before trying again
    state            string         // "closed", "open", or "half-open"
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker

// Call executes a function with circuit breaker protection
func (cb *CircuitBreaker) Call(ctx context.Context, fn func(context.Context) error) error
```

**Circuit breaker states:**
- **Closed** - Normal operation, requests pass through
- **Open** - Too many failures, requests immediately fail
- **Half-open** - Testing if service recovered, single request allowed

**State transitions:**
```
Closed --> (failures >= threshold) --> Open
Open --> (after recovery timeout) --> Half-open
Half-open --> (success) --> Closed
Half-open --> (failure) --> Open
```

**Usage in cluster client:**
```go
import "github.com/clusterpulse/cluster-controller/pkg/utils"

type ClusterClient struct {
    circuitBreaker *utils.CircuitBreaker
    // ... other fields
}

func NewClusterClient(...) *ClusterClient {
    return &ClusterClient{
        circuitBreaker: utils.NewCircuitBreaker(
            5,              // Open after 5 failures
            60*time.Second, // Try again after 60 seconds
        ),
    }
}

// Wrap API calls with circuit breaker
func (c *ClusterClient) GetNodes(ctx context.Context) ([]corev1.Node, error) {
    var nodes []corev1.Node
    
    err := c.circuitBreaker.Call(ctx, func(ctx context.Context) error {
        nodeList, err := c.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
        if err != nil {
            return err
        }
        nodes = nodeList.Items
        return nil
    })
    
    return nodes, err
}
```

**Why use circuit breakers:**
- Prevent hanging on unhealthy clusters
- Fast-fail when cluster is known to be down
- Automatic recovery testing
- Protect controller from cascading failures

**When to use:**
- Wrapping all external cluster API calls
- Any operation that might hang or fail repeatedly
- Operations that should fail fast when service is down

**Pattern for adding new utilities:**

```go
// pkg/utils/validator.go

package utils

import "net/url"

// ValidateURL checks if a string is a valid URL
func ValidateURL(urlStr string) error {
    _, err := url.Parse(urlStr)
    return err
}

// ValidateNamespace checks if namespace name is valid
func ValidateNamespace(name string) bool {
    // Kubernetes namespace validation logic
    return len(name) <= 63 && len(name) > 0
}
```

**Key principles for pkg/utils:**
- Pure functions with no side effects
- No dependencies on internal packages
- Clear, focused purpose
- Good error handling
- Comprehensive documentation

## Understanding Reconciliation

Reconciliation is the core concept. The controller watches CRDs and reconciles them to desired state.

### The Reconciliation Loop

```
┌─────────────────────────────────────────────────────┐
│ 1. Watch for ClusterConnection changes              │
│    - Created, Updated, Deleted                      │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│ 2. Reconcile(ctx, request)                          │
│    - Fetch the ClusterConnection resource           │
│    - Handle if deleted                              │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│ 3. Get cluster client from pool                     │
│    - Retrieve credentials from Secret               │
│    - Create or reuse client                         │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│ 4. Test connection                                  │
│    - Try to list namespaces with timeout           │
│    - Fail if unreachable                           │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│ 5. Collect data (parallel via errgroup)             │
│    - Node metrics                                   │
│    - Cluster info                                   │
│    - Operators (OLM) + ClusterOperators (OpenShift) │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│ 6. Store in Redis                                   │
│    - Node metrics, cluster info, operators, labels  │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│ 7. Update status (healthy if reachable)             │
│    - Patch ClusterConnection.Status                 │
│    - Update Redis status                            │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│ 8. Return with RequeueAfter                         │
│    - Schedule next reconciliation                   │
│    - Use configured interval (default 30s)          │
└─────────────────────────────────────────────────────┘
                  │
                  └──────────────> Loop continues
```

### MetricSource Reconciliation Flow

```
┌─────────────────────────────────────────────────────┐
│ 1. Watch for MetricSource changes                   │
│    - Created, Updated, Deleted                      │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│ 2. Compile MetricSource spec                        │
│    - Validate spec                                  │
│    - Parse API version, derive resource name        │
│    - Compile field paths, expressions, aggregations │
│    - Compile namespace patterns                     │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│ 3. Store compiled definition in Redis               │
│    - Update indexes (all, enabled, by-type)         │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│ 4. Collect from all connected clusters (parallel)   │
│    For each cluster:                                │
│    - Get/create dynamic client                      │
│    - Resolve namespaces                             │
│    - List resources with pagination                 │
│    - Extract fields, compute expressions            │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│ 5. Compute aggregations                             │
│    - Apply filters                                  │
│    - Run aggregation functions                      │
│    - Handle groupBy                                 │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│ 6. Store results in Redis                           │
│    - Resource collection per cluster                │
│    - Aggregation results per cluster                │
│    - Collection metadata                            │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│ 7. Update CRD status                                │
│    - Resources collected, clusters collected        │
│    - Duration, errors                               │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│ 8. Return with RequeueAfter                         │
│    - Use collection interval from spec              │
│    - Shorter interval if errors occurred            │
└─────────────────────────────────────────────────────┘
```

### Key Principles

**Always requeue:** Every reconciliation must return `RequeueAfter` to ensure periodic monitoring:

```go
return reconcile.Result{RequeueAfter: time.Duration(interval) * time.Second}, nil
```

**Parallel collection:** Use `errgroup` for collecting multiple metrics:

```go
g, gctx := errgroup.WithContext(ctx)

g.Go(func() error {
    nodeMetrics, err = clusterClient.GetNodeMetrics(gctx)
    return err
})

g.Go(func() error {
    clusterMetrics, err = clusterClient.GetClusterMetrics(gctx)
    return err
})

if err := g.Wait(); err != nil {
    return err
}
```

**Non-critical failures:** Some operations can fail without failing reconciliation:

```go
// Operators are optional - don't fail if not present
operators, err := clusterClient.GetOperators(gctx)
if err != nil {
    log.Debug("Failed to get operators (may not be installed)")
    operators = []types.OperatorInfo{}
}
```

**Status updates:** Use `Patch` instead of `Update` to avoid triggering reconciliation:

```go
// Patch only the status subresource
if err := r.Status().Patch(ctx, clusterConn, k8sclient.MergeFrom(originalClusterConn)); err != nil {
    log.WithError(err).Debug("Failed to patch status")
}
```

## Common Tasks

### Adding a New Field to a CRD

1. **Edit the type definition:**

```go
// api/v1alpha1/clusterconnection_types.go

type ClusterConnectionSpec struct {
    // Existing fields...
    
    // NewFeature enables a cool new thing
    // +optional
    NewFeature bool `json:"newFeature,omitempty"`
    
    // NewSetting configures the feature
    // +kubebuilder:validation:Minimum=10
    // +optional
    NewSetting int32 `json:"newSetting,omitempty"`
}
```

2. **Regenerate code:**

```bash
controller-gen object paths="./..."
controller-gen crd paths="./..." output:crd:artifacts:config=config/crd/bases
```

3. **Update the controller to use it:**

```go
// internal/controller/cluster/cluster_controller.go

func (r *ClusterReconciler) reconcileCluster(ctx context.Context, clusterConn *v1alpha1.ClusterConnection) error {
    // Use the new field
    if clusterConn.Spec.NewFeature {
        setting := clusterConn.Spec.NewSetting
        if setting == 0 {
            setting = 30 // default
        }
        // Do something with it
    }
}
```

4. **Test it:**

```bash
# Apply updated CRD
oc apply -f config/crd/bases/clusterpulse.io_clusterconnections.yaml

# Create a test resource
oc apply -f - <<EOF
apiVersion: clusterpulse.io/v1alpha1
kind: ClusterConnection
metadata:
  name: test-cluster
  namespace: clusterpulse
spec:
  endpoint: https://api.test.example.com:6443
  credentialsRef:
    name: test-cluster-creds
  newFeature: true
  newSetting: 60
EOF
```

### Adding New Metrics Collection

New metrics collection should be implemented as MetricSource CRDs rather than hard-coded in the cluster controller. See the MetricSource documentation for details on creating custom metric collectors.

The cluster controller only collects foundational connection-level data: node metrics, cluster info, operators, and labels.

### Adding a New MetricSource Field Type

1. **Add the type constant:**

```go
// pkg/types/metricsource.go

const (
    // ... existing types
    FieldTypeDuration = "duration"  // New type for parsing duration strings
)
```

2. **Update the CRD validation:**

```go
// api/v1alpha1/metricsource_types.go

type FieldExtraction struct {
    // ...
    // +kubebuilder:validation:Enum=string;integer;float;boolean;quantity;timestamp;arrayLength;duration
    Type string `json:"type,omitempty"`
}
```

3. **Implement extraction in extractor:**

```go
// internal/metricsource/extractor/extractor.go

func (e *Extractor) convertValue(value interface{}, fieldType string) (interface{}, error) {
    // ... existing cases
    
    case types.FieldTypeDuration:
        return e.toDuration(value)
    
    // ...
}

func (e *Extractor) toDuration(value interface{}) (int64, error) {
    str := e.toString(value)
    if str == "" {
        return 0, nil
    }
    
    d, err := time.ParseDuration(str)
    if err != nil {
        return 0, err
    }
    
    return int64(d.Seconds()), nil
}
```

4. **Regenerate CRDs:**

```bash
controller-gen object paths="./..."
controller-gen crd paths="./..." output:crd:artifacts:config=config/crd/bases
```

### Adding a New Expression Function

1. **Add the function definition:**

```go
// internal/metricsource/expression/functions.go

var BuiltinFunctions = map[string]FunctionDef{
    // ... existing functions
    
    "percentage": {MinArgs: 2, MaxArgs: 2, Fn: fnPercentage},
}

func fnPercentage(args []interface{}) (interface{}, error) {
    part := toFloat(args[0])
    total := toFloat(args[1])
    
    if total == 0 {
        return float64(0), nil
    }
    
    return (part / total) * 100, nil
}
```

2. **Use in MetricSource:**

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: MetricSource
metadata:
  name: pvc-usage
spec:
  source:
    apiVersion: v1
    kind: PersistentVolumeClaim
  fields:
    - name: used
      path: .status.capacity.storage
      type: quantity
    - name: capacity
      path: .spec.resources.requests.storage
      type: quantity
  computed:
    - name: usage_percent
      expression: "percentage(used, capacity)"
      type: float
```

### Adding a New Aggregation Function

1. **Add the constant:**

```go
// pkg/types/metricsource.go

const (
    // ... existing functions
    AggFunctionMedian = "median"
)
```

2. **Update CRD validation:**

```go
// api/v1alpha1/metricsource_types.go

type Aggregation struct {
    // +kubebuilder:validation:Enum=count;sum;avg;min;max;percentile;distinct;median
    Function string `json:"function"`
}
```

3. **Implement in aggregator:**

```go
// internal/metricsource/aggregator/aggregator.go

func (a *Aggregator) computeSingle(agg *types.CompiledAggregation, resources []types.CustomCollectedResource) interface{} {
    switch agg.Function {
    // ... existing cases
    
    case types.AggFunctionMedian:
        return a.computeMedian(resources, agg.Field)
    }
}

func (a *Aggregator) computeMedian(resources []types.CustomCollectedResource, field string) interface{} {
    var values []float64
    for i := range resources {
        val := a.getNumericValue(&resources[i], field)
        if val != nil {
            values = append(values, *val)
        }
    }
    
    if len(values) == 0 {
        return nil
    }
    
    sort.Float64s(values)
    mid := len(values) / 2
    
    if len(values)%2 == 0 {
        return (values[mid-1] + values[mid]) / 2
    }
    return values[mid]
}
```

4. **Regenerate CRDs:**

```bash
controller-gen object paths="./..."
controller-gen crd paths="./..." output:crd:artifacts:config=config/crd/bases
```

### Adding a New Utility Function

When you find yourself repeating logic, consider adding it to `pkg/utils/`:

1. **Create the utility file (if needed):**

```go
// pkg/utils/time.go

package utils

import "time"

// ParseDuration parses a duration string with fallback to default
func ParseDuration(s string, defaultDuration time.Duration) time.Duration {
    if s == "" {
        return defaultDuration
    }
    
    d, err := time.ParseDuration(s)
    if err != nil {
        return defaultDuration
    }
    
    return d
}

// DurationToSeconds converts duration to seconds as int
func DurationToSeconds(d time.Duration) int {
    return int(d.Seconds())
}
```

2. **Add tests:** - TODO

3. **Use it in your code:**

```go
import "github.com/clusterpulse/cluster-controller/pkg/utils"

timeout := utils.ParseDuration(config.Timeout, 30*time.Second)
```

### Adding a New Type to pkg/types/

When you need a new domain model type:

1. **Add to appropriate file:**

```go
// pkg/types/types.go (for core types)
// OR
// pkg/types/resources.go (for resource collection types)
// OR
// pkg/types/metricsource.go (for MetricSource types)

// IngressInfo represents an ingress resource
type IngressInfo struct {
    Name      string    `json:"name"`
    Namespace string    `json:"namespace"`
    Hosts     []string  `json:"hosts"`
    TLSHosts  []string  `json:"tls_hosts,omitempty"`
    CreatedAt time.Time `json:"created_at"`
}
```

2. **Use it in clients:**

```go
// internal/client/cluster/client.go

func (c *ClusterClient) GetIngresses(ctx context.Context) ([]types.IngressInfo, error) {
    // Implementation uses types.IngressInfo
}
```

3. **Store in Redis:**

```go
// internal/store/client.go

func (c *Client) StoreIngresses(ctx context.Context, clusterName string, ingresses []types.IngressInfo) error {
    // Convert to Python-compatible format and store
}
```

### Adding a New Controller

If you need to watch a new CRD type:

1. **Define the CRD** in `api/v1alpha1/`:

```go
// api/v1alpha1/newresource_types.go
type NewResourceSpec struct {
    // Fields
}

type NewResourceStatus struct {
    // Status fields
}

type NewResource struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`
    
    Spec   NewResourceSpec   `json:"spec,omitempty"`
    Status NewResourceStatus `json:"status,omitempty"`
}
```

2. **Create the controller** in `internal/controller/newresource/`:

```go
type NewResourceReconciler struct {
    client.Client
    Scheme      *runtime.Scheme
    RedisClient *redis.Client
    Config      *config.Config
}

func (r *NewResourceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
    // Reconciliation logic
    return reconcile.Result{RequeueAfter: 60 * time.Second}, nil
}

func (r *NewResourceReconciler) SetupWithManager(mgr ctrl.Manager) error {
    return ctrl.NewControllerManagedBy(mgr).
        For(&v1alpha1.NewResource{}).
        Complete(r)
}
```

3. **Register in main.go:**

```go
// cmd/manager/main.go

if err = (&newresourcecontroller.NewResourceReconciler{
    Client:      mgr.GetClient(),
    Scheme:      mgr.GetScheme(),
    RedisClient: redisClient,
    Config:      cfg,
}).SetupWithManager(mgr); err != nil {
    setupLog.Error(err, "unable to create controller", "controller", "NewResource")
    os.Exit(1)
}
```

### Changing Reconciliation Interval Logic

The interval can be set per-cluster via the CRD spec:

```go
func (r *ClusterReconciler) getReconcileInterval(clusterConn *v1alpha1.ClusterConnection) int {
    interval := r.Config.ReconciliationInterval // Default from config
    
    if clusterConn.Spec.Monitoring.Interval > 0 {
        specInterval := int(clusterConn.Spec.Monitoring.Interval)
        if specInterval >= 30 {
            interval = specInterval
        } else {
            // Enforce minimum
            interval = 30
        }
    }
    
    return interval
}
```

To add adaptive intervals based on health:

```go
func (r *ClusterReconciler) getReconcileInterval(clusterConn *v1alpha1.ClusterConnection) int {
    interval := r.Config.ReconciliationInterval
    
    // Override from spec if set
    if clusterConn.Spec.Monitoring.Interval > 0 {
        interval = int(clusterConn.Spec.Monitoring.Interval)
    }
    
    // Reduce interval for unhealthy clusters
    if clusterConn.Status.Health == string(types.HealthUnhealthy) {
        interval = interval / 2
        if interval < 30 {
            interval = 30
        }
    }
    
    return interval
}
```

### Adding Resource Collection Limits

Resource collection uses configured limits to prevent memory issues on large clusters:

```go
// internal/config/config.go

ResourceCollection: types.CollectionConfig{
    Enabled:        getEnvBool("RESOURCE_COLLECTION_ENABLED", true),
    MaxPodsPerNS:   getEnvIntWithMin("MAX_PODS_PER_NAMESPACE", 100, 10),
    MaxTotalPods:   getEnvIntWithMin("MAX_TOTAL_PODS", 1000, 50),
    MaxDeployments: getEnvIntWithMin("MAX_DEPLOYMENTS", 500, 10),
    MaxServices:    getEnvIntWithMin("MAX_SERVICES", 500, 10),
    IncludeLabels:  getEnvBool("COLLECT_RESOURCE_LABELS", false),
}
```

To add a new resource type to collection:

```go
// internal/client/cluster/resources.go

func (c *ClusterClient) GetResourceCollection(ctx context.Context, config types.CollectionConfig) (*types.ResourceCollection, error) {
    // ... existing code
    
    // Add new resource collection
    if config.MaxConfigMaps > 0 {
        g.Go(func() error {
            cms, _ := c.collectConfigMaps(gctx, config)
            mu.Lock()
            collection.ConfigMaps = cms
            mu.Unlock()
            return nil
        })
    }
    
    return collection, nil
}

func (c *ClusterClient) collectConfigMaps(ctx context.Context, config types.CollectionConfig) ([]types.ConfigMapSummary, bool) {
    opts := metav1.ListOptions{
        Limit: int64(config.MaxConfigMaps),
    }
    
    cmList, err := c.clientset.CoreV1().ConfigMaps("").List(ctx, opts)
    if err != nil {
        logrus.WithError(err).Warn("Failed to list configmaps")
        return nil, false
    }
    
    var configMaps []types.ConfigMapSummary
    for _, cm := range cmList.Items {
        configMaps = append(configMaps, types.ConfigMapSummary{
            Name:      cm.Name,
            Namespace: cm.Namespace,
            DataCount: len(cm.Data),
        })
    }
    
    return configMaps, len(cmList.Items) > config.MaxConfigMaps
}
```

## Testing

### Unit Tests - TODO

Test individual functions with fake clients:

### Testing Utilities - TODO

Test utility functions in `pkg/utils/`:

### Integration Tests - TODO

Test controllers with envtest (real Kubernetes API):

### Running Tests - TODO

```bash
# All tests
go test ./...
```

## Code Patterns

### Error Handling

Always wrap errors with context:

```go
// Good
if err != nil {
    return fmt.Errorf("failed to list nodes: %w", err)
}

// Also good
nodes, err := clientset.CoreV1().Nodes().List(ctx, opts)
if err != nil {
    return nil, fmt.Errorf("failed to list nodes for cluster %s: %w", c.Name, err)
}
```

Don't fail reconciliation for non-critical operations:

```go
// Optional operation - log but don't fail
operators, err := client.GetOperators(ctx)
if err != nil {
    log.WithError(err).Debug("Failed to get operators (may not be installed)")
    operators = []types.OperatorInfo{}
}
```

### Logging

Use structured logging with logrus:

```go
log := logrus.WithFields(logrus.Fields{
    "cluster":   clusterConn.Name,
    "namespace": clusterConn.Namespace,
})

log.Debug("Starting reconciliation")
log.Info("Cluster is healthy")
log.Warn("Some nodes not ready")
log.Error("Failed to connect to cluster")
```

**Log levels:**
- `Debug` - Detailed info for debugging (disabled by default)
- `Info` - Important state changes (cluster became healthy, operator issues)
- `Warn` - Degraded state or recoverable errors
- `Error` - Failed operations that need attention

**Only log at Info for significant events:**
```go
// Good - state change
if originalHealth != newHealth {
    log.Info("Cluster health changed")
}

// Bad - every reconciliation
log.Info("Reconciliation completed")

// Good - slow operation
if duration > 5*time.Second {
    log.Infof("Reconciliation took %v", duration)
}
```

### Context and Timeouts

Always use contexts with timeouts:

```go
// Connection test
connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
defer cancel()

if err := clusterClient.TestConnection(connCtx); err != nil {
    return fmt.Errorf("connection test failed: %w", err)
}
```

Use errgroup for parallel operations:

```go
g, gctx := errgroup.WithContext(ctx)

g.Go(func() error {
    nodeMetrics, err = client.GetNodeMetrics(gctx)
    return err
})

g.Go(func() error {
    clusterMetrics, err = client.GetClusterMetrics(gctx)
    return err
})

if err := g.Wait(); err != nil {
    return err
}
```

### Redis Storage Patterns

Always store Python-compatible data:

```go
// DON'T - Go conventions
data := map[string]interface{}{
    "cpuCapacity": metrics.CPUCapacity,  // ❌ camelCase
    "nodes": nil,                         // ❌ nil array
}

// DO - Python conventions
data := map[string]interface{}{
    "cpu_capacity": metrics.CPUCapacity,  // ✅ snake_case
    "nodes": []string{},                  // ✅ empty array
    "timestamp": time.Now().Format(time.RFC3339),  // ✅ ISO format
}
```

Use pipelines for batch operations:

```go
pipe := r.RedisClient.client.Pipeline()

// Add multiple operations
pipe.Set(ctx, key1, val1, ttl)
pipe.Set(ctx, key2, val2, ttl)
pipe.HSet(ctx, key3, field, value)

// Execute all at once
_, err := pipe.Exec(ctx)
```

### Client Pool Usage

Always use the pool for cluster clients:

```go
// DON'T create clients directly in reconciler
client, err := cluster.NewClusterClient(name, endpoint, token, caCert)

// DO use the pool
client, err := r.clientPool.Get(name, endpoint, token, caCert)
```

The pool handles:
- Connection reuse
- Connection testing before return
- Automatic cleanup of idle clients
- Thread safety

### Status Updates

Use `Patch` to avoid triggering reconciliation:

```go
// Save original for comparison
originalClusterConn := clusterConn.DeepCopy()

// Modify status
clusterConn.Status.Phase = "Connected"
clusterConn.Status.Health = string(health)
now := metav1.Now()
clusterConn.Status.LastSyncTime = &now

// Only patch if changed
if !r.statusEqual(originalClusterConn.Status, clusterConn.Status) {
    if err := r.Status().Patch(ctx, clusterConn, k8sclient.MergeFrom(originalClusterConn)); err != nil {
        log.WithError(err).Debug("Failed to patch status")
    }
}
```

Use `Update` only when you want to trigger reconciliation:

```go
// This will trigger a new reconciliation
if err := r.Status().Update(ctx, clusterConn); err != nil {
    return err
}
```

### Using pkg/utils in Your Code

Always use utilities when appropriate:

```go
import "github.com/clusterpulse/cluster-controller/pkg/utils"

// Parse CPU resources
cpuStr := container.Resources.Requests.Cpu().String()
cpuCores := utils.ParseCPU(cpuStr)

// Parse memory resources
memStr := container.Resources.Requests.Memory().String()
memBytes := utils.ParseMemory(memStr)

// Calculate percentages
cpuPercent := (cpuCores / totalCPU) * 100
memPercent := float64(memBytes) / float64(totalMemory) * 100

// Wrap API calls with circuit breaker
var nodes []corev1.Node
err := circuitBreaker.Call(ctx, func(ctx context.Context) error {
    nodeList, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
    if err != nil {
        return err
    }
    nodes = nodeList.Items
    return nil
})
```

### MetricSource Expression Patterns

When working with computed fields:

```go
// Simple arithmetic
expression: "capacity - used"

// Percentage calculation
expression: "round((used / capacity) * 100, 2)"

// Null handling
expression: "used ?? 0"

// String concatenation
expression: "concat(namespace, '/', name)"

// Conditional via coalesce
expression: "coalesce(requestedCPU, 0) + coalesce(limitCPU, 0)"
```

### MetricSource Aggregation Patterns

```yaml
# Count all resources
- name: total_count
  function: count

# Count with filter
- name: running_count
  function: count
  filter:
    field: status
    operator: equals
    value: "Running"

# Sum with filter
- name: total_storage_bound
  field: capacity
  function: sum
  filter:
    field: phase
    operator: equals
    value: "Bound"

# Group by field
- name: count_by_namespace
  function: count
  groupBy: namespace

# Percentile
- name: p95_cpu
  field: cpu_usage
  function: percentile
  percentile: 95
```

## Performance Considerations

### Rate Limiting

The controller uses rate limiting to prevent API server overload:

```go
// client.go
config := &rest.Config{
    QPS:   100,  // Queries per second
    Burst: 200,  // Burst capacity
}
```

For high-volume clusters, increase these values:

```go
config.QPS = 200
config.Burst = 400
```

### Resource Collection Optimization

Resource collection uses several optimizations:

1. **Limits** - Configure max items to collect
2. **Field selectors** - Filter at API level
3. **Parallel collection** - Use errgroup
4. **Truncation tracking** - Mark when limits reached

```go
// Only get running/pending pods
opts := metav1.ListOptions{
    FieldSelector: "status.phase!=Succeeded,status.phase!=Failed",
    Limit: int64(config.MaxTotalPods),
}

podList, err := c.clientset.CoreV1().Pods("").List(ctx, opts)
```

### MetricSource Collection Optimization

MetricSource collection is optimized for performance:

1. **Pre-compiled paths** - JSONPath segments parsed once at compile time
2. **Pre-compiled expressions** - AST built once, evaluated many times
3. **Pre-compiled regex** - Namespace patterns compiled once
4. **Parallel namespace collection** - Configurable parallelism
5. **Pagination** - Uses API pagination for large resource sets
6. **Limits** - Configurable max resources per cluster

```go
// Collection config with limits
Collection: types.CompiledCollectionConf{
    IntervalSeconds: 60,
    TimeoutSeconds:  30,
    MaxResources:    5000,  // Limit total resources
    BatchSize:       500,   // API pagination size
    Parallelism:     3,     // Concurrent namespace collection
}
```

### Redis Batching

Use pipelines for multiple Redis operations:

```go
pipe := c.client.Pipeline()

// Batch multiple operations
for _, node := range nodes {
    nodeData := nodeToDict(node)
    dataJSON, _ := json.Marshal(nodeData)
    pipe.HSet(ctx, nodeKey, "current", dataJSON)
}

// Execute once
_, err := pipe.Exec(ctx)
```

### Circuit Breakers

The cluster client uses circuit breakers to prevent hanging on unhealthy clusters:

```go
type CircuitBreaker struct {
    failures  int
    threshold int
    timeout   time.Duration
    lastFail  time.Time
}

func (cb *CircuitBreaker) Call(ctx context.Context, fn func(context.Context) error) error {
    // Check if circuit is open
    if cb.isOpen() {
        return fmt.Errorf("circuit breaker is open")
    }
    
    err := fn(ctx)
    
    if err != nil {
        cb.recordFailure()
    } else {
        cb.reset()
    }
    
    return err
}
```

The circuit opens after 5 consecutive failures and stays open for 60 seconds.

## Code Style

Use `gofmt`

```bash
# Format code
gofmt -w .
```

**Comment style:**
```go
// GetNodeMetrics retrieves detailed metrics for all nodes in the cluster.
// It collects resource usage, conditions, and pod counts for each node.
func (c *ClusterClient) GetNodeMetrics(ctx context.Context) ([]types.NodeMetrics, error) {
    // Implementation
}
```

## Pull Request Process

1. **Branch naming:** `feature/add-ingress-collection` or `fix/registry-timeout`

2. **Commits:**
   - ✅ "Add ingress collection to cluster metrics"
   - ✅ "Fix registry health check timeout handling"
   - ❌ "WIP" or "Fixes"

3. **Before submitting:**
   ```bash
   # Format code
   gofmt -w .
   
   # Run tests - TODO
   go test ./...
   
   # Generate CRDs
   controller-gen object paths="./..."
   controller-gen crd paths="./..." output:crd:artifacts:config=config/crd/bases
   
   # Verify CRDs compile
   oc apply --dry-run=client -f config/crd/bases/
   ```

4. **PR description should include:**
   - What changed and why
   - How to test it
   - Impact on existing clusters
   - Redis schema changes (if any)

5. **Things reviewers look for:**
   - Data is stored in Python-compatible format
   - Reconciliation always returns `RequeueAfter`
   - Non-critical operations don't fail reconciliation
   - Proper error wrapping and logging
   - Status updates use `Patch` not `Update`
   - Tests cover new functionality
   - CRD changes are documented
   - Utilities used from `pkg/utils` where appropriate

## Common Pitfalls

1. **Not storing Python-compatible data:**
   ```go
   // ❌ Wrong
   data := map[string]interface{}{
       "nodes": nil,  // Python expects []
       "cpuCapacity": 100,  // Should be cpu_capacity
   }
   
   // ✅ Right
   data := map[string]interface{}{
       "nodes": []string{},
       "cpu_capacity": 100,
   }
   ```

2. **Forgetting to requeue:**
   ```go
   // ❌ Wrong - reconciliation stops
   return reconcile.Result{}, nil
   
   // ✅ Right - periodic reconciliation
   return reconcile.Result{RequeueAfter: time.Duration(interval) * time.Second}, nil
   ```

3. **Triggering reconciliation loops with status updates:**
   ```go
   // ❌ Wrong - triggers reconciliation
   r.Status().Update(ctx, resource)
   
   // ✅ Right - doesn't trigger reconciliation
   r.Status().Patch(ctx, resource, k8sclient.MergeFrom(original))
   ```

4. **Not using timeouts:**
   ```go
   // ❌ Wrong - can hang forever
   err := clusterClient.TestConnection(ctx)
   
   // ✅ Right - has timeout
   connCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
   defer cancel()
   err := clusterClient.TestConnection(connCtx)
   ```

5. **Creating clients directly instead of using pool:**
   ```go
   // ❌ Wrong - expensive, not reused
   client, err := cluster.NewClusterClient(...)
   
   // ✅ Right - reuses connections
   client, err := r.clientPool.Get(...)
   ```

6. **Failing reconciliation for non-critical operations:**
   The cluster controller collects operators, cluster info, and ClusterOperators as non-critical data. Only node metrics are critical. Non-critical failures should be logged and skipped:
   ```go
   // ❌ Wrong - operators are optional
   operators, err := client.GetOperators(ctx)
   if err != nil {
       return err  // Fails entire reconciliation
   }

   // ✅ Right - log and continue
   operators, err := client.GetOperators(ctx)
   if err != nil {
       log.Debug("Failed to get operators (may not be installed)")
       operators = []types.OperatorInfo{}
   }
   ```

7. **Not handling deletions:**
   ```go
   // ✅ Must handle deletion timestamp
   if !clusterConn.DeletionTimestamp.IsZero() {
       return r.handleDeletion(ctx, req.Name)
   }
   ```

8. **Forgetting to regenerate after CRD changes:**
   ```bash
   # After editing api/v1alpha1/*.go, always run:
   controller-gen object paths="./..."
   controller-gen crd paths="./..." output:crd:artifacts:config=config/crd/bases
   ```

9. **Not using utilities from pkg/utils:**
   ```go
   // ❌ Wrong - reinventing the wheel
   cpuStr := strings.TrimSuffix(cpu, "m")
   cpuVal, _ := strconv.ParseFloat(cpuStr, 64)
   cpuCores := cpuVal / 1000
   
   // ✅ Right - use existing utility
   cpuCores := utils.ParseCPU(cpu)
   ```

10. **Not wrapping API calls with circuit breaker:**
    ```go
    // ❌ Wrong - can hang on unhealthy cluster
    nodes, err := clientset.CoreV1().Nodes().List(ctx, opts)
    
    // ✅ Right - protected by circuit breaker
    err := c.circuitBreaker.Call(ctx, func(ctx context.Context) error {
        nodeList, err := c.clientset.CoreV1().Nodes().List(ctx, opts)
        if err != nil {
            return err
        }
        nodes = nodeList.Items
        return nil
    })
    ```

11. **Not validating MetricSource expressions at compile time:**
    ```go
    // ❌ Wrong - invalid expression fails at runtime
    // Just store the expression string
    
    // ✅ Right - validate during compilation
    compiled, err := expression.Compile(comp.Expression, fieldType)
    if err != nil {
        return nil, fmt.Errorf("invalid expression for field '%s': %w", comp.Name, err)
    }
    ```

12. **Circular dependencies in computed fields:**
    ```yaml
    # ❌ Wrong - circular dependency
    computed:
      - name: a
        expression: "b + 1"
      - name: b
        expression: "a + 1"
    
    # ✅ Right - compiler detects this
    # The compiler runs detectCircularDependencies() and returns an error
    ```

## Security Considerations

### Credential Handling

Cluster credentials are stored in Kubernetes Secrets:

```go
// Get credentials from secret
secret := &corev1.Secret{}
if err := r.Get(ctx, k8sclient.ObjectKey{Name: secretName, Namespace: secretNamespace}, secret); err != nil {
    return nil, fmt.Errorf("failed to get secret: %w", err)
}

token := string(secret.Data["token"])
caCert := secret.Data["ca.crt"]
```

**Never log credentials:**
```go
// ❌ Don't do this
log.Debugf("Token: %s", token)

// ✅ Do this
log.Debug("Retrieved credentials from secret")
```

### RBAC in Kubernetes

The controller needs proper RBAC permissions:

```yaml
# config/rbac/role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-controller-manager-role
rules:
- apiGroups:
  - clusterpulse.io
  resources:
  - clusterconnections
  - registryconnections
  - metricsources
  verbs:
  - get
  - list
  - watch
  - update
  - patch
- apiGroups:
  - clusterpulse.io
  resources:
  - clusterconnections/status
  - registryconnections/status
  - metricsources/status
  verbs:
  - get
  - update
  - patch
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
  - list
  - watch
```

## Quick Reference

### Typical Controller Pattern

```go
func (r *ClusterReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
    log := logrus.WithField("cluster", req.Name)
    
    // 1. Fetch resource
    resource := &v1alpha1.ClusterConnection{}
    if err := r.Get(ctx, req.NamespacedName, resource); err != nil {
        if errors.IsNotFound(err) {
            return r.handleDeletion(ctx, req.Name)
        }
        return reconcile.Result{}, err
    }
    
    // 2. Handle deletion
    if !resource.DeletionTimestamp.IsZero() {
        return r.handleDeletion(ctx, req.Name)
    }
    
    // 3. Get reconciliation interval
    interval := r.getReconcileInterval(resource)
    
    // 4. Do the work
    if err := r.reconcileResource(ctx, resource); err != nil {
        log.WithError(err).Error("Reconciliation failed")
        
        // Update status with error
        resource.Status.Phase = "Error"
        resource.Status.Message = err.Error()
        r.Status().Patch(ctx, resource, k8sclient.MergeFrom(resource))
        
        // Retry after 1 minute
        return reconcile.Result{RequeueAfter: time.Minute}, nil
    }
    
    log.Debug("Reconciliation completed")
    
    // 5. Always requeue for periodic reconciliation
    return reconcile.Result{RequeueAfter: time.Duration(interval) * time.Second}, nil
}
```

### Common Imports

```go
// Kubernetes
import (
    corev1 "k8s.io/api/core/v1"
    "k8s.io/apimachinery/pkg/api/errors"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/apimachinery/pkg/runtime"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/dynamic"
    ctrl "sigs.k8s.io/controller-runtime"
    "sigs.k8s.io/controller-runtime/pkg/client"
    "sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Local
import (
    "github.com/clusterpulse/cluster-controller/api/v1alpha1"
    "github.com/clusterpulse/cluster-controller/internal/config"
    "github.com/clusterpulse/cluster-controller/internal/store"
    "github.com/clusterpulse/cluster-controller/pkg/types"
    "github.com/clusterpulse/cluster-controller/pkg/utils"
)

// MetricSource-specific
import (
    "github.com/clusterpulse/cluster-controller/internal/metricsource/compiler"
    "github.com/clusterpulse/cluster-controller/internal/metricsource/collector"
    "github.com/clusterpulse/cluster-controller/internal/metricsource/expression"
)

// Third-party
import (
    "github.com/sirupsen/logrus"
    "golang.org/x/sync/errgroup"
)
```

### Useful Commands

```bash
# Development
controller-gen object paths="./..."
controller-gen crd paths="./..." output:crd:artifacts:config=config/crd/bases
go run cmd/manager/main.go --namespace=clusterpulse

# Proto generation (requires buf CLI)
buf generate proto

# Testing
go test ./...
go test -v ./internal/controller/cluster/
go test -v ./internal/metricsource/expression/
go test -v ./pkg/utils/
go test -cover ./...

# Linting
gofmt -w .
golangci-lint run

# Building
go build -o bin/manager cmd/manager/main.go
go build -o bin/collector cmd/collector/main.go

# Docker
docker build -f Dockerfile.cluster-controller -t cluster-controller:latest .
docker build -f Dockerfile.collector -t collector:latest .
docker build -f Dockerfile.api -t api:latest .

# Applying CRDs
oc apply -f config/crd/bases/
```

## Getting Help

- Check existing controllers in `internal/controller/` for patterns
- Look at client implementations in `internal/client/cluster/` for examples
- Review Redis storage in `internal/store/` for data format
- Check utilities in `pkg/utils/` for reusable functions
- Review types in `pkg/types/` for data models
- Study the MetricSource subsystem in `internal/metricsource/` for expression and collection patterns
- Read controller-runtime docs: https://book.kubebuilder.io
- Check kubebuilder markers: https://book.kubebuilder.io/reference/markers.html
- Review errgroup examples for parallel operations

## Project-Specific Notes

- **Three reconcilers:** ClusterConnection, RegistryConnection, and MetricSource controllers
- **Redis is the bridge:** Controller writes, API reads
- **Python compatibility:** All Redis data must work with Python (snake_case, no nil arrays)
- **Periodic reconciliation:** Always return `RequeueAfter` to ensure monitoring continues
- **Status updates:** Use `Patch` to avoid reconciliation loops
- **Client pooling:** Reuse cluster connections via the pool
- **Parallel collection:** Use errgroup for collecting multiple metrics simultaneously
- **Circuit breakers:** Prevent hanging on unhealthy clusters (use from `pkg/utils`)
- **Resource limits:** Configure collection limits for large clusters
- **OpenShift support:** Special handling for ClusterVersion, ClusterOperators, and Routes
- **Shared utilities:** Use `pkg/utils` for parsing and circuit breakers
- **Domain types:** Define core types in `pkg/types` for reusability
- **MetricSource subsystem:** Modular design with compiler, collector, expression engine, and aggregator
- **Expression language:** Supports arithmetic, comparison, logical operators, and built-in functions
- **Aggregations:** Supports count, sum, avg, min, max, percentile, distinct with filters and grouping
- **Push mode:** Collector agents on managed clusters push metrics via gRPC to the hub ingester
- **Pull/push coexistence:** Both modes coexist per-cluster via `collectionMode` field on ClusterConnection
- **Ingester:** Embedded gRPC server in manager, dual-writes to Redis + VictoriaMetrics
- **Collector deployment:** Hub auto-deploys collector Deployment + RBAC on managed clusters
- **VictoriaMetrics:** Optional time-series storage for historical metrics (PromQL API)
- **History API:** `/metrics/history` endpoints query VictoriaMetrics with RBAC scoping
