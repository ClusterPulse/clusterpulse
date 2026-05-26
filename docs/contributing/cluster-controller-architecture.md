# Cluster Controller — Architecture

What's in the manager binary, what each package does, and how to extend it.

## Directory layout

```
api/v1alpha1/                # CRD type definitions (kubebuilder markers)
cmd/
  manager/                   # Controller manager entry point
  api/                       # REST API server entry point
  collector/                 # Push-mode collector agent entry point
proto/
  clusterpulse/collector/v1/ # gRPC service definition + generated code
internal/
  client/
    cluster/                 # Kubernetes client (per-target-cluster)
    registry/                # Docker Registry V2 client
    pool/                    # Cluster client connection pool
  collector/                 # Push-mode collector agent implementation
  controller/
    cluster/                 # ClusterConnection reconciler + collector deploy
    registry/                # RegistryConnection reconciler
    metricsource/            # MetricSource reconciler
    policy/                  # MonitorAccessPolicy reconciler + validator
  ingester/                  # gRPC ingester server (embedded in manager)
  metricsource/
    aggregator/              # Aggregation computation engine
    collector/               # Resource collection from clusters
    compiler/                # CRD spec → runtime compilation
    expression/              # Expression language (tokenizer, parser, evaluator)
    extractor/               # Field extraction from unstructured resources
  store/                     # Redis client + per-domain storage methods
  config/                    # Env-var configuration loader
  rbac/                      # RBAC authorization engine (consumed by API)
  version/                   # Build-time version constants
pkg/
  types/                     # Shared domain types (cluster, node, MetricSource, policy)
  utils/                     # Pure utilities (CPU/memory parsing, circuit breaker)
config/                      # Manifests + generated CRD YAML
```

## `api/v1alpha1/`

CRD type definitions. Edits here drive code generation; never edit `zz_generated.deepcopy.go` by hand.

| File | CRD |
|---|---|
| `clusterconnection_types.go` | `ClusterConnection` |
| `registryconnection_types.go` | `RegistryConnection` |
| `metricsource_types.go` | `MetricSource` |
| `monitoraccesspolicy_types.go` | `MonitorAccessPolicy` |
| `groupversion_info.go` | Scheme registration (`clusterpulse.io/v1alpha1`). |

Edit when:

- Adding a field to a CRD.
- Changing validation rules.
- Adding a status field.
- Adding/changing kubebuilder `printcolumn` markers.

```go
type ClusterConnectionSpec struct {
    // Existing fields...

    // NewField does something useful.
    // +optional
    NewField string `json:"newField,omitempty"`
}
```

After editing, regenerate:

```bash
controller-gen object paths="./api/v1alpha1/..."
controller-gen crd paths="./api/v1alpha1/..." output:crd:dir=config/crd/bases
```

Common markers:

```go
// +kubebuilder:validation:Required
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:Minimum=30
// +kubebuilder:default=30
// +optional
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.phase"
```

## `cmd/manager/`

Wires up the manager (`controller-runtime`), registers the four reconcilers, and conditionally starts the embedded ingester. The ingester reference is passed into `ClusterReconciler` so the cluster controller can check collector connection status for push-mode `ClusterConnection`s.

Edit when:

- Adding a new controller (register it here).
- Changing manager-level setup (leader election, health probes, metrics port).
- Changing ingester startup behaviour.

## `cmd/collector/`

The collector agent that runs on each managed cluster in push mode. Reads in-cluster kubeconfig, connects to the hub ingester (via `INGESTER_ADDRESS`), and reuses `internal/metricsource/collector` for actual collection — the same package the hub uses for pull mode. The hub-side reconciler in `internal/controller/cluster` deploys this binary on the managed cluster; see [Enable push-mode collection](../how-to/clusters/enable-push-mode.md) for the deployment side.

Env vars on the collector pod (set by the hub):

```
CLUSTER_NAME              # Identifies the cluster to the ingester
INGESTER_ADDRESS          # host:port of the hub ingester
COLLECTOR_TOKEN           # Bearer token for ingester auth
COLLECT_INTERVAL          # Collection cycle interval (default 60s)
BUFFER_SIZE               # Local buffer cycles during outages (default 10)
INGESTER_TLS_ENABLED      # TLS on/off for the ingester connection
INGESTER_TLS_CA           # CA cert path (when TLS enabled and not using system CA)
INGESTER_TLS_SERVER_NAME  # Override for cert verification (derived by hub)
OPERATOR_SCAN_INTERVAL    # Operator scan interval (default 300s)
```

## `internal/client/cluster/`

Kubernetes client used by both the pull-mode reconciler and the MetricSource collector. Wraps `clientset` + `dynamic.Interface`, adds circuit-breaker protection around remote calls, and exposes domain methods like `GetNodeMetrics`, `GetClusterMetrics`, `GetOperators`, `GetResourceCollection`, and `TestConnection`.

Edit when:

- Collecting a new built-in resource (most additions should go through a `MetricSource` instead, not here).
- Modifying how node metrics or operator info are extracted.
- Adding a new health-check codepath.

Every method that talks to the API server runs inside the circuit breaker. Don't add direct calls outside the breaker — see [Patterns → Circuit breakers](cluster-controller-patterns.md#circuit-breakers).

## `internal/client/registry/`

Docker Registry V2 API client. Used by `RegistryConnection` reconciler. Differentiates between connection refused, 401 (auth required), 404 (not a v2 registry), and 5xx in the health-check result so the reconciler can surface accurate status. Has an optional catalog scan capped by `maxCatalogEntries`.

## `internal/client/pool/`

Connection pool keyed by `ClusterConnection` name. Kubernetes clients are expensive to construct (TLS handshake, discovery cache warm-up). The pool keeps them around, tests them before returning, and reaps idle entries on a timer.

```go
// Get a pooled client. Creates one on miss, returns an existing one on hit.
client, err := pool.Get(name, endpoint, token, caCert)

// Drop on cluster deletion.
pool.Remove(name)
```

Edit when:

- Changing idle-timeout or pool-size policy.
- Adding pool-level metrics.

## `internal/ingester/`

The gRPC ingester server that accepts pushes from collector agents.

| File | What's there |
|---|---|
| `server.go` | gRPC server lifecycle, connection tracking, keepalives, TLS setup. |
| `handler.go` | Per-stream message handling: proto → internal type conversion, fan-out to Redis + (optionally) VictoriaMetrics. |
| `vmwriter.go` | VictoriaMetrics remote-write client (Prometheus text format). |

Connection tracking lets the cluster controller answer "is the collector connected right now?" without round-tripping anything — that's how a push-mode `ClusterConnection` decides whether to skip the pull-mode collection step on a given reconcile.

The VictoriaMetrics pipeline is gated on `VM_ENABLED` and writes `clusterpulse_cluster_*`, `clusterpulse_node_*`, `clusterpulse_operator_installed`, `clusterpulse_cluster_operator_*`, and `clusterpulse_custom_resource_*` series. The full label set per metric is in `internal/ingester/vmwriter.go`.

Edit when:

- Adding fields to the proto.
- Changing auth (currently bearer token in stream metadata).
- Changing the dual-write pipeline.
- Adding new connection-level health/metrics surfaces.

## `internal/collector/`

The hub side has the agent's source code here so the same binary can be built either way.

| File | What's there |
|---|---|
| `agent.go` | Connect → register → collect → push loop. Receives ConfigUpdate messages on the same stream. |
| `config.go` | Env-var config + exponential reconnect backoff. |
| `buffer.go` | Bounded FIFO buffer used during ingester outages. |

Buffers up to 10 collection cycles by default. Reconnect backoff starts at 1 s and caps at 5 min, reset on a successful register.

## `proto/`

Protocol Buffer definitions for collector ↔ ingester. The generated Go code under `proto/clusterpulse/collector/v1/` is committed but generated; don't edit it by hand.

Service: `CollectorService` with one bidirectional RPC `Connect`. Request stream carries `RegisterRequest`, `MetricsBatch`, `HealthReport`. Response stream carries `ConfigUpdate` and `Ack`.

After editing the proto:

```bash
buf generate proto
```

`buf lint && buf breaking --against '.git#branch=main'` runs in CI ([Workflow](workflow.md#ci-checks)).

## `internal/controller/cluster/`

The `ClusterConnection` reconciler.

| File | What's there |
|---|---|
| `cluster_controller.go` | Reconcile loop, status patching, helper methods. |
| `collector_deploy.go` | Provisions namespace/SA/role/binding/secret/deployment/CA-ConfigMap on managed clusters for push mode. |

On a push-mode `ClusterConnection`, the reconciler first asks the ingester whether the collector is connected; if it is, the reconciler updates `status.collectorStatus` and skips the pull-mode collection step. If it isn't, the reconciler falls through to pull mode and (re-)deploys the collector via `collector_deploy.go`.

Edit when:

- Changing reconcile-interval logic.
- Changing what's collected at the cluster level.
- Modifying the collector Deployment manifest or its RBAC.

## `internal/controller/registry/`

The `RegistryConnection` reconciler. Simpler than the cluster controller: create client → health check → store in Redis → patch status → requeue. Uses a `predicate.Funcs` filter on `UpdateFunc` to skip status-only updates (a pattern that's reused everywhere status-update loops would otherwise be a problem).

## `internal/controller/metricsource/`

The `MetricSource` reconciler.

```
Watch MetricSource → Compile → Store compiled definition in Redis
  → Collect from all Connected ClusterConnections (parallel)
  → Compute aggregations → Store results in Redis
  → Patch status → Requeue at collection interval
```

Owns two caches: `compiledCache` (compiled MetricSource definitions, keyed by namespace/name) and `clusterClients` (dynamic clients per target cluster). Both are invalidated on `ClusterConnection` deletion.

Edit when:

- Changing compilation, validation, or status fields.
- Changing how parallel collection is structured.

## `internal/controller/policy/`

The `MonitorAccessPolicy` reconciler. Documented in [Contributing → Policy Controller](policy-controller.md). Lives in the same binary even though it's a separate domain — it shares the same Redis client, scheme, and manager.

## `internal/metricsource/compiler/`

`MetricSource` spec → `CompiledMetricSource`. Validates the spec, parses API version, pluralises kind into resource name, parses JSONPath into segment lists for the extractor, compiles computed-field expressions, compiles aggregation filters, compiles namespace include/exclude patterns to regex, and hashes the canonical JSON for change detection.

```go
func (c *Compiler) Compile(ms *v1alpha1.MetricSource) (*types.CompiledMetricSource, error)
```

Cycle detection: `detectCircularDependencies()` rejects computed fields that reference each other.

Edit when:

- Adding a field type / aggregation function / expression operator (the compiler validates and pre-processes).
- Tightening validation.

## `internal/metricsource/collector/`

Collects resources from a single cluster using the dynamic client. Resolves namespaces (handling include/exclude patterns and cluster-wide list optimisation), paginates List calls (`BatchSize`), and respects `MaxResources` per cluster + `TimeoutSeconds`. Parallelism is bounded by `Parallelism` (default 3).

Edit when:

- Changing how namespaces are enumerated.
- Adding API-side filtering (label/field selectors).
- Changing pagination strategy.

## `internal/metricsource/extractor/`

Field extraction from `*unstructured.Unstructured`. Uses pre-parsed path segments from the compiler. Type conversions handle:

- `string`, `integer`, `float`, `boolean` — straight coercion.
- `quantity` — Kubernetes quantity → base-unit numeric (bytes/millicores).
- `timestamp` — RFC3339 validation.
- `arrayLength` — length of an array or map.

## `internal/metricsource/expression/`

The expression language used by MetricSource computed fields.

| File | What's there |
|---|---|
| `types.go` | AST node types + token definitions. |
| `tokenizer.go` | Lexer. |
| `parser.go` | Recursive descent parser. |
| `evaluator.go` | Tree walker with typed context. |
| `functions.go` | Built-in function implementations. |

Operators: arithmetic (`+ - * / %`), comparison, logical (`&& || !`), null-coalesce (`??`), string concat via `+`. Built-in functions cover the obvious set: `concat`, `lower`, `upper`, `len`, `substr`, `contains`, `startsWith`, `endsWith`, `round`, `floor`, `ceil`, `abs`, `min`, `max`, `coalesce`, `now`, `age`, `formatBytes`, `toString`, `toNumber`.

To add a function:

```go
// internal/metricsource/expression/functions.go
var BuiltinFunctions = map[string]FunctionDef{
    // ...
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

The function is then usable in any `MetricSource.spec.computed[].expression`.

## `internal/metricsource/aggregator/`

Aggregation engine. Supports `count`, `sum`, `avg`, `min`, `max`, `percentile`, `distinct`, optional `filter` (with `equals`/`notEquals`/`contains`/`startsWith`/`endsWith`/`greaterThan`/`lessThan`/`in`/`matches`), and `groupBy`. Regex patterns used by `matches` are cached.

To add a function: add the constant in `pkg/types/metricsource.go`, the enum case in the CRD validation marker, and the implementation in `aggregator.go`'s `computeSingle` switch.

## `internal/store/`

Redis storage. Keys are snake_case strings. Each Redis-bearing component (`cluster`, `registry`, `policy`, `metricsource`) has a dedicated file.

| File | What's there |
|---|---|
| `client.go` | Connection pool, shared client, generic helpers (`HSet`, `Pipeline`). |
| `policy_storage.go` | Policy compilation + indexes. See [Policy controller](policy-controller.md). |
| `resource_storage.go` | Cluster/node/operator/RBAC-resource state. |
| `registry_storage.go` | Registry status + spec. |
| `metricsource_storage.go` | Compiled MetricSource definitions + per-cluster collections + aggregation results. |
| `reader.go` | Read-side queries shared with the API. |

MetricSource Redis keys (for reference when debugging with `redis-cli`):

```
metricsource:{namespace}:{name}                  # Compiled definition (hash)
cluster:{cluster}:custom:{sourceID}:resources    # CollectedResource list (JSON)
cluster:{cluster}:custom:{sourceID}:aggregations # AggregationResults (JSON)
cluster:{cluster}:custom:{sourceID}:meta         # Collection metadata (hash)
metricsources:all                                # All MetricSource keys (set)
metricsources:enabled                            # Enabled MetricSource keys (set)
metricsources:by:resourcetype:{name}             # MetricSources by resourceTypeName
```

Cluster/policy key patterns are documented in [Policy controller → Redis data format](policy-controller.md#redis-data-format) and `client.go` itself.

## `internal/config/`

Loads everything from env vars. Adding a new option:

```go
type Config struct {
    // ...
    NewFeatureEnabled bool
    NewFeatureTimeout int
}

func Load() *Config {
    return &Config{
        // ...
        NewFeatureEnabled: getEnvBool("NEW_FEATURE_ENABLED", false),
        NewFeatureTimeout: getEnvIntWithMin("NEW_FEATURE_TIMEOUT", 30, 5),
    }
}
```

Defaults documented in [Quickstart → Configuration](cluster-controller-quickstart.md#configuration).

## `pkg/types/`

| File | Purpose |
|---|---|
| `types.go` | Core domain types: `ClusterMetrics`, `NodeMetrics`, `OperatorInfo`, `ClusterOperatorInfo`, plus health/status constants. |
| `resources.go` | Memory-optimised summaries for RBAC filtering: `PodSummary`, `DeploymentSummary`, `ServiceSummary`, `StatefulSetSummary`, `DaemonSetSummary`, plus `CollectionConfig`. |
| `metricsource.go` | Compiled MetricSource types: `CompiledMetricSource`, `CompiledField`, `CompiledComputation`, `CompiledAggregation`, `CustomCollectedResource`, `AggregationResults`, plus field-type and aggregation-function constants. |
| `policy.go` | Compiled policy types (consumed by both the policy reconciler and the RBAC engine). |

Use `pkg/types/` for anything that crosses package boundaries or gets serialised to Redis. Use `internal/.../types.go` files for types that stay inside their own package.

## `pkg/utils/`

| File | Purpose |
|---|---|
| `parser.go` | `ParseCPU` (string → cores as float64), `ParseMemory` (string → bytes as int64). Handles `m`/`u`/`n` for CPU and `Ki/Mi/Gi/K/M/G` for memory. |
| `circuit_breaker.go` | Three-state circuit breaker (closed/open/half-open) used by cluster client. Threshold + recovery timeout configurable. |

Pattern for adding a new utility: keep it pure (no dependencies on `internal/`), focused, and tested. See [Patterns → pkg/utils usage](cluster-controller-patterns.md#using-pkgutils).

## Adding common things

### A new CRD field

1. Add to the spec/status struct in `api/v1alpha1/`.
2. `controller-gen object paths="./..."` and `controller-gen crd paths="./..." output:crd:dir=config/crd/bases`.
3. Read the new field in the reconciler.
4. If it's persisted to Redis, add the storage path in `internal/store/`.

### A new resource summary for RBAC

1. Define the summary type in `pkg/types/resources.go`.
2. Add the limit knob to `CollectionConfig` (e.g. `MaxConfigMaps`).
3. Collect it in `internal/client/cluster/resources.go` (gated by the limit).
4. Plumb the limit through `internal/config/`.

### A new MetricSource field type

1. Add the constant in `pkg/types/metricsource.go`.
2. Update the kubebuilder enum on `MetricSourceSpec.Fields[].Type` in `api/v1alpha1/metricsource_types.go`.
3. Implement extraction in `internal/metricsource/extractor/extractor.go::convertValue`.
4. `controller-gen object/crd`.

### A new aggregation function

1. Add the constant in `pkg/types/metricsource.go`.
2. Update the kubebuilder enum on `MetricSourceSpec.Aggregations[].Function`.
3. Add the case in `internal/metricsource/aggregator/aggregator.go::computeSingle`.
4. `controller-gen object/crd`.

### A new controller

1. Define the CRD in `api/v1alpha1/`.
2. Create `internal/controller/<name>/`.
3. Reuse the predicate filter pattern from `registry_controller.go` to skip status-only updates.
4. Register the reconciler in `cmd/manager/main.go`.

See [Reconciliation](cluster-controller-reconciliation.md) for the reconcile-loop shape every controller in this repo follows.
