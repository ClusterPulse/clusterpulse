# Cluster Controller — Patterns

ClusterPulse-specific implementation patterns. Generic Go advice (formatting, commit hygiene, etc.) lives in [Workflow](workflow.md). General reconcile-loop shape is in [Reconciliation](cluster-controller-reconciliation.md).

## Redis storage

Two rules apply to everything written to Redis:

1. **Keep keys snake_case.** The API reads these keys; mixing camelCase will silently break consumers.
2. **Never write `nil` arrays.** Some consumers and Redis tooling distinguish `nil` from `[]`. Always pre-initialise.

```go
// Bad
data := map[string]interface{}{
    "cpuCapacity": metrics.CPUCapacity,  // wrong case
    "nodes":       nil,                  // wrong empty
}

// Good
data := map[string]interface{}{
    "cpu_capacity": metrics.CPUCapacity,
    "nodes":        []string{},
    "timestamp":    time.Now().Format(time.RFC3339),
}
```

Use Redis pipelines for batch writes — a reconcile cycle that writes a node-metrics map, a cluster-metrics blob, and an operator list should issue one round-trip, not three:

```go
pipe := r.RedisClient.client.Pipeline()
pipe.Set(ctx, key1, val1, ttl)
pipe.Set(ctx, key2, val2, ttl)
pipe.HSet(ctx, key3, field, value)
_, err := pipe.Exec(ctx)
```

`internal/store/policy_storage.go::StorePolicy` is the canonical example — a single pipeline writes the policy hash, deletes stale subject indexes from the previous compilation (diff-driven), adds new subject indexes, and updates the global sets and sorted sets, all atomically from the caller's perspective.

## Cluster client pool

Never instantiate cluster clients inline. The pool in `internal/client/pool/`:

- Reuses clients across reconciles (TLS handshake + discovery cache).
- Calls `TestConnection` before returning a cached client.
- Reaps idle clients on a timer.
- Is thread-safe.

```go
// Bad
client, err := cluster.NewClusterClient(name, endpoint, token, caCert)

// Good
client, err := r.clientPool.Get(name, endpoint, token, caCert)
```

`Remove(name)` is called from the deletion handler. The MetricSource reconciler keeps its own `clusterClients` cache for dynamic clients with the same lifecycle discipline.

## Circuit breakers

Every remote API call in `internal/client/cluster/` runs inside a circuit breaker (`pkg/utils/circuit_breaker.go`). Threshold defaults to 5 failures, recovery to 60 seconds. The closed/open/half-open state machine is in `circuit_breaker.go::Call`.

```go
err := c.circuitBreaker.Call(ctx, func(ctx context.Context) error {
    nodeList, err := c.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
    if err != nil {
        return err
    }
    nodes = nodeList.Items
    return nil
})
```

If you add a new method on `ClusterClient` that talks to the API server, wrap it in the breaker. Without the breaker, an unhealthy target cluster will hang one reconcile after another at the API call timeout, eating worker slots.

## Using `pkg/utils`

The two utilities currently in `pkg/utils`:

```go
import "github.com/clusterpulse/cluster-controller/pkg/utils"

// Quantities → numbers
cpuCores := utils.ParseCPU(container.Resources.Requests.Cpu().String())
memBytes := utils.ParseMemory(container.Resources.Requests.Memory().String())

// Wrap API calls
err := utils.NewCircuitBreaker(5, 60*time.Second).Call(ctx, fn)
```

`ParseCPU` understands `m`, `u`, `n` suffixes; `ParseMemory` understands binary (`Ki`, `Mi`, `Gi`) and decimal (`K`, `M`, `G`) suffixes. Both return zero on empty/invalid input rather than failing — they're used in hot paths where missing values are expected.

Adding a utility: keep it a pure function, no dependencies on `internal/`, no logging, no I/O. Test it with table-driven tests under `pkg/utils/<name>_test.go`.

## Status updates

Use `Patch` with `MergeFrom(original)` on the status subresource. Use `Update` only when you actively want a fresh reconcile event. The predicate filter (see [Reconciliation](cluster-controller-reconciliation.md#registryconnection-reconcile-loop)) ignores generation-unchanged updates, but `Update` still produces an audit-log entry and an etcd write.

```go
original := resource.DeepCopy()

resource.Status.Phase = "Connected"
resource.Status.Health = string(types.HealthHealthy)
now := metav1.Now()
resource.Status.LastSyncTime = &now

if !statusEqual(original.Status, resource.Status) {
    if err := r.Status().Patch(ctx, resource, k8sclient.MergeFrom(original)); err != nil {
        log.WithError(err).Debug("Failed to patch status")
    }
}
```

The `statusEqual` check is per-reconciler — what counts as "no change" depends on the CRD. See `cluster_controller.go::statusEqual` for an example that ignores monotonically-advancing fields (timestamps, counters).

## Expression patterns for MetricSource computed fields

The expression language is small. The recurring patterns are:

```text
# Plain arithmetic
expression: "capacity - used"

# Percentage with rounding
expression: "round((used / capacity) * 100, 2)"

# Null handling — null-coalesce
expression: "used ?? 0"

# Treat any null as zero for a sum
expression: "coalesce(requestedCPU, 0) + coalesce(limitCPU, 0)"

# String composition
expression: "concat(namespace, '/', name)"

# Conditional via if(cond, a, b) — see functions.go for the full list
expression: "if(phase == 'Bound', capacity, 0)"
```

The compiler validates every expression at compile time (`expression.Compile`). Runtime evaluation errors are rare — most class of mistake (wrong identifier, wrong number of arguments to a function) is caught when the `MetricSource` is applied.

## Aggregation patterns

```yaml
# Plain count
- name: total
  function: count

# Count with filter
- name: running
  function: count
  filter:
    field: status
    operator: equals
    value: "Running"

# Filtered sum
- name: total_bound_storage
  field: capacity
  function: sum
  filter:
    field: phase
    operator: equals
    value: "Bound"

# Group counts by field
- name: by_namespace
  function: count
  groupBy: namespace

# Percentile
- name: p95_cpu
  field: cpu_usage
  function: percentile
  percentile: 95
```

`distinct` is the odd one out — it counts unique values of `field`, with optional `filter`. `count` is the only function that doesn't require `field`.

## Performance

### Rate limiting

The cluster client uses the standard `rest.Config` QPS+Burst knobs. Defaults (`QPS: 100, Burst: 200`) are deliberately permissive — every call lives behind a circuit breaker so misbehaving clusters can't flood. Lower these only if you've observed actual issues; raising them on a hub talking to large managed clusters is the more common adjustment.

### Pagination

Resource lists use `Limit` + `Continue` to bound memory:

```go
opts := metav1.ListOptions{
    Limit: int64(config.MaxTotalPods),
    FieldSelector: "status.phase!=Succeeded,status.phase!=Failed",
}
```

Field selectors are evaluated on the apiserver side, so they're cheaper than client-side filtering — use them where the apiserver supports them.

### MetricSource collection

Three things make MetricSource collection fast at scale:

1. **Pre-compile everything.** JSONPaths become segment lists at compile time, expressions become AST, regexes are compiled once. Hot paths only do tree-walks and table lookups.
2. **Bound parallelism explicitly.** `CollectionConf.Parallelism` (default 3) limits concurrent namespace fetches per cluster. Don't let it grow with cluster count — concurrency-per-cluster scales independently.
3. **Cap output.** `MaxResources` and `BatchSize` exist for a reason. A misconfigured MetricSource on a 50k-pod cluster shouldn't be able to OOM the manager.

### VictoriaMetrics writes

`internal/ingester/vmwriter.go` writes via remote-write with Prometheus text format. The cluster controller writes once per reconcile per cluster; the ingester writes once per push from a connected collector. Series with high cardinality (per-node, per-operator) are emitted; the cardinality is the same as a single cluster's `kubectl get nodes -o yaml` would produce — manageable, but worth watching when scaling cluster count.

## Anti-patterns to avoid

These come up often enough to call out:

- **`Result{}, nil` from a reconcile.** Use `Result{RequeueAfter: ...}, nil`. The reconciler stops getting called otherwise.
- **`r.Status().Update(...)`** when you mean `Patch`. `Update` triggers a fresh reconcile event.
- **Calling `clientset.X().List(ctx, opts)` directly** outside the circuit breaker. The breaker is the only thing preventing one bad cluster from clogging the manager.
- **Storing camelCase keys in Redis.** The API reads snake_case.
- **Not regenerating after CRD edits.** `controller-gen object/crd` after every change to `api/v1alpha1/`. Build will fail anyway, but it fails noisily — easier to regen first.
- **Adding hard-coded resource collection to the cluster controller** when the right answer is a `MetricSource` CRD. The cluster controller collects connection-level data (nodes, operators, cluster info); everything else belongs in MetricSource.
- **Computed-field cycles.** `compiler.detectCircularDependencies` will reject them at compile time. If the compiler accepts but evaluation gives weird values, you're probably looking at the order in which computed fields are evaluated — the compiler topologically sorts them, but identical names across fields and computed fields will collide.
