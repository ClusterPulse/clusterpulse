# Cluster Controller — Reconciliation

Every reconciler in the manager binary follows the same shape:

```
Watch → Fetch → Handle deletion → Do work → Patch status → Requeue
```

The variations are in the "do work" step and in what gets requeued when. This page documents the patterns the codebase relies on. For specific reconcilers, see the source under `internal/controller/` and the per-CRD sections in [Architecture](cluster-controller-architecture.md).

## ClusterConnection reconcile loop

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Watch for ClusterConnection changes                       │
│    Predicate filter skips status-only updates                │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Reconcile(ctx, req)                                       │
│    Fetch the CR; handle NotFound + DeletionTimestamp        │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Branch on collectionMode                                  │
│      push: ask ingester GetConnectionInfo                    │
│        connected   → patch CollectorAgentStatus, skip pull  │
│        disconnected → ensure agent deployed, fall through    │
│      pull (default): proceed                                 │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Get cluster client from pool                              │
│    Fetch credentials secret; pool either reuses or creates  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. TestConnection (timeout-bounded)                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. Collect data in parallel via errgroup                     │
│      node metrics                                            │
│      cluster info                                            │
│      operators (OLM) + ClusterOperators (OpenShift)         │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 7. Write to Redis                                            │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 8. Patch ClusterConnection.status (only if changed)         │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 9. Return Result{RequeueAfter: interval}                     │
└─────────────────────────────────────────────────────────────┘
```

The interval comes from `ClusterConnection.spec.monitoring.interval` (clamped to a minimum of 30s), defaulting to `RECONCILIATION_INTERVAL` from config.

## MetricSource reconcile loop

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Watch for MetricSource changes                            │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Reconcile(ctx, req)                                       │
│    Fetch; handle NotFound + DeletionTimestamp                │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Compile the spec                                          │
│      validate, parse API version, derive resource name       │
│      compile JSONPaths, expressions, aggregation filters,    │
│      namespace patterns; hash the canonical JSON             │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Store compiled definition in Redis                        │
│      update metricsources:all, :enabled, by:resourcetype:*  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Collect from each Connected ClusterConnection (parallel)  │
│    For each cluster:                                         │
│      get/create dynamic client                               │
│      resolve namespaces                                      │
│      List with pagination                                    │
│      extract fields + compute expressions                    │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. Compute aggregations (filters, groupBy)                   │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 7. Write results to Redis                                    │
│      cluster:{n}:custom:{sourceID}:resources                │
│      cluster:{n}:custom:{sourceID}:aggregations             │
│      cluster:{n}:custom:{sourceID}:meta                     │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 8. Patch MetricSource.status                                 │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ 9. Return Result{RequeueAfter: interval}                     │
│      interval shortened when errors occurred                 │
└─────────────────────────────────────────────────────────────┘
```

The reconciler reads from `ClusterConnectionList` on every cycle — it doesn't watch `ClusterConnection`. That keeps the dependency one-way: clusters can be added/removed without forcing a re-compile of every MetricSource.

## RegistryConnection reconcile loop

The simplest of the four: fetch → handle deletion → create registry client → health-check → store in Redis → patch status → requeue. The interesting part is the predicate filter (also used by the cluster controller):

```go
pred := predicate.Funcs{
    UpdateFunc: func(e event.UpdateEvent) bool {
        oldReg, okOld := e.ObjectOld.(*v1alpha1.RegistryConnection)
        newReg, okNew := e.ObjectNew.(*v1alpha1.RegistryConnection)
        if !okOld || !okNew {
            return false
        }
        // Reconcile only when generation changes (spec change).
        // Skip status-only updates to avoid infinite reconciliation loops.
        return oldReg.Generation != newReg.Generation
    },
}
```

Every controller that patches its own status needs this filter (or the `Update`/`Patch` discipline below).

## Policy reconcile loop

See [Contributing → Policy Controller](policy-controller.md) for the policy-specific flow. The pattern is the same: watch → compile → store with diff-driven cleanup → patch status. There's no requeue interval — policies are recompiled only on spec change.

## Key principles

### Always requeue

Every reconciler returns `RequeueAfter` so the cluster gets re-checked even when nothing changed:

```go
return reconcile.Result{RequeueAfter: time.Duration(interval) * time.Second}, nil
```

Returning `Result{}, nil` looks fine in tests but breaks live monitoring — there's no next cycle until the CR changes.

### Parallel collection with errgroup

Anything that does N independent API calls runs them concurrently:

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

`errgroup.WithContext` cancels every other goroutine on first error, so partial failures don't block reconciliation.

### Non-critical failures shouldn't fail reconciliation

Some collections are best-effort (operators on a Kubernetes target that doesn't have OLM, ClusterOperators on a non-OpenShift target):

```go
operators, err := clusterClient.GetOperators(gctx)
if err != nil {
    log.WithError(err).Debug("Failed to get operators (may not be installed)")
    operators = []types.OperatorInfo{}
}
```

The cluster controller treats node metrics as critical (failure → `health: unhealthy`) and everything else as best-effort.

### `Patch` vs `Update` for status

Always use `Patch` for status updates to avoid retriggering reconciliation. The predicate filter takes care of *generation-change* triggers, but `Update` on the status subresource emits a full update event that some controllers still react to.

```go
originalCC := clusterConn.DeepCopy()

clusterConn.Status.Phase = "Connected"
clusterConn.Status.Health = string(types.HealthHealthy)
now := metav1.Now()
clusterConn.Status.LastSyncTime = &now

if !r.statusEqual(originalCC.Status, clusterConn.Status) {
    if err := r.Status().Patch(ctx, clusterConn, k8sclient.MergeFrom(originalCC)); err != nil {
        log.WithError(err).Debug("Failed to patch status")
    }
}
```

The `statusEqual` check avoids issuing patches for no-op status updates — those still produce etcd writes even when no field changed.

### Handle deletion

Every reconciler checks `DeletionTimestamp` before doing work:

```go
if !resource.DeletionTimestamp.IsZero() {
    return r.handleDeletion(ctx, req.Name)
}
```

`handleDeletion` is responsible for clearing the resource's Redis state (and, for cluster connections, removing the cluster client from the pool). Most CRDs don't carry finalizers — Redis cleanup is best-effort against an eventually-consistent store.

### Timeouts on every remote call

Never call out without a context deadline:

```go
connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
defer cancel()
if err := clusterClient.TestConnection(connCtx); err != nil {
    return fmt.Errorf("connection test failed: %w", err)
}
```

The base `ctx` from the reconciler is already cancelled when controller-runtime shuts down, but its deadline is too long for any single remote call.

### Don't create clients in the reconciler

```go
// Bad — creates a new client on every reconcile, no health check, no cleanup.
client, err := cluster.NewClusterClient(name, endpoint, token, caCert)

// Good — reuses, health-checks, ages out.
client, err := r.clientPool.Get(name, endpoint, token, caCert)
```

The pool is in `internal/client/pool/`. Same rationale for the MetricSource reconciler's `clusterClients` cache.
