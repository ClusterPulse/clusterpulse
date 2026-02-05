# Create a MetricSource

This guide covers creating a `MetricSource` custom resource to collect and aggregate data from any Kubernetes resource across your connected clusters.

## Overview

A MetricSource tells ClusterPulse **what** to collect from your clusters and **how** to process it. You define:

- A **source** — the Kubernetes resource kind to watch (e.g., PersistentVolumeClaim, Deployment, any CRD)
- **Fields** — values to extract from each resource instance using JSONPath
- **Computed fields** — derived values calculated from extracted fields
- **Aggregations** — cluster-wide summaries like counts, sums, and averages

Once created, ClusterPulse continuously collects matching resources from all connected clusters and makes the data available through the API.

## Prerequisites

- ClusterPulse deployed and running
- At least one cluster connected via `ClusterConnection`
- The service account on each target cluster must have `get` and `list` permissions for the resource kind you want to collect

## Step 1: Identify the Resource to Collect

Determine the API version, kind, and scope of the Kubernetes resource you want to monitor. For example:

| Resource | API Version | Kind | Scope |
|----------|-------------|------|-------|
| PVCs | `v1` | `PersistentVolumeClaim` | Namespaced |
| Nodes | `v1` | `Node` | Cluster |
| Deployments | `apps/v1` | `Deployment` | Namespaced |
| CronJobs | `batch/v1` | `CronJob` | Namespaced |

You can also target custom resources (e.g., `certificates.cert-manager.io/v1`).

## Step 2: Define Field Extractions

Fields use JSONPath expressions to pull values from each resource instance. Identify which fields matter for your use case.

Use `kubectl get <resource> -o json` to inspect the structure:

```bash
kubectl get pvc -o json | jq '.items[0]'
```

Each field needs:
- `name` — a unique identifier
- `path` — JSONPath to the value (e.g., `.status.phase`, `.spec.resources.requests.storage`)
- `type` — optional, defaults to `string`. Supported: `string`, `integer`, `float`, `boolean`, `quantity`, `timestamp`, `arrayLength`

Use the `quantity` type for Kubernetes resource quantities (storage, CPU, memory) so they are parsed into comparable numeric values.

## Step 3: Create the MetricSource

Here is a complete example that collects PersistentVolumeClaims:

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: MetricSource
metadata:
  name: pvc-metrics
  namespace: clusterpulse
spec:
  source:
    apiVersion: v1
    kind: PersistentVolumeClaim
    scope: Namespaced
    namespaces:
      exclude:
        - kube-system

  fields:
    - name: phase
      path: .status.phase
      type: string
    - name: capacity
      path: .status.capacity.storage
      type: quantity
    - name: storageClass
      path: .spec.storageClassName
      type: string
    - name: volumeMode
      path: .spec.volumeMode
      type: string
      default: "Filesystem"

  computed:
    - name: capacityGB
      expression: "capacity / 1073741824"
      type: float

  aggregations:
    - name: total_pvcs
      function: count
    - name: total_capacity
      function: sum
      field: capacity
    - name: avg_capacity
      function: avg
      field: capacity
    - name: bound_count
      function: count
      filter:
        field: phase
        operator: equals
        value: Bound
    - name: by_storage_class
      function: count
      groupBy: storageClass

  collection:
    intervalSeconds: 120
    maxResources: 10000

  rbac:
    resourceTypeName: pvc
    filterableFields:
      - storageClass
      - phase
    filterAggregations: true
```

Apply it:

```bash
kubectl apply -f metricsource-pvc.yaml
```

## Step 4: Verify Collection

Check the MetricSource status:

```bash
kubectl get metricsource pvc-metrics -n clusterpulse
```

For detailed status including collection results:

```bash
kubectl describe metricsource pvc-metrics -n clusterpulse
```

The status should show `Phase: Active` with `ResourcesCollected` and `ClustersCollected` populated after the first collection cycle.

## Key Concepts

### Namespace Selectors

Control which namespaces are collected. `exclude` takes precedence over `include`. Supports wildcards:

```yaml
source:
  namespaces:
    include:
      - "app-*"
      - "team-*"
    exclude:
      - "*-test"
```

If omitted, all namespaces are collected.

### Label Selectors

Filter resources by Kubernetes labels:

```yaml
source:
  labelSelector:
    matchLabels:
      app: my-app
    matchExpressions:
      - key: tier
        operator: In
        values: [frontend, backend]
```

### Computed Fields

Computed fields derive new values from extracted fields using an expression language:

```yaml
computed:
  - name: utilizationPercent
    expression: "(used / capacity) * 100"
    type: float
```

### Aggregation Functions

| Function | Description | Requires `field` |
|----------|-------------|------------------|
| `count` | Number of matching resources | No |
| `sum` | Sum of a numeric field | Yes |
| `avg` | Average of a numeric field | Yes |
| `min` | Minimum value | Yes |
| `max` | Maximum value | Yes |
| `percentile` | Percentile value (set `percentile` field) | Yes |
| `distinct` | Count of distinct values | Yes |

### Aggregation Filters

Run aggregations on a subset of resources:

```yaml
aggregations:
  - name: failed_pods
    function: count
    filter:
      field: phase
      operator: notEquals
      value: Running
```

Supported operators: `equals`, `notEquals`, `contains`, `startsWith`, `endsWith`, `greaterThan`, `lessThan`, `in`, `matches`.

### RBAC Integration

The `rbac` section connects your MetricSource to the policy system. `resourceTypeName` is the identifier you reference in `MonitorAccessPolicy` resources. `filterableFields` defines which extracted fields can be used in policy filters.

If `filterAggregations` is `true` (the default), aggregation results are recalculated to reflect only the resources a user is permitted to see.

## Collection Configuration Reference

| Field | Type | Default | Min | Description |
|-------|------|---------|-----|-------------|
| `intervalSeconds` | int32 | 60 | 30 | Seconds between collection cycles |
| `timeoutSeconds` | int32 | 30 | 5 | Per-cluster collection timeout |
| `maxResources` | int32 | 5000 | 1 | Max resources per cluster |
| `batchSize` | int32 | 500 | 10 | API pagination batch size |
| `retryAttempts` | int32 | 3 | 0 | Retries on transient failures |
| `parallelism` | int32 | 3 | 1 | Concurrent field extractions |

## Troubleshooting

### Phase Shows Error

Check the MetricSource status message:

```bash
kubectl describe metricsource pvc-metrics -n clusterpulse
```

Common causes:
- Invalid JSONPath in a field `path`
- The target resource kind does not exist on the cluster
- Missing RBAC permissions on the target cluster's service account

### Zero Resources Collected

1. Verify the resource exists on the connected clusters
2. Check namespace selectors are not excluding everything
3. Confirm the service account has `get` and `list` permissions for the resource

### Field Extraction Returns Empty

1. Verify the JSONPath is correct by testing locally: `kubectl get <resource> -o jsonpath='{.status.phase}'`
2. Check that a `default` value is set for optional paths
3. Confirm the `type` matches the actual value (e.g., use `quantity` for storage values, not `string`)

## Next Steps

- [RBAC Model](../../concepts/rbac-model.md) — Understand how access policies work
- [Filter By Namespace](../policies/filter-by-namespace.md) — Restrict visibility by namespace
- [Create Read-Only Policy](../policies/create-readonly-policy.md) — Set up policies that reference your MetricSource
