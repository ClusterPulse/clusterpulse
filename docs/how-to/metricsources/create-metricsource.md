# Create a MetricSource

A `MetricSource` defines what to collect from your connected clusters and how to summarise it. You point it at a Kubernetes Kind (built-in or CRD), extract fields by JSONPath, optionally compute derived fields, and define cluster-wide aggregations. The hub controller collects matching resources from every connected cluster and stores the per-cluster collections in Redis alongside the aggregations.

This guide starts with a small example, then walks through every section of the spec, the field types, edge cases for JSONPath, and the RBAC handoff.

## Defaults shipped with ClusterPulse

Two MetricSources are created on initial install (controllable via `defaults.metricsources.enabled` on the `ClusterPulse` CR):

- `default-pvc-capacity` — PVC storage capacity overview (phase, capacity, storage class, aggregations by storage class).
- `default-deployment-health` — Deployment availability tracking (replicas, ready %, degraded count).

They aren't continuously re-applied — delete or edit them as needed. List them:

```bash
oc get metricsource -l clusterpulse.io/default=true
```

Their YAML in the [operator repo](https://github.com/ClusterPulse/operator) is the most up-to-date reference for what a real MetricSource looks like.

## Prerequisites

- ClusterPulse running on the hub and at least one `ClusterConnection` registered.
- The service account on each target cluster has `get` + `list` for the resource Kind you want to collect. For pull-mode that's the SA the `ClusterConnection`'s credentials secret authenticates as; for push-mode it's the `clusterpulse-collector` SA the hub provisions automatically (which is granted `get`/`list`/`watch` on `*/*`).

## Minimal example

Start with the simplest possible MetricSource — count PVCs per cluster, nothing else:

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: MetricSource
metadata:
  name: pvc-count
  namespace: clusterpulse
spec:
  source:
    apiVersion: v1
    kind: PersistentVolumeClaim
    scope: Namespaced
  fields:
    - name: phase
      path: .status.phase
      type: string
  aggregations:
    - name: total
      function: count
  collection:
    intervalSeconds: 120
  rbac:
    resourceTypeName: pvc
```

Apply:

```bash
oc apply -f pvc-count.yaml
oc get metricsource pvc-count -n clusterpulse
```

Expected `phase: Active` once the first collection cycle completes.

This is enough to:

- Have ClusterPulse list every PVC across every connected cluster at `/api/v1/clusters/<cluster>/custom/pvc`.
- Get an aggregation called `total` per cluster.
- Reference the type as `pvc` in `MonitorAccessPolicy.spec...resources[].type`.

The rest of this guide shows what you'd add on top.

## Full example

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
        - openshift-*
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
    timeoutSeconds: 30
    maxResources: 10000
    batchSize: 500
  rbac:
    resourceTypeName: pvc
    filterableFields:
      - storageClass
      - phase
    filterAggregations: true
```

## Spec walkthrough

### `source` — what to collect

| Field | Description |
|---|---|
| `apiVersion` | Group + version, e.g. `v1`, `apps/v1`, `cert-manager.io/v1`. |
| `kind` | Kind of the resource. |
| `scope` | `Namespaced` or `Cluster`. Determines whether namespace selectors apply. |
| `namespaces.include` / `namespaces.exclude` | Pattern-based filter on which namespaces to scan. Wildcards (`*`, `?`) supported. `exclude` beats `include`. Omit both to collect from every namespace. |
| `labelSelector.matchLabels` | K8s label selector for resources. |
| `labelSelector.matchExpressions` | Set-based selector (`In`, `NotIn`, `Exists`, `DoesNotExist`). |

Use `kubectl explain` plus a real cluster to confirm the API path:

```bash
kubectl api-resources | grep -i pvc
kubectl explain persistentvolumeclaim.status
```

### `fields` — what to extract per resource

Each field needs a `name`, a `path` (JSONPath into the resource), and optionally a `type` and a `default`.

| `type` | What it does |
|---|---|
| `string` (default) | Pass through as-is. |
| `integer` | Coerce to int64. |
| `float` | Coerce to float64. |
| `boolean` | Coerce to bool. |
| `quantity` | Parse a Kubernetes resource quantity (`5Gi`, `100m`) into a numeric base-unit value. Use this for storage, CPU, memory. |
| `timestamp` | Parse an RFC3339 timestamp into a time.Time. |
| `arrayLength` | The path is expected to resolve to an array; the field holds its length. |

### `computed` — derived fields

Computed fields run an expression over the extracted fields. Supported operators include arithmetic (`+ - * / %`), comparison, logical (`&& || !`), and a set of built-in functions (`abs`, `min`, `max`, `round`, `if`, etc.).

```yaml
computed:
  - name: utilizationPercent
    expression: "(used / capacity) * 100"
    type: float
```

The full expression reference is in the [cluster-controller architecture](../../contributing/cluster-controller-architecture.md#internalmetricsourceexpression) doc; the cheap rule is "imagine a typed calculator with `if(cond, a, b)`."

### `aggregations` — cluster-wide summaries

| `function` | Requires `field` | Notes |
|---|---|---|
| `count` | No | Number of resources. |
| `sum` | Yes | Numeric sum. |
| `avg` | Yes | Numeric mean. |
| `min` | Yes | Numeric or string minimum (string is lexical). |
| `max` | Yes | Numeric or string maximum. |
| `percentile` | Yes | Set `percentile: 95` for P95, etc. |
| `distinct` | Yes | Count of distinct values. |

`filter` and `groupBy`:

```yaml
aggregations:
  - name: failed_pvcs
    function: count
    filter:
      field: phase
      operator: notEquals
      value: Failed

  - name: by_storage_class
    function: count
    groupBy: storageClass
```

Filter operators: `equals`, `notEquals`, `contains`, `startsWith`, `endsWith`, `greaterThan`, `lessThan`, `in`, `matches` (regex).

### `collection` — runtime knobs

| Field | Default | Min | What it controls |
|---|---|---|---|
| `intervalSeconds` | 60 | 30 | Time between full collection cycles. |
| `timeoutSeconds` | 30 | 5 | Per-cluster timeout for a single collection run. |
| `maxResources` | 5000 | 1 | Cap on resources collected per cluster per cycle. |
| `batchSize` | 500 | 10 | API list pagination size. |
| `retryAttempts` | 3 | 0 | Retries on transient failures. |
| `parallelism` | 3 | 1 | Concurrent field extractions per resource batch. |

### `rbac` — handoff to MonitorAccessPolicy

```yaml
rbac:
  resourceTypeName: pvc
  filterableFields:
    - storageClass
    - phase
  filterAggregations: true
```

- `resourceTypeName` is the string `MonitorAccessPolicy.spec...resources[].type` has to match for policies to reference this MetricSource. Pick something short and stable — renaming it later breaks every policy that references it.
- `filterableFields` controls which extracted fields can be used in policy `filters.fields` blocks. Filters that name a non-filterable field are silently ignored. List fields here deliberately — anything you list is effectively "this field is safe to filter on, even by users with limited permissions."
- `filterAggregations: true` (default) recomputes aggregations from the user's filtered resource set at API time. See [Grant custom resource access → Aggregation recomputation](../policies/grant-custom-resource-access.md#aggregation-recomputation).

## Step 4: Verify

```bash
oc get metricsource pvc-metrics -n clusterpulse
oc describe metricsource pvc-metrics -n clusterpulse
```

Status fields to look at:

| Field | Meaning |
|---|---|
| `phase` | `Active`, `Error`, `Disabled`. |
| `lastCollectionTime` | When the last full cycle finished. |
| `lastCollectionDuration` | How long it took (use this to tune `intervalSeconds`). |
| `resourcesCollected` | Last cycle's total across clusters. |
| `clustersCollected` | Number of clusters that responded. |
| `errorCount` | Cumulative collection errors since last reset. |
| `fieldValidation[]` | Per-field "this path actually returned a value in the last cycle" check. |

Then via the API:

```bash
ROUTE=$(oc get route clusterpulse -n clusterpulse -o jsonpath='{.spec.host}')

curl -s "https://$ROUTE/api/v1/custom-types" | jq
curl -s "https://$ROUTE/api/v1/clusters/<cluster>/custom/pvc" | jq
curl -s "https://$ROUTE/api/v1/custom-types/clusters?type=pvc&include_aggregations=true" | jq
```

Custom resources only appear in `/custom-types` if a `MonitorAccessPolicy` grants the current principal access — see [Grant custom resource access](../policies/grant-custom-resource-access.md).

## JSONPath edge cases

### Path returns nothing (optional field)

Set `default` so the field gets a value:

```yaml
- name: volumeMode
  path: .spec.volumeMode
  type: string
  default: "Filesystem"
```

Without a default, the field is missing from the resource record, and any aggregation that references it will skip the resource (for numeric functions) or treat it as the zero value.

### Path returns an array

`type: arrayLength` to count elements:

```yaml
- name: containerCount
  path: .spec.containers
  type: arrayLength
```

To pull a specific element, use a JSONPath index — `.spec.containers[0].image`. To pull every element's value, the engine flattens — but you'll get one record per resource, not one per element. If you need per-element rows, define a separate MetricSource keyed on a different resource.

### Path returns a Kubernetes quantity

`type: quantity` normalises to a base-unit number (bytes for storage, millicores for CPU, bytes for memory):

```yaml
- name: capacity
  path: .status.capacity.storage
  type: quantity
```

So `"5Gi"` becomes `5368709120`. Then `computed` fields can do arithmetic on it.

### Verifying a JSONPath

```bash
kubectl get pvc <name> -n <ns> -o jsonpath='{.status.phase}'
kubectl get pvc <name> -n <ns> -o jsonpath='{.spec.resources.requests.storage}'
```

If `kubectl -o jsonpath` returns empty, ClusterPulse's extractor will too. The MetricSource controller's `status.fieldValidation` will mark the field as failed after the first collection.

### Different schemas per cluster

If you collect a CRD that has different fields on different clusters (different operator versions, for example), set `default` on every optional field. The MetricSource is single-tenant per ClusterPulse install — every connected cluster runs the same MetricSource spec.

## Troubleshooting

### `phase: Error`

`status.message` and `status.fieldValidation` carry the cause:

- Invalid JSONPath → the path string is malformed. Test with `kubectl -o jsonpath`.
- Resource Kind not registered → `apiVersion`/`kind` mismatch. Confirm with `kubectl api-resources`.
- Missing RBAC on the target → check the SA bindings on the cluster you're collecting from.

### Zero resources collected

1. Confirm resources of that Kind exist on the cluster: `kubectl get <kind> -A | head`.
2. Check `namespaces.include`/`exclude` and `labelSelector` aren't filtering everything out.
3. Confirm the SA's permissions on the target cover the Kind: `kubectl auth can-i list <kind> --as=system:serviceaccount:...`.

### Field shows up empty in the API

`fieldValidation` for the field will be `false`. Re-check the path against `kubectl -o jsonpath`. If the path is right but the value is missing on some resources, add a `default`.

### Aggregation values look wrong via the API

You're hitting aggregation recomputation. When the requesting user is filtered by a `MonitorAccessPolicy`, the aggregations are recomputed against their filtered resource set, not the cluster total. To see the raw cluster total: call the API as a principal with full access, or fetch the `customresource:<source_id>:<cluster>` collection directly from Redis.

## Next steps

- [Grant custom resource access](../policies/grant-custom-resource-access.md) — how policies reference a MetricSource and filter its resources.
- [Filter by namespace](../policies/filter-by-namespace.md) — namespace filters interact with custom resources via the same rules.
- [RBAC model](../../concepts/rbac-model.md) — full RBAC reference.
