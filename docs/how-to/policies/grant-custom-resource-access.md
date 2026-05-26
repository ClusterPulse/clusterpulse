# Grant Custom Resource Access

Custom resources collected by `MetricSource` use **implicit deny**. A user can't see anything of a given custom type unless a `MonitorAccessPolicy` explicitly grants it. This makes new MetricSource types invisible by default — administrators have to opt principals in.

Custom resources live in the same `resources[]` list as built-in types (`nodes`, `namespaces`, etc.). The `type` field has to match the MetricSource's `spec.rbac.resourceTypeName`.

This guide assumes you've already read [Create your first policy](create-first-policy.md).

## Prerequisites

- A `MetricSource` deployed with `spec.rbac.resourceTypeName` set. See [Create a MetricSource](../metricsources/create-metricsource.md).
- A `MonitorAccessPolicy` that already covers the target principals (or, alternatively, you add the custom-type entries to a new policy).

## Grant full access to a type

Simplest form — unrestricted view of every resource of that type, in every cluster the principal can see:

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: MonitorAccessPolicy
metadata:
  name: pvc-full-access
  namespace: clusterpulse
spec:
  identity:
    priority: 100
    subjects:
      groups:
        - storage-admins
  access:
    effect: Allow
    enabled: true
  scope:
    clusters:
      default: allow
      rules:
        - selector:
            matchPattern: ".*"
          permissions:
            view: true
            viewMetrics: true
          resources:
            - type: pvc
              visibility: all
```

`type: pvc` must match the MetricSource's `spec.rbac.resourceTypeName` exactly.

## Filter by namespace

```yaml
resources:
  - type: pvc
    visibility: filtered
    filters:
      namespaces:
        allowed:
          - "app-*"
          - "shared-*"
        denied:
          - "shared-admin"
```

Same precedence rules as for built-in types: `denied` beats `allowed`, wildcards `*` and `?` are supported. The namespace dimension uses the field the MetricSource identifies as the namespace (`spec.rbac.identifiers.namespace` if set, otherwise the standard `metadata.namespace` path).

## Filter by resource name

```yaml
resources:
  - type: certificate
    visibility: filtered
    filters:
      names:
        allowed:
          - "public-*"
        denied:
          - "*-internal"
```

## Filter by field values

Fields must be listed in the MetricSource's `spec.rbac.filterableFields`. If a field isn't filterable, the engine ignores the filter (which means it's effectively wide open — define filterability deliberately on the MetricSource side).

```yaml
resources:
  - type: pvc
    visibility: filtered
    filters:
      fields:
        storageClass:
          allowed:
            - "gp3"
            - "io2"
        phase:
          denied:
            - "Failed"
```

## Control aggregation visibility

A policy can hide specific aggregation names. This is separate from aggregation **recomputation** (next section) — visibility controls which aggregation entries appear at all.

### Include (whitelist)

Only the listed aggregations are returned:

```yaml
resources:
  - type: pvc
    visibility: all
    aggregations:
      include:
        - total_pvcs
        - by_storage_class
```

### Exclude (blacklist)

Hide the listed aggregations; everything else is returned:

```yaml
resources:
  - type: pvc
    visibility: all
    aggregations:
      exclude:
        - cost_estimate
```

`include` takes precedence when both are set — only `include` is applied.

## Combining filters

The engine evaluates filters in order: namespaces → names → fields. A resource has to pass every filter to be returned.

```yaml
resources:
  - type: pvc
    visibility: filtered
    filters:
      namespaces:
        allowed: ["prod-*"]
      names:
        denied: ["*-temp"]
      fields:
        phase:
          allowed: ["Bound"]
        storageClass:
          allowed: ["gp3"]
    aggregations:
      include:
        - total_pvcs
        - total_capacity
```

Returned resources: PVCs in `prod-*` namespaces, name not `*-temp`, phase `Bound`, storage class `gp3`. Only the `total_pvcs` and `total_capacity` aggregations are returned.

## Multiple custom types in one policy

```yaml
resources:
  - type: pvc
    visibility: all
  - type: certificate
    visibility: filtered
    filters:
      namespaces:
        allowed: ["app-*"]
  - type: cronjob
    visibility: filtered
    filters:
      fields:
        schedule:
          denied:
            - "* * * * *"
```

Types not listed remain invisible — that's the implicit deny.

## End-to-end example

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: MonitorAccessPolicy
metadata:
  name: team-storage-access
  namespace: clusterpulse
spec:
  identity:
    priority: 100
    subjects:
      groups:
        - team-alpha
  access:
    effect: Allow
    enabled: true
  scope:
    clusters:
      default: deny
      rules:
        - selector:
            matchLabels:
              environment: production
          permissions:
            view: true
            viewMetrics: true
          resources:
            - type: namespaces
              visibility: filtered
              filters:
                names:
                  allowed: ["alpha-*"]
            - type: pvc
              visibility: filtered
              filters:
                namespaces:
                  allowed: ["alpha-*"]
                fields:
                  storageClass:
                    allowed: ["gp3"]
              aggregations:
                include:
                  - total_pvcs
                  - total_capacity
                  - by_storage_class
            - type: certificate
              visibility: all
```

## Aggregation recomputation

This is the canonical reference for how aggregation values change when a user has filtered visibility. Other pages link here.

When a `MetricSource` has `spec.rbac.filterAggregations: true` (the default), aggregation values are recomputed at API time from the user's filtered resource set, not from the cluster-wide totals. For example, if `team-alpha` is restricted to `alpha-*` namespaces, `total_pvcs` reflects PVCs in `alpha-*` only — not the cluster total.

Two switches matter:

- `MetricSource.spec.rbac.filterAggregations` (per type, default `true`) — turn recomputation on or off for the whole type.
- `MonitorAccessPolicy.spec.scope.clusters.rules[].resources[].aggregations.include` / `exclude` (per policy) — control which aggregation names appear after recomputation.

A user who's filtered to nothing will see aggregation values of zero (or `null` for things like averages) when recomputation is on; with recomputation off, they'd see the unfiltered values — which would leak the unfiltered totals to a user who can't see the resources behind them. Leave it on unless you have a specific reason not to.

## Verification

```bash
ROUTE=$(oc get route clusterpulse -n clusterpulse -o jsonpath='{.spec.host}')

# What custom types is the user allowed to see?
curl -s "https://$ROUTE/api/v1/custom-types" | jq

# Filtered resources of one type, for one cluster:
curl -s "https://$ROUTE/api/v1/clusters/<cluster>/custom/pvc" | jq

# Cluster-wide aggregations for the type:
curl -s "https://$ROUTE/api/v1/custom-types/clusters?type=pvc&include_aggregations=true" | jq
```

## Troubleshooting

### Custom type doesn't appear in `/custom-types`

1. Verify the MetricSource exists and `spec.rbac.resourceTypeName` is set: `oc get metricsource <name> -o yaml`.
2. Confirm the policy has a `resources[]` entry with the matching `type` and `visibility` is not `none`.
3. Confirm the policy is `Active` and applies to the principal (use `/api/v1/auth/policies`).

### Resources are filtered more aggressively than expected

1. Check every filter — `namespaces`, `names`, `fields`. A resource must pass all of them.
2. Look for a higher-priority `Deny` policy via `/api/v1/auth/policies`.
3. Confirm a `fields` filter you set is actually filterable: `oc get metricsource <name> -o jsonpath='{.spec.rbac.filterableFields}'`. Filters on non-filterable fields are silently ignored, which usually surfaces as "filter looks set but isn't taking effect."

### Aggregations missing

1. Confirm the aggregation name in your `include`/`exclude` matches `MetricSource.spec.aggregations[].name` exactly.
2. If `aggregations.include` is set, anything not listed is hidden — that's by design.
3. With `filterAggregations: true` and no resources passing the filter, numeric aggregations return zero/null, which can look like "missing."

## Next steps

- [Create a MetricSource](../metricsources/create-metricsource.md)
- [Filter by namespace](filter-by-namespace.md)
- [RBAC model](../../concepts/rbac-model.md)
- [Policy evaluation](../../concepts/policy-evaluation.md)
