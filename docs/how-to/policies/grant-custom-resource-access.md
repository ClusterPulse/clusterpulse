# Grant Custom Resource Access

This guide covers configuring `MonitorAccessPolicy` resources to control access to custom resources collected by MetricSource.

## Overview

Custom resources use **implicit deny**. A user cannot see any MetricSource-defined resource type unless a policy explicitly grants access. This provides a secure default — new MetricSource types are invisible until an administrator creates a policy for them.

The `custom` section under `resources` maps each resource type (by its `resourceTypeName`) to visibility and filter rules.

## Prerequisites

- At least one `MetricSource` deployed with an `rbac.resourceTypeName` configured
- Familiarity with `MonitorAccessPolicy` basics (see [Create Read-Only Policy](create-readonly-policy.md))

## Grant Full Access to a Custom Type

The simplest case — grant unrestricted read access to a custom resource type:

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
      default: all
      rules:
        - selector:
            matchPattern: .*
          permissions:
            view: true
            viewMetrics: true
          resources:
            custom:
              pvc:
                visibility: all
```

The `pvc` key must match the `rbac.resourceTypeName` in your MetricSource definition.

## Filter by Namespace

Restrict which namespaces a user can see resources from:

```yaml
resources:
  custom:
    pvc:
      visibility: filtered
      filters:
        namespaces:
          allowed:
            - "app-*"
            - "shared-*"
          denied:
            - "shared-admin"
```

`denied` takes precedence over `allowed`. Wildcards (`*`, `?`) are supported.

## Filter by Resource Name

Restrict which individual resources are visible:

```yaml
resources:
  custom:
    certificate:
      visibility: filtered
      filters:
        names:
          allowed:
            - "public-*"
          denied:
            - "*-internal"
```

## Filter by Field Values

Filter resources by the values of extracted fields. Only fields listed in the MetricSource's `rbac.filterableFields` can be used.

### Pattern Matching

```yaml
resources:
  custom:
    pvc:
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

### Operator-Based Conditions

For numeric or complex comparisons, use `conditions`:

```yaml
resources:
  custom:
    pvc:
      visibility: filtered
      filters:
        fields:
          storageBytes:
            conditions:
              - operator: greaterThan
                value: 1073741824
              - operator: lessThan
                value: 10737418240
```

Supported operators: `equals`, `notEquals`, `contains`, `startsWith`, `endsWith`, `greaterThan`, `lessThan`, `in`, `notIn`, `matches`.

## Control Aggregation Visibility

Policies can restrict which aggregations a user sees. This is independent of aggregation recomputation — it controls the names exposed, not the values.

### Include List (Whitelist)

Only these aggregations are visible:

```yaml
resources:
  custom:
    pvc:
      visibility: all
      aggregations:
        include:
          - total_pvcs
          - by_storage_class
```

### Exclude List (Blacklist)

Hide specific aggregations:

```yaml
resources:
  custom:
    pvc:
      visibility: all
      aggregations:
        exclude:
          - cost_estimate
```

`include` takes precedence — if both are set, only `include` is applied.

## Combining Multiple Filters

Filters are evaluated in order: namespace, then name, then fields. A resource must pass all filters to be visible:

```yaml
resources:
  custom:
    pvc:
      visibility: filtered
      filters:
        namespaces:
          allowed:
            - "prod-*"
        names:
          denied:
            - "*-temp"
        fields:
          phase:
            allowed:
              - "Bound"
          storageClass:
            allowed:
              - "gp3"
      aggregations:
        include:
          - total_pvcs
          - total_capacity
```

This policy shows only PVCs that are:
- In namespaces matching `prod-*`
- Not named `*-temp`
- In `Bound` phase
- Using `gp3` storage class

And only the `total_pvcs` and `total_capacity` aggregations are visible.

## Multiple Custom Types in One Policy

Grant access to multiple types with different rules:

```yaml
resources:
  custom:
    pvc:
      visibility: all
    certificate:
      visibility: filtered
      filters:
        namespaces:
          allowed:
            - "app-*"
    cronjob:
      visibility: filtered
      filters:
        fields:
          schedule:
            denied:
              - "* * * * *"
```

Types not listed remain invisible (implicit deny).

## Complete Example

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
      default: filtered
      rules:
        - selector:
            environment: production
          permissions:
            view: true
            viewMetrics: true
          resources:
            namespaces:
              visibility: filtered
              filters:
                allowed:
                  - "alpha-*"
            custom:
              pvc:
                visibility: filtered
                filters:
                  namespaces:
                    allowed:
                      - "alpha-*"
                  fields:
                    storageClass:
                      allowed:
                        - "gp3"
                aggregations:
                  include:
                    - total_pvcs
                    - total_capacity
                    - by_storage_class
              certificate:
                visibility: all
```

## Aggregation Recomputation

When a MetricSource has `rbac.filterAggregations: true` (the default), aggregation values are automatically recomputed from the user's filtered resource set. For example, if a user can only see PVCs in `alpha-*` namespaces, the `total_pvcs` count reflects only those PVCs — not the cluster total.

This is separate from aggregation visibility. Even with recomputation, a policy can further hide specific aggregation names using `aggregations.include` or `aggregations.exclude`.

## Verification

### List Accessible Types

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  https://clusterpulse.example.com/api/v1/custom-types | jq
```

Only types granted by the user's policy are returned.

### Check Filtered Resources

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  https://clusterpulse.example.com/api/v1/clusters/my-cluster/custom/pvc | jq
```

### Check Aggregations

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://clusterpulse.example.com/api/v1/custom-types/clusters?type=pvc&include_aggregations=true" | jq
```

## Troubleshooting

### Custom Type Not Visible

1. Verify the MetricSource exists and has `rbac.resourceTypeName` set
2. Confirm the policy includes the type in `resources.custom` with `visibility` not set to `none`
3. Check that the policy applies to the user (correct subjects, priority, enabled)

### Resources Filtered More Than Expected

1. Review namespace, name, and field filters — all must pass
2. Check for higher-priority `Deny` policies
3. Use the permissions endpoint to see effective rules:
   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" \
     https://clusterpulse.example.com/api/v1/auth/permissions | jq
   ```

### Aggregations Missing

1. Verify the aggregation name matches the MetricSource definition
2. Check if the policy uses `aggregations.include` — unlisted names are hidden
3. Confirm `filterAggregations` is not causing empty results (no resources match after filtering)

## Next Steps

- [Create a MetricSource](../metricsources/create-metricsource.md) - Define the resource type to collect
- [Filter by Namespace](filter-by-namespace.md) - Namespace filtering for built-in and custom resources
- [RBAC Model](../../concepts/rbac-model.md) - Full RBAC architecture reference
- [Policy Evaluation](../../concepts/policy-evaluation.md) - How policies are evaluated
