# Filter by Namespace

This guide explains how to configure `MonitorAccessPolicy` resources to restrict visibility to specific namespaces.

## Overview

Namespace filtering controls which namespaces a user can see within a cluster. When namespace filtering is applied:

- Namespace lists are filtered to show only permitted namespaces
- Pod, deployment, and service counts reflect only resources in permitted namespaces
- Cluster metrics are recalculated based on visible namespaces

## Basic Namespace Filter

The following policy allows access only to namespaces starting with `app-`:

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: MonitorAccessPolicy
metadata:
  name: app-namespace-access
  namespace: clusterpulse
spec:
  identity:
    priority: 100
    subjects:
      groups:
        - app-developers
  
  access:
    effect: Allow
    enabled: true
  
  scope:
    clusters:
      default: filtered
      rules:
        - selector:
            matchPattern: .*
          permissions:
            view: true
            viewMetrics: true
          resources:
            namespaces:
              visibility: filtered
              filters:
                allowed:
                  - "app-*"
```

## Visibility Options

The `visibility` field accepts three values:

| Value | Behavior |
|-------|----------|
| `all` | No filtering. User sees all namespaces. |
| `none` | Complete restriction. User sees no namespaces. |
| `filtered` | Apply include/exclude rules from `filters`. |

## Filter Patterns

### Wildcard Patterns

Use `*` to match any characters and `?` to match a single character:

```yaml
filters:
  allowed:
    - "app-*"        # Matches app-frontend, app-backend, etc.
    - "team-?-prod"  # Matches team-a-prod, team-b-prod, etc.
```

### Literal Values

Exact namespace names without wildcards:

```yaml
filters:
  allowed:
    - default
    - monitoring
    - logging
```

### Combining Allowed and Denied

The `denied` list takes precedence over `allowed`:

```yaml
resources:
  namespaces:
    visibility: filtered
    filters:
      allowed:
        - "app-*"
      denied:
        - "app-internal"
        - "app-secrets"
```

This configuration allows all `app-*` namespaces except `app-internal` and `app-secrets`.

## Complete Example: Team-Based Access

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: MonitorAccessPolicy
metadata:
  name: team-alpha-access
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
                  - "shared-*"
                denied:
                  - "shared-admin"
            pods:
              visibility: filtered
              filters:
                allowedNamespaces:
                  - "alpha-*"
                  - "shared-*"
```

## Filtering Related Resources

When filtering namespaces, you should also filter namespace-scoped resources to maintain consistency even though not explicitly necessary:

```yaml
resources:
  namespaces:
    visibility: filtered
    filters:
      allowed:
        - "app-*"
  
  pods:
    visibility: filtered
    filters:
      allowedNamespaces:
        - "app-*"
  
  operators:
    visibility: filtered
    filters:
      allowedNamespaces:
        - "app-*"
```

## Filtering Operators by Namespace

Operators can be filtered by the namespaces where they are available. Remember that cluster scoped (operators shown in every namespace) operators will always show:

```yaml
resources:
  operators:
    visibility: filtered
    filters:
      allowedNamespaces:
        - "operator-*"
        - monitoring
      deniedNames:
        - "*-test"
```

## How Metrics Are Affected

When namespace filtering is active, cluster metrics are recalculated:

| Metric | Behavior |
|--------|----------|
| `namespaces` | Count of visible namespaces only |
| `pods` | Count of pods in visible namespaces |
| `pods_running` | Running pods in visible namespaces |
| `deployments` | Deployments in visible namespaces |
| `services` | Services in visible namespaces |

The API response includes filtering metadata:

```json
{
  "metrics": {
    "namespaces": 5,
    "pods": 42,
    "filtered": true,
    "filter_metadata": {
      "allowed_namespaces": 5,
      "total_namespaces": 50
    }
  }
}
```

## Verification

### Check Allowed Namespaces via API

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://clusterpulse.example.com/api/v1/clusters/my-cluster/namespaces
```

### Check Filtered Metrics

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://clusterpulse.example.com/api/v1/clusters/my-cluster/metrics?detailed=true
```

The response includes `filter_details` when filtering is applied.

## Common Patterns

### Exclude System Namespaces

```yaml
filters:
  allowed:
    - "*"
  denied:
    - kube-system
    - kube-public
    - kube-node-lease
    - openshift-*
```

### Development Team Access

```yaml
filters:
  allowed:
    - "dev-*"
    - "staging-*"
  denied:
    - "*-secrets"
    - "*-internal"
```

### Production Read-Only with Limited Namespaces

```yaml
filters:
  allowed:
    - "prod-frontend"
    - "prod-backend"
    - "prod-api"
```

## Troubleshooting

### Namespace Not Visible

1. Verify the namespace name matches the allowed patterns exactly
2. Check that the namespace is not in the denied list
3. Confirm the policy is active and applies to the user

### Metrics Show Zero

If metrics show zero but namespaces exist:

1. Verify the pod filter matches the namespace filter
2. Check that `visibility` is set to `filtered`, not `none`

### Debug Policy Application

Use the auth endpoint to see effective permissions:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://clusterpulse.example.com/api/v1/auth/permissions
```

## Next Steps

- [Create Read-Only Policy](create-readonly-policy.md) - Basic policy creation
- [Policy Evaluation](../../concepts/policy-evaluation.md) - Understand how policies are evaluated
