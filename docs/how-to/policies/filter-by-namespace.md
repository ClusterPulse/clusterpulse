# Filter by Namespace

Restrict what namespaces (and the resources inside them) a user can see in a cluster by configuring a `MonitorAccessPolicy`.

When namespace filtering is applied:

- The namespace list returned for the cluster is filtered.
- Per-cluster counts (pods, deployments, services) are recomputed against only visible namespaces.
- Custom resources that the policy ties to the same namespace set are also filtered.

This guide assumes you've read [Create your first policy](create-first-policy.md).

## Minimal example

Allow `app-developers` to see only namespaces whose names start with `app-`:

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
      default: deny
      rules:
        - selector:
            matchPattern: ".*"
          permissions:
            view: true
            viewMetrics: true
          resources:
            - type: namespaces
              visibility: filtered
              filters:
                names:
                  allowed:
                    - "app-*"
```

Apply: `oc apply -f policy.yaml`.

> **Note:** `scope.clusters.default` accepts `allow`, `deny`, or `none` (CRD default `none`, which behaves like `deny`). It is **not** the same field as `resources[].visibility`, which accepts `all`/`none`/`filtered`.

## `visibility` options (per-resource)

| Value | Behaviour |
|---|---|
| `all` | No filtering on this resource type. Default if omitted. |
| `none` | Hide everything of this type. |
| `filtered` | Apply the `filters` block below. |

## Filter patterns

The `filters.names.allowed` and `filters.names.denied` fields take a mix of literals and wildcard patterns.

### Wildcards

`*` matches any run of characters, `?` matches exactly one:

```yaml
filters:
  names:
    allowed:
      - "app-*"        # app-frontend, app-backend, ...
      - "team-?-prod"  # team-a-prod, team-b-prod, ...
```

### Literals

```yaml
filters:
  names:
    allowed:
      - default
      - monitoring
      - logging
```

### Precedence

`denied` wins over `allowed`. The engine evaluates exclusions first, then inclusions:

```yaml
resources:
  - type: namespaces
    visibility: filtered
    filters:
      names:
        allowed:
          - "app-*"
        denied:
          - "app-internal"
          - "app-secrets"
```

Result: every `app-*` namespace except `app-internal` and `app-secrets`.

## Filtering related resources

When you restrict namespaces, you usually want pods (and any other namespace-scoped types you care about) restricted in lockstep. The engine doesn't infer this — list each type explicitly:

```yaml
resources:
  - type: namespaces
    visibility: filtered
    filters:
      names:
        allowed: ["app-*"]
  - type: pods
    visibility: filtered
    filters:
      namespaces:
        allowed: ["app-*"]
  - type: operators
    visibility: filtered
    filters:
      namespaces:
        allowed: ["app-*"]
```

> **Note on operators:** the `operators` filter restricts visibility based on the operator's *target* namespaces (from the CSV/Subscription). Operators that install into a single namespace are filtered cleanly. Operators with `AllNamespaces` install mode are visible whenever any matched namespace overlaps their target set, which in practice means they show up as long as you can see any namespace they manage.

## How metrics are affected

Cluster-level metric counts are recomputed from the visible namespaces:

| Metric | After filtering |
|---|---|
| `namespaces` | Count of visible namespaces. |
| `pods` | Pods in visible namespaces. |
| `pods_running` | Running pods in visible namespaces. |
| `deployments` | Deployments in visible namespaces. |
| `services` | Services in visible namespaces. |

The cluster response carries `filter_metadata` when filtering is active:

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

Custom resource aggregations are also recomputed by default — see [Grant custom resource access → Aggregation recomputation](grant-custom-resource-access.md#aggregation-recomputation).

## End-to-end example: team-scoped Allow

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
                  allowed:
                    - "alpha-*"
                    - "shared-*"
                  denied:
                    - "shared-admin"
            - type: pods
              visibility: filtered
              filters:
                namespaces:
                  allowed:
                    - "alpha-*"
                    - "shared-*"
```

This policy:

- Targets the `team-alpha` group at priority 100.
- Only matches clusters labelled `environment: production` (`default: deny` blocks the rest).
- Allows the `alpha-*` and `shared-*` namespaces, except `shared-admin`.
- Filters pods to the same namespace set.

## Filtering custom resources by namespace

Custom resources (types defined by `MetricSource`) follow the same pattern — list them by `type` (matching `MetricSource.spec.rbac.resourceTypeName`) and use `filters.namespaces`:

```yaml
resources:
  - type: pvc
    visibility: filtered
    filters:
      namespaces:
        allowed: ["app-*"]
        denied: ["kube-system"]
  - type: certificate
    visibility: filtered
    filters:
      namespaces:
        allowed: ["app-*"]
```

For the full set of options — name filters, field filters, aggregation visibility, and recomputation — see [Grant custom resource access](grant-custom-resource-access.md).

## Common patterns

### Exclude system namespaces

```yaml
filters:
  names:
    allowed: ["*"]
    denied:
      - kube-system
      - kube-public
      - kube-node-lease
      - "openshift-*"
```

### Two-team split

```yaml
filters:
  names:
    allowed:
      - "team-a-*"
      - "shared-*"
```

### Production read-only with explicit namespace allowlist

```yaml
filters:
  names:
    allowed:
      - "prod-frontend"
      - "prod-backend"
      - "prod-api"
```

## Verification

After applying:

```bash
ROUTE=$(oc get route clusterpulse -n clusterpulse -o jsonpath='{.spec.host}')

# What namespaces does the API return for the cluster?
curl -s "https://$ROUTE/api/v1/clusters/my-cluster/namespaces" | jq

# What does the engine think your effective permissions are?
curl -s "https://$ROUTE/api/v1/auth/permissions" | jq
```

`/auth/permissions` returns the per-cluster permissions and the resolved filters — useful when a policy looks correct on paper but isn't applying.

## Troubleshooting

### A namespace I expected to see isn't visible

1. Confirm the literal/pattern in `allowed` matches the namespace name exactly. The match is glob, not regex (with `?` matching one character and `*` matching any run).
2. Check `denied` — `denied` beats `allowed`. `openshift-*` is a common accidental exclusion.
3. Check for a higher-priority `Deny` policy via `/api/v1/auth/policies`.
4. Confirm the cluster itself is visible. If `scope.clusters.default: deny` (or `none`) and no rule selector matches the cluster, the user sees no namespaces at all.

### Pod count is zero but namespaces are visible

The `pods` resource entry probably doesn't include the same namespace set. Add an explicit `pods` filter mirroring the `namespaces` filter.

### Metric counts look wrong

Cluster-level counts (pods/deployments/services) are recomputed from visible namespaces every time `/api/v1/clusters/<name>` is fetched. If they look stale, decision caching is the usual culprit:

```bash
curl -X POST "https://$ROUTE/api/v1/auth/cache/clear"
```

(`RBAC_CACHE_TTL` is `0` by default — caching is off — but a non-default deployment may have it on.)

### Operators visible that shouldn't be

If you filtered `operators` by `namespaces` but a cluster-scoped operator is still visible, that's expected: operators with `AllNamespaces` install mode register against every namespace, so they overlap any allowed namespace. Add an explicit `names.denied` for the specific operator if you need to hide it.

## Next steps

- [Create your first policy](create-first-policy.md)
- [Grant custom resource access](grant-custom-resource-access.md)
- [Policy evaluation](../../concepts/policy-evaluation.md)
