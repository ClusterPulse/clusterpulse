# Create Your First Policy

A `MonitorAccessPolicy` is the CRD that controls what data ClusterPulse serves to whom. Until at least one matching `Allow` policy exists, the API returns nothing to a given user — the default is implicit deny.

This guide walks through writing, applying, verifying, and iterating on a basic policy. It uses an Allow-with-view-permissions policy because that's what the first policy in any installation looks like. More restrictive patterns (namespace filters, custom resources, deny rules) are covered in the follow-up guides linked at the bottom.

## What a policy looks like

A `MonitorAccessPolicy` has four spec sections:

| Section | Purpose |
|---|---|
| `identity` | Who the policy applies to (users / groups / service accounts) and its evaluation priority. |
| `access` | The effect (`Allow` or `Deny`) and whether the policy is `enabled`. |
| `scope` | What clusters and resources the policy covers. |
| `lifecycle` | Optional `notBefore` / `notAfter` time bounds. |

The full schema is in [`api/v1alpha1/monitoraccesspolicy_types.go`](https://github.com/ClusterPulse/clusterpulse/blob/main/api/v1alpha1/monitoraccesspolicy_types.go); the rendered reference is in [Concepts → RBAC Model](../../concepts/rbac-model.md).

## Prerequisites

- ClusterPulse running on the hub.
- `oc` (or `kubectl`) authenticated against the hub with permission to create `MonitorAccessPolicy` resources in the install namespace (usually `clusterpulse`).
- At least one `ClusterConnection` registered — otherwise the policy is valid but doesn't grant access to anything in particular.
- A test user or group you can apply policies to.

## Step 1: Look at what already exists

```bash
oc get monitoraccesspolicies -n clusterpulse
```

```
NAME              STATE    EFFECT   PRIORITY   USERS   AGE
default-admin     Active   Allow    10000      1       5d
```

Inspect one for reference:

```bash
oc get monitoraccesspolicy default-admin -n clusterpulse -o yaml
```

The columns in `oc get` come from the CRD's `printcolumn` markers — they reflect the live status (`affectedUsers`, `affectedGroups`).

## Step 2: Write a policy

Create `policy.yaml`:

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: MonitorAccessPolicy
metadata:
  name: viewers
  namespace: clusterpulse
spec:
  identity:
    priority: 100
    subjects:
      groups:
        - cluster-viewers
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
```

What each piece does:

- `identity.priority: 100` — higher numbers evaluate first. Range is 1–10000; CRD default is 100. The first `Allow` or `Deny` decision wins, so leave room above and below 100 for overrides you might add later.
- `identity.subjects.groups: [cluster-viewers]` — the policy applies to anyone in the `cluster-viewers` OpenShift group. To target individuals, use `subjects.users: [alice@example.com, bob@example.com]`. Service accounts use `subjects.serviceAccounts: [{name: foo, namespace: bar}]`.
- `access.effect: Allow` — the alternative is `Deny`, which short-circuits evaluation when it matches.
- `access.enabled: true` — set to `false` to deactivate the policy without deleting it. Disabled policies are not indexed for any subject.
- `scope.clusters.default: allow` — accepted values are `allow`, `deny`, `none`. `none` (CRD default) behaves like `deny`. `allow` makes every cluster accessible unless a rule restricts it. `deny`/`none` make only the clusters matched by `rules` accessible.
- `rules[0].selector.matchPattern: ".*"` — matches every cluster name. Other selector options: `matchNames: [a, b]` (exact name or wildcard), `matchLabels: {env: prod}`.
- `permissions.view: true` — basic visibility.
- `permissions.viewMetrics: true` — adds access to metrics (CPU/memory/etc.).

Apply it:

```bash
oc apply -f policy.yaml
```

## Step 3: Verify compilation

The manager compiles policies into Redis as soon as they're applied. Check the status:

```bash
oc get monitoraccesspolicy viewers -n clusterpulse \
  -o jsonpath='{.status}' | jq
```

Expected:

```json
{
  "state": "Active",
  "message": "Policy is active",
  "compiledAt": "2026-05-26T10:30:00Z",
  "hash": "a1b2c3d4e5f6",
  "affectedGroups": 1,
  "evaluationCount": 0
}
```

What to look for:

| Field | Meaning |
|---|---|
| `state: Active` | Compiled, indexed, currently in effect. Other states: `Pending` (just submitted), `Inactive` (`enabled: false`), `Expired` (past `notAfter`), `Error` (compile failure — see `message`). |
| `hash` | First 16 hex of SHA-256 over the spec. Changes when the spec changes; status-only updates don't trigger a recompile. |
| `affectedUsers` / `affectedGroups` / `affectedServiceAccounts` | Counts from the compiled subjects list, useful as a smoke test that you typed the subject names right. |
| `compiledAt` | When the compile last finished. Should advance every time you change the spec. |

If `state` is `Error`, the policy didn't compile. Look at the manager logs:

```bash
oc logs -n clusterpulse deployment/clusterpulse-cluster-controller | grep viewers
```

Common compile errors: invalid priority (outside 1–10000), unknown `effect`, malformed `notBefore`/`notAfter` time strings, custom resource type that doesn't match any `MetricSource.spec.rbac.resourceTypeName`.

## Step 4: Verify the policy applies to you (via the API)

The API exposes endpoints that show the engine's view of the current request.

```bash
# Adjust the host to wherever the ClusterPulse Route is exposed.
ROUTE=$(oc get route clusterpulse -n clusterpulse -o jsonpath='{.spec.host}')

# Who does the API think you are?
curl -s "https://$ROUTE/api/v1/auth/me" | jq

# Which policies apply to you, sorted highest priority first?
curl -s "https://$ROUTE/api/v1/auth/policies" | jq

# What does that resolve to per cluster?
curl -s "https://$ROUTE/api/v1/auth/permissions" | jq
```

If `/auth/policies` returns an empty list, the policy doesn't apply to you. Most common reasons:

- The group you named in `subjects.groups` isn't one of your groups. Check `/auth/me` for the groups the API resolved.
- The policy is disabled (`access.enabled: false`).
- The policy is expired (look at `lifecycle.validity` and `status.state`).

## Step 5: Iterate

Tighten the policy so it only matches development clusters by label:

```yaml
spec:
  identity:
    priority: 100
    subjects:
      groups:
        - cluster-viewers
  access:
    effect: Allow
    enabled: true
  scope:
    clusters:
      default: deny
      rules:
        - selector:
            matchLabels:
              environment: development
          permissions:
            view: true
            viewMetrics: true
```

```bash
oc apply -f policy.yaml
```

Effect: `default: deny` (or `none`, equivalent) means rules are the only way to access anything. Users in `cluster-viewers` only see `ClusterConnection`s with the label `environment: development`.

To verify, re-call `/api/v1/clusters` — only matching clusters should appear.

## Step 6: Add resource filtering

Restrict the policy to specific namespaces within the matched clusters:

```yaml
spec:
  identity:
    priority: 100
    subjects:
      groups:
        - cluster-viewers
  access:
    effect: Allow
    enabled: true
  scope:
    clusters:
      default: deny
      rules:
        - selector:
            matchLabels:
              environment: development
          permissions:
            view: true
            viewMetrics: true
          resources:
            - type: namespaces
              visibility: filtered
              filters:
                names:
                  allowed: ["app-*", "default"]
                  denied: ["app-internal"]
            - type: pods
              visibility: filtered
              filters:
                namespaces:
                  allowed: ["app-*", "default"]
```

Each `resources[]` entry's `visibility` is one of:

- `all` — show every instance of this resource type (the default if omitted on a rule that matches).
- `none` — show nothing of this type.
- `filtered` — apply the `filters` block. `denied` patterns beat `allowed` patterns. Wildcards `*` and `?` are supported.

For full filter semantics, see [Filter by namespace](filter-by-namespace.md).

## Step 7: Grant custom resource access

Custom resources collected by `MetricSource` use implicit deny — they're invisible unless explicitly granted. Add a `resources[]` entry with `type` set to the MetricSource's `rbac.resourceTypeName`:

```yaml
          resources:
            - type: namespaces
              visibility: filtered
              filters:
                names: { allowed: ["app-*"] }
            - type: pvc
              visibility: filtered
              filters:
                namespaces: { allowed: ["app-*"] }
                fields:
                  phase: { allowed: ["Bound"] }
```

The `fields` filter can only reference field names listed in the MetricSource's `spec.rbac.filterableFields`. See [Grant custom resource access](grant-custom-resource-access.md) for the full set of options including aggregation visibility.

Verify it took effect:

```bash
curl -s "https://$ROUTE/api/v1/custom-types" | jq
# pvc should now appear in the list

curl -s "https://$ROUTE/api/v1/clusters/<cluster>/custom/pvc" | jq
# only PVCs in app-* namespaces with phase=Bound should be returned
```

## Step 8: Clean up

```bash
oc delete monitoraccesspolicy viewers -n clusterpulse
```

Deletion clears the policy's Redis indexes (subjects, custom resource types, the by-priority sorted set) and invalidates the decision cache for every subject named in the previous compilation. The next API request from those subjects re-evaluates from scratch.

## Quick reference

### Priority

- Range: 1–10000.
- Higher numbers evaluate first (`ZRevRange` over the priority sorted set).
- First matching `Allow` or `Deny` wins — `Deny` short-circuits.

### Effect

| Effect | Behaviour |
|---|---|
| `Allow` | Grants access using the matching rule's `permissions` + `resources`. |
| `Deny` | Blocks access on match. Use higher priority than the `Allow`s you want to override. |

### Subject types

| Type | Spec | Example |
|---|---|---|
| Users | `subjects.users[]` | `alice@example.com` |
| Groups | `subjects.groups[]` | `cluster-viewers` |
| Service accounts | `subjects.serviceAccounts[]` (objects with `name` + `namespace`) | `{name: monitoring-sa, namespace: monitoring}` |

### `scope.clusters.default`

| Value | Behaviour |
|---|---|
| `allow` | Every cluster is reachable unless a rule overrides. |
| `deny` | Only clusters matched by `rules` are reachable. |
| `none` | CRD default. Same as `deny`. |

### `visibility` (per-resource)

| Value | Behaviour |
|---|---|
| `all` | No filtering. Default if omitted. |
| `none` | Hide everything of this type. |
| `filtered` | Apply the `filters` block. |

## Troubleshooting

### Policy is `Active` but I see nothing

1. `curl /api/v1/auth/me` — verify the group(s) and username the API resolved. If your group isn't there, the OAuth proxy or the OpenShift `User`/`Group` CR isn't producing the right membership.
2. `curl /api/v1/auth/policies` — verify the policy applies.
3. Check for a higher-priority `Deny` in the same response. `Deny` wins.

### Policy is `Active` but stale

The compile is keyed on `metadata.generation`. Status-only updates don't trigger a recompile. If you suspect the cached compiled policy is wrong:

```bash
curl -X POST "https://$ROUTE/api/v1/auth/cache/clear"
```

This clears `rbac:decision:*` and `rbac:custom:*` for the calling user.

### Policy stuck in `Error`

Look at `.status.message` first — it usually names the validation failure. Then the manager logs as in Step 3. Most failures are:

- Priority outside 1–10000.
- Unknown `effect`.
- Bad `notBefore` / `notAfter` (must be RFC3339).
- `resources[]` entry referencing a custom resource type not defined by any `MetricSource`.

### Custom resource type not visible

1. Confirm the `MetricSource` exists and has `spec.rbac.resourceTypeName` set.
2. Confirm the policy's `resources[].type` exactly matches that name.
3. `visibility: none` (or implicit absence from `resources[]`) hides it; use `all` or `filtered`.

## Next steps

- [Filter by namespace](filter-by-namespace.md)
- [Grant custom resource access](grant-custom-resource-access.md)
- [RBAC model](../../concepts/rbac-model.md)
- [Policy evaluation](../../concepts/policy-evaluation.md)
