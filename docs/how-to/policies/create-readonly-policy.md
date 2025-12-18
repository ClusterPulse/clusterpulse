# Create a Read-Only Policy

This guide demonstrates how to create a `MonitorAccessPolicy` that grants read-only access to cluster resources.

## Prerequisites

- ClusterPulse installed and running
- `kubectl` access to the cluster
- Appropriate RBAC permissions to create `MonitorAccessPolicy` resources

## Basic Read-Only Policy

The following policy grants view-only access to all clusters for members of the `cluster-viewers` group:

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: MonitorAccessPolicy
metadata:
  name: readonly-viewers
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
      default: all
      rules:
        - selector:
            matchPattern: .*
          permissions:
            view: true
            viewMetrics: true
            exec: false
            portForward: false
            logs: false
```

Apply the policy:

```bash
kubectl apply -f readonly-viewers.yaml
```

## Read-Only Policy for Specific Users

To grant read-only access to specific users instead of groups:

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: MonitorAccessPolicy
metadata:
  name: readonly-users
  namespace: clusterpulse
spec:
  identity:
    priority: 100
    subjects:
      users:
        - alice@example.com
        - bob@example.com
  
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
```

## Read-Only Access to Specific Clusters

Restrict read-only access to clusters matching specific criteria:

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: MonitorAccessPolicy
metadata:
  name: readonly-production
  namespace: clusterpulse
spec:
  identity:
    priority: 100
    subjects:
      groups:
        - production-viewers
  
  access:
    effect: Allow
    enabled: true
  
  scope:
    clusters:
      default: none
      rules:
        - selector:
            environment: production
          permissions:
            view: true
            viewMetrics: true
```

The `default: none` setting ensures users only see clusters that explicitly match the selector rules.

## Verification

After applying the policy, verify it was compiled successfully:

```bash
kubectl get monitoraccesspolicy readonly-viewers -n clusterpulse -o yaml
```

Check the `status` section:

```yaml
status:
  state: Active
  message: Policy is active
  compiledAt: "2024-01-15T10:30:00Z"
  affectedUsers: 0
  affectedGroups: 1
```

## Troubleshooting

### Policy Not Taking Effect

1. Verify the policy state is `Active`:
   ```bash
   kubectl get monitoraccesspolicy -n clusterpulse
   ```

2. Check the policy controller logs:
   ```bash
   kubectl logs -n clusterpulse deployment/policy-controller
   ```

3. Verify the user's group membership matches the policy subjects.

### Conflicting Policies

When multiple policies apply to a user, they are evaluated by priority (lower values first). The first matching `Allow` or `Deny` policy determines access.

To debug policy evaluation, use the `/api/v1/auth/policies` endpoint to see which policies apply to the current user.

## Next Steps

- [Filter by Namespace](filter-by-namespace.md) - Restrict access to specific namespaces
- [RBAC Basics Tutorial](../../tutorials/rbac-basics.md) - Learn the fundamentals of ClusterPulse RBAC
