# Add an OpenShift Cluster (Pull Mode)

Register an OpenShift cluster with ClusterPulse so the hub manager can collect metrics from it directly. This guide covers **pull mode** — the hub reaches the target cluster's API server and pulls data on a timer. For push mode (collector agent on the managed cluster), see [Enable push-mode collection](enable-push-mode.md).

Plain Kubernetes (non-OpenShift) targets work with the same steps; substitute `kubectl` for `oc` and use the standard service-account secret approach.

## Prerequisites

- `oc` (or `kubectl`) authenticated to the **target** cluster as `cluster-admin` (or a user with permissions to create service accounts and cluster role bindings).
- Network reachability from the hub's `cluster-controller` pod to the target cluster's API server. The hub doesn't need cluster-admin on the target; the service account it uses there will.
- ClusterPulse already installed on the hub (see [Installation](../../getting-started/installation.md)).

## Step 1: Create a service account on the target

```bash
oc create serviceaccount clusterpulse-reader -n kube-system
```

The namespace doesn't have to be `kube-system` — anywhere is fine — but `kube-system` is a reasonable home for an operational SA.

## Step 2: Grant the service account read permissions

`cluster-reader` plus `view` covers the common case (nodes/namespaces/pods/deployments plus the OLM API group used for operator discovery):

```bash
oc adm policy add-cluster-role-to-user cluster-reader \
  system:serviceaccount:kube-system:clusterpulse-reader

oc adm policy add-cluster-role-to-user view \
  system:serviceaccount:kube-system:clusterpulse-reader
```

If you've defined a `MetricSource` for a custom resource type (e.g., `certificates.cert-manager.io`), the service account needs `get` and `list` on that type too. Either bind a role that already grants it, or create a `ClusterRole` and `ClusterRoleBinding` granting `get`/`list` on the GVRs your MetricSources cover.

## Step 3: Mint a long-lived token

OpenShift 4.11+ no longer auto-populates a token in the service-account secret. Create a `Secret` of the dedicated type and let the controller fill it in:

```bash
oc apply -f - <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: clusterpulse-reader-token
  namespace: kube-system
  annotations:
    kubernetes.io/service-account.name: clusterpulse-reader
type: kubernetes.io/service-account-token
EOF
```

Wait until the controller populates the data (usually under a second), then extract it:

```bash
TOKEN=$(oc get secret clusterpulse-reader-token -n kube-system \
  -o jsonpath='{.data.token}' | base64 -d)
```

If `$TOKEN` is empty after waiting a few seconds, the token controller hasn't populated the secret yet. Re-run the `oc get` after a brief pause, or `oc describe secret clusterpulse-reader-token -n kube-system` to see if it's missing the annotation/type combination.

## Step 4: Get the CA certificate

```bash
oc get secret clusterpulse-reader-token -n kube-system \
  -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt
```

This is the cluster's serving CA — what the hub uses to verify the target's API server cert. If you'd rather pull it from your kubeconfig:

```bash
oc config view --minify --raw \
  -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' \
  | base64 -d > ca.crt
```

Either source works. If you skip `ca.crt` entirely, the hub will connect with TLS verification off — not recommended outside lab environments.

## Step 5: Get the API endpoint

```bash
API_SERVER=$(oc whoami --show-server)
echo "$API_SERVER"
# https://api.cluster.example.com:6443
```

The endpoint **must include the port** — `:6443` for OpenShift, `:443` for typical kubelet front-ends on managed Kubernetes. The controller doesn't add a default port.

## Step 6: Create the credentials secret on the hub

Switch contexts to the hub cluster:

```bash
oc create secret generic my-openshift-cluster-creds \
  --namespace clusterpulse \
  --from-literal=token="$TOKEN" \
  --from-file=ca.crt=ca.crt
```

The secret name doesn't need to be tied to the cluster name; the `ClusterConnection` in the next step references it explicitly. By default the secret must live in the same namespace as the `ClusterConnection` (`clusterpulse`); to put it elsewhere, set `credentialsRef.namespace`.

## Step 7: Create the ClusterConnection

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: ClusterConnection
metadata:
  name: my-openshift-cluster
  namespace: clusterpulse
spec:
  displayName: "Production OpenShift"
  endpoint: "https://api.cluster.example.com:6443"
  credentialsRef:
    name: my-openshift-cluster-creds
  labels:
    environment: production
    platform: openshift
  monitoring:
    interval: 30
    timeout: 10
```

Apply it:

```bash
oc apply -f clusterconnection.yaml
```

## Step 8: Verify

```bash
oc get clusterconnection my-openshift-cluster -n clusterpulse
```

```
NAME                   DISPLAY NAME          ENDPOINT                              STATUS      HEALTH    AGE
my-openshift-cluster   Production OpenShift  https://api.cluster.example.com:6443  Connected   healthy   30s
```

For the full status and any error message:

```bash
oc describe clusterconnection my-openshift-cluster -n clusterpulse
oc get clusterconnection my-openshift-cluster -n clusterpulse -o yaml
```

A healthy connection moves to `phase: Connected` and updates `lastSyncTime` on each reconciliation cycle.

## Configuration reference

### `ClusterConnection.spec`

| Field | Type | Required | Description |
|---|---|---|---|
| `displayName` | string | No | Human-readable name for the UI. |
| `endpoint` | string | Yes | Target API server URL including port. |
| `credentialsRef.name` | string | Yes | Name of the credentials secret. |
| `credentialsRef.namespace` | string | No | Namespace of the secret. Defaults to the `ClusterConnection`'s namespace. |
| `labels` | map | No | Free-form labels. Used by `MonitorAccessPolicy` selectors. |
| `monitoring.interval` | int32 | No | Reconciliation interval (seconds). Min 30, default 30. Values below 30 are clamped. |
| `monitoring.timeout` | int32 | No | Per-call timeout (seconds). Min 5, default 10. |
| `collectionMode` | enum | No | `pull` (default) or `push`. See [Enable push mode](enable-push-mode.md). |
| `ingesterAddress` | string | Push-only | Required when `collectionMode: push`. |
| `collectorVersion` | string | No | Image tag override for the collector agent (push mode only). |

### Credentials secret

| Key | Required | Description |
|---|---|---|
| `token` | Yes | Bearer token used in the `Authorization` header. |
| `ca.crt` | No | PEM-encoded CA. Without it, TLS verification is skipped — not safe outside trusted networks. |

## Edge cases

**Endpoint missing port.** The controller treats the URL literally. `https://api.cluster.example.com` (no port) will fail with a connection error. Use `:6443` for OpenShift, `:443` for most managed Kubernetes.

**Empty token secret.** The cluster reconciler logs `EmptyToken` and the `ClusterConnection` stays in `phase: Error`. The token controller hasn't populated the secret yet; wait or recreate.

**`monitoring.interval < 30`.** The CRD enforces a minimum of 30 on the kubebuilder validation marker for the underlying config; passing a smaller value either rejects the CRD or gets clamped at runtime depending on the path. Treat 30 as the floor.

**Insufficient permissions on the target.** Symptoms vary by what's missing:

- No `cluster-reader` → `nodes is forbidden` in the controller logs.
- No `view` against `operators.coreos.com` → operator counts stay at zero; nodes/namespaces look fine.
- No access to a `MetricSource`-defined GVR → that MetricSource shows `phase: Error` (or zero resources) for the cluster.

Test from the hub itself:

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "$API_SERVER/api/v1/namespaces?limit=1"

# Confirm what the SA can see directly from the target:
oc auth can-i --list \
  --as=system:serviceaccount:kube-system:clusterpulse-reader
```

**TLS verification failures.** If `oc get clusterconnection` shows a TLS error, the `ca.crt` doesn't match the certificate the API server is presenting. Re-extract from the target cluster (Step 4). For self-signed or rotated certs, regenerate the credentials secret on the hub.

**Non-OpenShift target.** Same steps with `kubectl` instead of `oc`. The `cluster-reader` ClusterRole isn't built in on every distribution — use `view` plus a custom role granting `get`/`list` on `nodes` if needed.

## Push mode

When the hub can't reach the target's API server (firewalled, behind NAT, in another VPC), use push mode: deploy a collector agent on the target that streams metrics out to the hub's ingester. See [Enable push-mode collection](enable-push-mode.md).

## Troubleshooting

### `phase: Error`, message says "connection refused"

The hub controller can't reach `endpoint`. Test from the cluster-controller pod:

```bash
oc exec -n clusterpulse deployment/clusterpulse-cluster-controller -- \
  wget -qO- --no-check-certificate "$ENDPOINT/healthz"
```

If this fails too, the issue is network — security group, NetworkPolicy, missing route, etc. Not a ClusterPulse problem.

### `phase: Error`, message mentions x509

Cert verification failed. Re-extract `ca.crt` from the target. If the API server cert is signed by a public CA, set `ca.crt` to the chain that includes it.

### `phase: Error`, message says "Unauthorized"

The token is rejected. Re-mint Step 3. Confirm the token isn't expired or revoked.

### Connection is healthy but the UI shows nothing

The `ClusterConnection` is fine, but no `MonitorAccessPolicy` grants the current user access to it. See [Create your first policy](../policies/create-first-policy.md).
