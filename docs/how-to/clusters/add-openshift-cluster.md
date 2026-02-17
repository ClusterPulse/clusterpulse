# Add an OpenShift Cluster

This guide covers connecting an OpenShift cluster to ClusterPulse for monitoring.

## Prerequisites

- `oc` CLI installed and authenticated to the target OpenShift cluster
- `cluster-admin` or equivalent permissions on the target cluster
- ClusterPulse deployed and running

## Step 1: Create a Service Account

Create a service account on the target cluster that ClusterPulse will use for authentication.

```bash
oc create serviceaccount clusterpulse-reader -n kube-system
```

## Step 2: Assign Permissions

Bind the `cluster-reader` ClusterRole to the service account. This grants read-only access to cluster resources.

```bash
oc adm policy add-cluster-role-to-user cluster-reader \
  system:serviceaccount:kube-system:clusterpulse-reader
```

For collecting operator information via OLM, add view permissions for the `operators.coreos.com` API group:

```bash
oc adm policy add-cluster-role-to-user view \
  system:serviceaccount:kube-system:clusterpulse-reader
```

## Step 3: Generate a Long-Lived Token

OpenShift 4.11+ requires explicit token creation. Create a secret to hold the service account token:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: clusterpulse-reader-token
  namespace: kube-system
  annotations:
    kubernetes.io/service-account.name: clusterpulse-reader
type: kubernetes.io/service-account-token
```

Apply the secret:

```bash
oc apply -f - <<EOF
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

Wait a few seconds for the token to be populated, then extract it:

```bash
TOKEN=$(oc get secret clusterpulse-reader-token -n kube-system \
  -o jsonpath='{.data.token}' | base64 -d)
```

## Step 4: Extract the CA Certificate

Retrieve the cluster CA certificate:

```bash
oc get secret clusterpulse-reader-token -n kube-system \
  -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt
```

## Step 5: Get the API Server Endpoint

```bash
API_SERVER=$(oc whoami --show-server)
echo $API_SERVER
```

## Step 6: Create the Credentials Secret in ClusterPulse

Switch to the cluster where ClusterPulse is deployed and create a secret containing the credentials:

```bash
oc create secret generic my-openshift-cluster-creds \
  --namespace clusterpulse \
  --from-literal=token="$TOKEN" \
  --from-file=ca.crt=ca.crt
```

## Step 7: Create the ClusterConnection Resource

Create a `ClusterConnection` custom resource to register the cluster:

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
    namespace: clusterpulse
  labels:
    environment: production
    platform: openshift
  monitoring:
    interval: 30
    timeout: 10
```

Apply the resource:

```bash
oc apply -f clusterconnection.yaml
```

## Step 8: Verify the Connection

Check the status of the ClusterConnection:

```bash
oc get clusterconnection my-openshift-cluster -n clusterpulse
```

Expected output:

```
NAME                   DISPLAY NAME          ENDPOINT                              STATUS      HEALTH    AGE
my-openshift-cluster   Production OpenShift  https://api.cluster.example.com:6443  Connected   healthy   30s
```

For detailed status:

```bash
oc describe clusterconnection my-openshift-cluster -n clusterpulse
```

## Configuration Reference

### ClusterConnection Spec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `displayName` | string | No | Human-readable name shown in the UI |
| `endpoint` | string | Yes | API server URL including port |
| `credentialsRef.name` | string | Yes | Name of the credentials secret |
| `credentialsRef.namespace` | string | No | Namespace of the secret (defaults to ClusterConnection namespace) |
| `labels` | map | No | Key-value pairs for categorization |
| `monitoring.interval` | int32 | No | Reconciliation interval in seconds (minimum 30, default 30) |
| `monitoring.timeout` | int32 | No | Connection timeout in seconds (minimum 5, default 10) |
| `collectorVersion` | string | No | Overrides the collector agent image tag for this cluster. Defaults to the controller's own version. |

### Credentials Secret Format

The secret must contain:

| Key | Required | Description |
|-----|----------|-------------|
| `token` | Yes | Bearer token for API authentication |
| `ca.crt` | No | CA certificate for TLS verification. If omitted, TLS verification is skipped. |

## Troubleshooting

### Connection Test Failed

Check that the token is valid:

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "$API_SERVER/api/v1/namespaces?limit=1"
```

### Certificate Verification Errors

Ensure the CA certificate matches the cluster. Re-extract it from the service account secret or retrieve it from the cluster:

```bash
oc config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d
```

### Insufficient Permissions

Verify the service account has the required roles:

```bash
oc auth can-i --list --as=system:serviceaccount:kube-system:clusterpulse-reader
```

The service account needs at minimum:
- `get`, `list`, `watch` on nodes, namespaces, pods, deployments, services, statefulsets, daemonsets
- `get`, `list` on clusterversions, clusteroperators (for OpenShift-specific features)
- `get`, `list` on subscriptions, clusterserviceversions (for OLM operator discovery)
