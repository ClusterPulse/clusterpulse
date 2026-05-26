# Enable Push-Mode Collection

Push mode runs a small collector agent on each managed cluster. The agent collects metrics in-cluster and streams them to the hub's gRPC ingester over a bidirectional channel. Use push mode when the hub can't reach the managed cluster's API server — typical for managed clusters behind NAT, in another VPC, or in a different security domain.

For pull mode (hub reaches out), see [Add an OpenShift cluster](add-openshift-cluster.md).

## What gets deployed

When a `ClusterConnection` has `collectionMode: push`, the hub controller uses the existing `credentialsRef` to bootstrap the agent on the managed cluster. On every successful reconcile, the hub ensures the following exist in the managed cluster:

- Namespace `clusterpulse-system`
- ServiceAccount `clusterpulse-collector`
- ClusterRole `clusterpulse-collector` (with `get`/`list`/`watch` on `*/*`)
- ClusterRoleBinding tying the SA to the role
- Secret holding the bearer token for ingester auth
- Deployment `clusterpulse-collector` (single replica)
- ConfigMap `ingester-ca` (only when ingester TLS is on and `useSystemCA` is false)

The collector then opens a long-lived gRPC stream to the hub's ingester, pushes metrics on the schedule it receives from the hub, and falls through to push-mode buffering during outages.

## Prerequisites

- Ingester enabled on the hub. The Helm/Operator option is `clusterEngine.ingester.enabled: true`. See [Configure ingester TLS](configure-ingester-tls.md) for the TLS setup that exposes the ingester externally — push mode over the public network requires TLS.
- The hub's ingester reachable from the managed cluster — usually an OpenShift Route on the hub.
- A `ClusterConnection`-style credentials secret on the hub whose token can:
    - Read everything the existing pull-mode setup reads (`cluster-reader` + `view`), **and**
    - Create namespaces, ServiceAccounts, ClusterRoles, ClusterRoleBindings, Secrets, and Deployments (to bootstrap `clusterpulse-system`).
  This is more permissive than pull mode's read-only SA. If you want to keep the long-running token read-only, create a separate bootstrap SA with `cluster-admin`, use it for the first reconcile, then swap the `credentialsRef` over to a read-only SA — once `clusterpulse-system` exists with its own SA, the hub's token is only used to update the Deployment manifest on subsequent reconciles. Practically, most installs just keep the bootstrap SA permissions in place.

## Step 1: Make sure the ingester is exposed

```bash
oc get route -n clusterpulse -l clusterpulse.io/component=ingester
```

If there's no Route (or no Service on the hub for the ingester), enable it via the `ClusterPulse` CR:

```yaml
spec:
  clusterEngine:
    ingester:
      enabled: true
      tls:
        enabled: true
      route:
        enabled: true
```

Then [Configure ingester TLS](configure-ingester-tls.md) Steps 2–3 to get the Route hostname.

## Step 2: Provision the credentials secret on the hub

If you already have a pull-mode `ClusterConnection` for the cluster, you can keep the same secret as long as the SA has the extra permissions described above. Otherwise follow the credentials steps from [Add an OpenShift cluster](add-openshift-cluster.md), but use a SA bound to a role that includes resource creation in `clusterpulse-system`.

A minimal extra ClusterRole:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: clusterpulse-bootstrap
rules:
  - apiGroups: [""]
    resources: ["namespaces", "serviceaccounts", "secrets"]
    verbs: ["get", "list", "create", "update", "patch"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles", "clusterrolebindings"]
    verbs: ["get", "list", "create", "update", "patch"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "create", "update", "patch"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "create", "update", "patch"]
```

Apply on the target, then bind it to your bootstrap SA in addition to `cluster-reader`/`view`.

## Step 3: Create the ClusterConnection in push mode

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: ClusterConnection
metadata:
  name: managed-cluster-1
  namespace: clusterpulse
spec:
  displayName: "Managed Cluster 1"
  endpoint: "https://api.managed.example.com:6443"
  credentialsRef:
    name: managed-cluster-1-creds
  labels:
    environment: production
    network: isolated
  collectionMode: push
  ingesterAddress: "clusterpulse-ingester-clusterpulse.apps.hub.example.com:443"
  monitoring:
    interval: 60
    timeout: 15
```

Two fields specific to push mode:

| Field | Purpose |
|---|---|
| `collectionMode: push` | Switches to push mode. Defaults to `pull` if omitted. |
| `ingesterAddress` | `host:port` of the hub ingester. Required when `collectionMode: push`. Use the OpenShift Route hostname on port 443 when ingester TLS is on. |
| `collectorVersion` (optional) | Pin the collector image tag (e.g. `0.4.2`). Defaults to the hub controller's own version. Use this when you want a managed cluster to lag behind a hub upgrade temporarily. |

Apply:

```bash
oc apply -f clusterconnection.yaml
```

## Step 4: Verify

On the hub:

```bash
oc get clusterconnection managed-cluster-1 -n clusterpulse -o yaml \
  | grep -A8 collectorStatus
```

The `status.collectorStatus` block fills in once the agent connects:

```yaml
status:
  collectorStatus:
    connected: true
    lastHeartbeat: "2026-05-26T10:30:00Z"
    version: "0.4.2"
```

On the managed cluster:

```bash
oc --context=managed get all -n clusterpulse-system

oc --context=managed logs -n clusterpulse-system deployment/clusterpulse-collector --tail=40
```

Expected log lines on a healthy startup:

- `Starting collector agent` with `cluster`, `ingester_address`, `tls_enabled`.
- `Connected to ingester`.
- `Sent metrics batch` (every collection interval).

## Edge cases

**`ingesterAddress` missing.** The reconciler returns `ingesterAddress is required when collectionMode is push` and the `ClusterConnection` stays in `phase: Error`. Add the field and re-apply.

**Agent connects, then disconnects.** The hub falls back to pull mode for that cluster: it pulls metrics over the API the way it would for a `pull`-mode connection. `collectorStatus.connected` flips to `false` and the cluster keeps reporting data — just less timely. The agent reconnects automatically with exponential backoff (caps at ~5 min).

**Stale cert after `service-ca` rotation.** Restart the hub manager pod (so it loads the new cert) and the collector Deployments will pick up the rotated CA on their next reconcile. Without the manager restart, collectors keep using the old CA in the `ingester-ca` ConfigMap.

**Pinned `collectorVersion`.** When the hub upgrades to a newer image but a managed cluster's `ClusterConnection` has `collectorVersion: 0.4.1`, the agent on that cluster stays on 0.4.1. Useful for staged rollouts. Drop the field to track the hub again.

**Bootstrap SA lacks permission.** First reconcile fails with a `cannot create` error on whichever resource was rejected (namespace, ClusterRoleBinding, etc.). Add the missing permission, re-trigger by editing the `ClusterConnection`.

**Multiple managed clusters with the same `cluster` name.** Each `ClusterConnection.metadata.name` becomes the collector's `CLUSTER_NAME` env var on the managed cluster. Make these unique per managed cluster, otherwise the ingester treats them as one and the most recent push wins.

## What the agent collects

Identical to pull mode plus a few items the agent can only get in-cluster:

- Node metrics (capacity, allocatable, usage, conditions, roles, IPs).
- Cluster metrics (counts of nodes / namespaces / pods / deployments, CPU + memory totals).
- Operators (OLM Subscriptions + CSVs) and ClusterOperators (OpenShift only).
- Cluster info (API URL, console URL, version, channel, platform, cluster ID).
- Any resources declared by `MetricSource` CRDs (the agent receives compiled MetricSource configs from the ingester over the same stream — no separate hub API access needed).

## Switching between modes

Pull → push: edit the `ClusterConnection`, set `collectionMode: push` and add `ingesterAddress`. The hub deploys the agent on the next reconcile. Pull-mode data continues until the agent connects; push-mode data takes over once it does.

Push → pull: edit the `ClusterConnection`, set `collectionMode: pull`, remove `ingesterAddress`. The agent Deployment on the managed cluster is **not** torn down automatically — clean it up by hand if you want it gone:

```bash
oc --context=managed delete namespace clusterpulse-system
```

## Troubleshooting

### `collectorStatus.connected: false` and no log entries in the agent

The agent can't reach `ingesterAddress`. Test from inside a pod on the managed cluster:

```bash
oc --context=managed run -it --rm test --image=alpine --restart=Never -- \
  sh -c 'apk add --no-cache openssl >/dev/null && openssl s_client -connect <route-host>:443 -servername <route-host>'
```

If that hangs or fails, it's a network/egress issue on the managed side. NetworkPolicy and egress firewalls are the usual culprits.

### Agent logs say "Unauthorized"

The bearer token in the `clusterpulse-collector` Secret is stale. The hub overwrites it on the next reconcile of the `ClusterConnection`; you can force a reconcile by editing the CR (`oc edit clusterconnection ...`).

### Agent crash-loops

```bash
oc --context=managed describe pod -n clusterpulse-system -l app=clusterpulse-collector
oc --context=managed logs -n clusterpulse-system -l app=clusterpulse-collector --previous
```

Common failure: TLS chain verification — see [Configure ingester TLS](configure-ingester-tls.md) troubleshooting.

### Metrics from a managed cluster look stale

`collectorStatus.lastHeartbeat` tells you when the agent last reported. If it's recent but the data is stale, look at the collection interval — `monitoring.interval` on the `ClusterConnection` only applies to pull-mode reconcile timing; the collector itself collects on `COLLECT_INTERVAL` (default 60s). Operator state has its own interval (`OPERATOR_SCAN_INTERVAL`, default 300s).
