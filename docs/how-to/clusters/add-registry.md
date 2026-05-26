# Add a Container Registry

A `RegistryConnection` configures ClusterPulse to health-check a container registry and (optionally) scan its catalog. ClusterPulse uses the Docker Registry HTTP API V2 protocol — anything that exposes `/v2/` works (Docker Hub, Quay, Harbor, ECR, GCR, Artifactory, in-cluster registries, etc.).

The connection runs on a timer from the hub manager. Results are stored in Redis and served at `GET /api/v1/registries/status`.

## Prerequisites

- ClusterPulse running on the hub.
- Network reachability from the hub's `cluster-controller` pod to the registry.
- Optional: registry credentials in a Kubernetes secret if the registry requires auth.

## Step 1: (Optional) Create the credentials secret

Skip this step for a public registry that exposes `/v2/` anonymously.

```bash
oc create secret generic my-registry-creds \
  --namespace clusterpulse \
  --from-literal=username='reader' \
  --from-literal=password='REDACTED'
```

Keys must be exactly `username` and `password`. A dockerconfigjson secret won't work — the reconciler looks up these two keys directly.

## Step 2: Create the RegistryConnection

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: RegistryConnection
metadata:
  name: quay-prod
  namespace: clusterpulse
spec:
  displayName: "Quay Production"
  endpoint: "https://quay.example.com"
  type: quay
  credentialsRef:
    name: my-registry-creds
  monitoring:
    interval: 60
    timeout: 10
    checkCatalog: false
    maxCatalogEntries: 100
  labels:
    environment: production
```

```bash
oc apply -f registry.yaml
```

## Step 3: Verify

```bash
oc get registryconnection quay-prod -n clusterpulse
```

```
NAME        DISPLAY NAME       ENDPOINT                    TYPE   AVAILABLE   HEALTH    RESPONSE TIME   AGE
quay-prod   Quay Production    https://quay.example.com    quay   true        healthy   42              30s
```

Full status:

```bash
oc get registryconnection quay-prod -n clusterpulse -o yaml
```

Status fields:

| Field | Meaning |
|---|---|
| `phase` | `Connecting`, `Connected`, `Error`, `Unknown`. |
| `health` | `healthy`, `degraded`, `unhealthy`, `unknown`. |
| `available` | True if the last `/v2/` probe succeeded. |
| `responseTime` | Last probe latency in milliseconds. |
| `repositoryCount` | Catalog size — only populated when `checkCatalog: true`. |
| `version` | Registry version string if the implementation advertises one. |
| `features` | Map of detected capabilities (varies by implementation). |

Via the API:

```bash
ROUTE=$(oc get route clusterpulse -n clusterpulse -o jsonpath='{.spec.host}')
curl -s "https://$ROUTE/api/v1/registries/status" | jq
```

## Configuration reference

### `RegistryConnection.spec`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `displayName` | string | No | — | Human-readable name. |
| `endpoint` | string | Yes | — | Registry base URL (no trailing path). |
| `type` | string | No | — | Informational tag (`dockerhub`, `harbor`, `ecr`, `gcr`, `artifactory`, `quay`, ...). Doesn't change behaviour. |
| `credentialsRef` | object | No | — | Reference to a secret with `username`/`password` keys. |
| `insecure` | bool | No | `false` | Allow plaintext HTTP connections. |
| `skipTLSVerify` | bool | No | `false` | Skip TLS chain verification for self-signed certs. |
| `monitoring.interval` | int32 | No | `60` (min 30) | Seconds between health checks. |
| `monitoring.timeout` | int32 | No | `10` (min 5) | Per-request timeout. |
| `monitoring.checkCatalog` | bool | No | `false` | Probe `/v2/_catalog`. Requires extra permissions on most registries. |
| `monitoring.maxCatalogEntries` | int32 | No | `100` | Cap on catalog page size when `checkCatalog: true`. |
| `labels` | map | No | — | Free-form labels for categorisation. |
| `healthCheckPaths` | []string | No | `["/v2/"]` | Override the probed paths. Rarely needed. |

### Credentials secret

| Key | Required | Description |
|---|---|---|
| `username` | Yes | Registry user. |
| `password` | Yes | Registry password / token. For services that issue tokens (ECR, GCR), include the token here. |

## Examples

### Public Docker Hub mirror — no auth, no catalog scan

```yaml
spec:
  endpoint: "https://registry-1.docker.io"
  type: dockerhub
  monitoring:
    interval: 120
```

### Internal Harbor with self-signed cert

```yaml
spec:
  endpoint: "https://harbor.internal.example.com"
  type: harbor
  credentialsRef:
    name: harbor-reader-creds
  skipTLSVerify: true
  monitoring:
    interval: 60
    checkCatalog: true
    maxCatalogEntries: 500
```

### Plain-HTTP in-cluster registry

```yaml
spec:
  endpoint: "http://docker-registry.kube-system.svc.cluster.local:5000"
  insecure: true
  monitoring:
    interval: 30
```

## Edge cases

**`/v2/` returns 401.** The registry requires auth even for the version probe. The reconciler treats this as `phase: Connected, health: healthy` because reaching the auth challenge proves the registry is online. If you supply `credentialsRef`, the catalog probe will retry with auth.

**`/v2/` returns 404.** The registry isn't a Docker v2 registry. `phase: Error`, `health: unhealthy`. Double-check the endpoint URL — `/v2/` is the Registry HTTP API root; many UIs are reachable at the same hostname but `/v2/` redirects to a login page on the wrong port.

**Connection refused.** Either the registry is down or the hub can't reach it from inside the cluster. Test from the manager pod:

```bash
oc exec -n clusterpulse deployment/clusterpulse-cluster-controller -- \
  wget -qO- --no-check-certificate "$ENDPOINT/v2/"
```

**`checkCatalog` returns 401/403 but `/v2/` returns 200.** Most public registries don't allow anonymous catalog reads. Add credentials with catalog read permission, or set `checkCatalog: false`.

**`interval < 30`.** Clamped to 30 at runtime; the CRD validator also enforces a minimum.

**Catalog has more than `maxCatalogEntries` repositories.** Only the first page is read. `repositoryCount` reflects what was returned, not the actual total. Increase `maxCatalogEntries` if you need an accurate count; the API request size grows linearly.

**Multiple `RegistryConnection`s pointing at the same endpoint.** Allowed, but you'll do duplicate health-check work. Use one per logical registry; differentiate with `displayName` and `labels`.

## Troubleshooting

### `phase: Error`, message mentions x509

The registry's TLS cert can't be verified. Either:

- Supply the CA via cluster-wide trust (preferred), or
- Set `skipTLSVerify: true` (lab/temporary).

### `available: false` flapping between true/false

Network instability or a registry that's overloaded. Look at `responseTime` over time — if it spikes above `timeout`, the check fails. Bump `monitoring.timeout`.

### `repositoryCount` is zero on a populated registry

`checkCatalog` is off (the default), or the credentials don't have `registry:catalog:*` permission. Enable `checkCatalog: true` and confirm the SA/user can list the catalog from `curl`:

```bash
curl -u $USER:$PASS "$ENDPOINT/v2/_catalog?n=10"
```

### Status keeps showing the wrong `version` or `features`

The reconciler reads version and feature hints from the registry's response headers. Some implementations don't advertise them; an empty `version` is normal. The reconciler doesn't try to guess — it only reports what the registry returns.
