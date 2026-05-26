# Configure Ingester TLS

The ingester is the gRPC server that accepts push-mode collector connections. When the ingester is exposed via an OpenShift Route, the Route is configured as **passthrough TLS** and the ingester terminates TLS itself. This guide covers enabling TLS on the ingester and pointing collectors at it. For the rest of the push-mode setup, see [Enable push-mode collection](enable-push-mode.md).

## Prerequisites

- ClusterPulse running on the hub.
- For the default flow: an OpenShift cluster with the `service-ca` operator (i.e., any standard OpenShift install). For non-OpenShift hubs, see the [Non-OpenShift](#non-openshift-hubs) section.
- `oc` authenticated to the hub with cluster-admin.

## Why passthrough TLS

gRPC requires HTTP/2 end-to-end. OpenShift's HAProxy router uses HTTP/1.1 on the backend leg of a re-encrypt route, which breaks gRPC. Passthrough avoids this — the router forwards raw TCP using SNI, and the ingester terminates TLS using its own certificate.

The cert that the ingester serves comes from OpenShift's `service-ca` (or a custom CA you supply). Its SAN is the in-cluster service FQDN (`clusterpulse-ingester.<namespace>.svc`), not the Route hostname collectors actually connect to. The collector handles this by setting `tls.Config.InsecureSkipVerify=true` and supplying a `VerifyConnection` callback that re-runs chain verification against the service FQDN. This is a [supported pattern in the Go standard library](https://pkg.go.dev/crypto/tls#Config): when `InsecureSkipVerify` is set, `VerifyConnection` still runs, so full chain verification is still performed — just against the service name rather than the route hostname. The controller derives `INGESTER_TLS_SERVER_NAME` automatically and injects it into the collector Deployment.

## Step 1: Enable on the ClusterPulse CR

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

This single change provisions the ingester Service (with the `service.beta.openshift.io/serving-cert-secret-name` annotation), the passthrough Route, the `ingester-ca` ConfigMap, the TLS volume mount on the manager pod, and the `INGESTER_TLS_*` env vars. No manual manifests required.

## Step 2: Get the Route hostname

```bash
ROUTE_HOST=$(oc get route -n clusterpulse \
  -l clusterpulse.io/component=ingester \
  -o jsonpath='{.items[0].spec.host}')
echo "$ROUTE_HOST"
```

If you have multiple ClusterPulse releases in the same namespace, scope by release: `oc get route <release-name>-ingester -n clusterpulse -o jsonpath='{.spec.host}'`.

## Step 3: Point each push-mode ClusterConnection at the Route

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: ClusterConnection
metadata:
  name: managed-cluster-1
  namespace: clusterpulse
spec:
  collectionMode: push
  ingesterAddress: "<route-host>:443"
  # ...other fields
```

Port 443 externally, regardless of the in-cluster port (the Route maps 443 to the Service's 9443 port).

The cluster controller then:

1. Copies the `ingester-ca` ConfigMap to the managed cluster (in `clusterpulse-system`).
2. Mounts it in the collector Deployment.
3. Sets `INGESTER_TLS_ENABLED=true`, `INGESTER_TLS_CA=/etc/ingester-ca/service-ca.crt`, and `INGESTER_TLS_SERVER_NAME=<in-cluster-fqdn>` on the collector.

## Verification

Probe the Route directly from a workstation:

```bash
openssl s_client -connect "$ROUTE_HOST:443" -servername "$ROUTE_HOST" </dev/null
```

You should see a TLS handshake and the ingester's certificate chain (SAN names will be `clusterpulse-ingester.<ns>.svc` and variants — that's correct).

Then check the collector logs on the managed cluster:

```bash
oc --context=managed logs -n clusterpulse-system deployment/clusterpulse-collector
```

Look for:

- `Connected to ingester` — handshake worked.
- `Using custom TLS server name for certificate verification` — the controller-supplied `INGESTER_TLS_SERVER_NAME` is in effect.

## Environment variables

These are the underlying env vars the operator sets on your behalf. You only touch them directly if you're running outside the operator.

| Variable | Component | Default | Description |
|---|---|---|---|
| `INGESTER_TLS_ENABLED` | Manager + Collector | `false` | Enable TLS on the ingester. |
| `INGESTER_TLS_CERT` | Manager | `/etc/ingester-tls/tls.crt` | Path to serving certificate. |
| `INGESTER_TLS_KEY` | Manager | `/etc/ingester-tls/tls.key` | Path to serving private key. |
| `INGESTER_SERVICE_NAME` | Manager | `clusterpulse-ingester` | Used to derive `INGESTER_TLS_SERVER_NAME`. |
| `INGESTER_TLS_USE_SYSTEM_CA` | Manager | `false` | Skip CA distribution; tell collectors to trust the system CA bundle. |
| `COLLECTOR_CA_CONFIGMAP` | Manager | `ingester-ca` | ConfigMap holding the CA cert that gets distributed to collectors. |
| `COLLECTOR_CA_NAMESPACE` | Manager | _release namespace_ | Namespace of the CA ConfigMap. |
| `COLLECTOR_CA_KEY` | Manager | `service-ca.crt` | Key inside the ConfigMap. |
| `INGESTER_TLS_CA` | Collector | _empty_ | CA cert path on the collector. Empty = use the system trust store. |
| `INGESTER_TLS_SERVER_NAME` | Collector | _empty_ | Override hostname for certificate verification. Set by the controller. |

## Custom CA mode

To use a CA you manage yourself (cert-manager, Vault, etc.) instead of `service-ca`:

```yaml
spec:
  clusterEngine:
    ingester:
      enabled: true
      tls:
        enabled: true
        customCAConfigMap:
          name: my-ca-bundle
          namespace: my-namespace   # optional; defaults to release namespace
          key: ca.crt
      route:
        enabled: true
```

You're responsible for provisioning the serving cert into the `clusterpulse-ingester` Service (or whatever Secret name the chart expects — `helm show values` to confirm) and the CA into `my-ca-bundle`.

## System CA mode

If the ingester cert is signed by a publicly-trusted or enterprise CA already present in every collector's trust store, skip CA distribution entirely:

```yaml
spec:
  clusterEngine:
    ingester:
      tls:
        enabled: true
        useSystemCA: true
```

Or set `INGESTER_TLS_USE_SYSTEM_CA=true` on the controller if running outside the operator.

## Non-OpenShift hubs

OpenShift's `service-ca` isn't available. Provide your own cert and CA:

1. Create a Secret with the serving cert: `tls.crt`, `tls.key` (mount at `/etc/ingester-tls/`).
2. Create a ConfigMap containing the CA that signed it.
3. Use `customCAConfigMap` as in [Custom CA mode](#custom-ca-mode).
4. Expose the ingester via your own Ingress/LoadBalancer with passthrough TLS (or terminate TLS at the LB and run the ingester in plaintext on a closed network).

## Notes

- **Cert rotation.** The ingester loads the cert at startup. Until file-watcher support lands, rotating the cert requires a pod restart.
- **Port mapping.** External 443 (Route) → Service 9443 → Pod 9443. The collector connects to whatever you put in `ingesterAddress`, port included.

## Troubleshooting

### Collector logs say "tls: bad certificate"

The collector's CA doesn't match the cert the ingester is presenting. Usual causes:

- `service-ca` rotated. Restart the manager pod so it picks up the new cert; verify the `ingester-ca` ConfigMap was updated.
- `customCAConfigMap` points to the wrong key, or the key holds a different CA than the one that signed the serving cert.

### Collector logs say "x509: certificate is valid for X, not Y"

`INGESTER_TLS_SERVER_NAME` wasn't applied. Confirm with `oc -n clusterpulse-system get deploy clusterpulse-collector -o yaml | grep -A1 INGESTER_TLS_SERVER_NAME`. If empty, the hub controller didn't compute it — usually because `INGESTER_SERVICE_NAME` was overridden to something that doesn't resolve.

### `openssl s_client` works but the collector can't connect

Usually a NetworkPolicy or egress firewall on the managed cluster blocking the Route hostname. Test from inside a pod on the managed cluster, not from a workstation.
