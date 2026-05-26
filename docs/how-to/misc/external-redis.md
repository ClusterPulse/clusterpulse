# Use an External Redis

By default, the Helm chart deploys a bundled Bitnami Redis subchart. To use a Redis you operate yourself (managed service, in-house cluster, sidecar in another namespace), disable the bundled subchart and point every ClusterPulse component at your endpoint.

## What uses Redis

Three components read and write to the same Redis instance:

| Component | Reads | Writes |
|---|---|---|
| `clusterEngine` (cluster controller) | Compiled policies, MetricSource configs | Cluster/node/operator state, aggregations, pub/sub events |
| `policyEngine` (policy controller, embedded in the manager) | MonitorAccessPolicy CRDs (via watch) | Compiled policies + indexes, pub/sub events |
| `api` | Everything above | RBAC decision cache, in-memory group cache primer |

All three must point at the same Redis (and, with the default config, the same database number). Don't aim them at different Redis instances.

## Prerequisites

- A reachable Redis 6.x or later (Redis 7 is fine).
- Network connectivity from the ClusterPulse namespace to the Redis endpoint.
- Optional but recommended: an `AUTH` password.

## Step 1: Put the password in a secret

```bash
oc create secret generic external-redis-secret \
  --namespace clusterpulse \
  --from-literal=password='<your-redis-password>'
```

Use a sealed secret / external-secrets operator for production. The key inside the secret can be any string — you'll reference it as `passwordKey` in the next step.

## Step 2: Update the ClusterPulse CR

```yaml
# Disable the bundled subchart
redis:
  enabled: false

# Repeat for each consumer; they must all match
api:
  redis:
    host: redis.example.com
    port: "6379"
    db: "0"
    passwordSecret: external-redis-secret
    passwordKey: password

clusterEngine:
  redis:
    host: redis.example.com
    port: "6379"
    db: "0"
    passwordSecret: external-redis-secret
    passwordKey: password

policyEngine:
  redis:
    host: redis.example.com
    port: "6379"
    db: "0"
    passwordSecret: external-redis-secret
    passwordKey: password
```

Apply the CR. The pods restart with the new env vars.

## Configuration reference

| Parameter | Description | Default |
|---|---|---|
| `redis.enabled` | Deploy the bundled Bitnami Redis subchart. | `true` |
| `<component>.redis.host` | Hostname or IP. | `<release>-redis-master` |
| `<component>.redis.port` | Port. | `6379` |
| `<component>.redis.db` | Database index (0–15 by default in stock Redis). | `0` |
| `<component>.redis.passwordSecret` | Secret name (in the install namespace) holding the password. | `<release>-redis` |
| `<component>.redis.passwordKey` | Key within the secret. | `redis-password` |

`<component>` is one of `api`, `clusterEngine`, `policyEngine`.

## What's not supported

These configurations aren't currently exposed by the Helm chart. Track them on [GitHub issues](https://github.com/ClusterPulse/clusterpulse/issues) and add a 👍 if you need them:

- **Redis Sentinel.** ClusterPulse doesn't speak the Sentinel protocol. Workaround: put a TCP proxy (HAProxy, Envoy) in front of Sentinel that resolves to the current master, then point ClusterPulse at the proxy. Managed Redis services (ElastiCache, Azure Cache, GCP Memorystore) already expose a stable endpoint.
- **Redis Cluster (sharded).** Not supported. ClusterPulse uses key patterns that don't map cleanly to a single hash slot. Workaround: use a non-sharded primary/replica setup.
- **TLS to Redis.** The chart doesn't currently expose TLS config. Workaround: terminate TLS at a sidecar/proxy (e.g., stunnel) and connect ClusterPulse to the proxy over plaintext.

## Database isolation

You can put each component on a different database number:

```yaml
api:
  redis: { db: "0" }
clusterEngine:
  redis: { db: "1" }
policyEngine:
  redis: { db: "2" }
```

This is **not** a supported configuration — the components read each other's data. Use the same `db` everywhere unless you're debugging and isolating writes deliberately.

## Validation

```bash
oc logs -n clusterpulse deployment/clusterpulse-api | grep -i redis
oc logs -n clusterpulse deployment/clusterpulse-cluster-controller | grep -i redis
```

A healthy startup shows lines like `Connected to Redis at redis.example.com:6379` and no subsequent reconnect messages.

## Troubleshooting

### `connection refused`

Network. Test from inside a pod:

```bash
oc run -it --rm redis-test -n clusterpulse \
  --image=redis:7-alpine --restart=Never \
  -- redis-cli -h redis.example.com -p 6379 PING
```

If this fails too, the issue is reachability — NetworkPolicy, egress firewall, missing service in DNS, etc.

### `NOAUTH Authentication required` or `WRONGPASS invalid username-password pair`

Password is wrong, missing, or not being read. Check:

1. `oc get secret external-redis-secret -n clusterpulse -o jsonpath='{.data.password}' | base64 -d` matches the actual Redis password.
2. The CR uses `passwordKey: password` matching the key in the secret.
3. The pod restarted since the secret was created — secrets aren't re-read on the fly without a restart.

### `WRONGTYPE Operation against a key holding the wrong kind of value`

The components are sharing a database with another application that's using the same key prefixes. Move ClusterPulse to its own `db` (and confirm all three components match).

### Components disagree about policy state

All three components have to point at the same `host`/`port`/`db`. If `clusterEngine` writes to DB 0 and the `api` reads from DB 1, the API will look like it has no policies.

### Slow API responses after switching

The default decision cache is off (`RBAC_CACHE_TTL=0`). High Redis latency directly translates to high API latency. Either turn on the cache (`RBAC_CACHE_TTL=60` or similar on the API Deployment env) or move Redis closer to the cluster (same VPC, dedicated subnet).
