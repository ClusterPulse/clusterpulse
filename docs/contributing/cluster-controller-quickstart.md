# Cluster Controller — Quickstart

The cluster controller is one of the three binaries in this repo. It runs as the controller manager (`cmd/manager`) and reconciles `ClusterConnection`, `RegistryConnection`, `MonitorAccessPolicy`, and `MetricSource` CRDs. The compiled binary also embeds the gRPC ingester for push-mode collectors when `INGESTER_ENABLED=true` (the default).

This page covers getting a local checkout to build, run, and regenerate code. For what's where, see [Architecture](cluster-controller-architecture.md). For how the reconcile loops work, see [Reconciliation](cluster-controller-reconciliation.md). For implementation patterns specific to this codebase, see [Patterns](cluster-controller-patterns.md). For the test suite, see [Testing](../testing/tests.md). For PR/release workflow, see [Workflow](workflow.md).

## Prerequisites

- Go 1.26+ (the toolchain version pinned in `go.mod`)
- `controller-gen` (`go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest`)
- `buf` for proto changes (<https://buf.build/docs/installation>)
- A running Kubernetes/OpenShift cluster with the ClusterPulse CRDs installed
- Redis running locally or remotely
- `KUBECONFIG` set or `~/.kube/config` configured

## Local setup

```bash
go mod download

# Start Redis (Docker, podman, anything with port 6379 reachable)
docker run -d -p 6379:6379 redis:7-alpine

# Regenerate CRDs + deep-copy methods (idempotent; safe to run anytime)
controller-gen object paths="./..."
controller-gen crd paths="./..." output:crd:artifacts:config=config/crd/bases

# Run the manager against your current kubeconfig context
NAMESPACE=clusterpulse REDIS_HOST=localhost REDIS_PORT=6379 \
    go run ./cmd/manager --namespace=clusterpulse
```

The manager will register the controllers, start the ingester (unless you set `INGESTER_ENABLED=false`), and begin reconciling whatever CRDs already exist in the target namespace.

## Build the binaries

```bash
go build -o bin/manager   ./cmd/manager
go build -o bin/api       ./cmd/api
go build -o bin/collector ./cmd/collector
```

`make build` runs all three. `make test`, `make lint`, and the Docker builds match what CI runs — see [Workflow](workflow.md#ci-checks).

## Code generation

After editing anything under `api/v1alpha1/`, regenerate:

```bash
controller-gen object paths="./api/v1alpha1/..."
controller-gen crd paths="./api/v1alpha1/..." output:crd:dir=config/crd/bases
```

`zz_generated.deepcopy.go` is generated and committed. CRD YAML in `config/crd/bases/` is committed and consumed by the operator chart. Don't edit either by hand.

After editing `proto/clusterpulse/collector/v1/collector.proto`, regenerate the Go code:

```bash
buf generate proto
```

The output (`proto/clusterpulse/collector/v1/*.pb.go`, `*_grpc.pb.go`) is committed.

## Configuration

The manager reads everything from environment variables (`internal/config/config.go`). The frequently-tweaked ones:

| Variable | Default | Notes |
|---|---|---|
| `NAMESPACE` | _required_ | Namespace the manager watches for CRDs. |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASSWORD` / `REDIS_DB` | `redis`/`6379`/_empty_/`0` | Redis connection. |
| `RECONCILIATION_INTERVAL` | `30` | Default cluster reconcile interval (min 30). Per-cluster overrides via `ClusterConnection.spec.monitoring.interval`. |
| `OPERATOR_SCAN_INTERVAL` | `300` | How often to refresh operator state (min 60). |
| `CACHE_TTL` | `600` | Redis cache TTL for collected data (min 60). |
| `INGESTER_ENABLED` | `true` | Embed the gRPC ingester in the manager. |
| `INGESTER_PORT` | `9443` | Ingester listen port (min 1024). |
| `INGESTER_TLS_ENABLED` | `false` | Enable TLS on the ingester. See [Configure ingester TLS](../how-to/clusters/configure-ingester-tls.md). |
| `INGESTER_SERVICE_NAME` | `clusterpulse-ingester` | Used to derive the in-cluster TLS server name passed to collectors. |
| `VM_ENABLED` / `VM_ENDPOINT` | `false` / `http://victoriametrics:8428` | Optional VictoriaMetrics time-series writer. |
| `LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, `error`. |

For TLS-related vars, see [Configure ingester TLS](../how-to/clusters/configure-ingester-tls.md#environment-variables).

## Running against a real target cluster

Once the manager is running, apply a `ClusterConnection` from the `examples/` directory or write your own. Watching the manager logs at `LOG_LEVEL=debug` shows the reconcile loop in detail (per-step timings, errgroup completion, what was written to Redis).

## Useful commands

```bash
# Regenerate, build, run, all in one shell
controller-gen object paths="./..." && \
    controller-gen crd paths="./..." output:crd:artifacts:config=config/crd/bases && \
    go build ./... && \
    go run ./cmd/manager --namespace=clusterpulse

# Quick Redis inspection
redis-cli KEYS 'cluster:*' | head
redis-cli HGETALL 'cluster:my-cluster:status'
redis-cli SMEMBERS 'policies:enabled'
redis-cli ZREVRANGE 'policies:by:priority' 0 -1 WITHSCORES

# Apply local CRDs
oc apply -f config/crd/bases/

# Dry-run a CRD manifest against the API
oc apply --dry-run=server -f my-clusterconnection.yaml
```

## Testing

Tests are documented in detail in [the test suite reference](../testing/tests.md). The short version:

```bash
make test                       # CI equivalent: race + coverage
go test ./internal/controller/cluster/ -run TestReconcile -v
go test -cover ./internal/store/...
```
