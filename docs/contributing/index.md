# Contributing

ClusterPulse ships three binaries from a single Go module:

| Binary | Source | What it does |
|---|---|---|
| `manager` | `cmd/manager/` | Controller manager. Reconciles `ClusterConnection`, `RegistryConnection`, `MonitorAccessPolicy`, `MetricSource`. Embeds the gRPC ingester. |
| `api` | `cmd/api/` | REST API server. Chi router, serves `/api/v1/*` with per-request RBAC. |
| `collector` | `cmd/collector/` | Push-mode agent. Runs on managed clusters, streams metrics to the hub ingester. |

The frontend is in a separate repository.

## Where to start

- **PR + release workflow** → [Workflow](workflow.md). Labels, CI checks, branch naming, Renovate, release process.
- **REST API** → [API contributing guide](api.md). Local setup, Swagger UI, env vars, route table, response shapes.
- **Cluster controller** (and the three other reconcilers it ships alongside): the guide is split into four pages because it covers a lot of ground.
    - [Quickstart](cluster-controller-quickstart.md) — local build, run, code generation, env vars.
    - [Architecture](cluster-controller-architecture.md) — directory layout, per-package responsibilities, common extension patterns.
    - [Reconciliation](cluster-controller-reconciliation.md) — the reconcile loops and the principles they share.
    - [Patterns](cluster-controller-patterns.md) — Redis storage, client pool, circuit breakers, MetricSource patterns, performance.
- **Policy controller** → [Policy controller guide](policy-controller.md). CRD compilation, Redis indexes, the diff-driven cleanup on update.

## Test suite

See [Testing → Go Test Suite](../testing/tests.md) for an inventory of what's tested and where. Run with `make test`.

## Code generation cheat sheet

After editing CRD types under `api/v1alpha1/`:

```bash
controller-gen object paths="./api/v1alpha1/..."
controller-gen crd paths="./api/v1alpha1/..." output:crd:dir=config/crd/bases
```

After editing the protobuf:

```bash
buf generate proto
```

After editing API handler annotations:

```bash
swag init -g cmd/api/main.go -o docs/swagger --parseDependency --parseInternal
```

All three sets of generated files are committed.
