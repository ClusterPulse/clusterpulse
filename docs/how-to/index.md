# How-To Guides

Step-by-step recipes for setting up and operating ClusterPulse. Each guide assumes the hub is already installed (see [Installation](../getting-started/installation.md)) and focuses on one workflow with verification and edge cases.

## Connecting clusters

- [Add an OpenShift cluster (pull mode)](clusters/add-openshift-cluster.md) — the common path: hub reaches out to the target cluster's API server.
- [Enable push-mode collection](clusters/enable-push-mode.md) — for managed clusters the hub can't reach directly. Deploys a collector agent on the target.
- [Configure ingester TLS](clusters/configure-ingester-tls.md) — exposing the hub's gRPC ingester over an OpenShift Route for push-mode collectors.
- [Add a container registry](clusters/add-registry.md) — `RegistryConnection` for Docker v2 registry health monitoring.

## Writing access policies

Policies are the only thing standing between authenticated users and your cluster data. The default is implicit deny.

- [Create your first policy](policies/create-first-policy.md) — write, apply, verify, iterate. Start here.
- [Filter by namespace](policies/filter-by-namespace.md) — restrict visibility to specific namespaces and the resources inside them.
- [Grant custom resource access](policies/grant-custom-resource-access.md) — control access to resources collected by `MetricSource`.

## Collecting custom metrics

- [Create a MetricSource](metricsources/create-metricsource.md) — define what to collect from any Kubernetes resource type and how to summarise it.

## Operating ClusterPulse

- [Use an external Redis](misc/external-redis.md) — disable the bundled subchart and point at your own Redis.

## Where to read next

- [Concepts → Architecture](../concepts/architecture.md) — how the moving parts fit together.
- [Concepts → RBAC model](../concepts/rbac-model.md) — the full policy reference.
- [Concepts → Policy evaluation](../concepts/policy-evaluation.md) — the order in which the engine resolves a request to an allow/deny/partial decision.
