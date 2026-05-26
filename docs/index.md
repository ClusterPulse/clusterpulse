# ClusterPulse

Multi-cluster Kubernetes/OpenShift monitoring with policy-based RBAC.

ClusterPulse aggregates cluster health, capacity, operator, and custom-resource state from a fleet of connected clusters and serves a filtered view to each user. Access is controlled by `MonitorAccessPolicy` CRDs that the operator compiles into Redis-indexed structures evaluated on every API request.

If you're new here, start with the [quickstart](getting-started/index.md). If you want to understand the moving parts before installing, read [Architecture](concepts/architecture.md) and the [RBAC Model](concepts/rbac-model.md).

## Quick Links

<div class="grid cards" markdown>

-   **Getting Started**

    ---

    Install ClusterPulse, connect a cluster, and create the first policy.

    [Quickstart](getting-started/index.md)

-   **How-To Guides**

    ---

    Step-by-step recipes for connecting clusters and registries, writing policies, and defining MetricSources.

    [How-To Guides](how-to/index.md)

-   **Concepts**

    ---

    Architecture, the RBAC model, and how policies are evaluated.

    [Concepts](concepts/architecture.md)

-   **Contributing**

    ---

    Per-component developer guides, test suite layout, and release workflow.

    [Contributing](contributing/index.md)

</div>
