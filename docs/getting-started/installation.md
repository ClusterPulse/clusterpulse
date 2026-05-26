# Installation

ClusterPulse installs on OpenShift (via OperatorHub or Helm) or any Kubernetes 1.21+ cluster (Helm). The operator manifests and Helm chart live in the [`ClusterPulse/operator`](https://github.com/ClusterPulse/operator) repo.

## Prerequisites

- OpenShift 4.x or Kubernetes 1.21+
- `cluster-admin` on the install cluster
- For Helm: Helm 3.x and either `kubectl` or `oc`

## FIPS clusters

If the hub cluster is FIPS-enabled, the default oauth-proxy image will not start. Override it in the `ClusterPulse` CR:

```yaml
spec:
  frontend:
    oauth:
      image: registry.redhat.io/openshift4/ose-oauth-proxy-rhel9
```

This applies to both the OperatorHub and Helm install paths. Apply it when you create the `ClusterPulse` CR, or patch it in afterwards.

## OperatorHub (OpenShift)

ClusterPulse is in the community operator index.

=== "Console (GUI)"

    1. Sign in to the OpenShift web console as `cluster-admin`.
    2. Go to **Operators → OperatorHub**.
    3. Search for `ClusterPulse` and select the tile.
    4. Click **Install**.
    5. Set:
        - **Update channel** — pick the channel you want to track.
        - **Installation mode** — namespace-scoped or all-namespaces. The operator is namespace-scoped; "A specific namespace" is the typical choice.
        - **Installed Namespace** — select or create the namespace (e.g. `clusterpulse`).
        - **Update approval** — Automatic or Manual.
    6. Click **Install** and wait for **Operators → Installed Operators** to show `Succeeded`.
    7. On the operator detail page, **Create Instance** under the `ClusterPulse` API. The defaults are enough to start. Add the FIPS override above if your cluster is FIPS-enabled.

=== "CLI"

    1. Create the namespace (skip if it already exists):

        ```bash
        oc create namespace clusterpulse
        ```

    2. Create an `OperatorGroup` (skip if one already exists in the namespace):

        ```yaml
        apiVersion: operators.coreos.com/v1
        kind: OperatorGroup
        metadata:
          name: clusterpulse-operatorgroup
          namespace: clusterpulse
        spec:
          targetNamespaces:
            - clusterpulse
        ```

        ```bash
        oc apply -f operatorgroup.yaml
        ```

    3. Create the `Subscription`:

        ```yaml
        apiVersion: operators.coreos.com/v1alpha1
        kind: Subscription
        metadata:
          name: clusterpulse
          namespace: clusterpulse
        spec:
          channel: stable
          name: clusterpulse
          source: community-operators
          sourceNamespace: openshift-marketplace
          installPlanApproval: Automatic
        ```

        ```bash
        oc apply -f subscription.yaml
        ```

    4. Verify the operator installed:

        ```bash
        oc get csv -n clusterpulse
        ```

        The ClusterPulse CSV should show `Succeeded`. If it sticks on `Pending` or `InstallReady`, check `oc get installplan -n clusterpulse` and `oc describe csv -n clusterpulse`.

    5. Create a `ClusterPulse` CR to deploy the workloads:

        ```yaml
        apiVersion: clusterpulse.io/v1alpha1
        kind: ClusterPulse
        metadata:
          name: clusterpulse
          namespace: clusterpulse
        spec: {}
        ```

        ```bash
        oc apply -f clusterpulse-cr.yaml
        ```

## Helm

Works on OpenShift and any Kubernetes 1.21+ cluster.

1. Clone the operator repo (it contains the chart):

    ```bash
    git clone https://github.com/ClusterPulse/operator.git
    cd operator/
    ```

2. Install the CRDs:

    ```bash
    make install
    ```

3. Install the chart:

    ```bash
    helm install clusterpulse ./helm-charts/clusterpulse \
        --namespace clusterpulse --create-namespace
    ```

4. Verify:

    ```bash
    kubectl get pods -n clusterpulse
    ```

### Configuration

Generate a `values.yaml` for overrides:

```bash
helm show values ./helm-charts/clusterpulse > values.yaml
helm install clusterpulse ./helm-charts/clusterpulse -f values.yaml
```

The chart's `values.yaml` documents every option. Notable sections:

- `redis.*` — bundled Bitnami Redis subchart. Disable (`redis.enabled: false`) to bring your own. See [Connect to an external Redis](../how-to/misc/external-redis.md).
- `api.*`, `clusterEngine.*`, `policyEngine.*` — per-component config including Redis connection.
- `clusterEngine.ingester.*` — enable the gRPC ingester for push-mode collectors. See [Configure ingester TLS](../how-to/clusters/configure-ingester-tls.md).
- `frontend.oauth.image` — override for FIPS (see above).

### Upgrade

```bash
cd operator/
git pull
helm upgrade clusterpulse ./helm-charts/clusterpulse -f values.yaml
```

### Uninstall

```bash
helm uninstall clusterpulse -n clusterpulse
make uninstall    # Removes CRDs
```

> **Note:** `make uninstall` deletes the CRDs cluster-wide, which deletes every `ClusterConnection`, `RegistryConnection`, `MonitorAccessPolicy`, and `MetricSource` in the cluster. Skip this step if other namespaces use those CRDs.

## Post-installation

Once pods are running, do these in order:

1. [Connect a target cluster](../how-to/clusters/add-openshift-cluster.md) — required before there's any data to view.
2. [Create your first policy](../how-to/policies/create-first-policy.md) — required before any user can see data (default is implicit deny).
3. (Optional) [Enable push-mode collection](../how-to/clusters/enable-push-mode.md) for clusters where the hub can't reach the kube-apiserver.
4. (Optional) [Add registries](../how-to/clusters/add-registry.md) for container registry health monitoring.
5. (Optional) [Create custom MetricSources](../how-to/metricsources/create-metricsource.md) to collect resources beyond the built-ins.
