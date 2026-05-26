# Quickstart

End-to-end walkthrough: install ClusterPulse, connect one cluster, and create a first policy so a group of users can see it.

This page is the minimum viable setup. For options and edge cases, the per-step links lead to the detailed how-tos.

## Prerequisites

- OpenShift 4.x or Kubernetes 1.21+ cluster for the hub (where ClusterPulse runs)
- `cluster-admin` on the hub
- `oc` (OpenShift) or `kubectl` configured
- Helm 3.x — only if you install via Helm

## 1. Install ClusterPulse on the hub

Pick one of:

=== "OperatorHub (OpenShift)"

    1. In the OpenShift web console, go to **Operators → OperatorHub**.
    2. Search for `ClusterPulse` and click **Install**.
    3. After the install completes, create a `ClusterPulse` CR from the operator detail page. Default spec is enough to start.

    Full walkthrough (including CLI install): [Installation](installation.md).

=== "Helm"

    ```bash
    git clone https://github.com/ClusterPulse/operator.git
    cd operator/
    make install                                              # Installs CRDs
    helm install clusterpulse ./helm-charts/clusterpulse \
        --namespace clusterpulse --create-namespace
    ```

Wait for pods to come up:

```bash
oc get pods -n clusterpulse
```

You should see the manager (cluster-controller), API, frontend (if enabled), and Redis pods running.

## 2. Connect a cluster

The full guide is [Add an OpenShift Cluster](../how-to/clusters/add-openshift-cluster.md). The minimum is:

1. On the **target** cluster, create a service account with `cluster-reader`:

    ```bash
    oc create serviceaccount clusterpulse-reader -n kube-system
    oc adm policy add-cluster-role-to-user cluster-reader \
        system:serviceaccount:kube-system:clusterpulse-reader
    ```

2. Mint a long-lived token (OpenShift 4.11+):

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

3. On the **hub** cluster, create the credentials secret and the `ClusterConnection`:

    ```bash
    TOKEN=$(oc --context=target get secret clusterpulse-reader-token \
        -n kube-system -o jsonpath='{.data.token}' | base64 -d)

    oc --context=target get secret clusterpulse-reader-token \
        -n kube-system -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt

    oc create secret generic my-cluster-creds -n clusterpulse \
        --from-literal=token="$TOKEN" --from-file=ca.crt=ca.crt
    ```

    ```yaml
    apiVersion: clusterpulse.io/v1alpha1
    kind: ClusterConnection
    metadata:
      name: my-cluster
      namespace: clusterpulse
    spec:
      displayName: "My Cluster"
      endpoint: "https://api.cluster.example.com:6443"
      credentialsRef:
        name: my-cluster-creds
      labels:
        environment: development
      monitoring:
        interval: 30
    ```

4. Watch it move to `Connected`:

    ```bash
    oc get clusterconnection -n clusterpulse -w
    ```

## 3. Create a first policy

Without a `MonitorAccessPolicy`, users see nothing — the default is implicit deny. Grant the `developers` group view access to all clusters:

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: MonitorAccessPolicy
metadata:
  name: dev-team-access
  namespace: clusterpulse
spec:
  identity:
    priority: 100
    subjects:
      groups: ["developers"]
  access:
    effect: Allow
    enabled: true
  scope:
    clusters:
      default: allow
      rules:
        - selector:
            matchPattern: ".*"
          permissions:
            view: true
            viewMetrics: true
```

```bash
oc apply -f policy.yaml
oc get monitoraccesspolicy dev-team-access -n clusterpulse -o jsonpath='{.status.state}'
# Expect: Active
```

> **Note:** `scope.clusters.default` accepts `allow`, `deny`, or `none`. `none` (the CRD default) means "deny everything unless a rule matches". `allow` means "allow everything unless a rule overrides it".

## 4. (Optional) Add MetricSources for custom resources

If you need to collect non-standard resources (PVCs, CronJobs, CRs from cert-manager, etc.), define a `MetricSource`. See [Create a MetricSource](../how-to/metricsources/create-metricsource.md). ClusterPulse ships with two defaults (`default-pvc-capacity`, `default-deployment-health`) that you can keep or delete.

## 5. Open the UI

```bash
oc get routes -n clusterpulse
```

Open the frontend Route's hostname. Log in via the configured OAuth provider. Members of the group(s) you named in your policy will see the cluster(s) they're allowed to.

## Next steps

- [Add an OpenShift cluster (full)](../how-to/clusters/add-openshift-cluster.md)
- [Enable push-mode collection](../how-to/clusters/enable-push-mode.md)
- [Create your first policy (detailed)](../how-to/policies/create-first-policy.md)
- [RBAC model](../concepts/rbac-model.md)
- [Filter by namespace](../how-to/policies/filter-by-namespace.md)
