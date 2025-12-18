# Quickstart

Get ClusterPulse running and monitoring a cluster in 5 minutes.

## Prerequisites

- Kubernetes cluster with `oc` access
- Helm 3.x installed
- Redis instance (or use the bundled one)

## Step 1: Install ClusterPulse
### OperatorHub
ClusterPulse can be deployed through OLM in the OperatorHub. It is currently inside the community operator index!

### Helm
```bash
git clone https://github.com/ClusterPulse/operator.git
cd operator/
make install							# Will install CRDs
helm install clusterpulse ./helm-charts/clusterpulse		# Will install ClusterPulse
```

## Step 2: Connect a Cluster

Create a ClusterConnection to monitor your cluster:
```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: ClusterConnection
metadata:
  name: my-cluster
  namespace: clusterpulse
spec:
  displayName: "My Production Cluster"
  endpoint: https://api.my-cluster.example.com:6443
  credentialsRef:
    name: my-cluster-creds
  monitoring:
    interval: 30
```
```bash
oc apply -f cluster-connection.yaml
```

## Step 3: Create an Access Policy

Allow your team to view the cluster:
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
      default: none
      rules:
        - selector:
            names: ["my-cluster"]
          permissions:
            view: true
            viewMetrics: true
```
```bash
oc apply -f policy.yaml
```

## Step 4: Access the UI
```bash
# Get the route ClusterPulse created
oc get routes -n <clusterpulse_ns>
```

## Next Steps

- [Add more clusters](../how-to/clusters/add-openshift-cluster.md)
- [Learn RBAC concepts](../concepts/rbac-model.md)
- [Create namespace-filtered policies](../how-to/policies/filter-by-namespace.md)
