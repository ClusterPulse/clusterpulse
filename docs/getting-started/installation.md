# Installation

ClusterPulse can be installed on OpenShift clusters via OperatorHub or on any Kubernetes cluster using Helm.

## Prerequisites

- OpenShift 4.x or Kubernetes 1.21+ cluster
- Cluster administrator privileges
- For Helm installation: Helm 3.x installed locally

## OperatorHub Installation (OpenShift)

ClusterPulse is available in the OperatorHub community operator index.

### GUI Installation

1. Log in to the OpenShift web console as a cluster administrator.

2. Navigate to **Operators** > **OperatorHub** in the left sidebar.

3. In the search field, enter `ClusterPulse`.

4. Select the **ClusterPulse** tile from the search results.

5. Review the operator information and click **Install**.

6. Configure the installation options:
    - **Update channel**: Select the desired release channel.
    - **Installation mode**: Choose whether to install in a specific namespace or all namespaces.
    - **Installed Namespace**: Select or create the target namespace.
    - **Update approval**: Select `Automatic` or `Manual` based on your upgrade policy.

7. Click **Install** to begin the installation.

8. Wait for the operator status to display `Succeeded`. This can be monitored under **Operators** > **Installed Operators**.

9. Once installed, create a ClusterPulse instance by navigating to the operator's detail page and selecting **Create Instance** under the provided API.

### CLI Installation

1. Create a namespace for the operator (optional, if not using an existing namespace):

    ```bash
    oc create namespace clusterpulse
    ```

2. Create an `OperatorGroup` if one does not already exist in the target namespace:

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

    Apply the manifest:

    ```bash
    oc apply -f operatorgroup.yaml
    ```

3. Create a `Subscription` to install the operator:

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

    Apply the manifest:

    ```bash
    oc apply -f subscription.yaml
    ```

4. Verify the operator installation:

    ```bash
    oc get csv -n clusterpulse
    ```

    The output should show the ClusterPulse operator with a phase of `Succeeded`.

5. Create a ClusterPulse custom resource to deploy the application. The default options should suffice for most instances:

    ```yaml
    apiVersion: clusterpulse.io/v1alpha1
    kind: ClusterPulse
    metadata:
      name: clusterpulse
      namespace: clusterpulse
    spec:
      # Add configuration options as needed
    ```

    Apply the manifest:

    ```bash
    oc apply -f clusterpulse-cr.yaml
    ```

## Helm Installation

Helm installation is suitable for any Kubernetes cluster, including OpenShift.

1. Clone the operator repository:

    ```bash
    git clone https://github.com/ClusterPulse/operator.git
    cd operator/
    ```

2. Install the Custom Resource Definitions:

    ```bash
    make install
    ```

3. Install ClusterPulse using Helm:

    ```bash
    helm install clusterpulse ./helm-charts/clusterpulse
    ```

4. To install in a specific namespace:

    ```bash
    helm install clusterpulse ./helm-charts/clusterpulse --namespace clusterpulse --create-namespace
    ```

5. Verify the installation:

    ```bash
    kubectl get pods -n clusterpulse
    ```

### Helm Configuration

To customize the installation, create a `values.yaml` file with your configuration overrides:

```bash
helm install clusterpulse ./helm-charts/clusterpulse -f values.yaml
```

Refer to the chart's default `values.yaml` in `./helm-charts/clusterpulse/values.yaml` for available configuration options.

### Upgrading

To upgrade an existing Helm installation:

```bash
cd operator/
git pull
helm upgrade clusterpulse ./helm-charts/clusterpulse
```

### Uninstalling

To remove ClusterPulse installed via Helm:

```bash
helm uninstall clusterpulse
make uninstall  # Removes CRDs
```

## Post-Installation

After installation, configure the following:

1. **Target Clusters**: Add the Kubernetes clusters you want to monitor.
2. **RBAC Policies**: Define access control policies for your users and teams.
3. **Authentication**: Configure OAuth2 integration with your identity provider.
