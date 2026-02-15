package cluster

import (
	"context"
	"fmt"

	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
	"github.com/clusterpulse/cluster-controller/internal/version"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	collectorNamespace      = "clusterpulse-system"
	collectorServiceAccount = "clusterpulse-collector"
	collectorClusterRole    = "clusterpulse-collector"
	collectorDeploymentName = "clusterpulse-collector"
	collectorImage          = "quay.io/clusterpulse/collector"
)

// ensureCollectorDeployed creates the collector agent on the managed cluster if it doesn't exist.
func (r *ClusterReconciler) ensureCollectorDeployed(ctx context.Context, clusterConn *v1alpha1.ClusterConnection) error {
	log := logrus.WithField("cluster", clusterConn.Name)

	client, err := r.getClusterClient(ctx, clusterConn)
	if err != nil {
		return fmt.Errorf("failed to get cluster client: %w", err)
	}

	dynClient := client.DynamicClient()
	if dynClient == nil {
		return fmt.Errorf("dynamic client not available for cluster %s", clusterConn.Name)
	}

	// Check if collector Deployment already exists — skip if so
	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	_, err = dynClient.Resource(deployGVR).Namespace(collectorNamespace).Get(ctx, collectorDeploymentName, metav1.GetOptions{})
	if err == nil {
		log.Debug("Collector deployment already exists, skipping deploy")
		return nil
	}
	if !errors.IsNotFound(err) {
		return fmt.Errorf("failed to check collector deployment: %w", err)
	}

	// Ingester address reachable from managed cluster
	ingesterAddr := clusterConn.Spec.IngesterAddress
	if ingesterAddr == "" {
		return fmt.Errorf("ingesterAddress is required when collectionMode is push")
	}

	// Reuse the ClusterConnection bearer token for collector auth
	token, err := r.getClusterToken(ctx, clusterConn)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	log.Info("Deploying collector agent on managed cluster")

	if err := ensureNamespace(ctx, dynClient, collectorNamespace); err != nil {
		return fmt.Errorf("namespace: %w", err)
	}
	if err := ensureServiceAccount(ctx, dynClient, collectorNamespace); err != nil {
		return fmt.Errorf("serviceaccount: %w", err)
	}
	if err := ensureClusterRole(ctx, dynClient); err != nil {
		return fmt.Errorf("clusterrole: %w", err)
	}
	if err := ensureClusterRoleBinding(ctx, dynClient, collectorNamespace); err != nil {
		return fmt.Errorf("clusterrolebinding: %w", err)
	}
	if err := ensureCollectorSecret(ctx, dynClient, collectorNamespace, token); err != nil {
		return fmt.Errorf("secret: %w", err)
	}
	if err := ensureCollectorDeployment(ctx, dynClient, collectorNamespace, clusterConn.Name, ingesterAddr); err != nil {
		return fmt.Errorf("deployment: %w", err)
	}

	log.Info("Collector agent deployed successfully")
	return nil
}

func (r *ClusterReconciler) getClusterToken(ctx context.Context, clusterConn *v1alpha1.ClusterConnection) (string, error) {
	secretName := clusterConn.Spec.CredentialsRef.Name
	secretNamespace := clusterConn.Spec.CredentialsRef.Namespace
	if secretNamespace == "" {
		secretNamespace = clusterConn.Namespace
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, k8sclient.ObjectKey{Name: secretName, Namespace: secretNamespace}, secret); err != nil {
		return "", err
	}
	return string(secret.Data["token"]), nil
}

func ensureNamespace(ctx context.Context, client dynamic.Interface, name string) error {
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}

	_, err := client.Resource(gvr).Get(ctx, name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		ns := &unstructured.Unstructured{}
		ns.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "Namespace"})
		ns.SetName(name)
		_, err = client.Resource(gvr).Create(ctx, ns, metav1.CreateOptions{})
	}
	return err
}

func ensureServiceAccount(ctx context.Context, client dynamic.Interface, namespace string) error {
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "serviceaccounts"}

	_, err := client.Resource(gvr).Namespace(namespace).Get(ctx, collectorServiceAccount, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		sa := &unstructured.Unstructured{}
		sa.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "ServiceAccount"})
		sa.SetName(collectorServiceAccount)
		sa.SetNamespace(namespace)
		_, err = client.Resource(gvr).Namespace(namespace).Create(ctx, sa, metav1.CreateOptions{})
	}
	return err
}

func ensureClusterRole(ctx context.Context, client dynamic.Interface) error {
	gvr := schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"}

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind":       "ClusterRole",
			"metadata": map[string]interface{}{
				"name": collectorClusterRole,
			},
			"rules": []interface{}{
				map[string]interface{}{
					"apiGroups": []interface{}{"*"},
					"resources": []interface{}{"*"},
					"verbs":     []interface{}{"get", "list", "watch"},
				},
			},
		},
	}

	existing, err := client.Resource(gvr).Get(ctx, collectorClusterRole, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		_, err = client.Resource(gvr).Create(ctx, cr, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}

	cr.SetResourceVersion(existing.GetResourceVersion())
	_, err = client.Resource(gvr).Update(ctx, cr, metav1.UpdateOptions{})
	return err
}

func ensureClusterRoleBinding(ctx context.Context, client dynamic.Interface, namespace string) error {
	gvr := schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"}

	crb := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind":       "ClusterRoleBinding",
			"metadata": map[string]interface{}{
				"name": collectorClusterRole,
			},
			"subjects": []interface{}{
				map[string]interface{}{
					"kind":      "ServiceAccount",
					"name":      collectorServiceAccount,
					"namespace": namespace,
				},
			},
			"roleRef": map[string]interface{}{
				"apiGroup": "rbac.authorization.k8s.io",
				"kind":     "ClusterRole",
				"name":     collectorClusterRole,
			},
		},
	}

	_, err := client.Resource(gvr).Get(ctx, collectorClusterRole, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		_, err = client.Resource(gvr).Create(ctx, crb, metav1.CreateOptions{})
	}
	return err
}

func ensureCollectorSecret(ctx context.Context, client dynamic.Interface, namespace, token string) error {
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "secrets"}
	name := "clusterpulse-collector-token"

	secret := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"type": "Opaque",
			"stringData": map[string]interface{}{
				"token": token,
			},
		},
	}

	existing, err := client.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		_, err = client.Resource(gvr).Namespace(namespace).Create(ctx, secret, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}

	secret.SetResourceVersion(existing.GetResourceVersion())
	_, err = client.Resource(gvr).Namespace(namespace).Update(ctx, secret, metav1.UpdateOptions{})
	return err
}

func ensureCollectorDeployment(ctx context.Context, client dynamic.Interface, namespace, clusterName, ingesterAddr string) error {
	gvr := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

	imageTag := version.Version
	if imageTag == "" || imageTag == "dev" {
		imageTag = "latest"
	}

	deploy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      collectorDeploymentName,
				"namespace": namespace,
				"labels": map[string]interface{}{
					"app.kubernetes.io/name":      "clusterpulse-collector",
					"app.kubernetes.io/component": "collector",
					"app.kubernetes.io/part-of":   "clusterpulse",
				},
			},
			"spec": map[string]interface{}{
				"replicas": int64(1),
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app.kubernetes.io/name": "clusterpulse-collector",
					},
				},
				"template": map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{
							"app.kubernetes.io/name":      "clusterpulse-collector",
							"app.kubernetes.io/component": "collector",
							"app.kubernetes.io/part-of":   "clusterpulse",
						},
					},
					"spec": map[string]interface{}{
						"serviceAccountName": collectorServiceAccount,
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "collector",
								"image": fmt.Sprintf("%s:%s", collectorImage, imageTag),
								"env": []interface{}{
									map[string]interface{}{
										"name":  "CLUSTER_NAME",
										"value": clusterName,
									},
									map[string]interface{}{
										"name":  "INGESTER_ADDRESS",
										"value": ingesterAddr,
									},
									map[string]interface{}{
										"name": "COLLECTOR_TOKEN",
										"valueFrom": map[string]interface{}{
											"secretKeyRef": map[string]interface{}{
												"name": "clusterpulse-collector-token",
												"key":  "token",
											},
										},
									},
								},
								"resources": map[string]interface{}{
									"requests": map[string]interface{}{
										"cpu":    "50m",
										"memory": "32Mi",
									},
									"limits": map[string]interface{}{
										"cpu":    "200m",
										"memory": "64Mi",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	existing, err := client.Resource(gvr).Namespace(namespace).Get(ctx, collectorDeploymentName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		_, err = client.Resource(gvr).Namespace(namespace).Create(ctx, deploy, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}

	deploy.SetResourceVersion(existing.GetResourceVersion())
	_, err = client.Resource(gvr).Namespace(namespace).Update(ctx, deploy, metav1.UpdateOptions{})
	return err
}
