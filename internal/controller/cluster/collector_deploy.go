package cluster

import (
	"context"
	"fmt"
	"reflect"

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
	ingesterCAConfigMap     = "ingester-ca"
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

	log.Debug("Ensuring collector agent on managed cluster")

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
	tlsEnabled := r.Config.IngesterTLSEnabled
	useSystemCA := r.Config.IngesterTLSUseSystemCA
	if tlsEnabled && !useSystemCA {
		if err := r.ensureIngesterCA(ctx, dynClient, collectorNamespace); err != nil {
			return fmt.Errorf("ingester CA: %w", err)
		}
	}
	// Compute in-cluster service FQDN for TLS server name verification.
	// Passthrough routes forward TLS by SNI (route hostname), but the service-ca
	// cert has SANs for the in-cluster name. The collector uses VerifyConnection
	// to verify against this name while keeping SNI as the route hostname.
	var tlsServerName string
	if tlsEnabled {
		tlsServerName = fmt.Sprintf("%s.%s.svc", r.Config.IngesterServiceName, r.Config.Namespace)
	}
	if err := ensureCollectorDeployment(ctx, dynClient, collectorNamespace, clusterConn.Name, ingesterAddr, clusterConn.Spec.CollectorVersion, tlsEnabled, useSystemCA, tlsServerName); err != nil {
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
		Object: map[string]any{
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind":       "ClusterRole",
			"metadata": map[string]any{
				"name": collectorClusterRole,
			},
			"rules": []any{
				map[string]any{
					"apiGroups": []any{"*"},
					"resources": []any{"*"},
					"verbs":     []any{"get", "list", "watch"},
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
		Object: map[string]any{
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind":       "ClusterRoleBinding",
			"metadata": map[string]any{
				"name": collectorClusterRole,
			},
			"subjects": []any{
				map[string]any{
					"kind":      "ServiceAccount",
					"name":      collectorServiceAccount,
					"namespace": namespace,
				},
			},
			"roleRef": map[string]any{
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
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]any{
				"name":      name,
				"namespace": namespace,
			},
			"type": "Opaque",
			"stringData": map[string]any{
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

// ensureIngesterCA reads the CA ConfigMap from the hub and creates a matching
// ConfigMap on the managed cluster so collectors can verify the ingester's TLS certificate.
// The source ConfigMap is configurable via COLLECTOR_CA_CONFIGMAP, COLLECTOR_CA_NAMESPACE,
// and COLLECTOR_CA_KEY environment variables.
func (r *ClusterReconciler) ensureIngesterCA(ctx context.Context, managedClient dynamic.Interface, namespace string) error {
	// Determine source ConfigMap location
	srcName := r.Config.CollectorCAConfigMap
	srcNamespace := r.Config.CollectorCANamespace
	if srcNamespace == "" {
		srcNamespace = r.Config.Namespace
	}
	srcKey := r.Config.CollectorCAKey

	// Read the CA bundle from the hub cluster
	hubCM := &corev1.ConfigMap{}
	if err := r.Get(ctx, k8sclient.ObjectKey{
		Name:      srcName,
		Namespace: srcNamespace,
	}, hubCM); err != nil {
		return fmt.Errorf("failed to get CA ConfigMap %s/%s: %w", srcNamespace, srcName, err)
	}

	caBundle, ok := hubCM.Data[srcKey]
	if !ok {
		return fmt.Errorf("CA ConfigMap %s/%s missing key %q", srcNamespace, srcName, srcKey)
	}

	gvr := schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
	cm := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"name":      ingesterCAConfigMap,
				"namespace": namespace,
			},
			"data": map[string]any{
				"service-ca.crt": caBundle,
			},
		},
	}

	existing, err := managedClient.Resource(gvr).Namespace(namespace).Get(ctx, ingesterCAConfigMap, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		_, err = managedClient.Resource(gvr).Namespace(namespace).Create(ctx, cm, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}

	cm.SetResourceVersion(existing.GetResourceVersion())
	_, err = managedClient.Resource(gvr).Namespace(namespace).Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

func ensureCollectorDeployment(ctx context.Context, client dynamic.Interface, namespace, clusterName, ingesterAddr, collectorVersion string, tlsEnabled, useSystemCA bool, tlsServerName string) error {
	gvr := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

	imageTag := collectorVersion
	if imageTag == "" {
		imageTag = version.Version
	}
	if imageTag == "" || imageTag == "dev" {
		imageTag = "latest"
	}

	envVars := []any{
		map[string]any{
			"name":  "CLUSTER_NAME",
			"value": clusterName,
		},
		map[string]any{
			"name":  "INGESTER_ADDRESS",
			"value": ingesterAddr,
		},
		map[string]any{
			"name": "COLLECTOR_TOKEN",
			"valueFrom": map[string]any{
				"secretKeyRef": map[string]any{
					"name": "clusterpulse-collector-token",
					"key":  "token",
				},
			},
		},
	}

	var volumeMounts []any
	var volumes []any

	if tlsEnabled {
		envVars = append(envVars,
			map[string]any{"name": "INGESTER_TLS_ENABLED", "value": "true"},
		)
		if tlsServerName != "" {
			envVars = append(envVars,
				map[string]any{"name": "INGESTER_TLS_SERVER_NAME", "value": tlsServerName},
			)
		}
		if !useSystemCA {
			envVars = append(envVars,
				map[string]any{"name": "INGESTER_TLS_CA", "value": "/etc/ingester-ca/service-ca.crt"},
			)
			volumeMounts = append(volumeMounts, map[string]any{
				"name":      "ingester-ca",
				"mountPath": "/etc/ingester-ca",
				"readOnly":  true,
			})
			volumes = append(volumes, map[string]any{
				"name": "ingester-ca",
				"configMap": map[string]any{
					"name": ingesterCAConfigMap,
				},
			})
		}
	}

	container := map[string]any{
		"name":  "collector",
		"image": fmt.Sprintf("%s:%s", collectorImage, imageTag),
		"env":   envVars,
		"resources": map[string]any{
			"requests": map[string]any{
				"cpu":    "50m",
				"memory": "128Mi",
			},
			"limits": map[string]any{
				"cpu":    "200m",
				"memory": "512Mi",
			},
		},
	}
	if len(volumeMounts) > 0 {
		container["volumeMounts"] = volumeMounts
	}

	podSpec := map[string]any{
		"serviceAccountName": collectorServiceAccount,
		"containers":         []any{container},
	}
	if len(volumes) > 0 {
		podSpec["volumes"] = volumes
	}

	deploy := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]any{
				"name":      collectorDeploymentName,
				"namespace": namespace,
				"labels": map[string]any{
					"app.kubernetes.io/name":      "clusterpulse-collector",
					"app.kubernetes.io/component": "collector",
					"app.kubernetes.io/part-of":   "clusterpulse",
				},
			},
			"spec": map[string]any{
				"replicas": int64(1),
				"selector": map[string]any{
					"matchLabels": map[string]any{
						"app.kubernetes.io/name": "clusterpulse-collector",
					},
				},
				"template": map[string]any{
					"metadata": map[string]any{
						"labels": map[string]any{
							"app.kubernetes.io/name":      "clusterpulse-collector",
							"app.kubernetes.io/component": "collector",
							"app.kubernetes.io/part-of":   "clusterpulse",
						},
					},
					"spec": podSpec,
				},
			},
		},
	}

	log := logrus.WithField("deployment", collectorDeploymentName)

	existing, err := client.Resource(gvr).Namespace(namespace).Get(ctx, collectorDeploymentName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		_, err = client.Resource(gvr).Namespace(namespace).Create(ctx, deploy, metav1.CreateOptions{})
		if err == nil {
			log.Info("Created collector deployment on managed cluster")
		}
		return err
	}
	if err != nil {
		return err
	}

	if deploymentSpecMatches(existing, deploy) {
		return nil
	}

	deploy.SetResourceVersion(existing.GetResourceVersion())
	_, err = client.Resource(gvr).Namespace(namespace).Update(ctx, deploy, metav1.UpdateOptions{})
	if err == nil {
		log.Info("Updated collector deployment on managed cluster")
	}
	return err
}

func deploymentSpecMatches(existing, desired *unstructured.Unstructured) bool {
	existingContainers, _, _ := unstructured.NestedSlice(existing.Object,
		"spec", "template", "spec", "containers")
	desiredContainers, _, _ := unstructured.NestedSlice(desired.Object,
		"spec", "template", "spec", "containers")
	return reflect.DeepEqual(existingContainers, desiredContainers)
}
