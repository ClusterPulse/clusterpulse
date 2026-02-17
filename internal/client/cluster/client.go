package cluster

import (
	"context"
	"crypto/x509"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/clusterpulse/cluster-controller/pkg/utils"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// ClusterClient manages connection to a remote cluster
type ClusterClient struct {
	Name           string
	Endpoint       string
	config         *rest.Config
	clientset      kubernetes.Interface
	dynamicClient  dynamic.Interface
	circuitBreaker *utils.CircuitBreaker
	mu             sync.RWMutex
	lastUsed       time.Time
}

// NewClusterClient creates a new cluster client
func NewClusterClient(name, endpoint, token string, caCert []byte) (*ClusterClient, error) {
	config := &rest.Config{
		Host:        endpoint,
		BearerToken: token,
		Timeout:     30 * time.Second,
		QPS:         100,
		Burst:       200,
	}

	if len(caCert) > 0 {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		config.TLSClientConfig = rest.TLSClientConfig{
			CAData: caCert,
		}
	} else {
		config.TLSClientConfig = rest.TLSClientConfig{
			Insecure: true,
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	return &ClusterClient{
		Name:           name,
		Endpoint:       endpoint,
		config:         config,
		clientset:      clientset,
		dynamicClient:  dynamicClient,
		circuitBreaker: utils.NewCircuitBreaker(5, 60*time.Second),
		lastUsed:       time.Now(),
	}, nil
}

// DynamicClient returns the underlying dynamic.Interface for direct resource operations.
func (c *ClusterClient) DynamicClient() dynamic.Interface {
	return c.dynamicClient
}

// TestConnection tests the connection to the cluster
func (c *ClusterClient) TestConnection(ctx context.Context) error {
	return c.circuitBreaker.Call(ctx, func(ctx context.Context) error {
		_, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1})
		if err != nil {
			return fmt.Errorf("connection test failed: %w", err)
		}
		c.updateLastUsed()
		return nil
	})
}

// GetClusterInfo retrieves cluster version and console URL
func (c *ClusterClient) GetClusterInfo(ctx context.Context) (map[string]interface{}, error) {
	c.updateLastUsed()

	info := make(map[string]interface{})
	info["api_url"] = c.Endpoint

	// Try to get OpenShift ClusterVersion first
	clusterVersionInfo, err := c.getOpenShiftClusterVersion(ctx)
	if err == nil && clusterVersionInfo != nil {
		// We have OpenShift cluster version info
		for k, v := range clusterVersionInfo {
			info[k] = v
		}
	} else {
		// Fallback to standard Kubernetes version
		version, err := c.clientset.Discovery().ServerVersion()
		if err == nil {
			info["version"] = version.GitVersion
			info["platform"] = version.Platform
		} else {
			info["version"] = "unknown"
		}
	}

	// Try to get console URL for OpenShift
	consoleURL, err := c.getOpenShiftConsoleURL(ctx)
	if err == nil && consoleURL != "" {
		info["console_url"] = consoleURL
	} else if c.Endpoint != "" {
		// Fallback: derive from API URL
		info["console_url"] = c.deriveConsoleURL()
	}

	return info, nil
}

// getOpenShiftClusterVersion fetches ClusterVersion from OpenShift
func (c *ClusterClient) getOpenShiftClusterVersion(ctx context.Context) (map[string]interface{}, error) {
	// Define the ClusterVersion GVR
	clusterVersionGVR := schema.GroupVersionResource{
		Group:    "config.openshift.io",
		Version:  "v1",
		Resource: "clusterversions",
	}

	// Try to get the ClusterVersion object named "version"
	clusterVersion, err := c.dynamicClient.Resource(clusterVersionGVR).Get(ctx, "version", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ClusterVersion: %w", err)
	}

	result := make(map[string]interface{})

	// Extract spec information
	if spec, found, err := unstructured.NestedMap(clusterVersion.Object, "spec"); found && err == nil {
		if channel, ok := spec["channel"].(string); ok {
			result["channel"] = channel
		}
		if clusterID, ok := spec["clusterID"].(string); ok {
			result["cluster_id"] = clusterID
		}
	}

	// Extract status information
	if status, found, err := unstructured.NestedMap(clusterVersion.Object, "status"); found && err == nil {
		// Get desired version
		if desired, ok := status["desired"].(map[string]interface{}); ok {
			if version, ok := desired["version"].(string); ok {
				result["version"] = version
			}
			if image, ok := desired["image"].(string); ok {
				result["image"] = image
			}
		}

		// Check for available updates
		if availableUpdates, ok := status["availableUpdates"].([]interface{}); ok && len(availableUpdates) > 0 {
			result["update_available"] = true

			// Get details of first available update
			if firstUpdate, ok := availableUpdates[0].(map[string]interface{}); ok {
				if updateVersion, ok := firstUpdate["version"].(string); ok {
					result["available_update_version"] = updateVersion
				}
			}
		} else {
			result["update_available"] = false
		}

		// Get history for current version info
		if history, ok := status["history"].([]interface{}); ok && len(history) > 0 {
			// First item in history is the current version
			if currentVersion, ok := history[0].(map[string]interface{}); ok {
				if state, ok := currentVersion["state"].(string); ok {
					result["version_state"] = state
				}
				if startedTime, ok := currentVersion["startedTime"].(string); ok {
					result["version_started_time"] = startedTime
				}
				if completionTime, ok := currentVersion["completionTime"].(string); ok {
					result["version_completion_time"] = completionTime
				}
			}
		}

		// Get conditions
		if conditions, ok := status["conditions"].([]interface{}); ok {
			var conditionsList []map[string]interface{}
			for _, cond := range conditions {
				if condition, ok := cond.(map[string]interface{}); ok {
					condMap := map[string]interface{}{
						"type":    condition["type"],
						"status":  condition["status"],
						"message": condition["message"],
						"reason":  condition["reason"],
					}
					conditionsList = append(conditionsList, condMap)

					// Check for progressing or degraded conditions
					if condType, ok := condition["type"].(string); ok {
						if condStatus, ok := condition["status"].(string); ok {
							if condType == "Progressing" && condStatus == "True" {
								result["is_progressing"] = true
							}
							if condType == "Degraded" && condStatus == "True" {
								result["is_degraded"] = true
							}
							if condType == "Available" && condStatus == "True" {
								result["is_available"] = true
							}
						}
					}
				}
			}
			if len(conditionsList) > 0 {
				result["conditions"] = conditionsList
			}
		}
	}

	// Set platform as OpenShift
	result["platform"] = "OpenShift"

	return result, nil
}

// getOpenShiftConsoleURL fetches the console URL from OpenShift routes
func (c *ClusterClient) getOpenShiftConsoleURL(ctx context.Context) (string, error) {
	// Define the Route GVR
	routeGVR := schema.GroupVersionResource{
		Group:    "route.openshift.io",
		Version:  "v1",
		Resource: "routes",
	}

	// Try to get the console route in openshift-console namespace
	consoleRoute, err := c.dynamicClient.Resource(routeGVR).Namespace("openshift-console").Get(ctx, "console", metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get console route: %w", err)
	}

	// Extract the host from spec
	if spec, found, err := unstructured.NestedMap(consoleRoute.Object, "spec"); found && err == nil {
		if host, ok := spec["host"].(string); ok {
			// Check if TLS is enabled
			if _, hasTLS := spec["tls"]; hasTLS {
				return fmt.Sprintf("https://%s", host), nil
			}
			return fmt.Sprintf("http://%s", host), nil
		}
	}

	return "", fmt.Errorf("console host not found in route")
}

func (c *ClusterClient) deriveConsoleURL() string {
	// Derive console URL from API endpoint for OpenShift
	// Convert api.cluster.domain:6443 to console-openshift-console.apps.cluster.domain
	apiURL := c.Endpoint

	// Remove protocol
	apiURL = strings.TrimPrefix(apiURL, "https://")
	apiURL = strings.TrimPrefix(apiURL, "http://")

	// Remove port
	if idx := strings.Index(apiURL, ":"); idx != -1 {
		apiURL = apiURL[:idx]
	}

	// Convert api.* to console-openshift-console.apps.*
	if strings.HasPrefix(apiURL, "api.") {
		baseDomain := strings.TrimPrefix(apiURL, "api.")
		return fmt.Sprintf("https://console-openshift-console.apps.%s", baseDomain)
	}

	return c.Endpoint
}

// GetNodeMetrics retrieves detailed metrics for all nodes
func (c *ClusterClient) GetNodeMetrics(ctx context.Context) ([]types.NodeMetrics, error) {
	c.updateLastUsed()

	var nodeMetrics []types.NodeMetrics

	err := c.circuitBreaker.Call(ctx, func(ctx context.Context) error {
		// Get nodes
		nodes, err := c.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("failed to list nodes: %w", err)
		}

		// Get all pods for node assignment
		pods, err := c.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("failed to list pods: %w", err)
		}

		// Group pods by node
		podsByNode := make(map[string][]corev1.Pod)
		for _, pod := range pods.Items {
			if pod.Spec.NodeName != "" {
				podsByNode[pod.Spec.NodeName] = append(podsByNode[pod.Spec.NodeName], pod)
			}
		}

		// Process each node
		for _, node := range nodes.Items {
			metrics := c.extractNodeMetrics(&node, podsByNode[node.Name])
			nodeMetrics = append(nodeMetrics, metrics)
		}

		return nil
	})

	return nodeMetrics, err
}

// extractNodeMetrics extracts metrics from a node
func (c *ClusterClient) extractNodeMetrics(node *corev1.Node, pods []corev1.Pod) types.NodeMetrics {
	metrics := types.NodeMetrics{
		Name:        node.Name,
		Timestamp:   time.Now(),
		Labels:      node.Labels,
		Annotations: node.Annotations,
	}

	// Extract roles from labels
	for label := range node.Labels {
		if len(label) > 23 && label[:23] == "node-role.kubernetes.io/" {
			metrics.Roles = append(metrics.Roles, label[23:])
		}
	}

	// Process node conditions
	metrics.Status = string(types.NodeUnknown)
	for _, condition := range node.Status.Conditions {
		nc := types.NodeCondition{
			Type:               string(condition.Type),
			Status:             string(condition.Status),
			Reason:             condition.Reason,
			Message:            condition.Message,
			LastTransitionTime: condition.LastTransitionTime.Time,
		}
		metrics.Conditions = append(metrics.Conditions, nc)

		if condition.Type == corev1.NodeReady {
			if condition.Status == corev1.ConditionTrue {
				metrics.Status = string(types.NodeReady)
			} else {
				metrics.Status = string(types.NodeNotReady)
			}
		}
	}

	if node.Spec.Unschedulable {
		metrics.Status = string(types.NodeSchedulingDisabled)
	}

	// Parse resources
	metrics.CPUCapacity = utils.ParseCPU(node.Status.Capacity.Cpu().String())
	metrics.MemoryCapacity = utils.ParseMemory(node.Status.Capacity.Memory().String())
	metrics.StorageCapacity = utils.ParseMemory(node.Status.Capacity.StorageEphemeral().String())
	metrics.PodsCapacity = int32(node.Status.Capacity.Pods().Value())

	metrics.CPUAllocatable = utils.ParseCPU(node.Status.Allocatable.Cpu().String())
	metrics.MemoryAllocatable = utils.ParseMemory(node.Status.Allocatable.Memory().String())
	metrics.StorageAllocatable = utils.ParseMemory(node.Status.Allocatable.StorageEphemeral().String())
	metrics.PodsAllocatable = int32(node.Status.Allocatable.Pods().Value())

	// Calculate resource requests from pods
	var cpuRequested float64
	var memoryRequested int64
	podsByPhase := make(map[corev1.PodPhase]int32)

	for _, pod := range pods {
		phase := pod.Status.Phase
		podsByPhase[phase]++

		if phase == corev1.PodRunning || phase == corev1.PodPending {
			for _, container := range pod.Spec.Containers {
				if container.Resources.Requests != nil {
					cpuRequested += utils.ParseCPU(container.Resources.Requests.Cpu().String())
					memoryRequested += utils.ParseMemory(container.Resources.Requests.Memory().String())
				}
			}
		}
	}

	metrics.CPURequested = cpuRequested
	metrics.MemoryRequested = memoryRequested

	// Calculate usage percentages
	if metrics.CPUAllocatable > 0 {
		metrics.CPUUsagePercent = (cpuRequested / metrics.CPUAllocatable) * 100
	}
	if metrics.MemoryAllocatable > 0 {
		metrics.MemoryUsagePercent = float64(memoryRequested) / float64(metrics.MemoryAllocatable) * 100
	}

	// Set pod counts
	metrics.PodsRunning = podsByPhase[corev1.PodRunning]
	metrics.PodsPending = podsByPhase[corev1.PodPending]
	metrics.PodsFailed = podsByPhase[corev1.PodFailed]
	metrics.PodsSucceeded = podsByPhase[corev1.PodSucceeded]
	metrics.PodsTotal = int32(len(pods))

	// System info
	metrics.KernelVersion = node.Status.NodeInfo.KernelVersion
	metrics.OSImage = node.Status.NodeInfo.OSImage
	metrics.ContainerRuntime = node.Status.NodeInfo.ContainerRuntimeVersion
	metrics.KubeletVersion = node.Status.NodeInfo.KubeletVersion
	metrics.Architecture = node.Status.NodeInfo.Architecture

	// Network info
	for _, addr := range node.Status.Addresses {
		switch addr.Type {
		case corev1.NodeInternalIP:
			metrics.InternalIP = addr.Address
		case corev1.NodeExternalIP:
			metrics.ExternalIP = addr.Address
		case corev1.NodeHostName:
			metrics.Hostname = addr.Address
		}
	}

	// Taints
	for _, taint := range node.Spec.Taints {
		metrics.Taints = append(metrics.Taints, map[string]string{
			"key":    taint.Key,
			"value":  taint.Value,
			"effect": string(taint.Effect),
		})
	}

	metrics.ImagesCount = len(node.Status.Images)
	metrics.VolumesAttached = len(node.Status.VolumesAttached)

	return metrics
}

// GetClusterMetrics retrieves cluster-wide metrics
func (c *ClusterClient) GetClusterMetrics(ctx context.Context) (*types.ClusterMetrics, error) {
	c.updateLastUsed()

	var metrics types.ClusterMetrics
	metrics.Timestamp = time.Now()

	err := c.circuitBreaker.Call(ctx, func(ctx context.Context) error {
		// Get node metrics first
		nodeMetrics, err := c.GetNodeMetrics(ctx)
		if err != nil {
			return err
		}

		// Aggregate node metrics
		for _, nm := range nodeMetrics {
			if nm.Status == string(types.NodeReady) {
				metrics.NodesReady++
			}

			metrics.CPUCapacity += nm.CPUCapacity
			metrics.MemoryCapacity += nm.MemoryCapacity
			metrics.PodsRunning += int(nm.PodsRunning)
			metrics.Pods += int(nm.PodsTotal)
		}

		metrics.Nodes = len(nodeMetrics)

		// Get namespaces
		namespaces, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			logrus.WithError(err).Debug("Failed to list namespaces")
			metrics.Namespaces = 0
			metrics.NamespaceList = []string{}
		} else {
			metrics.Namespaces = len(namespaces.Items)
			metrics.NamespaceList = make([]string, 0, len(namespaces.Items))
			for _, ns := range namespaces.Items {
				metrics.NamespaceList = append(metrics.NamespaceList, ns.Name)
			}
			logrus.Debugf("Collected %d namespaces for metrics", len(metrics.NamespaceList))
		}

		// Workload counts
		deployments, err := c.clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
		if err == nil {
			metrics.Deployments = len(deployments.Items)
		} else {
			logrus.WithError(err).Debug("Failed to list deployments")
		}

		return nil
	})

	return &metrics, err
}

// GetNamespaces retrieves all namespaces from the cluster
func (c *ClusterClient) GetNamespaces(ctx context.Context) ([]string, error) {
	c.updateLastUsed()

	var namespaceList []string

	err := c.circuitBreaker.Call(ctx, func(ctx context.Context) error {
		namespaces, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("failed to list namespaces: %w", err)
		}

		namespaceList = make([]string, 0, len(namespaces.Items))
		for _, ns := range namespaces.Items {
			namespaceList = append(namespaceList, ns.Name)
		}

		logrus.Debugf("Retrieved %d namespaces from cluster %s", len(namespaceList), c.Name)

		return nil
	})

	return namespaceList, err
}

// GetOperators retrieves installed operators using subscription-based optimization
func (c *ClusterClient) GetOperators(ctx context.Context) ([]types.OperatorInfo, error) {
	c.updateLastUsed()

	var operators []types.OperatorInfo

	// Define GVRs
	subscriptionGVR := schema.GroupVersionResource{
		Group:    "operators.coreos.com",
		Version:  "v1alpha1",
		Resource: "subscriptions",
	}

	csvGVR := schema.GroupVersionResource{
		Group:    "operators.coreos.com",
		Version:  "v1alpha1",
		Resource: "clusterserviceversions",
	}

	log := logrus.WithField("cluster", c.Name)
	startTime := time.Now()

	// Step 1: Get all subscriptions (much fewer than CSVs)
	subList, err := c.dynamicClient.Resource(subscriptionGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		if errors.IsNotFound(err) || strings.Contains(err.Error(), "the server could not find the requested resource") {
			log.Debug("Subscription CRD not found, skipping operators")
			return []types.OperatorInfo{}, nil
		}
		log.Debug("Could not list subscriptions")
		return []types.OperatorInfo{}, nil
	}

	log.Debugf("Found %d subscriptions", len(subList.Items))

	// Step 2: Process each subscription
	for i := range subList.Items {
		sub := &subList.Items[i] // Get pointer to the item
		namespace := sub.GetNamespace()

		// Step 3: Get the installed CSV name from subscription status
		status, found, _ := unstructured.NestedMap(sub.Object, "status")
		if !found {
			continue
		}

		installedCSV, found, _ := unstructured.NestedString(status, "installedCSV")
		if !found || installedCSV == "" {
			// Subscription might be pending or failed
			continue
		}

		// Step 4: Fetch the specific CSV directly
		csv, err := c.dynamicClient.Resource(csvGVR).Namespace(namespace).Get(ctx, installedCSV, metav1.GetOptions{})
		if err != nil {
			log.Debugf("Could not get CSV %s in namespace %s: %v", installedCSV, namespace, err)
			continue
		}

		// Step 5: Extract operator info from CSV
		operator := c.extractOperatorInfo(csv, sub)
		if operator != nil {
			operators = append(operators, *operator)
		}
	}

	elapsed := time.Since(startTime)
	log.Debugf("Retrieved %d operators from %d subscriptions in %v", len(operators), len(subList.Items), elapsed)

	return operators, nil
}

// extractOperatorInfo extracts operator information from CSV and subscription
func (c *ClusterClient) extractOperatorInfo(csv, sub *unstructured.Unstructured) *types.OperatorInfo {
	operator := &types.OperatorInfo{
		Name:               csv.GetName(),
		InstalledNamespace: csv.GetNamespace(),
		CreatedAt:          csv.GetCreationTimestamp().Time,
		UpdatedAt:          csv.GetCreationTimestamp().Time,
	}

	// Get spec fields
	spec, found, _ := unstructured.NestedMap(csv.Object, "spec")
	if !found {
		return nil
	}

	// Display name and version
	if displayName, ok := spec["displayName"].(string); ok {
		operator.DisplayName = displayName
	} else {
		operator.DisplayName = csv.GetName()
	}

	if version, ok := spec["version"].(string); ok {
		operator.Version = version
	} else {
		operator.Version = "unknown"
	}

	// Provider
	if provider, found, _ := unstructured.NestedString(spec, "provider", "name"); found {
		operator.Provider = provider
	}

	// Install modes
	if modes, found, _ := unstructured.NestedSlice(spec, "installModes"); found {
		installModes := make([]string, 0, len(modes))
		for _, mode := range modes {
			if modeMap, ok := mode.(map[string]interface{}); ok {
				if modeName, ok := modeMap["type"].(string); ok {
					if supported, ok := modeMap["supported"].(bool); ok && supported {
						installModes = append(installModes, modeName)
						if modeName == "AllNamespaces" {
							operator.IsClusterWide = true
							operator.InstallMode = "AllNamespaces"
						}
					}
				}
			}
		}
		operator.InstallModes = installModes
		if operator.InstallMode == "" {
			operator.InstallMode = "SingleNamespace"
		}
	}

	// Get actual install mode from subscription
	if subSpec, found, _ := unstructured.NestedMap(sub.Object, "spec"); found {
		if installPlanApproval, ok := subSpec["installPlanApproval"].(string); ok {
			// This tells us if it's manual or automatic approval
			operator.Subscription = map[string]string{
				"installPlanApproval": installPlanApproval,
			}
		}

		// Check the actual install mode from subscription config
		if config, found, _ := unstructured.NestedMap(subSpec, "config"); found {
			if env, found, _ := unstructured.NestedSlice(config, "env"); found {
				for _, e := range env {
					if envMap, ok := e.(map[string]interface{}); ok {
						if name, _ := envMap["name"].(string); name == "WATCH_NAMESPACE" {
							if value, _ := envMap["value"].(string); value != "" {
								// Specific namespaces being watched
								operator.AvailableInNamespaces = strings.Split(value, ",")
							}
						}
					}
				}
			}
		}
	}

	// Determine availability
	if operator.IsClusterWide {
		operator.AvailableInNamespaces = []string{"*"}
	} else {
		// Check OLM target namespaces annotation
		annotations := csv.GetAnnotations()
		if targetNs, ok := annotations["olm.targetNamespaces"]; ok && targetNs != "" {
			targetNs = strings.Trim(targetNs, `"'`)
			if targetNs != "" {
				operator.AvailableInNamespaces = strings.Split(targetNs, ",")
			}
		} else if operatorGroup, ok := annotations["olm.operatorGroup"]; ok && operatorGroup != "" {
			// Could fetch the operator group to get target namespaces, but that's another API call
			// For now, default to the installation namespace
			operator.AvailableInNamespaces = []string{operator.InstalledNamespace}
		} else {
			operator.AvailableInNamespaces = []string{operator.InstalledNamespace}
		}
	}

	// Get status from CSV
	if status, found, _ := unstructured.NestedMap(csv.Object, "status"); found {
		if phase, ok := status["phase"].(string); ok {
			operator.Status = phase
		} else {
			operator.Status = "Unknown"
		}

		if lastUpdateTime, found, _ := unstructured.NestedString(status, "lastUpdateTime"); found {
			if t, err := time.Parse(time.RFC3339, lastUpdateTime); err == nil {
				operator.UpdatedAt = t
			}
		}
	}

	return operator
}

// GetClusterOperators retrieves OpenShift ClusterOperators
func (c *ClusterClient) GetClusterOperators(ctx context.Context) ([]types.ClusterOperatorInfo, error) {
	c.updateLastUsed()

	var clusterOperators []types.ClusterOperatorInfo

	// Define the ClusterOperator GVR
	clusterOperatorGVR := schema.GroupVersionResource{
		Group:    "config.openshift.io",
		Version:  "v1",
		Resource: "clusteroperators",
	}

	log := logrus.WithField("cluster", c.Name)
	startTime := time.Now()

	// List all ClusterOperators
	coList, err := c.dynamicClient.Resource(clusterOperatorGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		if errors.IsNotFound(err) || strings.Contains(err.Error(), "the server could not find the requested resource") {
			// Not an OpenShift cluster or doesn't have ClusterOperator CRD
			log.Debug("ClusterOperator CRD not found, likely not an OpenShift cluster")
			return []types.ClusterOperatorInfo{}, nil
		}
		return nil, fmt.Errorf("failed to list ClusterOperators: %w", err)
	}

	log.Debugf("Found %d ClusterOperators", len(coList.Items))

	// Process each ClusterOperator
	for _, item := range coList.Items {
		co := c.extractClusterOperatorInfo(&item)
		if co != nil {
			clusterOperators = append(clusterOperators, *co)
		}
	}

	// Sort by name for consistent ordering
	sort.Slice(clusterOperators, func(i, j int) bool {
		return clusterOperators[i].Name < clusterOperators[j].Name
	})

	elapsed := time.Since(startTime)
	log.Debugf("Retrieved %d ClusterOperators in %v", len(clusterOperators), elapsed)

	return clusterOperators, nil
}

// extractClusterOperatorInfo extracts ClusterOperator information from unstructured data
func (c *ClusterClient) extractClusterOperatorInfo(co *unstructured.Unstructured) *types.ClusterOperatorInfo {
	operator := &types.ClusterOperatorInfo{
		Name: co.GetName(),
	}

	// Get status
	status, found, err := unstructured.NestedMap(co.Object, "status")
	if !found || err != nil {
		logrus.Warnf("No status found for ClusterOperator %s", co.GetName())
		return operator
	}

	// Process conditions
	if conditions, found, _ := unstructured.NestedSlice(status, "conditions"); found {
		for _, cond := range conditions {
			if condMap, ok := cond.(map[string]interface{}); ok {
				condition := types.ClusterOperatorCondition{
					Type:    getStringValue(condMap, "type"),
					Status:  getStringValue(condMap, "status"),
					Reason:  getStringValue(condMap, "reason"),
					Message: getStringValue(condMap, "message"),
				}

				// Parse last transition time
				if lastTransition := getStringValue(condMap, "lastTransitionTime"); lastTransition != "" {
					if t, err := time.Parse(time.RFC3339, lastTransition); err == nil {
						condition.LastTransitionTime = t
					}
				}

				operator.Conditions = append(operator.Conditions, condition)

				// Set the main status booleans based on conditions
				switch condition.Type {
				case "Available":
					operator.Available = (condition.Status == "True")
					if condition.Status != "True" && condition.Message != "" {
						operator.Message = condition.Message
						operator.Reason = condition.Reason
					}
				case "Progressing":
					operator.Progressing = (condition.Status == "True")
					if condition.Status == "True" && condition.Message != "" && operator.Message == "" {
						operator.Message = condition.Message
					}
				case "Degraded":
					operator.Degraded = (condition.Status == "True")
					if condition.Status == "True" && condition.Message != "" {
						// Degraded messages take priority
						operator.Message = condition.Message
						operator.Reason = condition.Reason
					}
				case "Upgradeable":
					operator.Upgradeable = (condition.Status == "True")
				}

				// Track the latest transition time
				if condition.LastTransitionTime.After(operator.LastTransitionTime) {
					operator.LastTransitionTime = condition.LastTransitionTime
				}
			}
		}
	}

	// Process versions
	if versions, found, _ := unstructured.NestedSlice(status, "versions"); found {
		for _, ver := range versions {
			if verMap, ok := ver.(map[string]interface{}); ok {
				version := types.ClusterOperatorVersion{
					Name:    getStringValue(verMap, "name"),
					Version: getStringValue(verMap, "version"),
				}
				operator.Versions = append(operator.Versions, version)

				// Set the main version to the "operator" version if available
				if version.Name == "operator" || version.Name == operator.Name {
					operator.Version = version.Version
				}
			}
		}
	}

	// If no specific version found, try to get the first version
	if operator.Version == "" && len(operator.Versions) > 0 {
		operator.Version = operator.Versions[0].Version
	}

	// Process related objects
	if relatedObjects, found, _ := unstructured.NestedSlice(status, "relatedObjects"); found {
		for _, obj := range relatedObjects {
			if objMap, ok := obj.(map[string]interface{}); ok {
				relatedObj := types.RelatedObject{
					Group:     getStringValue(objMap, "group"),
					Resource:  getStringValue(objMap, "resource"),
					Namespace: getStringValue(objMap, "namespace"),
					Name:      getStringValue(objMap, "name"),
				}
				operator.RelatedObjects = append(operator.RelatedObjects, relatedObj)
			}
		}
	}

	return operator
}

// Helper function to safely get string values from map
func getStringValue(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return ""
}

// updateLastUsed returns when the client was last updated
func (c *ClusterClient) updateLastUsed() {
	c.mu.Lock()
	c.lastUsed = time.Now()
	c.mu.Unlock()
}

// GetLastUsed returns when the client was last used
func (c *ClusterClient) GetLastUsed() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastUsed
}

// Close closes the client connections
func (c *ClusterClient) Close() {
	// Nothing to close for standard clients
}
