package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/clusterpulse/cluster-controller/internal/config"
	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

// Client wraps Redis operations
type Client struct {
	client *redis.Client
	config *config.Config
}

// NewClient creates a new Redis client
func NewClient(cfg *config.Config) (*Client, error) {
	opts := &redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.RedisHost, cfg.RedisPort),
		Password:     cfg.RedisPassword,
		DB:           cfg.RedisDB,
		PoolSize:     50,
		MinIdleConns: 10,
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &Client{
		client: client,
		config: cfg,
	}, nil
}

// StoreOperators stores operator information in Redis (Python-compatible format)
func (c *Client) StoreOperators(ctx context.Context, clusterName string, operators []types.OperatorInfo) error {
	// Convert to Python-compatible format
	operatorsList := make([]map[string]any, 0, len(operators))

	for _, op := range operators {
		// Ensure arrays are never nil for Python compatibility
		installModes := op.InstallModes
		if installModes == nil {
			installModes = []string{}
		}

		availableNamespaces := op.AvailableInNamespaces
		if availableNamespaces == nil {
			availableNamespaces = []string{}
		}

		operatorData := map[string]any{
			"name":                    op.Name,
			"display_name":            op.DisplayName,
			"version":                 op.Version,
			"status":                  op.Status,
			"namespace":               op.InstalledNamespace, // Python uses 'namespace'
			"installed_namespace":     op.InstalledNamespace, // Also include this for compatibility
			"install_modes":           installModes,
			"install_mode":            op.InstallMode,
			"provider":                op.Provider,
			"created_at":              op.CreatedAt.Format(time.RFC3339),
			"updated_at":              op.UpdatedAt.Format(time.RFC3339),
			"is_cluster_wide":         op.IsClusterWide,
			"available_in_namespaces": availableNamespaces,
			"available_count":         len(availableNamespaces),
		}

		// Add availability detail for API compatibility
		if op.IsClusterWide || (len(availableNamespaces) == 1 && availableNamespaces[0] == "*") {
			operatorData["available_namespaces_detail"] = "All namespaces"
		} else if len(availableNamespaces) > 20 {
			operatorData["available_namespaces_detail"] = fmt.Sprintf("%d namespaces (showing first 20)", len(availableNamespaces))
			operatorData["all_available_namespaces"] = availableNamespaces
			// Truncate for display
			truncated := make([]string, 20)
			copy(truncated, availableNamespaces[:20])
			operatorData["available_in_namespaces"] = truncated
		} else {
			operatorData["available_namespaces_detail"] = strings.Join(availableNamespaces, ", ")
		}

		operatorsList = append(operatorsList, operatorData)
	}

	// Store operators list
	data, err := json.Marshal(operatorsList)
	if err != nil {
		return fmt.Errorf("failed to marshal operators: %w", err)
	}

	key := fmt.Sprintf("cluster:%s:operators", clusterName)

	// Also create and store summary
	summary := c.createOperatorSummary(operators)
	summaryData, err := json.Marshal(summary)
	if err != nil {
		return fmt.Errorf("failed to marshal operators summary: %w", err)
	}

	pipe := c.client.Pipeline()
	pipe.Set(ctx, key, string(data), time.Duration(c.config.CacheTTL)*time.Second)
	pipe.Set(ctx, fmt.Sprintf("cluster:%s:operators_summary", clusterName), string(summaryData), time.Duration(c.config.CacheTTL)*time.Second)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to store operators: %w", err)
	}

	logrus.Debugf("Stored %d operators for cluster %s", len(operators), clusterName)
	return nil
}

// createOperatorSummary creates a summary of operators
func (c *Client) createOperatorSummary(operators []types.OperatorInfo) map[string]any {
	summary := map[string]any{
		"total":        len(operators),
		"by_status":    make(map[string]int),
		"by_namespace": make(map[string]int),
		"by_install_mode": map[string]int{
			"cluster_wide":     0,
			"namespace_scoped": 0,
		},
	}

	byStatus := summary["by_status"].(map[string]int)
	byNamespace := summary["by_namespace"].(map[string]int)
	byInstallMode := summary["by_install_mode"].(map[string]int)

	for _, op := range operators {
		// Count by status
		status := op.Status
		if status == "" {
			status = "Unknown"
		}
		byStatus[status]++

		// Count by install mode
		if op.IsClusterWide {
			byInstallMode["cluster_wide"]++
		} else {
			byInstallMode["namespace_scoped"]++
			// Count by namespace for namespace-scoped operators
			if op.InstalledNamespace != "" {
				byNamespace[op.InstalledNamespace]++
			}
		}
	}

	return summary
}

// StoreNodeMetrics stores node metrics in Redis (Python-compatible format)
func (c *Client) StoreNodeMetrics(ctx context.Context, clusterName string, metrics []types.NodeMetrics) error {
	pipe := c.client.Pipeline()
	timestamp := time.Now().UTC()

	for _, node := range metrics {
		nodeKey := fmt.Sprintf("cluster:%s:node:%s", clusterName, node.Name)

		// Convert to Python-compatible format
		nodeData := c.nodeMetricsToDict(node)

		// Store current state
		currentJSON, err := json.Marshal(nodeData)
		if err != nil {
			logrus.WithError(err).Debugf("Failed to marshal node metrics for %s", node.Name)
			continue
		}

		pipe.HSet(ctx, nodeKey,
			"current", string(currentJSON),
			"last_update", timestamp.Format(time.RFC3339),
			"status", node.Status,
			"cpu_usage", fmt.Sprintf("%.2f", node.CPUUsagePercent),
			"memory_usage", fmt.Sprintf("%.2f", node.MemoryUsagePercent),
			"pods_total", node.PodsTotal,
		)

		// Store time-series metrics
		metricsKey := fmt.Sprintf("%s:metrics", nodeKey)
		metricsData := map[string]any{
			"timestamp":        node.Timestamp.Format(time.RFC3339),
			"cpu_usage":        node.CPUUsagePercent,
			"memory_usage":     node.MemoryUsagePercent,
			"cpu_requested":    node.CPURequested,
			"memory_requested": node.MemoryRequested,
			"pods_running":     node.PodsRunning,
			"pods_pending":     node.PodsPending,
			"pods_total":       node.PodsTotal,
		}

		metricsJSON, _ := json.Marshal(metricsData)
		pipe.ZAdd(ctx, metricsKey, &redis.Z{
			Score:  float64(timestamp.Unix()),
			Member: string(metricsJSON),
		})

		// Trim old metrics
		cutoff := timestamp.Add(-time.Duration(c.config.MetricsRetention) * time.Second).Unix()
		pipe.ZRemRangeByScore(ctx, metricsKey, "-inf", fmt.Sprintf("%d", cutoff))

		// Set TTLs
		pipe.Expire(ctx, nodeKey, time.Duration(c.config.CacheTTL)*time.Second)
		pipe.Expire(ctx, metricsKey, time.Duration(c.config.MetricsRetention)*time.Second)

		// Add to cluster's node set
		pipe.SAdd(ctx, fmt.Sprintf("cluster:%s:nodes", clusterName), node.Name)
	}

	// Store summary
	c.storeNodeSummary(ctx, pipe, clusterName, metrics, timestamp)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to execute Redis pipeline: %w", err)
	}

	logrus.Debugf("Stored node metrics for %d nodes in cluster %s", len(metrics), clusterName)
	return nil
}

// nodeMetricsToDict converts NodeMetrics to Python-compatible dictionary format
func (c *Client) nodeMetricsToDict(node types.NodeMetrics) map[string]any {
	// Convert conditions to list of dicts
	conditions := make([]map[string]any, len(node.Conditions))
	for i, cond := range node.Conditions {
		conditions[i] = map[string]any{
			"type":                 cond.Type,
			"status":               cond.Status,
			"reason":               cond.Reason,
			"message":              cond.Message,
			"last_transition_time": cond.LastTransitionTime.Format(time.RFC3339),
		}
	}

	// Ensure roles is never nil (Python expects empty list, not null)
	roles := node.Roles
	if roles == nil {
		roles = []string{}
	}

	// Ensure labels is never nil
	labels := node.Labels
	if labels == nil {
		labels = make(map[string]string)
	}

	// Ensure annotations is never nil
	annotations := node.Annotations
	if annotations == nil {
		annotations = make(map[string]string)
	}

	// Ensure taints is never nil
	taints := node.Taints
	if taints == nil {
		taints = []map[string]string{}
	}

	return map[string]any{
		"name":       node.Name,
		"timestamp":  node.Timestamp.Format(time.RFC3339),
		"status":     node.Status,
		"roles":      roles, // Always an array, never nil
		"conditions": conditions,

		// Resource capacity (using underscores like Python)
		"cpu_capacity":     node.CPUCapacity,
		"memory_capacity":  node.MemoryCapacity,
		"storage_capacity": node.StorageCapacity,
		"pods_capacity":    node.PodsCapacity,

		// Resource allocatable
		"cpu_allocatable":     node.CPUAllocatable,
		"memory_allocatable":  node.MemoryAllocatable,
		"storage_allocatable": node.StorageAllocatable,
		"pods_allocatable":    node.PodsAllocatable,

		// Resource usage
		"cpu_requested":        node.CPURequested,
		"memory_requested":     node.MemoryRequested,
		"cpu_usage_percent":    node.CPUUsagePercent,
		"memory_usage_percent": node.MemoryUsagePercent,

		// Pod metrics
		"pods_running":   node.PodsRunning,
		"pods_pending":   node.PodsPending,
		"pods_failed":    node.PodsFailed,
		"pods_succeeded": node.PodsSucceeded,
		"pods_total":     node.PodsTotal,

		// System info
		"kernel_version":    node.KernelVersion,
		"os_image":          node.OSImage,
		"container_runtime": node.ContainerRuntime,
		"kubelet_version":   node.KubeletVersion,
		"architecture":      node.Architecture,

		// Labels and annotations
		"labels":      labels,
		"annotations": annotations,
		"taints":      taints,

		// Network info
		"internal_ip": node.InternalIP,
		"external_ip": node.ExternalIP,
		"hostname":    node.Hostname,

		// Additional metrics
		"images_count":     node.ImagesCount,
		"volumes_attached": node.VolumesAttached,
	}
}

func (c *Client) storeNodeSummary(ctx context.Context, pipe redis.Pipeliner, clusterName string, metrics []types.NodeMetrics, timestamp time.Time) {
	summary := map[string]any{
		"total":                 len(metrics),
		"ready":                 0,
		"not_ready":             0,
		"scheduling_disabled":   0,
		"by_role":               make(map[string]int), // Initialize map
		"total_cpu_capacity":    float64(0),
		"total_memory_capacity": int64(0),
		"avg_cpu_usage":         float64(0),
		"avg_memory_usage":      float64(0),
		"timestamp":             timestamp.Format(time.RFC3339),
	}

	totalCPU := float64(0)
	totalMemory := float64(0)
	byRole := make(map[string]int)

	for _, node := range metrics {
		switch node.Status {
		case string(types.NodeReady):
			summary["ready"] = summary["ready"].(int) + 1
		case string(types.NodeNotReady):
			summary["not_ready"] = summary["not_ready"].(int) + 1
		case string(types.NodeSchedulingDisabled):
			summary["scheduling_disabled"] = summary["scheduling_disabled"].(int) + 1
		}

		summary["total_cpu_capacity"] = summary["total_cpu_capacity"].(float64) + node.CPUCapacity
		summary["total_memory_capacity"] = summary["total_memory_capacity"].(int64) + node.MemoryCapacity
		totalCPU += node.CPUUsagePercent
		totalMemory += node.MemoryUsagePercent

		// Count roles
		for _, role := range node.Roles {
			byRole[role] = byRole[role] + 1
		}
	}

	summary["by_role"] = byRole

	if len(metrics) > 0 {
		summary["avg_cpu_usage"] = totalCPU / float64(len(metrics))
		summary["avg_memory_usage"] = totalMemory / float64(len(metrics))
	}

	summaryJSON, _ := json.Marshal(summary)
	pipe.HSet(ctx, fmt.Sprintf("cluster:%s:nodes:summary", clusterName), "data", string(summaryJSON))
	pipe.Expire(ctx, fmt.Sprintf("cluster:%s:nodes:summary", clusterName), time.Duration(c.config.CacheTTL)*time.Second)
}

// StoreClusterMetrics stores cluster metrics (Python-compatible)
func (c *Client) StoreClusterMetrics(ctx context.Context, name string, metrics *types.ClusterMetrics) error {
	// Convert to Python-compatible format (WITHOUT namespace_list)
	metricsDict := map[string]any{
		"timestamp":       metrics.Timestamp.Format(time.RFC3339),
		"nodes":           metrics.Nodes,
		"nodes_ready":     metrics.NodesReady,
		"namespaces":      metrics.Namespaces, // Just the count
		"pods":            metrics.Pods,
		"pods_running":    metrics.PodsRunning,
		"cpu_capacity":    metrics.CPUCapacity,
		"memory_capacity": metrics.MemoryCapacity,
		"deployments":     metrics.Deployments,
	}

	data, err := json.Marshal(metricsDict)
	if err != nil {
		return fmt.Errorf("failed to marshal cluster metrics: %w", err)
	}

	// Use pipeline for atomic operations
	pipe := c.client.Pipeline()

	// Store main metrics
	metricsKey := fmt.Sprintf("cluster:%s:metrics", name)
	pipe.Set(ctx, metricsKey, string(data), 5*time.Minute)

	// Store namespace list separately
	if err := c.storeNamespaceList(ctx, pipe, name, metrics.NamespaceList); err != nil {
		return fmt.Errorf("failed to prepare namespace list storage: %w", err)
	}

	// Execute pipeline
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to execute Redis pipeline: %w", err)
	}

	logrus.Debugf("Stored cluster metrics for %s (%d nodes, %d namespaces)", name, metrics.Nodes, metrics.Namespaces)

	return nil
}

// storeNamespaceList stores the namespace list separately for easier access
func (c *Client) storeNamespaceList(ctx context.Context, pipe redis.Pipeliner, clusterName string, namespaces []string) error {
	// Ensure namespaces is never nil
	if namespaces == nil {
		namespaces = []string{}
	}

	// Create namespace data structure (Python-compatible)
	namespaceData := map[string]any{
		"namespaces": namespaces,
		"count":      len(namespaces),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(namespaceData)
	if err != nil {
		return fmt.Errorf("failed to marshal namespace list: %w", err)
	}

	// Store under cluster:<n>:namespaces
	namespacesKey := fmt.Sprintf("cluster:%s:namespaces", clusterName)
	pipe.Set(ctx, namespacesKey, string(data), time.Duration(c.config.CacheTTL)*time.Second)

	// Also store as a set for efficient membership checks
	namespaceSetKey := fmt.Sprintf("cluster:%s:namespaces:set", clusterName)
	pipe.Del(ctx, namespaceSetKey) // Clear existing set
	if len(namespaces) > 0 {
		members := make([]any, len(namespaces))
		for i, ns := range namespaces {
			members[i] = ns
		}
		pipe.SAdd(ctx, namespaceSetKey, members...)
		pipe.Expire(ctx, namespaceSetKey, time.Duration(c.config.CacheTTL)*time.Second)
	}

	return nil
}

// StoreNamespaces stores namespace list independently (can be called separately)
func (c *Client) StoreNamespaces(ctx context.Context, clusterName string, namespaces []string) error {
	if namespaces == nil {
		namespaces = []string{}
	}

	// Create namespace data structure (Python-compatible)
	namespaceData := map[string]any{
		"namespaces": namespaces,
		"count":      len(namespaces),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(namespaceData)
	if err != nil {
		return fmt.Errorf("failed to marshal namespace list: %w", err)
	}

	pipe := c.client.Pipeline()

	// Store under cluster:<n>:namespaces
	namespacesKey := fmt.Sprintf("cluster:%s:namespaces", clusterName)
	pipe.Set(ctx, namespacesKey, string(data), time.Duration(c.config.CacheTTL)*time.Second)

	// Also store as a set for efficient membership checks
	namespaceSetKey := fmt.Sprintf("cluster:%s:namespaces:set", clusterName)
	pipe.Del(ctx, namespaceSetKey) // Clear existing set
	if len(namespaces) > 0 {
		members := make([]any, len(namespaces))
		for i, ns := range namespaces {
			members[i] = ns
		}
		pipe.SAdd(ctx, namespaceSetKey, members...)
		pipe.Expire(ctx, namespaceSetKey, time.Duration(c.config.CacheTTL)*time.Second)
	}

	// Execute pipeline
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to store namespaces: %w", err)
	}

	logrus.Debugf("Stored %d namespaces for cluster %s", len(namespaces), clusterName)
	return nil
}

// StoreClusterInfo stores cluster info
func (c *Client) StoreClusterInfo(ctx context.Context, name string, info map[string]any) error {
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal cluster info: %w", err)
	}

	key := fmt.Sprintf("cluster:%s:info", name)
	return c.client.Set(ctx, key, string(data), 1*time.Hour).Err()
}

// StoreClusterStatus stores cluster status
func (c *Client) StoreClusterStatus(ctx context.Context, name string, status map[string]any) error {
	data, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("failed to marshal cluster status: %w", err)
	}

	key := fmt.Sprintf("cluster:%s:status", name)

	pipe := c.client.Pipeline()
	pipe.Set(ctx, key, string(data), 0)
	pipe.HSet(ctx, fmt.Sprintf("cluster:%s:meta", name), "last_update", time.Now().UTC().Format(time.RFC3339))
	pipe.SAdd(ctx, "clusters:all", name)

	_, err = pipe.Exec(ctx)
	return err
}

// StoreClusterSpec stores the cluster spec (for backend compatibility)
func (c *Client) StoreClusterSpec(ctx context.Context, name string, spec map[string]any) error {
	data, err := json.Marshal(spec)
	if err != nil {
		return fmt.Errorf("failed to marshal cluster spec: %w", err)
	}

	key := fmt.Sprintf("cluster:%s:spec", name)
	return c.client.Set(ctx, key, string(data), 0).Err()
}

// StoreClusterLabels stores cluster labels
func (c *Client) StoreClusterLabels(ctx context.Context, name string, labels map[string]string) error {
	data, err := json.Marshal(labels)
	if err != nil {
		return fmt.Errorf("failed to marshal cluster labels: %w", err)
	}

	key := fmt.Sprintf("cluster:%s:labels", name)
	return c.client.Set(ctx, key, string(data), 0).Err()
}

// StoreClusterOperators stores OpenShift ClusterOperator information
func (c *Client) StoreClusterOperators(ctx context.Context, clusterName string, operators []types.ClusterOperatorInfo) error {
	if len(operators) == 0 {
		// No cluster operators means it's likely not an OpenShift cluster
		return nil
	}

	// Convert to Python-compatible format
	operatorsList := make([]map[string]any, 0, len(operators))

	// Track overall health metrics
	totalCount := len(operators)
	availableCount := 0
	degradedCount := 0
	progressingCount := 0
	upgradeableCount := 0

	for _, op := range operators {
		// Count statuses
		if op.Available {
			availableCount++
		}
		if op.Degraded {
			degradedCount++
		}
		if op.Progressing {
			progressingCount++
		}
		if op.Upgradeable {
			upgradeableCount++
		}

		// Convert conditions to list of dicts
		conditions := make([]map[string]any, len(op.Conditions))
		for i, cond := range op.Conditions {
			conditions[i] = map[string]any{
				"type":                 cond.Type,
				"status":               cond.Status,
				"last_transition_time": cond.LastTransitionTime.Format(time.RFC3339),
				"reason":               cond.Reason,
				"message":              cond.Message,
			}
		}

		// Convert versions
		versions := make([]map[string]any, len(op.Versions))
		for i, ver := range op.Versions {
			versions[i] = map[string]any{
				"name":    ver.Name,
				"version": ver.Version,
			}
		}

		// Convert related objects
		relatedObjects := make([]map[string]any, len(op.RelatedObjects))
		for i, obj := range op.RelatedObjects {
			relatedObjects[i] = map[string]any{
				"group":     obj.Group,
				"resource":  obj.Resource,
				"namespace": obj.Namespace,
				"name":      obj.Name,
			}
		}

		operatorData := map[string]any{
			"name":                 op.Name,
			"version":              op.Version,
			"available":            op.Available,
			"progressing":          op.Progressing,
			"degraded":             op.Degraded,
			"upgradeable":          op.Upgradeable,
			"message":              op.Message,
			"reason":               op.Reason,
			"last_transition_time": op.LastTransitionTime.Format(time.RFC3339),
			"conditions":           conditions,
			"versions":             versions,
			"related_objects":      relatedObjects,
		}

		operatorsList = append(operatorsList, operatorData)
	}

	// Store the full list
	data, err := json.Marshal(operatorsList)
	if err != nil {
		return fmt.Errorf("failed to marshal cluster operators: %w", err)
	}

	key := fmt.Sprintf("cluster:%s:cluster_operators", clusterName)

	// Create summary for quick access
	summary := map[string]any{
		"total":       totalCount,
		"available":   availableCount,
		"degraded":    degradedCount,
		"progressing": progressingCount,
		"upgradeable": upgradeableCount,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"all_healthy": availableCount == totalCount && degradedCount == 0,
		"has_issues":  degradedCount > 0 || availableCount < totalCount,
	}

	// Find any degraded or unavailable operators for quick reference
	var issues []string
	for _, op := range operators {
		if op.Degraded {
			issues = append(issues, fmt.Sprintf("%s: degraded - %s", op.Name, op.Message))
		} else if !op.Available {
			issues = append(issues, fmt.Sprintf("%s: not available - %s", op.Name, op.Message))
		}
	}
	if len(issues) > 0 {
		summary["issues"] = issues
	}

	summaryData, err := json.Marshal(summary)
	if err != nil {
		return fmt.Errorf("failed to marshal cluster operators summary: %w", err)
	}

	// Store both the full data and summary
	pipe := c.client.Pipeline()
	pipe.Set(ctx, key, string(data), time.Duration(c.config.CacheTTL)*time.Second)
	pipe.Set(ctx, fmt.Sprintf("cluster:%s:cluster_operators_summary", clusterName),
		string(summaryData), time.Duration(c.config.CacheTTL)*time.Second)

	// Store individual operator status for quick lookups
	for _, op := range operators {
		opKey := fmt.Sprintf("cluster:%s:cluster_operator:%s", clusterName, op.Name)
		opData := map[string]any{
			"available":   op.Available,
			"degraded":    op.Degraded,
			"progressing": op.Progressing,
			"version":     op.Version,
			"message":     op.Message,
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
		}
		opJSON, _ := json.Marshal(opData)
		pipe.Set(ctx, opKey, string(opJSON), time.Duration(c.config.CacheTTL)*time.Second)
	}

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to store cluster operators: %w", err)
	}

	// Only log at info if there are issues
	if degradedCount > 0 || availableCount < totalCount {
		logrus.Warnf("Cluster %s has operator issues: %d/%d available, %d degraded",
			clusterName, availableCount, totalCount, degradedCount)
	} else {
		logrus.Debugf("Stored %d cluster operators for %s (all healthy)", totalCount, clusterName)
	}

	return nil
}

// GetClusterOperatorsSummary retrieves the cluster operators summary
func (c *Client) GetClusterOperatorsSummary(ctx context.Context, clusterName string) (map[string]any, error) {
	key := fmt.Sprintf("cluster:%s:cluster_operators_summary", clusterName)
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	var summary map[string]any
	if err := json.Unmarshal([]byte(data), &summary); err != nil {
		return nil, err
	}

	return summary, nil
}

// GetClusterOperators retrieves all cluster operators for a cluster
func (c *Client) GetClusterOperators(ctx context.Context, clusterName string) ([]map[string]any, error) {
	key := fmt.Sprintf("cluster:%s:cluster_operators", clusterName)
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	var operators []map[string]any
	if err := json.Unmarshal([]byte(data), &operators); err != nil {
		return nil, err
	}

	return operators, nil
}

// GetClusterOperatorStatus retrieves status for a specific cluster operator
func (c *Client) GetClusterOperatorStatus(ctx context.Context, clusterName, operatorName string) (map[string]any, error) {
	key := fmt.Sprintf("cluster:%s:cluster_operator:%s", clusterName, operatorName)
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	var status map[string]any
	if err := json.Unmarshal([]byte(data), &status); err != nil {
		return nil, err
	}

	return status, nil
}

// PublishEvent publishes an event
func (c *Client) PublishEvent(eventType, clusterName string, data map[string]any) {
	event := map[string]any{
		"type":      eventType,
		"cluster":   clusterName,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"data":      data,
	}

	eventJSON, _ := json.Marshal(event)

	ctx := context.Background()

	// Publish to channel
	c.client.Publish(ctx, "cluster-events", string(eventJSON))

	// Store in event list
	eventKey := fmt.Sprintf("events:%s", clusterName)
	c.client.LPush(ctx, eventKey, string(eventJSON))
	c.client.LTrim(ctx, eventKey, 0, 99)
	c.client.Expire(ctx, eventKey, 24*time.Hour)
}

// DeleteClusterData deletes all data for a cluster
func (c *Client) DeleteClusterData(ctx context.Context, name string) error {
	pattern := fmt.Sprintf("cluster:%s:*", name)

	// Use SCAN to find all keys
	iter := c.client.Scan(ctx, 0, pattern, 100).Iterator()

	pipe := c.client.Pipeline()
	count := 0

	for iter.Next(ctx) {
		pipe.Del(ctx, iter.Val())
		count++

		// Execute in batches
		if count%1000 == 0 {
			if _, err := pipe.Exec(ctx); err != nil {
				return err
			}
			pipe = c.client.Pipeline()
		}
	}

	if count%1000 != 0 {
		if _, err := pipe.Exec(ctx); err != nil {
			return err
		}
	}

	// Explicitly delete namespace-related keys to ensure cleanup
	pipe = c.client.Pipeline()
	pipe.Del(ctx, fmt.Sprintf("cluster:%s:namespaces", name))
	pipe.Del(ctx, fmt.Sprintf("cluster:%s:namespaces:set", name))
	pipe.SRem(ctx, "clusters:all", name)

	if _, err := pipe.Exec(ctx); err != nil {
		logrus.WithError(err).Debugf("Failed to delete some namespace keys for cluster %s", name)
	}

	return iter.Err()
}

// RedisClient returns the underlying redis.Client for direct access.
func (c *Client) RedisClient() *redis.Client {
	return c.client
}

// Close closes the Redis connection
func (c *Client) Close() error {
	return c.client.Close()
}
