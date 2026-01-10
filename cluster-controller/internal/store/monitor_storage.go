package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
	"github.com/sirupsen/logrus"
)

// StoreResourceMonitor stores a ResourceMonitor spec in Redis
func (c *Client) StoreResourceMonitor(ctx context.Context, name string, spec v1alpha1.ResourceMonitorSpec) error {
	monitorData := map[string]interface{}{
		"name":         name,
		"display_name": spec.DisplayName,
		"description":  spec.Description,
		"category":     spec.Category,
		"target": map[string]interface{}{
			"api_version": spec.Target.APIVersion,
			"kind":        spec.Target.Kind,
		},
		"collection": c.collectionToDict(spec.Collection),
		"schema":     c.schemaToDict(spec.Schema),
		"updated_at": time.Now().UTC().Format(time.RFC3339),
	}

	if spec.Health != nil {
		monitorData["health"] = c.healthToDict(spec.Health)
	}

	data, err := json.Marshal(monitorData)
	if err != nil {
		return fmt.Errorf("failed to marshal resource monitor: %w", err)
	}

	pipe := c.client.Pipeline()

	specKey := fmt.Sprintf("monitor:%s:spec", name)
	pipe.Set(ctx, specKey, string(data), 0)

	pipe.SAdd(ctx, "monitors:all", name)

	kindKey := fmt.Sprintf("monitors:kind:%s", spec.Target.Kind)
	pipe.SAdd(ctx, kindKey, name)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to store resource monitor: %w", err)
	}

	logrus.Debugf("Stored ResourceMonitor %s (target: %s/%s)", name, spec.Target.APIVersion, spec.Target.Kind)
	return nil
}

func (c *Client) collectionToDict(collection v1alpha1.CollectionSettings) map[string]interface{} {
	enabled := true
	if collection.Enabled != nil {
		enabled = *collection.Enabled
	}

	interval := collection.IntervalSeconds
	if interval < 30 {
		interval = 60
	}

	result := map[string]interface{}{
		"enabled":          enabled,
		"interval_seconds": interval,
		"limits": map[string]interface{}{
			"per_namespace": collection.Limits.PerNamespace,
			"per_cluster":   collection.Limits.PerCluster,
		},
	}

	if collection.NamespaceSelector != nil {
		nsSelector := map[string]interface{}{}
		if len(collection.NamespaceSelector.Include) > 0 {
			nsSelector["include"] = collection.NamespaceSelector.Include
		}
		if len(collection.NamespaceSelector.Exclude) > 0 {
			nsSelector["exclude"] = collection.NamespaceSelector.Exclude
		}
		if len(collection.NamespaceSelector.MatchLabels) > 0 {
			nsSelector["match_labels"] = collection.NamespaceSelector.MatchLabels
		}
		result["namespace_selector"] = nsSelector
	}

	if collection.ResourceSelector != nil {
		rsSelector := map[string]interface{}{}
		if collection.ResourceSelector.MatchLabels != nil {
			rsSelector["match_labels"] = collection.ResourceSelector.MatchLabels
		}
		if len(collection.ResourceSelector.MatchExpressions) > 0 {
			expressions := make([]map[string]interface{}, len(collection.ResourceSelector.MatchExpressions))
			for i, expr := range collection.ResourceSelector.MatchExpressions {
				expressions[i] = map[string]interface{}{
					"key":      expr.Key,
					"operator": string(expr.Operator),
					"values":   expr.Values,
				}
			}
			rsSelector["match_expressions"] = expressions
		}
		result["resource_selector"] = rsSelector
	}

	return result
}

func (c *Client) schemaToDict(schema v1alpha1.SchemaDefinition) map[string]interface{} {
	result := map[string]interface{}{
		"include_annotations": schema.IncludeAnnotations,
	}

	if len(schema.Fields) > 0 {
		fields := make([]map[string]interface{}, len(schema.Fields))
		for i, field := range schema.Fields {
			f := map[string]interface{}{
				"name": field.Name,
				"path": field.Path,
			}
			if field.Type != "" {
				f["type"] = field.Type
			}
			if field.Transform != "" {
				f["transform"] = field.Transform
			}
			if field.Default != "" {
				f["default"] = field.Default
			}
			fields[i] = f
		}
		result["fields"] = fields
	}

	return result
}

func (c *Client) healthToDict(health *v1alpha1.HealthMapping) map[string]interface{} {
	if health == nil {
		return nil
	}

	result := map[string]interface{}{}

	if health.Field != "" {
		result["field"] = health.Field
	}
	if health.Expression != "" {
		result["expression"] = health.Expression
	}

	mapping := map[string]interface{}{}
	if len(health.Mapping.Healthy) > 0 {
		mapping["healthy"] = health.Mapping.Healthy
	}
	if len(health.Mapping.Degraded) > 0 {
		mapping["degraded"] = health.Mapping.Degraded
	}
	if len(health.Mapping.Unhealthy) > 0 {
		mapping["unhealthy"] = health.Mapping.Unhealthy
	}
	if len(mapping) > 0 {
		result["mapping"] = mapping
	}

	return result
}

// GetResourceMonitor retrieves a ResourceMonitor spec from Redis
func (c *Client) GetResourceMonitor(ctx context.Context, name string) (map[string]interface{}, error) {
	key := fmt.Sprintf("monitor:%s:spec", name)
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	var spec map[string]interface{}
	if err := json.Unmarshal([]byte(data), &spec); err != nil {
		return nil, err
	}

	return spec, nil
}

// GetAllResourceMonitors retrieves all ResourceMonitor names
func (c *Client) GetAllResourceMonitors(ctx context.Context) ([]string, error) {
	members, err := c.client.SMembers(ctx, "monitors:all").Result()
	if err != nil {
		return nil, err
	}
	return members, nil
}

// GetActiveResourceMonitors retrieves specs for all enabled monitors
func (c *Client) GetActiveResourceMonitors(ctx context.Context) ([]map[string]interface{}, error) {
	names, err := c.GetAllResourceMonitors(ctx)
	if err != nil {
		return nil, err
	}

	var monitors []map[string]interface{}
	for _, name := range names {
		spec, err := c.GetResourceMonitor(ctx, name)
		if err != nil {
			logrus.WithError(err).Debugf("Failed to get monitor %s", name)
			continue
		}

		if collection, ok := spec["collection"].(map[string]interface{}); ok {
			if enabled, ok := collection["enabled"].(bool); ok && !enabled {
				continue
			}
		}

		monitors = append(monitors, spec)
	}

	return monitors, nil
}

// DeleteResourceMonitor removes a ResourceMonitor from Redis
func (c *Client) DeleteResourceMonitor(ctx context.Context, name string) error {
	spec, err := c.GetResourceMonitor(ctx, name)
	if err != nil {
		logrus.Debugf("Monitor %s not found in Redis, skipping deletion", name)
		return nil
	}

	pipe := c.client.Pipeline()

	pipe.Del(ctx, fmt.Sprintf("monitor:%s:spec", name))
	pipe.SRem(ctx, "monitors:all", name)

	if target, ok := spec["target"].(map[string]interface{}); ok {
		if kind, ok := target["kind"].(string); ok {
			pipe.SRem(ctx, fmt.Sprintf("monitors:kind:%s", kind), name)
		}
	}

	// Remove collected data for this monitor across all clusters
	pattern := fmt.Sprintf("cluster:*:monitor:%s:*", name)
	iter := c.client.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		pipe.Del(ctx, iter.Val())
	}

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete resource monitor: %w", err)
	}

	logrus.Debugf("Deleted ResourceMonitor %s from Redis", name)
	return nil
}

// UpdateMonitorCollectionStatus updates the collection status for a monitor on a specific cluster
func (c *Client) UpdateMonitorCollectionStatus(ctx context.Context, monitorName, clusterName string, resourceCount int, errMsg string) error {
	status := map[string]interface{}{
		"cluster":        clusterName,
		"resource_count": resourceCount,
		"collected_at":   time.Now().UTC().Format(time.RFC3339),
	}
	if errMsg != "" {
		status["error"] = errMsg
	}

	data, err := json.Marshal(status)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("monitor:%s:status:%s", monitorName, clusterName)
	return c.client.Set(ctx, key, string(data), time.Duration(c.config.CacheTTL)*time.Second).Err()
}

// StoreMonitoredResources stores collected resources for a monitor with summary data
func (c *Client) StoreMonitoredResources(ctx context.Context, clusterName, monitorName string, resources []map[string]interface{}, truncated bool) error {
	now := time.Now().UTC()

	// Build summary statistics
	byNamespace := make(map[string]int)
	byLabel := make(map[string]map[string]int)

	for _, res := range resources {
		if meta, ok := res["_meta"].(map[string]interface{}); ok {
			// Count by namespace
			if ns, ok := meta["namespace"].(string); ok && ns != "" {
				byNamespace[ns]++
			}

			// Count by common labels
			if labels, ok := meta["labels"].(map[string]string); ok {
				for k, v := range labels {
					// Only track well-known labels to avoid explosion
					if isCommonLabel(k) {
						if byLabel[k] == nil {
							byLabel[k] = make(map[string]int)
						}
						byLabel[k][v]++
					}
				}
			}
		}
	}

	// Main data payload
	data := map[string]interface{}{
		"resources":    resources,
		"truncated":    truncated,
		"total_count":  len(resources),
		"collected_at": now.Format(time.RFC3339),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal monitored resources: %w", err)
	}

	// Summary payload
	summary := map[string]interface{}{
		"count":        len(resources),
		"truncated":    truncated,
		"by_namespace": byNamespace,
		"by_label":     byLabel,
		"collected_at": now.Format(time.RFC3339),
	}

	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		return fmt.Errorf("failed to marshal summary: %w", err)
	}

	pipe := c.client.Pipeline()
	ttl := time.Duration(c.config.CacheTTL) * time.Second

	// Store main data
	dataKey := fmt.Sprintf("cluster:%s:monitor:%s:data", clusterName, monitorName)
	pipe.Set(ctx, dataKey, string(jsonData), ttl)

	// Store summary for quick access
	summaryKey := fmt.Sprintf("cluster:%s:monitor:%s:summary", clusterName, monitorName)
	pipe.Set(ctx, summaryKey, string(summaryJSON), ttl)

	// Store metadata
	metaKey := fmt.Sprintf("cluster:%s:monitor:%s:meta", clusterName, monitorName)
	pipe.HSet(ctx, metaKey,
		"collected_at", now.Format(time.RFC3339),
		"resource_count", len(resources),
		"truncated", truncated,
	)
	pipe.Expire(ctx, metaKey, ttl)

	// Track which monitors have data for this cluster
	pipe.SAdd(ctx, fmt.Sprintf("cluster:%s:monitors", clusterName), monitorName)
	pipe.Expire(ctx, fmt.Sprintf("cluster:%s:monitors", clusterName), ttl)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to store monitored resources: %w", err)
	}

	logrus.Debugf("Stored %d resources for monitor %s on cluster %s", len(resources), monitorName, clusterName)
	return nil
}

// GetMonitoredResources retrieves collected resources for a monitor from a cluster
func (c *Client) GetMonitoredResources(ctx context.Context, clusterName, monitorName string) ([]map[string]interface{}, error) {
	key := fmt.Sprintf("cluster:%s:monitor:%s:data", clusterName, monitorName)
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	var result struct {
		Resources []map[string]interface{} `json:"resources"`
	}
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return nil, err
	}

	return result.Resources, nil
}

// GetMonitoredResourcesSummary retrieves the summary for a monitor from a cluster
func (c *Client) GetMonitoredResourcesSummary(ctx context.Context, clusterName, monitorName string) (map[string]interface{}, error) {
	key := fmt.Sprintf("cluster:%s:monitor:%s:summary", clusterName, monitorName)
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	var summary map[string]interface{}
	if err := json.Unmarshal([]byte(data), &summary); err != nil {
		return nil, err
	}

	return summary, nil
}

// GetClusterMonitors returns all monitors with data for a cluster
func (c *Client) GetClusterMonitors(ctx context.Context, clusterName string) ([]string, error) {
	key := fmt.Sprintf("cluster:%s:monitors", clusterName)
	return c.client.SMembers(ctx, key).Result()
}

// isCommonLabel checks if a label is commonly used and worth tracking
func isCommonLabel(key string) bool {
	commonLabels := map[string]bool{
		"app":                          true,
		"app.kubernetes.io/name":       true,
		"app.kubernetes.io/instance":   true,
		"app.kubernetes.io/component":  true,
		"app.kubernetes.io/part-of":    true,
		"app.kubernetes.io/managed-by": true,
		"environment":                  true,
		"env":                          true,
		"tier":                         true,
		"team":                         true,
		"owner":                        true,
		"version":                      true,
	}
	return commonLabels[key]
}
