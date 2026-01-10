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
	// Convert to Python-compatible format
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

	// Store the monitor spec
	specKey := fmt.Sprintf("monitor:%s:spec", name)
	pipe.Set(ctx, specKey, string(data), 0) // No TTL - monitors are persistent

	// Add to the set of all monitors
	pipe.SAdd(ctx, "monitors:all", name)

	// Index by target kind for quick lookups
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

		// Check if enabled
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
	// Get the spec first to know which indexes to clean up
	spec, err := c.GetResourceMonitor(ctx, name)
	if err != nil {
		// Already gone, that's fine
		logrus.Debugf("Monitor %s not found in Redis, skipping deletion", name)
		return nil
	}

	pipe := c.client.Pipeline()

	// Remove spec
	pipe.Del(ctx, fmt.Sprintf("monitor:%s:spec", name))

	// Remove from monitors set
	pipe.SRem(ctx, "monitors:all", name)

	// Remove from kind index
	if target, ok := spec["target"].(map[string]interface{}); ok {
		if kind, ok := target["kind"].(string); ok {
			pipe.SRem(ctx, fmt.Sprintf("monitors:kind:%s", kind), name)
		}
	}

	// Remove any collected data for this monitor across all clusters
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

// StoreMonitoredResources stores collected resources for a monitor
func (c *Client) StoreMonitoredResources(ctx context.Context, clusterName, monitorName string, resources []map[string]interface{}, truncated bool) error {
	data := map[string]interface{}{
		"resources":    resources,
		"truncated":    truncated,
		"total_count":  len(resources),
		"collected_at": time.Now().UTC().Format(time.RFC3339),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal monitored resources: %w", err)
	}

	key := fmt.Sprintf("cluster:%s:monitor:%s:data", clusterName, monitorName)
	ttl := time.Duration(c.config.CacheTTL) * time.Second

	return c.client.Set(ctx, key, string(jsonData), ttl).Err()
}
