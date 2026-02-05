package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/sirupsen/logrus"
)

// MetricSource Redis key patterns
const (
	keyMetricSourceDef          = "metricsource:%s:%s"                // namespace:name
	keyMetricSourceResources    = "cluster:%s:custom:%s:resources"    // cluster:sourceId
	keyMetricSourceAggregations = "cluster:%s:custom:%s:aggregations" // cluster:sourceId
	keyMetricSourceMeta         = "cluster:%s:custom:%s:meta"         // cluster:sourceId
	keyMetricSourcesAll         = "metricsources:all"
	keyMetricSourcesEnabled     = "metricsources:enabled"
	keyMetricSourceByType       = "metricsources:by:resourcetype:%s" // resourceTypeName
)

// StoreCompiledMetricSource stores a compiled MetricSource definition in Redis
func (c *Client) StoreCompiledMetricSource(ctx context.Context, source *types.CompiledMetricSource) error {
	key := fmt.Sprintf(keyMetricSourceDef, source.Namespace, source.Name)
	sourceID := source.Namespace + "/" + source.Name

	// Serialize to JSON (excluding non-serializable fields)
	data, err := json.Marshal(source)
	if err != nil {
		return fmt.Errorf("failed to marshal MetricSource: %w", err)
	}

	pipe := c.client.Pipeline()

	// Store the compiled definition
	pipe.Set(ctx, key, string(data), 0) // No expiry for definitions

	// Update indexes
	pipe.SAdd(ctx, keyMetricSourcesAll, sourceID)
	pipe.SAdd(ctx, keyMetricSourcesEnabled, sourceID)

	// Index by resource type name for policy lookups
	if source.RBAC.ResourceTypeName != "" {
		typeKey := fmt.Sprintf(keyMetricSourceByType, source.RBAC.ResourceTypeName)
		pipe.SAdd(ctx, typeKey, sourceID)
	}

	// Store metadata
	metaKey := fmt.Sprintf("metricsource:%s:%s:meta", source.Namespace, source.Name)
	pipe.HSet(ctx, metaKey,
		"compiledAt", source.CompiledAt,
		"hash", source.Hash,
		"kind", source.Source.Kind,
		"apiVersion", source.Source.APIVersion,
		"resourceTypeName", source.RBAC.ResourceTypeName,
	)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to store MetricSource: %w", err)
	}

	logrus.Debugf("Stored MetricSource %s (hash: %s)", sourceID, source.Hash)
	return nil
}

// GetCompiledMetricSource retrieves a compiled MetricSource by namespace and name
func (c *Client) GetCompiledMetricSource(ctx context.Context, namespace, name string) (*types.CompiledMetricSource, error) {
	key := fmt.Sprintf(keyMetricSourceDef, namespace, name)

	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	var source types.CompiledMetricSource
	if err := json.Unmarshal([]byte(data), &source); err != nil {
		return nil, fmt.Errorf("failed to unmarshal MetricSource: %w", err)
	}

	// Rebuild field name index
	source.FieldNameToIndex = make(map[string]int)
	for i, f := range source.Fields {
		source.FieldNameToIndex[f.Name] = i
	}

	return &source, nil
}

// DeleteMetricSource removes a MetricSource and all its associated data
func (c *Client) DeleteMetricSource(ctx context.Context, namespace, name string) error {
	key := fmt.Sprintf(keyMetricSourceDef, namespace, name)
	sourceID := namespace + "/" + name

	// Get the source first to clean up type index
	source, err := c.GetCompiledMetricSource(ctx, namespace, name)
	if err != nil {
		logrus.Debugf("MetricSource %s not found for deletion", sourceID)
	}

	pipe := c.client.Pipeline()

	// Delete definition
	pipe.Del(ctx, key)

	// Remove from indexes
	pipe.SRem(ctx, keyMetricSourcesAll, sourceID)
	pipe.SRem(ctx, keyMetricSourcesEnabled, sourceID)

	// Remove from type index
	if source != nil && source.RBAC.ResourceTypeName != "" {
		typeKey := fmt.Sprintf(keyMetricSourceByType, source.RBAC.ResourceTypeName)
		pipe.SRem(ctx, typeKey, sourceID)
	}

	// Delete metadata
	metaKey := fmt.Sprintf("metricsource:%s:%s:meta", namespace, name)
	pipe.Del(ctx, metaKey)

	// Delete all cluster data for this source
	pattern := fmt.Sprintf("cluster:*:custom:%s:*", sourceID)
	iter := c.client.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		pipe.Del(ctx, iter.Val())
	}

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete MetricSource: %w", err)
	}

	logrus.Infof("Deleted MetricSource %s", sourceID)
	return nil
}

// ListMetricSources returns all MetricSource identifiers
func (c *Client) ListMetricSources(ctx context.Context) ([]string, error) {
	return c.client.SMembers(ctx, keyMetricSourcesAll).Result()
}

// ListEnabledMetricSources returns enabled MetricSource identifiers
func (c *Client) ListEnabledMetricSources(ctx context.Context) ([]string, error) {
	return c.client.SMembers(ctx, keyMetricSourcesEnabled).Result()
}

// GetMetricSourceByType returns MetricSource identifiers that provide a given resource type
func (c *Client) GetMetricSourceByType(ctx context.Context, resourceTypeName string) ([]string, error) {
	typeKey := fmt.Sprintf(keyMetricSourceByType, resourceTypeName)
	return c.client.SMembers(ctx, typeKey).Result()
}

// StoreCustomResourceCollection stores collected resources for a cluster/source combination
func (c *Client) StoreCustomResourceCollection(ctx context.Context, clusterName string, collection *types.CustomResourceCollection) error {
	key := fmt.Sprintf(keyMetricSourceResources, clusterName, collection.SourceID)

	data, err := json.Marshal(collection)
	if err != nil {
		return fmt.Errorf("failed to marshal resource collection: %w", err)
	}

	ttl := time.Duration(c.config.CacheTTL) * time.Second

	pipe := c.client.Pipeline()
	pipe.Set(ctx, key, string(data), ttl)

	// Store collection metadata separately for quick lookups
	metaKey := fmt.Sprintf(keyMetricSourceMeta, clusterName, collection.SourceID)
	meta := types.CollectionMetadata{
		SourceID:           collection.SourceID,
		ClusterName:        clusterName,
		LastCollectionTime: collection.CollectedAt,
		DurationMs:         collection.DurationMs,
		ResourceCount:      collection.ResourceCount,
		Truncated:          collection.Truncated,
	}

	metaData, _ := json.Marshal(meta)
	pipe.Set(ctx, metaKey, string(metaData), ttl)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to store resource collection: %w", err)
	}

	logrus.Debugf("Stored %d resources for %s/%s (took %dms)",
		collection.ResourceCount, clusterName, collection.SourceID, collection.DurationMs)

	return nil
}

// GetCustomResourceCollection retrieves collected resources for a cluster/source
func (c *Client) GetCustomResourceCollection(ctx context.Context, clusterName, sourceID string) (*types.CustomResourceCollection, error) {
	key := fmt.Sprintf(keyMetricSourceResources, clusterName, sourceID)

	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	var collection types.CustomResourceCollection
	if err := json.Unmarshal([]byte(data), &collection); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resource collection: %w", err)
	}

	return &collection, nil
}

// StoreAggregationResults stores computed aggregations for a cluster/source
func (c *Client) StoreAggregationResults(ctx context.Context, clusterName string, results *types.AggregationResults) error {
	key := fmt.Sprintf(keyMetricSourceAggregations, clusterName, results.SourceID)

	data, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("failed to marshal aggregation results: %w", err)
	}

	ttl := time.Duration(c.config.CacheTTL) * time.Second
	if err := c.client.Set(ctx, key, string(data), ttl).Err(); err != nil {
		return err
	}

	logrus.Debugf("Stored aggregation results for %s/%s", clusterName, results.SourceID)
	return nil
}

// GetAggregationResults retrieves computed aggregations for a cluster/source
func (c *Client) GetAggregationResults(ctx context.Context, clusterName, sourceID string) (*types.AggregationResults, error) {
	key := fmt.Sprintf(keyMetricSourceAggregations, clusterName, sourceID)

	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	var results types.AggregationResults
	if err := json.Unmarshal([]byte(data), &results); err != nil {
		return nil, fmt.Errorf("failed to unmarshal aggregation results: %w", err)
	}

	return &results, nil
}

// GetCollectionMetadata retrieves collection metadata for a cluster/source
func (c *Client) GetCollectionMetadata(ctx context.Context, clusterName, sourceID string) (*types.CollectionMetadata, error) {
	key := fmt.Sprintf(keyMetricSourceMeta, clusterName, sourceID)

	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	var meta types.CollectionMetadata
	if err := json.Unmarshal([]byte(data), &meta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal collection metadata: %w", err)
	}

	return &meta, nil
}

// DeleteMetricSourceClusterData removes all data for a MetricSource from a specific cluster
func (c *Client) DeleteMetricSourceClusterData(ctx context.Context, clusterName, sourceID string) error {
	pipe := c.client.Pipeline()

	pipe.Del(ctx, fmt.Sprintf(keyMetricSourceResources, clusterName, sourceID))
	pipe.Del(ctx, fmt.Sprintf(keyMetricSourceAggregations, clusterName, sourceID))
	pipe.Del(ctx, fmt.Sprintf(keyMetricSourceMeta, clusterName, sourceID))

	_, err := pipe.Exec(ctx)
	return err
}

// PublishMetricSourceEvent publishes an event related to MetricSource operations
func (c *Client) PublishMetricSourceEvent(eventType, sourceID string, data map[string]interface{}) {
	event := map[string]interface{}{
		"type":      eventType,
		"sourceId":  sourceID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"data":      data,
	}

	eventJSON, _ := json.Marshal(event)

	ctx := context.Background()
	c.client.Publish(ctx, "metricsource-events", string(eventJSON))

	logrus.Debugf("Published MetricSource event: %s for %s", eventType, sourceID)
}
