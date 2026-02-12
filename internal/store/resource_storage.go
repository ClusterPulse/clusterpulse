package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/sirupsen/logrus"
)

// StoreResourceCollection stores detailed resource data for RBAC filtering
// This is stored separately from metrics to maintain backward compatibility
func (c *Client) StoreResourceCollection(ctx context.Context, clusterName string, collection *types.ResourceCollection) error {
	if collection == nil {
		return nil
	}

	pipe := c.client.Pipeline()
	ttl := time.Duration(c.config.CacheTTL) * time.Second

	// Store pods if present
	if len(collection.Pods) > 0 {
		podsData, err := json.Marshal(collection.Pods)
		if err != nil {
			logrus.WithError(err).Debug("Failed to marshal pods")
		} else {
			pipe.Set(ctx, fmt.Sprintf("cluster:%s:pods", clusterName), string(podsData), ttl)
		}
	}

	// Store deployments if present
	if len(collection.Deployments) > 0 {
		depsData, err := json.Marshal(collection.Deployments)
		if err != nil {
			logrus.WithError(err).Debug("Failed to marshal deployments")
		} else {
			pipe.Set(ctx, fmt.Sprintf("cluster:%s:deployments", clusterName), string(depsData), ttl)
		}
	}

	// Store services if present
	if len(collection.Services) > 0 {
		svcsData, err := json.Marshal(collection.Services)
		if err != nil {
			logrus.WithError(err).Debug("Failed to marshal services")
		} else {
			pipe.Set(ctx, fmt.Sprintf("cluster:%s:services", clusterName), string(svcsData), ttl)
		}
	}

	// Store statefulsets if present
	if len(collection.StatefulSets) > 0 {
		stsData, err := json.Marshal(collection.StatefulSets)
		if err != nil {
			logrus.WithError(err).Debug("Failed to marshal statefulsets")
		} else {
			pipe.Set(ctx, fmt.Sprintf("cluster:%s:statefulsets", clusterName), string(stsData), ttl)
		}
	}

	// Store daemonsets if present
	if len(collection.DaemonSets) > 0 {
		dsData, err := json.Marshal(collection.DaemonSets)
		if err != nil {
			logrus.WithError(err).Debug("Failed to marshal daemonsets")
		} else {
			pipe.Set(ctx, fmt.Sprintf("cluster:%s:daemonsets", clusterName), string(dsData), ttl)
		}
	}

	// Store collection metadata
	metadata := map[string]interface{}{
		"timestamp":          collection.Timestamp.Format(time.RFC3339),
		"collection_time_ms": collection.CollectionTimeMs,
		"truncated":          collection.Truncated,
		"total_resources":    collection.TotalResources,
		"pods_count":         len(collection.Pods),
		"deployments_count":  len(collection.Deployments),
		"services_count":     len(collection.Services),
		"statefulsets_count": len(collection.StatefulSets),
		"daemonsets_count":   len(collection.DaemonSets),
	}

	metadataJSON, _ := json.Marshal(metadata)
	pipe.Set(ctx, fmt.Sprintf("cluster:%s:resource_metadata", clusterName), string(metadataJSON), ttl)

	// Execute pipeline
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to store resource collection: %w", err)
	}

	logrus.Debugf("Stored resource collection for %s: %d pods, %d deployments, %d services (took %dms)",
		clusterName,
		len(collection.Pods),
		len(collection.Deployments),
		len(collection.Services),
		collection.CollectionTimeMs)

	return nil
}
