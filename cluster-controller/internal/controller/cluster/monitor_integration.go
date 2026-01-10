package cluster

import (
	"context"
	"encoding/json"
	"time"

	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
	clusterclient "github.com/clusterpulse/cluster-controller/internal/client/cluster"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// collectDynamicResources fetches active ResourceMonitors and collects their resources
func (r *ClusterReconciler) collectDynamicResources(ctx context.Context, clusterConn *v1alpha1.ClusterConnection, clusterClient *clusterclient.ClusterClient) {
	log := logrus.WithField("cluster", clusterConn.Name)

	// Get all active monitors from the same namespace
	monitors, err := r.getActiveMonitors(ctx)
	if err != nil {
		log.WithError(err).Debug("Failed to fetch ResourceMonitors")
		return
	}

	if len(monitors) == 0 {
		log.Debug("No active ResourceMonitors found")
		return
	}

	log.Debugf("Found %d active ResourceMonitors", len(monitors))

	// Collect resources for each monitor
	for _, monitor := range monitors {
		if !monitor.IsEnabled() {
			continue
		}

		// Check collection interval - we might want to collect less frequently than cluster reconciliation
		if !r.shouldCollectMonitor(clusterConn.Name, monitor.Name, monitor.GetInterval()) {
			log.Debugf("Skipping monitor %s (not due for collection)", monitor.Name)
			continue
		}

		if err := r.collectMonitorResources(ctx, clusterConn, clusterClient, &monitor); err != nil {
			log.WithError(err).Warnf("Failed to collect resources for monitor %s", monitor.Name)
			// Update collection status with error
			r.RedisClient.UpdateMonitorCollectionStatus(ctx, monitor.Name, clusterConn.Name, 0, err.Error())
		}
	}
}

// getActiveMonitors fetches all enabled ResourceMonitor CRs
func (r *ClusterReconciler) getActiveMonitors(ctx context.Context) ([]v1alpha1.ResourceMonitor, error) {
	var monitorList v1alpha1.ResourceMonitorList

	listOpts := []client.ListOption{
		client.InNamespace(r.WatchNamespace),
	}

	if err := r.List(ctx, &monitorList, listOpts...); err != nil {
		return nil, err
	}

	// Filter to only active monitors
	var active []v1alpha1.ResourceMonitor
	for _, m := range monitorList.Items {
		if m.IsEnabled() && m.Status.State == "Active" {
			active = append(active, m)
		}
	}

	return active, nil
}

// monitorCollectionTracker tracks when each monitor was last collected per cluster
type monitorCollectionKey struct {
	cluster string
	monitor string
}

var lastMonitorCollection = make(map[monitorCollectionKey]time.Time)

// shouldCollectMonitor checks if enough time has passed since last collection
func (r *ClusterReconciler) shouldCollectMonitor(clusterName, monitorName string, intervalSeconds int32) bool {
	key := monitorCollectionKey{cluster: clusterName, monitor: monitorName}
	lastTime, exists := lastMonitorCollection[key]

	if !exists {
		return true
	}

	return time.Since(lastTime) >= time.Duration(intervalSeconds)*time.Second
}

// updateMonitorCollectionTime records when a monitor was last collected
func (r *ClusterReconciler) updateMonitorCollectionTime(clusterName, monitorName string) {
	key := monitorCollectionKey{cluster: clusterName, monitor: monitorName}
	lastMonitorCollection[key] = time.Now()
}

// collectMonitorResources collects resources for a single monitor
func (r *ClusterReconciler) collectMonitorResources(
	ctx context.Context,
	clusterConn *v1alpha1.ClusterConnection,
	clusterClient *clusterclient.ClusterClient,
	monitor *v1alpha1.ResourceMonitor,
) error {
	log := logrus.WithFields(logrus.Fields{
		"cluster": clusterConn.Name,
		"monitor": monitor.Name,
		"kind":    monitor.Spec.Target.Kind,
	})

	log.Debug("Collecting resources")

	// Use a shorter timeout for individual monitor collection
	collectionCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Collect resources using the dynamic client
	result, err := clusterClient.CollectMonitoredResources(collectionCtx, monitor)
	if err != nil {
		return err
	}

	// Update collection time tracker
	r.updateMonitorCollectionTime(clusterConn.Name, monitor.Name)

	// Store in Redis
	if err := r.RedisClient.StoreMonitoredResources(ctx, clusterConn.Name, monitor.Name, result.Resources, result.Truncated); err != nil {
		log.WithError(err).Warn("Failed to store collected resources")
		return err
	}

	// Update collection status
	r.RedisClient.UpdateMonitorCollectionStatus(ctx, monitor.Name, clusterConn.Name, result.TotalCount, result.Error)

	// Publish event for real-time updates
	r.RedisClient.PublishEvent("monitor.collected", monitor.Name, map[string]interface{}{
		"cluster":        clusterConn.Name,
		"monitor":        monitor.Name,
		"kind":           monitor.Spec.Target.Kind,
		"resource_count": result.TotalCount,
		"truncated":      result.Truncated,
		"duration_ms":    result.CollectionTimeMs,
	})

	log.Debugf("Collected %d resources in %dms", result.TotalCount, result.CollectionTimeMs)

	return nil
}

// cleanupMonitorCollection removes stale collection tracking entries
func (r *ClusterReconciler) cleanupMonitorCollection(clusterName string) {
	for key := range lastMonitorCollection {
		if key.cluster == clusterName {
			delete(lastMonitorCollection, key)
		}
	}
}

// MonitorCollectionSummary provides a summary of collected resources across monitors
type MonitorCollectionSummary struct {
	MonitorName   string                 `json:"monitor_name"`
	Kind          string                 `json:"kind"`
	ResourceCount int                    `json:"resource_count"`
	Truncated     bool                   `json:"truncated"`
	CollectedAt   string                 `json:"collected_at"`
	DurationMs    int64                  `json:"duration_ms"`
	ByNamespace   map[string]int         `json:"by_namespace,omitempty"`
	Health        map[string]int         `json:"health,omitempty"`
	Error         string                 `json:"error,omitempty"`
}

// buildCollectionSummary creates a summary from collected resources
func buildCollectionSummary(monitor *v1alpha1.ResourceMonitor, resources []map[string]interface{}, truncated bool, durationMs int64) *MonitorCollectionSummary {
	summary := &MonitorCollectionSummary{
		MonitorName:   monitor.Name,
		Kind:          monitor.Spec.Target.Kind,
		ResourceCount: len(resources),
		Truncated:     truncated,
		CollectedAt:   time.Now().UTC().Format(time.RFC3339),
		DurationMs:    durationMs,
		ByNamespace:   make(map[string]int),
		Health:        make(map[string]int),
	}

	// Aggregate by namespace
	for _, res := range resources {
		if meta, ok := res["_meta"].(map[string]interface{}); ok {
			if ns, ok := meta["namespace"].(string); ok && ns != "" {
				summary.ByNamespace[ns]++
			}
		}

		// Aggregate health if monitor has health mapping
		if monitor.Spec.Health != nil && monitor.Spec.Health.Field != "" {
			healthField := monitor.Spec.Health.Field
			if val, ok := res[healthField]; ok {
				health := determineHealth(val, monitor.Spec.Health)
				summary.Health[health]++
			} else {
				summary.Health["unknown"]++
			}
		}
	}

	return summary
}

// determineHealth maps a field value to a health status
func determineHealth(value interface{}, healthMapping *v1alpha1.HealthMapping) string {
	if healthMapping == nil {
		return "unknown"
	}

	strVal := ""
	switch v := value.(type) {
	case string:
		strVal = v
	case bool:
		if v {
			strVal = "true"
		} else {
			strVal = "false"
		}
	default:
		// Convert to string via JSON
		if b, err := json.Marshal(v); err == nil {
			strVal = string(b)
		}
	}

	// Check healthy values
	for _, h := range healthMapping.Mapping.Healthy {
		if h == strVal {
			return "healthy"
		}
	}

	// Check degraded values
	for _, d := range healthMapping.Mapping.Degraded {
		if d == strVal {
			return "degraded"
		}
	}

	// Check unhealthy values
	for _, u := range healthMapping.Mapping.Unhealthy {
		if u == strVal {
			return "unhealthy"
		}
	}

	return "unknown"
}
