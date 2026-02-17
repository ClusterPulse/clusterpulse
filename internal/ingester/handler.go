package ingester

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	redis "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/clusterpulse/cluster-controller/pkg/types"
	pb "github.com/clusterpulse/cluster-controller/proto/collectorpb"
	"github.com/sirupsen/logrus"
)

// Handler processes incoming MetricsBatch messages and writes to storage.
type Handler struct {
	redisClient *redis.Client
	vmWriter    *VMWriter
}

// NewHandler creates a new batch handler.
func NewHandler(redisClient *redis.Client, vmWriter *VMWriter) *Handler {
	return &Handler{
		redisClient: redisClient,
		vmWriter:    vmWriter,
	}
}

// ProcessBatch handles a MetricsBatch from a collector: transforms proto types
// to internal types and dual-writes to Redis (current state) and optionally
// VictoriaMetrics (time-series history).
func (h *Handler) ProcessBatch(ctx context.Context, batch *pb.MetricsBatch) error {
	cluster := batch.ClusterName
	log := logrus.WithFields(logrus.Fields{
		"cluster":  cluster,
		"batch_id": batch.BatchId,
	})

	// Store cluster metrics
	if batch.ClusterMetrics != nil {
		cm := protoToClusterMetrics(batch.ClusterMetrics)
		if err := h.redisClient.StoreClusterMetrics(ctx, cluster, cm); err != nil {
			log.WithError(err).Warn("Failed to store cluster metrics")
		}
		if len(cm.NamespaceList) > 0 {
			if err := h.redisClient.StoreNamespaces(ctx, cluster, cm.NamespaceList); err != nil {
				log.WithError(err).Warn("Failed to store namespaces")
			}
		}
		// Write to VictoriaMetrics
		if h.vmWriter != nil {
			h.vmWriter.WriteClusterMetrics(ctx, cluster, cm)
		}
	}

	// Store node metrics
	if len(batch.NodeMetrics) > 0 {
		nodes := protoToNodeMetrics(batch.NodeMetrics)
		if err := h.redisClient.StoreNodeMetrics(ctx, cluster, nodes); err != nil {
			log.WithError(err).Warn("Failed to store node metrics")
		}
		if h.vmWriter != nil {
			h.vmWriter.WriteNodeMetrics(ctx, cluster, nodes)
		}
	}

	// Store operators
	var ops []types.OperatorInfo
	if len(batch.Operators) > 0 {
		ops = protoToOperators(batch.Operators)
		if err := h.redisClient.StoreOperators(ctx, cluster, ops); err != nil {
			log.WithError(err).Warn("Failed to store operators")
		}
	}

	// Store cluster operators
	var cops []types.ClusterOperatorInfo
	if len(batch.ClusterOperators) > 0 {
		cops = protoToClusterOperators(batch.ClusterOperators)
		if err := h.redisClient.StoreClusterOperators(ctx, cluster, cops); err != nil {
			log.WithError(err).Warn("Failed to store cluster operators")
		}
	}

	// Write operator metrics to VictoriaMetrics
	if h.vmWriter != nil && (len(ops) > 0 || len(cops) > 0) {
		h.vmWriter.WriteOperatorMetrics(ctx, cluster, ops, cops)
	}

	// Store custom resource collections
	for _, crBatch := range batch.CustomResources {
		collection, aggregations := protoToCustomResources(crBatch, cluster)
		if err := h.redisClient.StoreCustomResourceCollection(ctx, cluster, collection); err != nil {
			log.WithError(err).Warn("Failed to store custom resources")
		}
		if aggregations != nil {
			if err := h.redisClient.StoreAggregationResults(ctx, cluster, aggregations); err != nil {
				log.WithError(err).Warn("Failed to store aggregations")
			}
			if h.vmWriter != nil && len(crBatch.AggregationValues) > 0 {
				h.vmWriter.WriteCustomResourceMetrics(ctx, cluster, crBatch.SourceId, crBatch.AggregationValues)
			}
		}
	}

	// Update cluster status in Redis to mark it as connected/healthy
	status := map[string]interface{}{
		"health":     "healthy",
		"message":    "Collector push active",
		"last_check": time.Now().Format(time.RFC3339),
	}
	if err := h.redisClient.StoreClusterStatus(ctx, cluster, status); err != nil {
		log.WithError(err).Debug("Failed to update cluster status")
	}

	// Publish reconciled event
	h.redisClient.PublishEvent("cluster.reconciled", cluster, map[string]interface{}{
		"health": "healthy",
		"source": "collector-push",
	})

	return nil
}

// BuildConfigUpdate constructs a ConfigUpdate message with current MetricSource configs.
func (h *Handler) BuildConfigUpdate(ctx context.Context, clusterName string) (*pb.ConfigUpdate, error) {
	sourceIDs, err := h.redisClient.ListEnabledMetricSources(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list metric sources: %w", err)
	}
	if len(sourceIDs) == 0 {
		return nil, nil
	}

	var configs [][]byte
	for _, id := range sourceIDs {
		src, err := h.redisClient.GetCompiledMetricSourceByID(ctx, id)
		if err != nil {
			logrus.WithError(err).Debugf("Failed to get metric source %s", id)
			continue
		}
		data, err := json.Marshal(src)
		if err != nil {
			continue
		}
		configs = append(configs, data)
	}

	return &pb.ConfigUpdate{
		MetricSourcesJson: configs,
	}, nil
}

// --- Proto to internal type conversions ---

func protoToClusterMetrics(p *pb.ClusterMetrics) *types.ClusterMetrics {
	return &types.ClusterMetrics{
		Timestamp:      time.Now(),
		Nodes:          int(p.Nodes),
		NodesReady:     int(p.NodesReady),
		Namespaces:     int(p.Namespaces),
		NamespaceList:  p.NamespaceList,
		Pods:           int(p.Pods),
		PodsRunning:    int(p.PodsRunning),
		CPUCapacity:    p.CpuCapacity,
		MemoryCapacity: p.MemoryCapacity,
		Deployments:    int(p.Deployments),
	}
}

func protoToNodeMetrics(nodes []*pb.NodeMetrics) []types.NodeMetrics {
	result := make([]types.NodeMetrics, len(nodes))
	for i, n := range nodes {
		result[i] = types.NodeMetrics{
			Name:               n.Name,
			Timestamp:          time.Now(),
			Status:             n.Status,
			Roles:              n.Roles,
			CPUCapacity:        n.CpuCapacity,
			MemoryCapacity:     n.MemoryCapacity,
			StorageCapacity:    n.StorageCapacity,
			PodsCapacity:       n.PodsCapacity,
			CPUAllocatable:     n.CpuAllocatable,
			MemoryAllocatable:  n.MemoryAllocatable,
			StorageAllocatable: n.StorageAllocatable,
			PodsAllocatable:    n.PodsAllocatable,
			CPURequested:       n.CpuRequested,
			MemoryRequested:    n.MemoryRequested,
			CPUUsagePercent:    n.CpuUsagePercent,
			MemoryUsagePercent: n.MemoryUsagePercent,
			PodsRunning:        n.PodsRunning,
			PodsPending:        n.PodsPending,
			PodsFailed:         n.PodsFailed,
			PodsSucceeded:      n.PodsSucceeded,
			PodsTotal:          n.PodsTotal,
			KernelVersion:      n.KernelVersion,
			OSImage:            n.OsImage,
			ContainerRuntime:   n.ContainerRuntime,
			KubeletVersion:     n.KubeletVersion,
			Architecture:       n.Architecture,
			Labels:             n.Labels,
			InternalIP:         n.InternalIp,
			Hostname:           n.Hostname,
		}
	}
	return result
}

func protoToOperators(ops []*pb.OperatorInfo) []types.OperatorInfo {
	result := make([]types.OperatorInfo, len(ops))
	for i, o := range ops {
		result[i] = types.OperatorInfo{
			Name:               o.Name,
			DisplayName:        o.DisplayName,
			Version:            o.Version,
			Status:             o.Status,
			InstalledNamespace: o.InstalledNamespace,
			InstallMode:        o.InstallMode,
			Provider:           o.Provider,
			IsClusterWide:      o.IsClusterWide,
			CreatedAt:          time.Now(),
			UpdatedAt:          time.Now(),
		}
	}
	return result
}

func protoToClusterOperators(cops []*pb.ClusterOperatorInfo) []types.ClusterOperatorInfo {
	result := make([]types.ClusterOperatorInfo, len(cops))
	for i, c := range cops {
		result[i] = types.ClusterOperatorInfo{
			Name:               c.Name,
			Version:            c.Version,
			Available:          c.Available,
			Progressing:        c.Progressing,
			Degraded:           c.Degraded,
			Upgradeable:        c.Upgradeable,
			Message:            c.Message,
			LastTransitionTime: time.Now(),
		}
	}
	return result
}

func protoToCustomResources(crBatch *pb.CustomResourceBatch, clusterName string) (*types.CustomResourceCollection, *types.AggregationResults) {
	resources := make([]types.CustomCollectedResource, len(crBatch.Resources))
	for i, r := range crBatch.Resources {
		values := make(map[string]interface{})
		if len(r.ValuesJson) > 0 {
			_ = json.Unmarshal(r.ValuesJson, &values)
		}
		resources[i] = types.CustomCollectedResource{
			ID:        r.Id,
			Namespace: r.Namespace,
			Name:      r.Name,
			Labels:    r.Labels,
			Values:    values,
		}
	}

	collection := &types.CustomResourceCollection{
		CollectedAt:   time.Now(),
		SourceID:      crBatch.SourceId,
		ClusterName:   clusterName,
		ResourceCount: int(crBatch.ResourceCount),
		Truncated:     crBatch.Truncated,
		DurationMs:    crBatch.DurationMs,
		Resources:     resources,
	}

	var aggregations *types.AggregationResults
	if len(crBatch.AggregationValues) > 0 {
		values := make(map[string]interface{}, len(crBatch.AggregationValues))
		for k, v := range crBatch.AggregationValues {
			values[k] = v
		}
		aggregations = &types.AggregationResults{
			ComputedAt: time.Now(),
			SourceID:   crBatch.SourceId,
			Values:     values,
		}
	}

	return collection, aggregations
}
