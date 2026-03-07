package ingester

import (
	"encoding/json"
	"net"
	"strconv"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/clusterpulse/cluster-controller/internal/config"
	redis "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/clusterpulse/cluster-controller/pkg/types"
	pb "github.com/clusterpulse/cluster-controller/proto/collectorpb"
)

func newTestHandler(t *testing.T) (*Handler, *redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	host, portStr, _ := net.SplitHostPort(mr.Addr())
	port, _ := strconv.Atoi(portStr)
	cfg := &config.Config{
		RedisHost:        host,
		RedisPort:        port,
		CacheTTL:         600,
		MetricsRetention: 3600,
	}
	client, err := redis.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(client, nil) // no VMWriter
	return h, client, mr
}

func TestProcessBatch_ClusterMetrics(t *testing.T) {
	h, client, _ := newTestHandler(t)
	ctx := t.Context()

	batch := &pb.MetricsBatch{
		ClusterName: "test-cluster",
		BatchId:     "batch-1",
		ClusterMetrics: &pb.ClusterMetrics{
			Nodes: 3, NodesReady: 3,
			Pods: 50, PodsRunning: 40,
			CpuCapacity: 12.0, MemoryCapacity: 48000000000,
			Namespaces:    5,
			NamespaceList: []string{"default", "kube-system", "monitoring"},
		},
	}

	if err := h.ProcessBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}

	// Verify cluster status was updated
	var status map[string]any
	if err := client.GetJSON(ctx, "cluster:test-cluster:status", &status); err != nil {
		t.Fatal(err)
	}
	if status["health"] != "healthy" {
		t.Errorf("health = %v, want healthy", status["health"])
	}
}

func TestProcessBatch_NodeMetrics(t *testing.T) {
	h, _, _ := newTestHandler(t)
	ctx := t.Context()

	batch := &pb.MetricsBatch{
		ClusterName: "test-cluster",
		BatchId:     "batch-2",
		NodeMetrics: []*pb.NodeMetrics{
			{Name: "node-1", Status: "Ready", CpuCapacity: 8.0},
			{Name: "node-2", Status: "Ready", CpuCapacity: 4.0},
		},
	}

	if err := h.ProcessBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
}

func TestProcessBatch_ClusterInfo(t *testing.T) {
	h, client, _ := newTestHandler(t)
	ctx := t.Context()

	batch := &pb.MetricsBatch{
		ClusterName: "test-cluster",
		BatchId:     "batch-3",
		ClusterInfo: &pb.ClusterInfo{
			ApiUrl:   "https://api.test:6443",
			Version:  "4.14.0",
			Platform: "OpenShift",
		},
	}

	if err := h.ProcessBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}

	var info map[string]any
	if err := client.GetJSON(ctx, "cluster:test-cluster:info", &info); err != nil {
		t.Fatal(err)
	}
	if info["version"] != "4.14.0" {
		t.Errorf("version = %v", info["version"])
	}
}

func TestProcessBatch_CustomResources(t *testing.T) {
	h, _, _ := newTestHandler(t)
	ctx := t.Context()

	batch := &pb.MetricsBatch{
		ClusterName: "test-cluster",
		BatchId:     "batch-4",
		CustomResources: []*pb.CustomResourceBatch{
			{
				SourceId:      "ns/vms",
				ResourceCount: 1,
				Resources: []*pb.CustomCollectedResource{
					{Id: "vm-1", Namespace: "default", Name: "my-vm", ValuesJson: []byte(`{"cpu":2}`)},
				},
				AggregationValues: map[string]float64{"total_cpu": 2.0},
			},
		},
	}

	if err := h.ProcessBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
}

func TestBuildConfigUpdate_NoSources(t *testing.T) {
	h, _, _ := newTestHandler(t)
	ctx := t.Context()

	result, err := h.BuildConfigUpdate(ctx, "test-cluster")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected nil when no enabled sources")
	}
}

func TestBuildConfigUpdate_WithSources(t *testing.T) {
	h, client, _ := newTestHandler(t)
	ctx := t.Context()

	// Seed a compiled metric source
	src := &types.CompiledMetricSource{
		Name:      "vms",
		Namespace: "monitoring",
		Source: types.CompiledSourceTarget{
			Kind:       "VirtualMachine",
			APIVersion: "kubevirt.io/v1",
			Group:      "kubevirt.io",
			Version:    "v1",
			Resource:   "virtualmachines",
		},
		RBAC: types.CompiledRBAC{
			ResourceTypeName: "virtualmachines",
		},
		CompiledAt: "2025-01-01T00:00:00Z",
		Hash:       "abc123",
	}
	if err := client.StoreCompiledMetricSource(ctx, src); err != nil {
		t.Fatal(err)
	}

	result, err := h.BuildConfigUpdate(ctx, "test-cluster")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected non-nil config update")
	}
	if len(result.MetricSourcesJson) != 1 {
		t.Fatalf("expected 1 config, got %d", len(result.MetricSourcesJson))
	}

	// Verify the JSON round-trips
	var decoded types.CompiledMetricSource
	if err := json.Unmarshal(result.MetricSourcesJson[0], &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Name != "vms" || decoded.Namespace != "monitoring" {
		t.Errorf("decoded source = %s/%s", decoded.Namespace, decoded.Name)
	}
}
