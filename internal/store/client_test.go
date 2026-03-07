package redis

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/clusterpulse/cluster-controller/pkg/types"
)

func TestStoreOperators_RoundTrip(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	ops := []types.OperatorInfo{
		{
			Name: "cert-manager", DisplayName: "Cert Manager",
			Version: "1.12", Status: "Succeeded",
			InstalledNamespace: "cert-manager",
			InstallMode: "AllNamespaces", IsClusterWide: true,
			InstallModes:          []string{"AllNamespaces"},
			AvailableInNamespaces: []string{"*"},
			CreatedAt:             time.Now(), UpdatedAt: time.Now(),
		},
	}

	if err := c.StoreOperators(ctx, "cluster-1", ops); err != nil {
		t.Fatal(err)
	}

	// Verify the operators data key exists
	data, err := c.client.Get(ctx, "cluster:cluster-1:operators").Result()
	if err != nil {
		t.Fatal(err)
	}
	var stored []map[string]any
	if err := json.Unmarshal([]byte(data), &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0]["name"] != "cert-manager" {
		t.Errorf("stored operators = %v", stored)
	}

	// Verify summary
	summData, err := c.client.Get(ctx, "cluster:cluster-1:operators_summary").Result()
	if err != nil {
		t.Fatal(err)
	}
	var summary map[string]any
	json.Unmarshal([]byte(summData), &summary)
	if summary["total"] != float64(1) {
		t.Errorf("summary total = %v", summary["total"])
	}
}

func TestStoreOperators_NilArraysReplaced(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	ops := []types.OperatorInfo{
		{
			Name: "test-op", Status: "Succeeded",
			// InstallModes and AvailableInNamespaces are nil
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		},
	}

	if err := c.StoreOperators(ctx, "c1", ops); err != nil {
		t.Fatal(err)
	}

	data, _ := c.client.Get(ctx, "cluster:c1:operators").Result()
	var stored []map[string]any
	json.Unmarshal([]byte(data), &stored)

	// Arrays should be [] not null
	modes, ok := stored[0]["install_modes"].([]any)
	if !ok {
		t.Error("install_modes should be an array")
	}
	if len(modes) != 0 {
		t.Error("install_modes should be empty")
	}
}

func TestStoreNodeMetrics(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	metrics := []types.NodeMetrics{
		{
			Name: "node-1", Status: "Ready",
			CPUCapacity: 8.0, MemoryCapacity: 32000000000,
			CPUUsagePercent: 45.0, MemoryUsagePercent: 60.0,
			PodsRunning: 10, PodsTotal: 15,
			Timestamp: time.Now(),
		},
	}

	if err := c.StoreNodeMetrics(ctx, "cluster-1", metrics); err != nil {
		t.Fatal(err)
	}

	// Verify hash storage
	current, err := c.client.HGet(ctx, "cluster:cluster-1:node:node-1", "current").Result()
	if err != nil {
		t.Fatal(err)
	}
	var nodeData map[string]any
	json.Unmarshal([]byte(current), &nodeData)
	if nodeData["name"] != "node-1" {
		t.Errorf("node name = %v", nodeData["name"])
	}

	// Verify time-series
	members, err := c.client.ZRange(ctx, "cluster:cluster-1:node:node-1:metrics", 0, -1).Result()
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 {
		t.Errorf("time-series len = %d, want 1", len(members))
	}

	// Verify node set membership
	isMember, _ := c.client.SIsMember(ctx, "cluster:cluster-1:nodes", "node-1").Result()
	if !isMember {
		t.Error("node-1 should be in cluster's node set")
	}
}

func TestNodeMetricsToDict_NilFields(t *testing.T) {
	c, _ := newTestClient(t)
	node := types.NodeMetrics{
		Name:      "test",
		Timestamp: time.Now(),
		// Roles, Labels, Annotations, Taints are all nil
	}
	d := c.nodeMetricsToDict(node)

	// Should not be nil
	if d["roles"] == nil {
		t.Error("roles should be empty slice, not nil")
	}
	if d["labels"] == nil {
		t.Error("labels should be empty map, not nil")
	}
	if d["annotations"] == nil {
		t.Error("annotations should be empty map, not nil")
	}
	if d["taints"] == nil {
		t.Error("taints should be empty slice, not nil")
	}
}

func TestStoreClusterMetrics(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	cm := &types.ClusterMetrics{
		Timestamp: time.Now(),
		Nodes: 3, NodesReady: 3, Namespaces: 10,
		NamespaceList: []string{"default", "kube-system"},
		Pods: 50, PodsRunning: 45,
	}

	if err := c.StoreClusterMetrics(ctx, "c1", cm); err != nil {
		t.Fatal(err)
	}

	// Verify metrics
	data, err := c.client.Get(ctx, "cluster:c1:metrics").Result()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal([]byte(data), &m)
	if m["nodes"] != float64(3) {
		t.Errorf("nodes = %v", m["nodes"])
	}

	// Verify namespace list stored separately
	nsData, err := c.client.Get(ctx, "cluster:c1:namespaces").Result()
	if err != nil {
		t.Fatal(err)
	}
	var ns map[string]any
	json.Unmarshal([]byte(nsData), &ns)
	if ns["count"] != float64(2) {
		t.Errorf("ns count = %v", ns["count"])
	}
}

func TestStoreNamespaces(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	if err := c.StoreNamespaces(ctx, "c1", []string{"default", "prod"}); err != nil {
		t.Fatal(err)
	}

	// Verify JSON
	data, _ := c.client.Get(ctx, "cluster:c1:namespaces").Result()
	var ns map[string]any
	json.Unmarshal([]byte(data), &ns)
	if ns["count"] != float64(2) {
		t.Errorf("count = %v", ns["count"])
	}

	// Verify set
	members, _ := c.client.SMembers(ctx, "cluster:c1:namespaces:set").Result()
	if len(members) != 2 {
		t.Errorf("set members = %v", members)
	}
}

func TestStoreNamespaces_Nil(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	if err := c.StoreNamespaces(ctx, "c1", nil); err != nil {
		t.Fatal(err)
	}

	data, _ := c.client.Get(ctx, "cluster:c1:namespaces").Result()
	var ns map[string]any
	json.Unmarshal([]byte(data), &ns)
	if ns["count"] != float64(0) {
		t.Errorf("nil input should result in count=0, got %v", ns["count"])
	}
}

func TestStoreClusterInfo(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	info := map[string]any{"version": "4.14", "platform": "OpenShift"}
	if err := c.StoreClusterInfo(ctx, "c1", info); err != nil {
		t.Fatal(err)
	}

	data, _ := c.client.Get(ctx, "cluster:c1:info").Result()
	var stored map[string]any
	json.Unmarshal([]byte(data), &stored)
	if stored["version"] != "4.14" {
		t.Errorf("version = %v", stored["version"])
	}
}

func TestStoreClusterStatus(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	status := map[string]any{"health": "healthy"}
	if err := c.StoreClusterStatus(ctx, "c1", status); err != nil {
		t.Fatal(err)
	}

	// Verify status stored
	data, _ := c.client.Get(ctx, "cluster:c1:status").Result()
	var s map[string]any
	json.Unmarshal([]byte(data), &s)
	if s["health"] != "healthy" {
		t.Errorf("health = %v", s["health"])
	}

	// Verify added to clusters:all set
	isMember, _ := c.client.SIsMember(ctx, "clusters:all", "c1").Result()
	if !isMember {
		t.Error("c1 should be in clusters:all")
	}
}

func TestStoreClusterSpec(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	spec := map[string]any{"endpoint": "https://api.c1:6443"}
	if err := c.StoreClusterSpec(ctx, "c1", spec); err != nil {
		t.Fatal(err)
	}

	data, _ := c.client.Get(ctx, "cluster:c1:spec").Result()
	var s map[string]any
	json.Unmarshal([]byte(data), &s)
	if s["endpoint"] != "https://api.c1:6443" {
		t.Errorf("endpoint = %v", s["endpoint"])
	}
}

func TestStoreClusterLabels(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	labels := map[string]string{"env": "prod", "region": "us-east"}
	if err := c.StoreClusterLabels(ctx, "c1", labels); err != nil {
		t.Fatal(err)
	}

	data, _ := c.client.Get(ctx, "cluster:c1:labels").Result()
	var stored map[string]string
	json.Unmarshal([]byte(data), &stored)
	if stored["env"] != "prod" {
		t.Errorf("env = %v", stored["env"])
	}
}

func TestStoreClusterOperators(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	cops := []types.ClusterOperatorInfo{
		{
			Name: "console", Version: "4.14",
			Available: true, Degraded: false,
			LastTransitionTime: time.Now(),
		},
	}

	if err := c.StoreClusterOperators(ctx, "c1", cops); err != nil {
		t.Fatal(err)
	}

	// Verify list stored
	data, _ := c.client.Get(ctx, "cluster:c1:cluster_operators").Result()
	var stored []map[string]any
	json.Unmarshal([]byte(data), &stored)
	if len(stored) != 1 || stored[0]["name"] != "console" {
		t.Errorf("stored = %v", stored)
	}

	// Verify individual operator status
	opData, _ := c.client.Get(ctx, "cluster:c1:cluster_operator:console").Result()
	var opStatus map[string]any
	json.Unmarshal([]byte(opData), &opStatus)
	if opStatus["available"] != true {
		t.Error("console should be available")
	}
}

func TestStoreClusterOperators_Empty(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	// Empty list is a no-op
	if err := c.StoreClusterOperators(ctx, "c1", nil); err != nil {
		t.Fatal(err)
	}
	exists, _ := c.client.Exists(ctx, "cluster:c1:cluster_operators").Result()
	if exists != 0 {
		t.Error("empty operators should not create key")
	}
}

func TestPublishEvent(t *testing.T) {
	c, _ := newTestClient(t)
	c.PublishEvent("cluster.reconciled", "c1", map[string]any{"health": "healthy"})

	// Verify stored in event list
	events, _ := c.client.LRange(t.Context(), "events:c1", 0, -1).Result()
	if len(events) != 1 {
		t.Fatalf("events len = %d", len(events))
	}
	var ev map[string]any
	json.Unmarshal([]byte(events[0]), &ev)
	if ev["type"] != "cluster.reconciled" {
		t.Errorf("event type = %v", ev["type"])
	}
}

func TestDeleteClusterData(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	// Seed some data
	c.StoreClusterStatus(ctx, "c1", map[string]any{"health": "healthy"})
	c.StoreClusterInfo(ctx, "c1", map[string]any{"version": "4.14"})
	c.StoreNamespaces(ctx, "c1", []string{"default"})

	if err := c.DeleteClusterData(ctx, "c1"); err != nil {
		t.Fatal(err)
	}

	// Verify gone
	exists, _ := c.client.Exists(ctx, "cluster:c1:status").Result()
	if exists != 0 {
		t.Error("status should be deleted")
	}

	// Verify removed from clusters:all
	isMember, _ := c.client.SIsMember(ctx, "clusters:all", "c1").Result()
	if isMember {
		t.Error("c1 should be removed from clusters:all")
	}
}
