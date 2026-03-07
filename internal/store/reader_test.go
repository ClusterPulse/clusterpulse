package redis

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/clusterpulse/cluster-controller/pkg/types"
)

func TestGetJSON_RoundTrip(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	c.client.Set(ctx, "test:key", `{"name":"alice"}`, 0)

	var result map[string]any
	if err := c.GetJSON(ctx, "test:key", &result); err != nil {
		t.Fatal(err)
	}
	if result["name"] != "alice" {
		t.Errorf("name = %v", result["name"])
	}
}

func TestGetJSON_Missing(t *testing.T) {
	c, _ := newTestClient(t)
	var result map[string]any
	if err := c.GetJSON(t.Context(), "nonexistent", &result); err == nil {
		t.Error("expected error for missing key")
	}
}

func TestGetJSONList(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	c.client.Set(ctx, "test:list", `[{"name":"a"},{"name":"b"}]`, 0)

	result, err := c.GetJSONList(ctx, "test:list")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 {
		t.Errorf("len = %d", len(result))
	}
}

func TestGetHashJSON(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	c.client.HSet(ctx, "test:hash", "data", `{"x":42}`)

	var result map[string]any
	if err := c.GetHashJSON(ctx, "test:hash", "data", &result); err != nil {
		t.Fatal(err)
	}
	if result["x"] != float64(42) {
		t.Errorf("x = %v", result["x"])
	}
}

func TestGetClusterBundle(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	c.StoreClusterSpec(ctx, "c1", map[string]any{"endpoint": "https://api"})
	c.StoreClusterStatus(ctx, "c1", map[string]any{"health": "healthy"})
	c.StoreClusterInfo(ctx, "c1", map[string]any{"version": "4.14"})

	bundle, err := c.GetClusterBundle(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Spec["endpoint"] != "https://api" {
		t.Errorf("spec = %v", bundle.Spec)
	}
	if bundle.Status["health"] != "healthy" {
		t.Errorf("status = %v", bundle.Status)
	}
	if bundle.Info["version"] != "4.14" {
		t.Errorf("info = %v", bundle.Info)
	}
}

func TestGetClusterBundle_PartialData(t *testing.T) {
	c, _ := newTestClient(t)
	// Only status, no spec/info/metrics
	c.StoreClusterStatus(t.Context(), "c1", map[string]any{"health": "ok"})

	bundle, err := c.GetClusterBundle(t.Context(), "c1")
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Status["health"] != "ok" {
		t.Error("status should be set")
	}
	if bundle.Spec != nil {
		t.Error("spec should be nil when not set")
	}
}

func TestGetAllClusterNames(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	c.StoreClusterStatus(ctx, "c1", map[string]any{})
	c.StoreClusterStatus(ctx, "c2", map[string]any{})

	names, err := c.GetAllClusterNames(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Errorf("names = %v", names)
	}
}

func TestGetClusterNodes(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	metrics := []types.NodeMetrics{
		{Name: "node-1", Status: "Ready", Timestamp: time.Now()},
	}
	c.StoreNodeMetrics(ctx, "c1", metrics)

	nodes, err := c.GetClusterNodes(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0]["name"] != "node-1" {
		t.Errorf("nodes = %v", nodes)
	}
}

func TestGetClusterNamespaces_JSONPath(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	c.StoreNamespaces(ctx, "c1", []string{"default", "prod"})

	ns, err := c.GetClusterNamespaces(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 2 {
		t.Errorf("namespaces = %v", ns)
	}
}

func TestGetClusterNamespaces_SetFallback(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	// Only set the set key, not the JSON key
	c.client.SAdd(ctx, "cluster:c1:namespaces:set", "ns1", "ns2")

	ns, err := c.GetClusterNamespaces(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 2 {
		t.Errorf("namespaces = %v", ns)
	}
}

func TestGetNodeMetricsHistory(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	metrics := []types.NodeMetrics{
		{Name: "node-1", Status: "Ready", CPUUsagePercent: 45.0, Timestamp: time.Now()},
	}
	c.StoreNodeMetrics(ctx, "c1", metrics)

	history, err := c.GetNodeMetricsHistory(ctx, "c1", "node-1", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 {
		t.Errorf("history len = %d", len(history))
	}
}

func TestGetClusterEvents(t *testing.T) {
	c, _ := newTestClient(t)
	c.PublishEvent("test.event", "c1", map[string]any{"data": "x"})
	c.PublishEvent("test.event2", "c1", map[string]any{"data": "y"})

	events, err := c.GetClusterEvents(t.Context(), "c1", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Errorf("events = %d", len(events))
	}
}

func TestGetPoliciesForPrincipal(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	p1 := testPolicy()
	p1.Priority = 200
	c.StorePolicy(ctx, p1)

	p2 := testPolicy()
	p2.PolicyName = "policy-2"
	p2.Priority = 100
	p2.Groups = []string{"admins"}
	p2.Users = nil
	c.StorePolicy(ctx, p2)

	// Query for alice who is in group admins
	policies, err := c.GetPoliciesForPrincipal(ctx, "alice", []string{"admins"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 2 {
		t.Fatalf("policies = %d, want 2", len(policies))
	}
	// Should be sorted by priority descending
	if policies[0].Priority != 200 {
		t.Errorf("first policy priority = %d, want 200", policies[0].Priority)
	}
}

func TestGetPoliciesForPrincipal_SA(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	p := testPolicy()
	p.Users = nil
	p.Groups = nil
	p.ServiceAccounts = []string{"system:serviceaccount:default:sa1"}
	c.StorePolicy(ctx, p)

	policies, err := c.GetPoliciesForPrincipal(ctx, "system:serviceaccount:default:sa1", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 {
		t.Errorf("SA policies = %d, want 1", len(policies))
	}
}

func TestGetSourceIDForType(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	c.StoreCompiledMetricSource(ctx, testMetricSource())

	ids, err := c.GetSourceIDForType(ctx, "virtualmachines")
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "default/vms" {
		t.Errorf("ids = %v", ids)
	}
}

func TestGetMetricSourceDef(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	c.StoreCompiledMetricSource(ctx, testMetricSource())

	def, err := c.GetMetricSourceDef(ctx, "default/vms")
	if err != nil {
		t.Fatal(err)
	}
	if def["name"] != "vms" {
		t.Errorf("name = %v", def["name"])
	}
}

func TestBatchGetCustomResources(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	// Seed data
	data := map[string]any{"resources": []any{map[string]any{"name": "vm-1"}}}
	dataJSON, _ := json.Marshal(data)
	c.client.Set(ctx, "cluster:c1:custom:default/vms:resources", string(dataJSON), 0)

	result, err := c.BatchGetCustomResources(ctx, "default/vms", []string{"c1", "c2"})
	if err != nil {
		t.Fatal(err)
	}
	if result["c1"] == nil {
		t.Error("c1 data should be present")
	}
	if result["c2"] != nil {
		t.Error("c2 should be nil (no data)")
	}
}

func TestPing(t *testing.T) {
	c, _ := newTestClient(t)
	if err := c.Ping(t.Context()); err != nil {
		t.Errorf("ping failed: %v", err)
	}
}
