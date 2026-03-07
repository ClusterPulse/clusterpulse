package redis

import (
	"testing"
	"time"

	"github.com/clusterpulse/cluster-controller/pkg/types"
)

func testMetricSource() *types.CompiledMetricSource {
	return &types.CompiledMetricSource{
		Name:      "vms",
		Namespace: "default",
		Source: types.CompiledSourceTarget{
			APIVersion: "kubevirt.io/v1",
			Kind:       "VirtualMachine",
			Scope:      "Namespaced",
		},
		Fields: []types.CompiledField{
			{Name: "cpu", Path: "spec.cpu.cores", Index: 0},
		},
		RBAC: types.CompiledRBAC{
			ResourceTypeName: "virtualmachines",
		},
		CompiledAt: "2025-01-01T00:00:00Z",
		Hash:       "hash123",
	}
}

func TestStoreCompiledMetricSource_RoundTrip(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	src := testMetricSource()
	if err := c.StoreCompiledMetricSource(ctx, src); err != nil {
		t.Fatal(err)
	}

	got, err := c.GetCompiledMetricSource(ctx, "default", "vms")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "vms" || got.Hash != "hash123" {
		t.Errorf("got %+v", got)
	}
	// FieldNameToIndex should be rebuilt
	if got.FieldNameToIndex["cpu"] != 0 {
		t.Errorf("FieldNameToIndex = %v", got.FieldNameToIndex)
	}
}

func TestStoreCompiledMetricSource_Indexes(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	src := testMetricSource()
	c.StoreCompiledMetricSource(ctx, src)

	// Check all index
	members, _ := c.client.SMembers(ctx, "metricsources:all").Result()
	if len(members) != 1 || members[0] != "default/vms" {
		t.Errorf("all = %v", members)
	}

	// Check enabled index
	members, _ = c.client.SMembers(ctx, "metricsources:enabled").Result()
	if len(members) != 1 {
		t.Errorf("enabled = %v", members)
	}

	// Check type index
	members, _ = c.client.SMembers(ctx, "metricsources:by:resourcetype:virtualmachines").Result()
	if len(members) != 1 {
		t.Errorf("by type = %v", members)
	}
}

func TestGetCompiledMetricSourceByID(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	src := testMetricSource()
	c.StoreCompiledMetricSource(ctx, src)

	got, err := c.GetCompiledMetricSourceByID(ctx, "default/vms")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "vms" {
		t.Errorf("name = %q", got.Name)
	}
}

func TestGetCompiledMetricSourceByID_InvalidFormat(t *testing.T) {
	c, _ := newTestClient(t)
	_, err := c.GetCompiledMetricSourceByID(t.Context(), "invalid")
	if err == nil {
		t.Error("expected error for invalid ID format")
	}
}

func TestDeleteMetricSource(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	src := testMetricSource()
	c.StoreCompiledMetricSource(ctx, src)

	if err := c.DeleteMetricSource(ctx, "default", "vms"); err != nil {
		t.Fatal(err)
	}

	// Verify removed from indexes
	members, _ := c.client.SMembers(ctx, "metricsources:all").Result()
	if len(members) != 0 {
		t.Errorf("all should be empty after delete, got %v", members)
	}

	// Verify definition deleted
	_, err := c.GetCompiledMetricSource(ctx, "default", "vms")
	if err == nil {
		t.Error("expected error after deletion")
	}
}

func TestListMetricSources(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	c.StoreCompiledMetricSource(ctx, testMetricSource())

	ids, err := c.ListMetricSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Errorf("len = %d", len(ids))
	}
}

func TestListEnabledMetricSources(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	c.StoreCompiledMetricSource(ctx, testMetricSource())

	ids, err := c.ListEnabledMetricSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Errorf("len = %d", len(ids))
	}
}

func TestGetMetricSourceByType(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	c.StoreCompiledMetricSource(ctx, testMetricSource())

	ids, err := c.GetMetricSourceByType(ctx, "virtualmachines")
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "default/vms" {
		t.Errorf("by type = %v", ids)
	}
}

func TestStoreCustomResourceCollection_RoundTrip(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	coll := &types.CustomResourceCollection{
		CollectedAt:   time.Now(),
		SourceID:      "default/vms",
		ClusterName:   "cluster-1",
		ResourceCount: 2,
		Resources: []types.CustomCollectedResource{
			{ID: "r1", Name: "vm-1", Namespace: "prod"},
		},
	}

	if err := c.StoreCustomResourceCollection(ctx, "cluster-1", coll); err != nil {
		t.Fatal(err)
	}

	got, err := c.GetCustomResourceCollection(ctx, "cluster-1", "default/vms")
	if err != nil {
		t.Fatal(err)
	}
	if got.ResourceCount != 2 || len(got.Resources) != 1 {
		t.Errorf("got %+v", got)
	}

	// Verify metadata
	meta, err := c.GetCollectionMetadata(ctx, "cluster-1", "default/vms")
	if err != nil {
		t.Fatal(err)
	}
	if meta.ResourceCount != 2 {
		t.Errorf("meta count = %d", meta.ResourceCount)
	}
}

func TestStoreAggregationResults_RoundTrip(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	agg := &types.AggregationResults{
		ComputedAt: time.Now(),
		SourceID:   "default/vms",
		Values:     map[string]any{"total_cpu": 16.0, "count": 4},
	}

	if err := c.StoreAggregationResults(ctx, "cluster-1", agg); err != nil {
		t.Fatal(err)
	}

	got, err := c.GetAggregationResults(ctx, "cluster-1", "default/vms")
	if err != nil {
		t.Fatal(err)
	}
	if got.Values["total_cpu"] != 16.0 {
		t.Errorf("total_cpu = %v", got.Values["total_cpu"])
	}
}

func TestDeleteMetricSourceClusterData(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	// Seed data
	coll := &types.CustomResourceCollection{
		CollectedAt: time.Now(), SourceID: "default/vms", ClusterName: "c1",
	}
	c.StoreCustomResourceCollection(ctx, "c1", coll)
	agg := &types.AggregationResults{
		ComputedAt: time.Now(), SourceID: "default/vms",
		Values: map[string]any{"x": 1},
	}
	c.StoreAggregationResults(ctx, "c1", agg)

	if err := c.DeleteMetricSourceClusterData(ctx, "c1", "default/vms"); err != nil {
		t.Fatal(err)
	}

	_, err := c.GetCustomResourceCollection(ctx, "c1", "default/vms")
	if err == nil {
		t.Error("collection should be deleted")
	}
}
