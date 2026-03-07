package redis

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/clusterpulse/cluster-controller/pkg/types"
)

func TestStoreResourceCollection_AllTypes(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	coll := &types.ResourceCollection{
		Timestamp: time.Now(),
		Pods:      []types.PodSummary{{Name: "pod-1", Namespace: "default"}},
		Deployments: []types.DeploymentSummary{{Name: "dep-1", Namespace: "default"}},
		Services:    []types.ServiceSummary{{Name: "svc-1", Namespace: "default"}},
		TotalResources: 3,
	}

	if err := c.StoreResourceCollection(ctx, "c1", coll); err != nil {
		t.Fatal(err)
	}

	// Verify pods stored
	data, _ := c.client.Get(ctx, "cluster:c1:pods").Result()
	var pods []map[string]any
	json.Unmarshal([]byte(data), &pods)
	if len(pods) != 1 {
		t.Errorf("pods = %d", len(pods))
	}

	// Verify metadata
	metaData, _ := c.client.Get(ctx, "cluster:c1:resource_metadata").Result()
	var meta map[string]any
	json.Unmarshal([]byte(metaData), &meta)
	if meta["pods_count"] != float64(1) {
		t.Errorf("pods_count = %v", meta["pods_count"])
	}
}

func TestStoreResourceCollection_Nil(t *testing.T) {
	c, _ := newTestClient(t)
	// Should be a no-op
	if err := c.StoreResourceCollection(t.Context(), "c1", nil); err != nil {
		t.Fatal(err)
	}
}

func TestStoreResourceCollection_Partial(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	// Only pods, no other types
	coll := &types.ResourceCollection{
		Timestamp: time.Now(),
		Pods:      []types.PodSummary{{Name: "pod-1"}},
	}
	if err := c.StoreResourceCollection(ctx, "c1", coll); err != nil {
		t.Fatal(err)
	}

	// Deployments key should not exist
	exists, _ := c.client.Exists(ctx, "cluster:c1:deployments").Result()
	if exists != 0 {
		t.Error("deployments key should not be created for empty list")
	}
}
