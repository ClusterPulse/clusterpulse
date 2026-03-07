package redis

import (
	"encoding/json"
	"testing"
)

func TestStoreRegistrySpec(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	spec := map[string]any{"url": "https://registry.example.com", "interval": 60}
	if err := c.StoreRegistrySpec(ctx, "r1", spec); err != nil {
		t.Fatal(err)
	}

	data, _ := c.client.Get(ctx, "registry:r1:spec").Result()
	var s map[string]any
	json.Unmarshal([]byte(data), &s)
	if s["url"] != "https://registry.example.com" {
		t.Errorf("url = %v", s["url"])
	}

	// No expiry
	ttl, _ := c.client.TTL(ctx, "registry:r1:spec").Result()
	if ttl != -1 {
		t.Errorf("ttl = %v, want -1 (no expiry)", ttl)
	}
}

func TestStoreRegistryStatus(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	status := map[string]any{"available": true, "health": "healthy"}
	if err := c.StoreRegistryStatus(ctx, "r1", status); err != nil {
		t.Fatal(err)
	}

	// Verify status
	got, err := c.GetRegistryStatus(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if got["health"] != "healthy" {
		t.Errorf("health = %v", got["health"])
	}

	// Verify in registries:all
	isMember, _ := c.client.SIsMember(ctx, "registries:all", "r1").Result()
	if !isMember {
		t.Error("r1 should be in registries:all")
	}

	// Verify metadata
	lastUpdate, _ := c.client.HGet(ctx, "registry:r1:meta", "last_update").Result()
	if lastUpdate == "" {
		t.Error("metadata should have last_update")
	}
}

func TestStoreRegistryMetrics(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	metrics := map[string]any{"response_time_ms": 150, "available": true}
	if err := c.StoreRegistryMetrics(ctx, "r1", metrics); err != nil {
		t.Fatal(err)
	}

	// Verify time-series
	members, _ := c.client.ZRange(ctx, "registry:r1:metrics", 0, -1).Result()
	if len(members) != 1 {
		t.Errorf("metrics len = %d", len(members))
	}

	// Verify latest
	latest, _ := c.client.Get(ctx, "registry:r1:metrics:latest").Result()
	if latest == "" {
		t.Error("latest metrics should be set")
	}
}

func TestGetRegistryStatus_RoundTrip(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	status := map[string]any{"health": "degraded", "message": "high latency"}
	c.StoreRegistryStatus(ctx, "r1", status)

	got, err := c.GetRegistryStatus(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if got["health"] != "degraded" {
		t.Errorf("health = %v", got["health"])
	}
}

func TestGetAllRegistries(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	c.StoreRegistryStatus(ctx, "r1", map[string]any{"available": true})
	c.StoreRegistryStatus(ctx, "r2", map[string]any{"available": false})

	names, err := c.GetAllRegistries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Errorf("registries = %v", names)
	}
}

func TestDeleteRegistryData(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	c.StoreRegistrySpec(ctx, "r1", map[string]any{"url": "x"})
	c.StoreRegistryStatus(ctx, "r1", map[string]any{"health": "ok"})

	if err := c.DeleteRegistryData(ctx, "r1"); err != nil {
		t.Fatal(err)
	}

	exists, _ := c.client.Exists(ctx, "registry:r1:spec").Result()
	if exists != 0 {
		t.Error("spec should be deleted")
	}

	isMember, _ := c.client.SIsMember(ctx, "registries:all", "r1").Result()
	if isMember {
		t.Error("r1 should be removed from registries:all")
	}
}
