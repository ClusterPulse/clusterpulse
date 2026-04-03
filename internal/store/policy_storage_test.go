package redis

import (
	"encoding/json"
	"testing"

	"github.com/clusterpulse/cluster-controller/pkg/types"
)

func testPolicy() *types.CompiledPolicy {
	return &types.CompiledPolicy{
		PolicyName:           "test-policy",
		Namespace:            "default",
		Priority:             100,
		Effect:               "Allow",
		Enabled:              true,
		Users:                []string{"alice"},
		Groups:               []string{"admins"},
		ServiceAccounts:      []string{"system:serviceaccount:default:sa1"},
		DefaultClusterAccess: "allow",
		CompiledAt:           "2025-01-01T00:00:00Z",
		Hash:                 "abc123",
		CustomResourceTypes:  []string{"virtualmachines"},
	}
}

func TestStorePolicy_Indexes(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	p := testPolicy()
	if err := c.StorePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}

	policyKey := "policy:default:test-policy"

	// Verify in policies:all
	isMember, _ := c.client.SIsMember(ctx, "policies:all", policyKey).Result()
	if !isMember {
		t.Error("should be in policies:all")
	}

	// Verify in policies:enabled
	isMember, _ = c.client.SIsMember(ctx, "policies:enabled", policyKey).Result()
	if !isMember {
		t.Error("should be in policies:enabled")
	}

	// Verify user index
	isMember, _ = c.client.SIsMember(ctx, "policy:user:alice", policyKey).Result()
	if !isMember {
		t.Error("should be in user index")
	}

	// Verify group index
	isMember, _ = c.client.SIsMember(ctx, "policy:group:admins", policyKey).Result()
	if !isMember {
		t.Error("should be in group index")
	}

	// Verify SA index
	isMember, _ = c.client.SIsMember(ctx, "policy:sa:system:serviceaccount:default:sa1", policyKey).Result()
	if !isMember {
		t.Error("should be in SA index")
	}

	// Verify custom type index
	isMember, _ = c.client.SIsMember(ctx, "policy:customtype:virtualmachines", policyKey).Result()
	if !isMember {
		t.Error("should be in custom type index")
	}

	// Verify by-priority sorted set
	score, _ := c.client.ZScore(ctx, "policies:by:priority", policyKey).Result()
	if score != 100 {
		t.Errorf("priority score = %v, want 100", score)
	}

	// Verify by-effect set
	isMember, _ = c.client.SIsMember(ctx, "policies:effect:allow", policyKey).Result()
	if !isMember {
		t.Error("should be in effect:allow set")
	}
}

func TestStorePolicy_Disabled(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	p := testPolicy()
	p.Enabled = false
	if err := c.StorePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}

	policyKey := "policy:default:test-policy"

	// Should be in policies:all but NOT in policies:enabled
	isMember, _ := c.client.SIsMember(ctx, "policies:all", policyKey).Result()
	if !isMember {
		t.Error("disabled policy should still be in policies:all")
	}

	isMember, _ = c.client.SIsMember(ctx, "policies:enabled", policyKey).Result()
	if isMember {
		t.Error("disabled policy should NOT be in policies:enabled")
	}

	// Should NOT be in user/group indexes
	isMember, _ = c.client.SIsMember(ctx, "policy:user:alice", policyKey).Result()
	if isMember {
		t.Error("disabled policy should NOT be in user index")
	}
}

func TestGetPolicy_RoundTrip(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	p := testPolicy()
	if err := c.StorePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}

	got, err := c.GetPolicy(ctx, "default", "test-policy")
	if err != nil {
		t.Fatal(err)
	}
	if got.PolicyName != "test-policy" || got.Effect != "Allow" {
		t.Errorf("got policy = %+v", got)
	}
	if len(got.Users) != 1 || got.Users[0] != "alice" {
		t.Errorf("users = %v", got.Users)
	}
}

func TestRemovePolicy(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	p := testPolicy()
	c.StorePolicy(ctx, p)

	if err := c.RemovePolicy(ctx, "default", "test-policy"); err != nil {
		t.Fatal(err)
	}

	policyKey := "policy:default:test-policy"

	// Verify all indexes cleaned
	isMember, _ := c.client.SIsMember(ctx, "policies:all", policyKey).Result()
	if isMember {
		t.Error("should be removed from policies:all")
	}
	isMember, _ = c.client.SIsMember(ctx, "policy:user:alice", policyKey).Result()
	if isMember {
		t.Error("should be removed from user index")
	}

	// Verify hash deleted
	exists, _ := c.client.Exists(ctx, policyKey).Result()
	if exists != 0 {
		t.Error("policy hash should be deleted")
	}
}

func TestRemovePolicy_NonExistent(t *testing.T) {
	c, _ := newTestClient(t)
	// Should not error
	if err := c.RemovePolicy(t.Context(), "default", "nonexistent"); err != nil {
		t.Errorf("removing non-existent should return nil, got %v", err)
	}
}

func TestListPolicies(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	p1 := testPolicy()
	p2 := testPolicy()
	p2.PolicyName = "policy-2"
	p2.Enabled = false

	c.StorePolicy(ctx, p1)
	c.StorePolicy(ctx, p2)

	all, err := c.ListPolicies(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("all policies = %d, want 2", len(all))
	}

	enabled, err := c.ListPolicies(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(enabled) != 1 {
		t.Errorf("enabled policies = %d, want 1", len(enabled))
	}
}

func TestUpdatePolicyStatus(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	p := testPolicy()
	c.StorePolicy(ctx, p)

	status := map[string]any{"state": "Active", "message": "OK"}
	if err := c.UpdatePolicyStatus(ctx, "default", "test-policy", status); err != nil {
		t.Fatal(err)
	}

	data, _ := c.client.HGet(ctx, "policy:default:test-policy", "status").Result()
	var s map[string]any
	json.Unmarshal([]byte(data), &s)
	if s["state"] != "Active" {
		t.Errorf("state = %v", s["state"])
	}
}

func TestStorePolicy_UpdateCleansOldIndexes(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	policyKey := "policy:default:test-policy"

	// Store initial policy with alice, bob and admins group
	p := testPolicy()
	p.Users = []string{"alice", "bob"}
	p.Groups = []string{"admins"}
	p.ServiceAccounts = []string{"system:serviceaccount:default:sa1"}
	p.CustomResourceTypes = []string{"virtualmachines"}
	if err := c.StorePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}

	// Verify initial indexes
	isMember, _ := c.client.SIsMember(ctx, "policy:user:bob", policyKey).Result()
	if !isMember {
		t.Fatal("bob should be in user index after initial store")
	}
	isMember, _ = c.client.SIsMember(ctx, "policy:group:admins", policyKey).Result()
	if !isMember {
		t.Fatal("admins should be in group index after initial store")
	}

	// Update: remove bob, change group from admins to devs, change SA, change custom type
	p.Users = []string{"alice"}
	p.Groups = []string{"devs"}
	p.ServiceAccounts = []string{"system:serviceaccount:default:sa2"}
	p.CustomResourceTypes = []string{"configaudits"}
	if err := c.StorePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}

	// Removed entries should be gone
	isMember, _ = c.client.SIsMember(ctx, "policy:user:bob", policyKey).Result()
	if isMember {
		t.Error("bob should be removed from user index after update")
	}
	score, err := c.client.ZScore(ctx, "policy:user:bob:sorted", policyKey).Result()
	if err == nil {
		t.Errorf("bob:sorted should not contain policy, got score %v", score)
	}

	isMember, _ = c.client.SIsMember(ctx, "policy:group:admins", policyKey).Result()
	if isMember {
		t.Error("admins should be removed from group index after update")
	}

	isMember, _ = c.client.SIsMember(ctx, "policy:sa:system:serviceaccount:default:sa1", policyKey).Result()
	if isMember {
		t.Error("sa1 should be removed from SA index after update")
	}

	isMember, _ = c.client.SIsMember(ctx, "policy:customtype:virtualmachines", policyKey).Result()
	if isMember {
		t.Error("virtualmachines should be removed from custom type index after update")
	}

	// Kept/new entries should be present
	isMember, _ = c.client.SIsMember(ctx, "policy:user:alice", policyKey).Result()
	if !isMember {
		t.Error("alice should still be in user index")
	}

	isMember, _ = c.client.SIsMember(ctx, "policy:group:devs", policyKey).Result()
	if !isMember {
		t.Error("devs should be in group index")
	}

	isMember, _ = c.client.SIsMember(ctx, "policy:sa:system:serviceaccount:default:sa2", policyKey).Result()
	if !isMember {
		t.Error("sa2 should be in SA index")
	}

	isMember, _ = c.client.SIsMember(ctx, "policy:customtype:configaudits", policyKey).Result()
	if !isMember {
		t.Error("configaudits should be in custom type index")
	}
}

func TestDiffSlices(t *testing.T) {
	tests := []struct {
		name     string
		old, new []string
		want     []string
	}{
		{"remove one", []string{"a", "b", "c"}, []string{"a", "c"}, []string{"b"}},
		{"remove all", []string{"a", "b"}, nil, []string{"a", "b"}},
		{"no change", []string{"a", "b"}, []string{"a", "b"}, nil},
		{"add only", []string{"a"}, []string{"a", "b"}, nil},
		{"both empty", nil, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := diffSlices(tt.old, tt.new)
			if len(got) != len(tt.want) {
				t.Errorf("diffSlices(%v, %v) = %v, want %v", tt.old, tt.new, got, tt.want)
			}
		})
	}
}

func TestUnionSlices(t *testing.T) {
	got := unionSlices([]string{"a", "b"}, []string{"b", "c"})
	if len(got) != 3 {
		t.Errorf("unionSlices = %v, want 3 elements", got)
	}
	want := map[string]bool{"a": true, "b": true, "c": true}
	for _, v := range got {
		if !want[v] {
			t.Errorf("unexpected element %q", v)
		}
	}
}

func TestEscapeRedisGlobChars(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"user*", `user\*`},
		{"user?", `user\?`},
		{"user[0]", `user\[0\]`},
		{"normal", "normal"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := escapeRedisGlobChars(tt.input); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClearStaleEvalCaches(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	// Seed some eval cache keys
	c.client.Set(ctx, "policy:eval:alice:cluster1", "data", 0)
	c.client.Set(ctx, "policy:eval:bob:cluster2", "data", 0)
	c.client.Set(ctx, "other:key", "data", 0)

	count, err := c.ClearStaleEvalCaches(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("cleared %d, want 2", count)
	}

	// Verify non-eval keys untouched
	exists, _ := c.client.Exists(ctx, "other:key").Result()
	if exists != 1 {
		t.Error("other:key should not be deleted")
	}
}
