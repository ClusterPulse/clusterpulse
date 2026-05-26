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

func TestStorePolicy_RemovesStaleSubjectIndexesOnUpdate(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	p := testPolicy()
	p.Users = []string{"alice", "bob"}
	p.Groups = []string{"team-a", "team-b"}
	p.ServiceAccounts = []string{"system:serviceaccount:default:sa1"}
	p.CustomResourceTypes = []string{"virtualmachines", "routes"}
	if err := c.StorePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}

	// Re-store with bob, team-b, the SA, and "routes" removed.
	p2 := testPolicy()
	p2.Users = []string{"alice"}
	p2.Groups = []string{"team-a"}
	p2.ServiceAccounts = nil
	p2.CustomResourceTypes = []string{"virtualmachines"}
	if err := c.StorePolicy(ctx, p2); err != nil {
		t.Fatal(err)
	}

	policyKey := "policy:default:test-policy"

	mustNotIndex := []struct{ key, label string }{
		{"policy:user:bob", "removed user"},
		{"policy:user:bob:sorted", "removed user sorted set"},
		{"policy:group:team-b", "removed group"},
		{"policy:group:team-b:sorted", "removed group sorted set"},
		{"policy:sa:system:serviceaccount:default:sa1", "removed SA"},
		{"policy:customtype:routes", "removed custom resource type"},
	}
	for _, k := range mustNotIndex {
		if isMember, _ := c.client.SIsMember(ctx, k.key, policyKey).Result(); isMember {
			t.Errorf("policy still indexed under %s (%s)", k.key, k.label)
		}
	}

	mustIndex := []string{
		"policy:user:alice",
		"policy:group:team-a",
		"policy:customtype:virtualmachines",
	}
	for _, k := range mustIndex {
		if isMember, _ := c.client.SIsMember(ctx, k, policyKey).Result(); !isMember {
			t.Errorf("policy missing from preserved index %s", k)
		}
	}
}

func TestStorePolicy_DisablingRemovesSubjectsFromIndexes(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	p := testPolicy()
	if err := c.StorePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}

	p.Enabled = false
	if err := c.StorePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}

	policyKey := "policy:default:test-policy"
	for _, k := range []string{
		"policy:user:alice",
		"policy:group:admins",
		"policy:sa:system:serviceaccount:default:sa1",
		"policy:customtype:virtualmachines",
		keyPoliciesEnabled,
	} {
		if isMember, _ := c.client.SIsMember(ctx, k, policyKey).Result(); isMember {
			t.Errorf("disabled policy still indexed under %s", k)
		}
	}
}

func TestStorePolicy_EffectChangeRemovesOldEffectSet(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	p := testPolicy()
	if err := c.StorePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}

	p.Effect = "Deny"
	if err := c.StorePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}

	policyKey := "policy:default:test-policy"
	if isMember, _ := c.client.SIsMember(ctx, "policies:effect:allow", policyKey).Result(); isMember {
		t.Error("policy should not remain in policies:effect:allow after switching to Deny")
	}
	if isMember, _ := c.client.SIsMember(ctx, "policies:effect:deny", policyKey).Result(); !isMember {
		t.Error("policy should be in policies:effect:deny after switching effect")
	}
}

func TestInvalidateEvaluationCaches_GroupScansDecisionKeys(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	// Seed cache entries for a few principals.
	keysShouldGo := []string{
		"rbac:decision:bob:eng,team:view:cluster:c1",
		"rbac:custom:bob:eng,team:vms:c1:view",
		// Group alone (single-group CSV).
		"rbac:decision:carol:team:view:cluster:c1",
	}
	keysShouldStay := []string{
		"rbac:decision:dave:other:view:cluster:c1",
		"rbac:custom:dave:other:vms:c1:view",
		// User with empty groups CSV — should be untouched by group invalidation.
		"rbac:decision:erin::view:cluster:c1",
		// Unrelated key shape.
		"rbac:decision:other:noise:noise:noise",
	}
	for _, k := range append(append([]string{}, keysShouldGo...), keysShouldStay...) {
		if err := c.client.Set(ctx, k, "x", 0).Err(); err != nil {
			t.Fatal(err)
		}
	}

	// No group:members:* key is set anywhere — fix should still find affected entries.
	c.InvalidateEvaluationCaches(ctx, nil, []string{"team"}, nil)

	for _, k := range keysShouldGo {
		if exists, _ := c.client.Exists(ctx, k).Result(); exists != 0 {
			t.Errorf("expected %s to be invalidated", k)
		}
	}
	for _, k := range keysShouldStay {
		if exists, _ := c.client.Exists(ctx, k).Result(); exists != 1 {
			t.Errorf("expected %s to remain", k)
		}
	}
}

func TestStorePolicy_UpdateInvalidatesRemovedUserCache(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := t.Context()

	p := testPolicy()
	p.Users = []string{"alice"}
	p.Groups = nil
	p.ServiceAccounts = nil
	if err := c.StorePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}

	// Seed an "allow" decision for alice.
	aliceKey := "rbac:decision:alice::view:cluster:c1"
	c.client.Set(ctx, aliceKey, "x", 0)

	// Re-store with alice removed.
	p2 := testPolicy()
	p2.Users = []string{"bob"}
	p2.Groups = nil
	p2.ServiceAccounts = nil
	if err := c.StorePolicy(ctx, p2); err != nil {
		t.Fatal(err)
	}

	// alice's stale "allow" decision must be cleared even though she's not in the new policy.
	if exists, _ := c.client.Exists(ctx, aliceKey).Result(); exists != 0 {
		t.Error("expected stale decision for removed user 'alice' to be invalidated on policy update")
	}
}

func TestCacheKeyMatchesGroup(t *testing.T) {
	changed := map[string]struct{}{"team": {}}
	tests := []struct {
		name   string
		suffix string
		want   bool
	}{
		{"empty groups csv", "bob::view:cluster:c1", false},
		{"single group hit", "bob:team:view:cluster:c1", true},
		{"multi-group hit", "bob:eng,team:view:cluster:c1", true},
		{"miss", "bob:other:view:cluster:c1", false},
		{"sa-style with colons in username", "system:serviceaccount:default:sa1::view:cluster:c1", false},
		{"sa-style colliding with group name in middle segment", "system:team:default:sa1::view:cluster:c1", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cacheKeyMatchesGroup(tc.suffix, changed); got != tc.want {
				t.Errorf("cacheKeyMatchesGroup(%q) = %v, want %v", tc.suffix, got, tc.want)
			}
		})
	}
}

func TestDiffAndUnionStrings(t *testing.T) {
	t.Run("diff basic", func(t *testing.T) {
		got := diffStrings([]string{"a", "b", "c"}, []string{"b"})
		if len(got) != 2 || got[0] != "a" || got[1] != "c" {
			t.Errorf("diffStrings = %v", got)
		}
	})
	t.Run("diff empty a", func(t *testing.T) {
		if got := diffStrings(nil, []string{"x"}); got != nil {
			t.Errorf("diffStrings(nil, ...) = %v, want nil", got)
		}
	})
	t.Run("union dedupes", func(t *testing.T) {
		got := unionStrings([]string{"a", "b"}, []string{"b", "c"})
		set := map[string]struct{}{}
		for _, s := range got {
			set[s] = struct{}{}
		}
		if len(set) != 3 {
			t.Errorf("unionStrings = %v (deduped set len = %d, want 3)", got, len(set))
		}
	})
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
