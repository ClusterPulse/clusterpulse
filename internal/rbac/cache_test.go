package rbac

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/go-redis/redis/v8"
)

func newTestCache(t *testing.T, ttl int) (*Cache, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	return NewCache(rdb, ttl), mr
}

func TestNewCache_Disabled(t *testing.T) {
	c, _ := newTestCache(t, 0)
	if c.enabled {
		t.Error("cache should be disabled when ttl=0")
	}

	c2, _ := newTestCache(t, -1)
	if c2.enabled {
		t.Error("cache should be disabled when ttl<0")
	}
}

func TestNewCache_Enabled(t *testing.T) {
	c, _ := newTestCache(t, 300)
	if !c.enabled {
		t.Error("cache should be enabled when ttl>0")
	}
}

func TestGetDecision_Disabled(t *testing.T) {
	c, _ := newTestCache(t, 0)
	if d := c.GetDecision(t.Context(), "rbac:decision:test"); d != nil {
		t.Error("disabled cache should return nil")
	}
}

func TestSetDecision_Disabled(t *testing.T) {
	c, mr := newTestCache(t, 0)
	d := &RBACDecision{Decision: DecisionAllow, Permissions: map[Action]struct{}{}}
	c.SetDecision(t.Context(), "rbac:decision:test", d)
	if mr.Exists("rbac:decision:test") {
		t.Error("disabled cache should not store anything")
	}
}

func TestDecision_RoundTrip(t *testing.T) {
	c, _ := newTestCache(t, 300)
	ctx := t.Context()

	original := &RBACDecision{
		Decision:        DecisionAllow,
		Reason:          "policy matched",
		Permissions:     map[Action]struct{}{ActionView: {}, ActionViewMetrics: {}},
		AppliedPolicies: []string{"policy-1", "policy-2"},
		Metadata:        map[string]any{"source": "test"},
		Matchers:        map[string]*ResourceMatcher{},
	}

	c.SetDecision(ctx, "rbac:decision:test", original)
	got := c.GetDecision(ctx, "rbac:decision:test")
	if got == nil {
		t.Fatal("expected cached decision")
	}
	if got.Decision != DecisionAllow {
		t.Errorf("decision = %v", got.Decision)
	}
	if got.Reason != "policy matched" {
		t.Errorf("reason = %v", got.Reason)
	}
	if len(got.Permissions) != 2 {
		t.Errorf("permissions = %d", len(got.Permissions))
	}
	if len(got.AppliedPolicies) != 2 {
		t.Errorf("applied_policies = %d", len(got.AppliedPolicies))
	}
	if got.Metadata["source"] != "test" {
		t.Errorf("metadata = %v", got.Metadata)
	}
}

func TestDecision_WithMatchers(t *testing.T) {
	c, _ := newTestCache(t, 300)
	ctx := t.Context()

	original := &RBACDecision{
		Decision:    DecisionPartial,
		Permissions: map[Action]struct{}{ActionView: {}},
		Matchers: map[string]*ResourceMatcher{
			"nodes": {
				Visibility: VisibilityFiltered,
				Names: &MatchSpec{
					Include:         map[string]struct{}{"node-1": {}, "node-2": {}},
					Exclude:         map[string]struct{}{"node-bad": {}},
					IncludePatterns: []CompiledPattern{{Original: "worker-*", Regexp: regexp.MustCompile("^worker-.*$")}},
					ExcludePatterns: []CompiledPattern{{Original: "infra-*", Regexp: regexp.MustCompile("^infra-.*$")}},
				},
				Namespaces: &MatchSpec{
					Include: map[string]struct{}{"prod": {}},
					Exclude: map[string]struct{}{},
				},
				Labels: map[string]string{"env": "production"},
				FieldFilters: map[string]*MatchSpec{
					"status": {
						Include: map[string]struct{}{"Ready": {}},
						Exclude: map[string]struct{}{},
					},
				},
			},
		},
	}

	c.SetDecision(ctx, "rbac:decision:matchers", original)
	got := c.GetDecision(ctx, "rbac:decision:matchers")
	if got == nil {
		t.Fatal("expected cached decision")
	}

	m := got.Matchers["nodes"]
	if m == nil {
		t.Fatal("missing nodes matcher")
	}
	if m.Visibility != VisibilityFiltered {
		t.Errorf("visibility = %v", m.Visibility)
	}
	if _, ok := m.Names.Include["node-1"]; !ok {
		t.Error("missing node-1 in names include")
	}
	if _, ok := m.Names.Exclude["node-bad"]; !ok {
		t.Error("missing node-bad in names exclude")
	}
	if len(m.Names.IncludePatterns) != 1 || m.Names.IncludePatterns[0].Original != "worker-*" {
		t.Errorf("include patterns = %v", m.Names.IncludePatterns)
	}
	if len(m.Names.ExcludePatterns) != 1 {
		t.Errorf("exclude patterns = %v", m.Names.ExcludePatterns)
	}
	if _, ok := m.Namespaces.Include["prod"]; !ok {
		t.Error("missing prod in namespaces include")
	}
	if m.Labels["env"] != "production" {
		t.Errorf("labels = %v", m.Labels)
	}
	ff := m.FieldFilters["status"]
	if ff == nil {
		t.Fatal("missing status field filter")
	}
	if _, ok := ff.Include["Ready"]; !ok {
		t.Error("missing Ready in field filter include")
	}
}

func TestGetDecision_Missing(t *testing.T) {
	c, _ := newTestCache(t, 300)
	if d := c.GetDecision(t.Context(), "rbac:decision:nonexistent"); d != nil {
		t.Error("expected nil for missing key")
	}
}

func TestClearDecisions(t *testing.T) {
	c, _ := newTestCache(t, 300)
	ctx := t.Context()

	// Seed some decisions
	d := &RBACDecision{Decision: DecisionAllow, Permissions: map[Action]struct{}{}, Matchers: map[string]*ResourceMatcher{}}
	c.SetDecision(ctx, "rbac:decision:user1:cluster1", d)
	c.SetDecision(ctx, "rbac:decision:user1:cluster2", d)
	c.SetDecision(ctx, "rbac:decision:user2:cluster1", d)

	count := c.ClearDecisions(ctx, "rbac:decision:user1:*")
	if count != 2 {
		t.Errorf("cleared = %d, want 2", count)
	}

	// user2 should remain
	if got := c.GetDecision(ctx, "rbac:decision:user2:cluster1"); got == nil {
		t.Error("user2 decision should still exist")
	}
}

func TestCustomDecision_Disabled(t *testing.T) {
	c, _ := newTestCache(t, 0)
	ctx := t.Context()

	if d := c.GetCustomDecision(ctx, "rbac:custom:test"); d != nil {
		t.Error("disabled cache should return nil")
	}
	// SetCustomDecision should be no-op
	d := &CustomResourceDecision{Decision: DecisionAllow, Permissions: map[Action]struct{}{}, DeniedAggregations: map[string]struct{}{}, Matcher: &ResourceMatcher{Visibility: VisibilityAll}}
	c.SetCustomDecision(ctx, "rbac:custom:test", d)
}

func TestCustomDecision_RoundTrip(t *testing.T) {
	c, _ := newTestCache(t, 300)
	ctx := t.Context()

	original := &CustomResourceDecision{
		Decision:           DecisionAllow,
		ResourceTypeName:   "virtualmachines",
		Cluster:            "cluster-1",
		Reason:             "policy match",
		Permissions:        map[Action]struct{}{ActionView: {}},
		AppliedPolicies:    []string{"p1"},
		Metadata:           map[string]any{"info": "test"},
		DeniedAggregations: map[string]struct{}{"secret_field": {}},
		Matcher:            &ResourceMatcher{Visibility: VisibilityAll},
	}

	c.SetCustomDecision(ctx, "rbac:custom:test", original)
	got := c.GetCustomDecision(ctx, "rbac:custom:test")
	if got == nil {
		t.Fatal("expected cached custom decision")
	}
	if got.Decision != DecisionAllow {
		t.Errorf("decision = %v", got.Decision)
	}
	if got.ResourceTypeName != "virtualmachines" {
		t.Errorf("type = %v", got.ResourceTypeName)
	}
	if got.Cluster != "cluster-1" {
		t.Errorf("cluster = %v", got.Cluster)
	}
	if _, ok := got.Permissions[ActionView]; !ok {
		t.Error("missing view permission")
	}
	if _, ok := got.DeniedAggregations["secret_field"]; !ok {
		t.Error("missing denied aggregation")
	}
	// AllowedAggregations was nil → should remain nil
	if got.AllowedAggregations != nil {
		t.Error("allowed aggregations should be nil when not set")
	}
}

func TestCustomDecision_AllowedAggregations(t *testing.T) {
	c, _ := newTestCache(t, 300)
	ctx := t.Context()

	allowed := map[string]struct{}{"cpu": {}, "memory": {}}
	original := &CustomResourceDecision{
		Decision:            DecisionAllow,
		Permissions:         map[Action]struct{}{},
		AllowedAggregations: &allowed,
		DeniedAggregations:  map[string]struct{}{},
		Matcher:             &ResourceMatcher{Visibility: VisibilityAll},
	}

	c.SetCustomDecision(ctx, "rbac:custom:agg", original)
	got := c.GetCustomDecision(ctx, "rbac:custom:agg")
	if got == nil {
		t.Fatal("expected cached decision")
	}
	if got.AllowedAggregations == nil {
		t.Fatal("allowed aggregations should not be nil")
	}
	if _, ok := (*got.AllowedAggregations)["cpu"]; !ok {
		t.Error("missing cpu in allowed aggregations")
	}
	if _, ok := (*got.AllowedAggregations)["memory"]; !ok {
		t.Error("missing memory in allowed aggregations")
	}
}

func TestCustomResourceCacheKey(t *testing.T) {
	p := &Principal{Username: "alice", Groups: []string{"admins"}}

	key := CustomResourceCacheKey(p, "virtualmachines", "cluster-1", ActionView)
	if key != "rbac:custom:alice:admins:virtualmachines:cluster-1:view" {
		t.Errorf("key = %v", key)
	}
}

func TestCustomResourceCacheKey_EmptyCluster(t *testing.T) {
	p := &Principal{Username: "bob", Groups: []string{}}
	key := CustomResourceCacheKey(p, "pods", "", ActionViewMetrics)
	if key != "rbac:custom:bob::pods:all:view_metrics" {
		t.Errorf("key = %v", key)
	}
}

func TestSerializeResourceMatcher_RoundTrip(t *testing.T) {
	original := &ResourceMatcher{
		Visibility: VisibilityFiltered,
		Names: &MatchSpec{
			Include:         map[string]struct{}{"a": {}},
			Exclude:         map[string]struct{}{"b": {}},
			IncludePatterns: []CompiledPattern{{Original: "test-*", Regexp: regexp.MustCompile("^test-.*$")}},
			ExcludePatterns: []CompiledPattern{},
		},
		Labels: map[string]string{"env": "prod"},
	}

	// Simulate JSON round-trip (as the cache does)
	serialized := serializeResourceMatcher(original)
	raw, _ := json.Marshal(serialized)
	var deserialized map[string]any
	json.Unmarshal(raw, &deserialized)
	got := deserializeResourceMatcher(deserialized)

	if got.Visibility != VisibilityFiltered {
		t.Errorf("visibility = %v", got.Visibility)
	}
	if _, ok := got.Names.Include["a"]; !ok {
		t.Error("missing include 'a'")
	}
	if _, ok := got.Names.Exclude["b"]; !ok {
		t.Error("missing exclude 'b'")
	}
	if len(got.Names.IncludePatterns) != 1 {
		t.Errorf("include patterns = %d", len(got.Names.IncludePatterns))
	}
	if got.Labels["env"] != "prod" {
		t.Errorf("labels = %v", got.Labels)
	}
}

func TestDeserializeResourceMatcher_EmptyVisibility(t *testing.T) {
	m := deserializeResourceMatcher(map[string]any{})
	if m.Visibility != VisibilityAll {
		t.Errorf("default visibility = %v, want 'all'", m.Visibility)
	}
}

func TestSerializeMatchSpec_RoundTrip(t *testing.T) {
	original := &MatchSpec{
		Include:         map[string]struct{}{"x": {}, "y": {}},
		Exclude:         map[string]struct{}{"z": {}},
		IncludePatterns: []CompiledPattern{{Original: "foo-*", Regexp: regexp.MustCompile("^foo-.*$")}},
		ExcludePatterns: []CompiledPattern{{Original: "bar-?", Regexp: regexp.MustCompile("^bar-.$")}},
	}

	// Simulate JSON round-trip (as the cache does)
	serialized := serializeMatchSpec(original)
	raw, _ := json.Marshal(serialized)
	var deserialized map[string]any
	json.Unmarshal(raw, &deserialized)
	got := deserializeMatchSpec(deserialized)

	if _, ok := got.Include["x"]; !ok {
		t.Error("missing include 'x'")
	}
	if _, ok := got.Exclude["z"]; !ok {
		t.Error("missing exclude 'z'")
	}
	if len(got.IncludePatterns) != 1 || got.IncludePatterns[0].Original != "foo-*" {
		t.Errorf("include patterns = %v", got.IncludePatterns)
	}
	if len(got.ExcludePatterns) != 1 || got.ExcludePatterns[0].Original != "bar-?" {
		t.Errorf("exclude patterns = %v", got.ExcludePatterns)
	}
}

func TestStrVal(t *testing.T) {
	m := map[string]any{"key": "value", "num": 42}
	if got := strVal(m, "key"); got != "value" {
		t.Errorf("got %q", got)
	}
	if got := strVal(m, "num"); got != "" {
		t.Errorf("non-string should return empty, got %q", got)
	}
	if got := strVal(m, "missing"); got != "" {
		t.Errorf("missing should return empty, got %q", got)
	}
}

func TestMapVal(t *testing.T) {
	inner := map[string]any{"a": 1}
	m := map[string]any{"data": inner, "str": "nope"}
	if got := mapVal(m, "data"); got == nil || got["a"] != 1 {
		t.Errorf("got %v", got)
	}
	if got := mapVal(m, "str"); got != nil {
		t.Errorf("non-map should return nil, got %v", got)
	}
	if got := mapVal(m, "missing"); got != nil {
		t.Errorf("missing should return nil, got %v", got)
	}
}

func TestSliceVal(t *testing.T) {
	m := map[string]any{"items": []any{"a", "b"}, "str": "nope"}
	if got := sliceVal(m, "items"); len(got) != 2 {
		t.Errorf("got %v", got)
	}
	if got := sliceVal(m, "str"); got != nil {
		t.Errorf("non-slice should return nil, got %v", got)
	}
	if got := sliceVal(m, "missing"); got != nil {
		t.Errorf("missing should return nil, got %v", got)
	}
}
