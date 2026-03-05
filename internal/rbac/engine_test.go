package rbac

import (
	"regexp"
	"testing"
)

// =========================================================================
// Nil Principal Guard
// =========================================================================

func TestAuthorize_NilPrincipal_ReturnsDeny(t *testing.T) {
	e := &Engine{}

	request := &Request{
		Principal: nil,
		Action:    ActionView,
		Resource:  &Resource{Type: ResourceCluster, Name: "test"},
	}
	decision := e.Authorize(t.Context(), request)
	if decision.Decision != DecisionDeny {
		t.Fatalf("expected Deny for nil principal, got %s", decision.Decision)
	}
	if decision.Reason != "No principal provided" {
		t.Fatalf("unexpected reason: %s", decision.Reason)
	}
}

// =========================================================================
// Regex Compilation / compilePattern
// =========================================================================

func TestCompilePattern_Valid(t *testing.T) {
	e := &Engine{}
	re := e.compilePattern("^prod-.*")
	if re == nil {
		t.Fatal("expected non-nil compiled regex")
	}
	if !re.MatchString("prod-cluster") {
		t.Fatal("expected regex to match 'prod-cluster'")
	}
}

func TestCompilePattern_Cached(t *testing.T) {
	e := &Engine{}
	re1 := e.compilePattern("^test-.*")
	re2 := e.compilePattern("^test-.*")
	if re1 != re2 {
		t.Fatal("expected same *regexp.Regexp instance from cache")
	}
}

func TestCompilePattern_TooLong(t *testing.T) {
	e := &Engine{}
	long := make([]byte, maxPatternLength+1)
	for i := range long {
		long[i] = 'a'
	}
	re := e.compilePattern(string(long))
	if re != nil {
		t.Fatal("expected nil for pattern exceeding max length")
	}
}

func TestCompilePattern_Invalid(t *testing.T) {
	e := &Engine{}
	re := e.compilePattern("[invalid")
	if re != nil {
		t.Fatal("expected nil for invalid regex")
	}
}

// =========================================================================
// First-match-wins for Allow
// =========================================================================

func TestEvaluatePolicies_FirstMatchWins(t *testing.T) {
	e := &Engine{}

	principal := &Principal{Username: "alice", Groups: []string{"team"}}
	resource := &Resource{Type: ResourceCluster, Name: "prod-1", Cluster: "prod-1"}
	request := &Request{Principal: principal, Action: ActionView, Resource: resource}

	// Higher-priority policy with restricted permissions (view only)
	highPriority := map[string]any{
		"policy_name": "restrictive",
		"effect":      "Allow",
		"enabled":     true,
		"cluster_rules": []any{
			map[string]any{
				"cluster_selector": map[string]any{
					"matchNames": []any{"prod-1"},
				},
				"permissions": map[string]any{"view": true},
			},
		},
	}

	// Lower-priority policy with broader permissions
	lowPriority := map[string]any{
		"policy_name": "broad",
		"effect":      "Allow",
		"enabled":     true,
		"cluster_rules": []any{
			map[string]any{
				"cluster_selector": map[string]any{
					"matchNames": []any{"prod-1"},
				},
				"permissions": map[string]any{"view": true, "viewMetrics": true, "viewSensitive": true},
			},
		},
	}

	// Policies sorted by priority descending — higher priority first
	policies := []map[string]any{highPriority, lowPriority}

	decision := e.evaluatePolicies(request, policies)
	if decision.Decision == DecisionDeny {
		t.Fatal("expected Allow, got Deny")
	}

	if _, has := decision.Permissions[ActionViewMetrics]; has {
		t.Fatal("expected viewMetrics NOT granted (first-match-wins should use restrictive policy)")
	}
	if _, has := decision.Permissions[ActionViewSensitive]; has {
		t.Fatal("expected viewSensitive NOT granted (first-match-wins should use restrictive policy)")
	}
}

// =========================================================================
// Filter.Matches with only Patterns or Labels
// =========================================================================

func TestFilterMatches_PatternsOnly_NotBypassed(t *testing.T) {
	f := NewFilter(VisibilityAll)
	f.Patterns = []CompiledPattern{
		{Original: "prod-.*", Regexp: mustCompile("^prod-.*")},
	}

	if f.Matches("dev-cluster", nil) {
		t.Fatal("expected 'dev-cluster' to NOT match pattern-only filter")
	}
	if !f.Matches("prod-cluster", nil) {
		t.Fatal("expected 'prod-cluster' to match pattern-only filter")
	}
}

func TestFilterMatches_LabelsOnly_NotBypassed(t *testing.T) {
	f := NewFilter(VisibilityAll)
	f.Labels = map[string]string{"env": "prod"}

	if f.Matches("anything", map[string]string{"env": "dev"}) {
		t.Fatal("expected non-matching labels to fail")
	}
	if !f.Matches("anything", map[string]string{"env": "prod"}) {
		t.Fatal("expected matching labels to pass")
	}
}

// =========================================================================
// Label Filter with Nil Labels
// =========================================================================

func TestFilterMatches_NilLabels_FailsWhenLabelFilterSet(t *testing.T) {
	f := NewFilter(VisibilityAll)
	f.Labels = map[string]string{"env": "prod"}

	if f.Matches("resource", nil) {
		t.Fatal("expected nil labels to fail when label filter is set")
	}
}

// =========================================================================
// PermissionMapping covers all actions
// =========================================================================

func TestPermissionMapping_CoversAllActions(t *testing.T) {
	mapped := make(map[Action]struct{})
	for _, a := range PermissionMapping {
		mapped[a] = struct{}{}
	}
	for _, a := range AllActions {
		if _, ok := mapped[a]; !ok {
			t.Fatalf("action %q has no entry in PermissionMapping", a)
		}
	}
}

// =========================================================================
// Time Constraints Fail Closed on Parse Error
// =========================================================================

func TestIsPolicyValid_BadNotBefore_Invalid(t *testing.T) {
	e := &Engine{}
	policy := map[string]any{
		"policy_name": "test",
		"enabled":     true,
		"not_before":  "not-a-date",
	}
	if e.isPolicyValid(policy) {
		t.Fatal("expected policy with unparseable not_before to be invalid")
	}
}

func TestIsPolicyValid_BadNotAfter_Invalid(t *testing.T) {
	e := &Engine{}
	policy := map[string]any{
		"policy_name": "test",
		"enabled":     true,
		"not_after":   "also-not-a-date",
	}
	if e.isPolicyValid(policy) {
		t.Fatal("expected policy with unparseable not_after to be invalid")
	}
}

// =========================================================================
// escapeRedisGlob
// =========================================================================

func TestEscapeRedisGlob(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"normal-user", "normal-user"},
		{"user*admin", `user\*admin`},
		{"user?admin", `user\?admin`},
		{"user[admin]", `user\[admin\]`},
		{"*?[]", `\*\?\[\]`},
	}
	for _, tt := range tests {
		got := escapeRedisGlob(tt.input)
		if got != tt.want {
			t.Errorf("escapeRedisGlob(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// =========================================================================
// Empty matchLabels matches all resources
// =========================================================================

func TestMatchCluster_EmptyMatchLabels_MatchesAll(t *testing.T) {
	e := &Engine{}
	resource := &Resource{Type: ResourceCluster, Name: "test", Labels: nil}
	policy := map[string]any{
		"cluster_rules": []any{
			map[string]any{
				"cluster_selector": map[string]any{
					"matchLabels": map[string]any{},
				},
				"permissions": map[string]any{"view": true},
			},
		},
	}

	result := e.matchCluster(resource, policy)
	if result == nil {
		t.Fatal("expected empty matchLabels to match all resources")
	}
}

// =========================================================================
// Secrets field uses count semantic
// =========================================================================

func TestApplyDataFilters_SecretsUsesCountSemantic(t *testing.T) {
	e := &Engine{}
	resource := map[string]any{
		"name":    "test",
		"secrets": []any{"s1", "s2"},
	}

	permissions := map[Action]struct{}{ActionView: {}}

	filtered := e.applyDataFilters(resource, ResourceCluster, permissions)

	val, exists := filtered["secrets"]
	if !exists {
		t.Fatal("expected 'secrets' to be present (replaced with count)")
	}
	if count, ok := val.(int); !ok || count != 2 {
		t.Fatalf("expected secrets count=2, got %v", val)
	}
}

// =========================================================================
// Helpers
// =========================================================================

func mustCompile(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}
