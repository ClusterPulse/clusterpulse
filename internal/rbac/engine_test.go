package rbac

import (
	"regexp"
	"testing"

	"github.com/clusterpulse/cluster-controller/pkg/types"
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

	highPriority := types.CompiledPolicy{
		PolicyName: "restrictive",
		Effect:     "Allow",
		Enabled:    true,
		ClusterRules: []types.CompiledClusterRule{{
			ClusterSelector: types.CompiledClusterSelector{MatchNames: []string{"prod-1"}},
			Permissions:     map[string]bool{"view": true},
		}},
	}

	lowPriority := types.CompiledPolicy{
		PolicyName: "broad",
		Effect:     "Allow",
		Enabled:    true,
		ClusterRules: []types.CompiledClusterRule{{
			ClusterSelector: types.CompiledClusterSelector{MatchNames: []string{"prod-1"}},
			Permissions:     map[string]bool{"view": true, "viewMetrics": true, "viewSensitive": true},
		}},
	}

	policies := []types.CompiledPolicy{highPriority, lowPriority}

	decision := e.evaluatePolicies(request, policies)
	if decision.Decision == DecisionDeny {
		t.Fatal("expected Allow, got Deny")
	}

	if _, has := decision.Permissions[ActionViewMetrics]; has {
		t.Fatal("expected viewMetrics NOT granted (first-match-wins should use restrictive policy)")
	}
}

// =========================================================================
// MatchSpec.Matches
// =========================================================================

func TestMatchSpec_PatternsOnly_NotBypassed(t *testing.T) {
	ms := &MatchSpec{
		Include:         make(map[string]struct{}),
		Exclude:         make(map[string]struct{}),
		IncludePatterns: []CompiledPattern{{Original: "prod-.*", Regexp: mustCompile("^prod-.*")}},
	}

	if ms.Matches("dev-cluster") {
		t.Fatal("expected 'dev-cluster' to NOT match pattern-only spec")
	}
	if !ms.Matches("prod-cluster") {
		t.Fatal("expected 'prod-cluster' to match pattern-only spec")
	}
}

func TestMatchSpec_ExcludePatterns(t *testing.T) {
	ms := &MatchSpec{
		Include:         make(map[string]struct{}),
		Exclude:         make(map[string]struct{}),
		ExcludePatterns: []CompiledPattern{{Original: "test-.*", Regexp: mustCompile("^test-.*$")}},
	}

	if ms.Matches("test-ns") {
		t.Fatal("expected 'test-ns' to be excluded by pattern")
	}
	if !ms.Matches("prod-ns") {
		t.Fatal("expected 'prod-ns' to pass")
	}
}

// =========================================================================
// ResourceMatcher with labels
// =========================================================================

func TestResourceMatcher_LabelsNotBypassed(t *testing.T) {
	matcher := &ResourceMatcher{
		Visibility: VisibilityAll,
		Labels:     map[string]string{"env": "prod"},
	}
	handler := &ResourceHandler{
		ExtractName:       func(r map[string]any) string { return getStr(r, "name") },
		ExtractNamespaces: func(map[string]any) []string { return nil },
		ExtractLabels: func(r map[string]any) map[string]string {
			if l, ok := r["labels"].(map[string]string); ok {
				return l
			}
			return nil
		},
	}
	e := &Engine{}

	devResource := map[string]any{"name": "r1", "labels": map[string]string{"env": "dev"}}
	prodResource := map[string]any{"name": "r1", "labels": map[string]string{"env": "prod"}}
	nilLabelsResource := map[string]any{"name": "r1"}

	if e.matchesResource(devResource, matcher, handler) {
		t.Fatal("expected non-matching labels to fail")
	}
	if !e.matchesResource(prodResource, matcher, handler) {
		t.Fatal("expected matching labels to pass")
	}
	if e.matchesResource(nilLabelsResource, matcher, handler) {
		t.Fatal("expected nil labels to fail when label filter is set")
	}
}

// =========================================================================
// ResourceMatcher unified filter: namespace + name
// =========================================================================

func TestResourceMatcher_UnifiedNamespaceAndName(t *testing.T) {
	matcher := &ResourceMatcher{
		Visibility: VisibilityFiltered,
		Names:      &MatchSpec{Include: map[string]struct{}{"my-pod": {}}, Exclude: make(map[string]struct{})},
		Namespaces: &MatchSpec{Include: map[string]struct{}{"kube-system": {}}, Exclude: make(map[string]struct{})},
	}
	handler := standardHandlers["pods"]
	e := &Engine{}

	match := map[string]any{"name": "my-pod", "namespace": "kube-system"}
	wrongNS := map[string]any{"name": "my-pod", "namespace": "default"}
	wrongName := map[string]any{"name": "other-pod", "namespace": "kube-system"}

	if !e.matchesResource(match, matcher, handler) {
		t.Fatal("expected matching name+namespace to pass")
	}
	if e.matchesResource(wrongNS, matcher, handler) {
		t.Fatal("expected wrong namespace to fail")
	}
	if e.matchesResource(wrongName, matcher, handler) {
		t.Fatal("expected wrong name to fail")
	}
}

// =========================================================================
// Operator filtering via standard ResourceMatcher
// =========================================================================

func TestResourceMatcher_OperatorNamespaces(t *testing.T) {
	matcher := &ResourceMatcher{
		Visibility: VisibilityFiltered,
		Namespaces: &MatchSpec{Include: map[string]struct{}{"monitoring": {}}, Exclude: make(map[string]struct{})},
	}
	handler := standardHandlers["operators"]
	e := &Engine{}

	// Operator available in monitoring
	opMatch := map[string]any{"name": "prom", "available_in_namespaces": []any{"monitoring", "default"}}
	// Operator NOT in monitoring
	opNoMatch := map[string]any{"name": "other", "available_in_namespaces": []any{"default"}}
	// Cluster-wide operator
	opWild := map[string]any{"name": "global", "available_in_namespaces": []any{"*"}}

	if !e.matchesResource(opMatch, matcher, handler) {
		t.Fatal("expected operator in monitoring to pass")
	}
	if e.matchesResource(opNoMatch, matcher, handler) {
		t.Fatal("expected operator NOT in monitoring to fail")
	}
	if !e.matchesResource(opWild, matcher, handler) {
		t.Fatal("expected cluster-wide operator to pass")
	}
}

// =========================================================================
// Custom resource field filtering
// =========================================================================

func TestResourceMatcher_FieldFilters(t *testing.T) {
	matcher := &ResourceMatcher{
		Visibility: VisibilityFiltered,
		FieldFilters: map[string]*MatchSpec{
			"status": {
				Include: map[string]struct{}{"running": {}},
				Exclude: make(map[string]struct{}),
			},
		},
	}
	handler := defaultCustomHandler
	e := &Engine{}

	match := map[string]any{"_name": "vm-1", "values": map[string]any{"status": "running"}}
	noMatch := map[string]any{"_name": "vm-2", "values": map[string]any{"status": "stopped"}}

	if !e.matchesResource(match, matcher, handler) {
		t.Fatal("expected matching field to pass")
	}
	if e.matchesResource(noMatch, matcher, handler) {
		t.Fatal("expected non-matching field to fail")
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
	nb := "not-a-date"
	policy := &types.CompiledPolicy{
		PolicyName: "test",
		Enabled:    true,
		NotBefore:  &nb,
	}
	if e.isPolicyValid(policy) {
		t.Fatal("expected policy with unparseable not_before to be invalid")
	}
}

func TestIsPolicyValid_BadNotAfter_Invalid(t *testing.T) {
	e := &Engine{}
	na := "also-not-a-date"
	policy := &types.CompiledPolicy{
		PolicyName: "test",
		Enabled:    true,
		NotAfter:   &na,
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
	policy := &types.CompiledPolicy{
		ClusterRules: []types.CompiledClusterRule{{
			ClusterSelector: types.CompiledClusterSelector{MatchLabels: map[string]string{}},
			Permissions:     map[string]bool{"view": true},
		}},
	}

	result := e.matchCluster(resource, policy)
	if result == nil {
		t.Fatal("expected empty matchLabels to match all resources")
	}
}

// =========================================================================
// Resource handler registry
// =========================================================================

func TestResourceHandler_DefaultCustomHandler(t *testing.T) {
	e := &Engine{}
	handler := e.getHandler("virtualmachines")
	if handler != defaultCustomHandler {
		t.Fatal("expected default custom handler for unknown type")
	}

	handler = e.getHandler("nodes")
	if handler != standardHandlers["nodes"] {
		t.Fatal("expected standard handler for nodes")
	}
}

// =========================================================================
// buildMatcherFromCompiled round-trip
// =========================================================================

func TestBuildMatcherFromCompiled(t *testing.T) {
	crf := &types.CompiledResourceFilter{
		Type:       "pods",
		Visibility: "filtered",
		AllowedNS:  []string{"kube-system"},
		DeniedNS:   []string{"test"},
		NSPatterns: [][2]string{{"prod-*", "^prod-.*$"}},
	}

	matcher := buildMatcherFromCompiled(crf)
	if matcher.Visibility != VisibilityFiltered {
		t.Fatalf("expected filtered visibility, got %s", matcher.Visibility)
	}
	if matcher.Namespaces == nil {
		t.Fatal("expected non-nil namespace matcher")
	}
	if !matcher.Namespaces.Matches("kube-system") {
		t.Fatal("expected kube-system to match")
	}
	if matcher.Namespaces.Matches("test") {
		t.Fatal("expected test to be excluded")
	}
	if !matcher.Namespaces.Matches("prod-east") {
		t.Fatal("expected prod-east to match pattern")
	}
	if matcher.Namespaces.Matches("dev") {
		t.Fatal("expected dev to not match")
	}
}

// =========================================================================
// Custom resource cluster selector scoping
// =========================================================================

func TestCustomResource_ClusterSelectorScoping(t *testing.T) {
	e := &Engine{}

	policies := []types.CompiledPolicy{{
		PolicyName: "prod-vms",
		Effect:     "Allow",
		Enabled:    true,
		ClusterRules: []types.CompiledClusterRule{{
			ClusterSelector: types.CompiledClusterSelector{MatchPattern: "^prod-.*"},
			Permissions:     map[string]bool{"view": true},
			Resources: []types.CompiledResourceFilter{{
				Type:       "virtualmachines",
				Visibility: "all",
			}},
		}},
	}}

	// dev-1 should NOT match the prod-* rule
	devDecision := e.evaluateCustomResourcePolicies("virtualmachines", "dev-1", ActionView, policies)
	if devDecision.Decision != DecisionDeny {
		t.Fatalf("expected Deny for dev-1, got %s", devDecision.Decision)
	}

	// prod-east should match
	prodDecision := e.evaluateCustomResourcePolicies("virtualmachines", "prod-east", ActionView, policies)
	if prodDecision.Decision == DecisionDeny {
		t.Fatalf("expected Allow for prod-east, got Deny: %s", prodDecision.Reason)
	}
}

func TestCustomResource_DenyRespectsClusterSelector(t *testing.T) {
	e := &Engine{}

	policies := []types.CompiledPolicy{
		{
			PolicyName: "deny-prod-vms",
			Effect:     "Deny",
			Enabled:    true,
			ClusterRules: []types.CompiledClusterRule{{
				ClusterSelector: types.CompiledClusterSelector{MatchPattern: "^prod-.*"},
				Resources: []types.CompiledResourceFilter{{
					Type:       "virtualmachines",
					Visibility: "all",
				}},
			}},
		},
		{
			PolicyName: "allow-all-vms",
			Effect:     "Allow",
			Enabled:    true,
			ClusterRules: []types.CompiledClusterRule{{
				ClusterSelector: types.CompiledClusterSelector{MatchPattern: ".*"},
				Permissions:     map[string]bool{"view": true},
				Resources: []types.CompiledResourceFilter{{
					Type:       "virtualmachines",
					Visibility: "all",
				}},
			}},
		},
	}

	// prod-east should be denied
	prodDecision := e.evaluateCustomResourcePolicies("virtualmachines", "prod-east", ActionView, policies)
	if prodDecision.Decision != DecisionDeny {
		t.Fatalf("expected Deny for prod-east, got %s", prodDecision.Decision)
	}

	// dev-1 should be allowed (deny rule doesn't match)
	devDecision := e.evaluateCustomResourcePolicies("virtualmachines", "dev-1", ActionView, policies)
	if devDecision.Decision == DecisionDeny {
		t.Fatalf("expected Allow for dev-1, got Deny: %s", devDecision.Reason)
	}
}

func TestCustomResource_EmptyClusterSkipsSelectorCheck(t *testing.T) {
	e := &Engine{}

	policies := []types.CompiledPolicy{{
		PolicyName: "prod-vms",
		Effect:     "Allow",
		Enabled:    true,
		ClusterRules: []types.CompiledClusterRule{{
			ClusterSelector: types.CompiledClusterSelector{MatchPattern: "^prod-.*"},
			Permissions:     map[string]bool{"view": true},
			Resources: []types.CompiledResourceFilter{{
				Type:       "virtualmachines",
				Visibility: "all",
			}},
		}},
	}}

	// Empty cluster (type discovery) should find the type
	decision := e.evaluateCustomResourcePolicies("virtualmachines", "", ActionView, policies)
	if decision.Decision == DecisionDeny {
		t.Fatalf("expected Allow for empty cluster (type discovery), got Deny: %s", decision.Reason)
	}
}

// =========================================================================
// Helpers
// =========================================================================

func mustCompile(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}
