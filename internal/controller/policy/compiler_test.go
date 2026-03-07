package policy

import (
	"testing"

	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
)

func boolPtr(b bool) *bool { return &b }

func minimalSpec(effect string, priority int) *v1alpha1.MonitorAccessPolicySpec {
	return &v1alpha1.MonitorAccessPolicySpec{
		Identity: v1alpha1.PolicyIdentity{
			Subjects: v1alpha1.PolicySubjects{Users: []string{"alice"}},
			Priority: priority,
		},
		Access: v1alpha1.PolicyAccess{Effect: effect},
		Scope:  v1alpha1.PolicyScope{Clusters: v1alpha1.PolicyClusters{Default: "allow"}},
	}
}

func TestCompile_BasicAllow(t *testing.T) {
	c := NewCompiler()
	p, err := c.Compile("test", "ns", minimalSpec("Allow", 100))
	if err != nil {
		t.Fatal(err)
	}
	if p.PolicyName != "test" || p.Namespace != "ns" {
		t.Error("name/namespace not set")
	}
	if p.Effect != "Allow" {
		t.Errorf("effect = %q, want Allow", p.Effect)
	}
	if p.Priority != 100 {
		t.Errorf("priority = %d, want 100", p.Priority)
	}
	if !p.Enabled {
		t.Error("default should be enabled")
	}
}

func TestCompile_Deny(t *testing.T) {
	c := NewCompiler()
	p, err := c.Compile("test", "ns", minimalSpec("Deny", 50))
	if err != nil {
		t.Fatal(err)
	}
	if p.Effect != "Deny" {
		t.Errorf("effect = %q, want Deny", p.Effect)
	}
}

func TestCompile_InvalidEffect(t *testing.T) {
	c := NewCompiler()
	_, err := c.Compile("test", "ns", minimalSpec("Invalid", 1))
	if err == nil {
		t.Error("expected error for invalid effect")
	}
}

func TestCompile_NegativePriority(t *testing.T) {
	c := NewCompiler()
	_, err := c.Compile("test", "ns", minimalSpec("Allow", -1))
	if err == nil {
		t.Error("expected error for negative priority")
	}
}

func TestCompile_Subjects(t *testing.T) {
	c := NewCompiler()
	spec := minimalSpec("Allow", 100)
	spec.Identity.Subjects = v1alpha1.PolicySubjects{
		Users:  []string{"alice", "bob"},
		Groups: []string{"admins"},
		ServiceAccounts: []v1alpha1.PolicyServiceAccount{
			{Name: "sa1", Namespace: "prod"},
			{Name: "sa2"},
		},
	}
	p, err := c.Compile("test", "ns", spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Users) != 2 {
		t.Errorf("users len = %d, want 2", len(p.Users))
	}
	if len(p.Groups) != 1 {
		t.Errorf("groups len = %d, want 1", len(p.Groups))
	}
	if len(p.ServiceAccounts) != 2 {
		t.Fatalf("SAs len = %d, want 2", len(p.ServiceAccounts))
	}
	if p.ServiceAccounts[0] != "system:serviceaccount:prod:sa1" {
		t.Errorf("SA[0] = %q", p.ServiceAccounts[0])
	}
	if p.ServiceAccounts[1] != "system:serviceaccount:default:sa2" {
		t.Errorf("SA[1] = %q (default ns expected)", p.ServiceAccounts[1])
	}
}

func TestCompile_ClusterRules(t *testing.T) {
	c := NewCompiler()
	spec := minimalSpec("Allow", 100)
	spec.Scope.Clusters.Rules = []v1alpha1.PolicyClusterRule{
		{
			Selector: v1alpha1.PolicyClusterSelector{
				MatchNames: []string{"prod-*"},
				MatchLabels: map[string]string{"env": "prod"},
			},
			Permissions: &v1alpha1.PolicyPermissions{View: boolPtr(true)},
			Resources: []v1alpha1.ResourceFilter{
				{Type: "nodes", Visibility: "all"},
			},
		},
	}
	p, err := c.Compile("test", "ns", spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ClusterRules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(p.ClusterRules))
	}
	rule := p.ClusterRules[0]
	if rule.ClusterSelector.MatchNames[0] != "prod-*" {
		t.Error("selector not propagated")
	}
	if !rule.Permissions["view"] {
		t.Error("view permission should be true")
	}
	if len(rule.Resources) != 1 || rule.Resources[0].Type != "nodes" {
		t.Error("resources not compiled")
	}
}

func TestCompile_CustomResourceTypes(t *testing.T) {
	c := NewCompiler()
	spec := minimalSpec("Allow", 100)
	spec.Scope.Clusters.Rules = []v1alpha1.PolicyClusterRule{
		{
			Selector: v1alpha1.PolicyClusterSelector{},
			Resources: []v1alpha1.ResourceFilter{
				{Type: "nodes"},
				{Type: "virtualmachines"},
				{Type: "certificates"},
			},
		},
	}
	p, err := c.Compile("test", "ns", spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.CustomResourceTypes) != 2 {
		t.Fatalf("custom types = %v, want [certificates virtualmachines]", p.CustomResourceTypes)
	}
	// Sorted
	if p.CustomResourceTypes[0] != "certificates" || p.CustomResourceTypes[1] != "virtualmachines" {
		t.Errorf("custom types = %v, want [certificates virtualmachines]", p.CustomResourceTypes)
	}
}

func TestCompile_ResourceFilters(t *testing.T) {
	c := NewCompiler()
	spec := minimalSpec("Allow", 100)
	spec.Scope.Clusters.Rules = []v1alpha1.PolicyClusterRule{
		{
			Selector: v1alpha1.PolicyClusterSelector{},
			Resources: []v1alpha1.ResourceFilter{
				{
					Type:       "operators",
					Visibility: "filtered",
					Filters: &v1alpha1.ResourceFilterSpec{
						Names:      &v1alpha1.PatternFilter{Allowed: []string{"cert-*"}, Denied: []string{"old-*"}},
						Namespaces: &v1alpha1.PatternFilter{Allowed: []string{"prod"}},
						Labels:     map[string]string{"team": "platform"},
					},
				},
			},
		},
	}
	p, err := c.Compile("test", "ns", spec)
	if err != nil {
		t.Fatal(err)
	}
	rf := p.ClusterRules[0].Resources[0]
	if rf.Visibility != "filtered" {
		t.Errorf("visibility = %q, want filtered", rf.Visibility)
	}
	if len(rf.NamePatterns) != 1 {
		t.Errorf("name patterns = %d, want 1 (cert-*)", len(rf.NamePatterns))
	}
	if len(rf.DenyNamePatterns) != 1 {
		t.Errorf("deny name patterns = %d, want 1", len(rf.DenyNamePatterns))
	}
	if len(rf.AllowedNS) != 1 || rf.AllowedNS[0] != "prod" {
		t.Errorf("allowed NS = %v, want [prod]", rf.AllowedNS)
	}
	if rf.Labels["team"] != "platform" {
		t.Error("labels not propagated")
	}
}

func TestCompile_FieldFilters(t *testing.T) {
	c := NewCompiler()
	spec := minimalSpec("Allow", 100)
	spec.Scope.Clusters.Rules = []v1alpha1.PolicyClusterRule{
		{
			Selector: v1alpha1.PolicyClusterSelector{},
			Resources: []v1alpha1.ResourceFilter{
				{
					Type: "virtualmachines",
					Filters: &v1alpha1.ResourceFilterSpec{
						Fields: map[string]v1alpha1.PatternFilter{
							"status": {Allowed: []string{"Running"}, Denied: []string{"err*"}},
						},
					},
				},
			},
		},
	}
	p, err := c.Compile("test", "ns", spec)
	if err != nil {
		t.Fatal(err)
	}
	rf := p.ClusterRules[0].Resources[0]
	if rf.FieldFilters == nil || rf.FieldFilters["status"] == nil {
		t.Fatal("field filters should be set")
	}
	ff := rf.FieldFilters["status"]
	if len(ff.AllowedLiterals) != 1 || ff.AllowedLiterals[0] != "Running" {
		t.Errorf("allowed literals = %v", ff.AllowedLiterals)
	}
	if len(ff.DeniedPatterns) != 1 {
		t.Errorf("denied patterns len = %d, want 1", len(ff.DeniedPatterns))
	}
}

func TestCompile_AggregationRules(t *testing.T) {
	c := NewCompiler()
	spec := minimalSpec("Allow", 100)
	spec.Scope.Clusters.Rules = []v1alpha1.PolicyClusterRule{
		{
			Selector: v1alpha1.PolicyClusterSelector{},
			Resources: []v1alpha1.ResourceFilter{
				{
					Type:         "virtualmachines",
					Aggregations: &v1alpha1.AggregationVisibility{Include: []string{"total"}, Exclude: []string{"secret_count"}},
				},
			},
		},
	}
	p, err := c.Compile("test", "ns", spec)
	if err != nil {
		t.Fatal(err)
	}
	agg := p.ClusterRules[0].Resources[0].AggregationRules
	if agg == nil {
		t.Fatal("aggregation rules should be set")
	}
	if len(agg.Include) != 1 || agg.Include[0] != "total" {
		t.Errorf("include = %v", agg.Include)
	}
	if len(agg.Exclude) != 1 || agg.Exclude[0] != "secret_count" {
		t.Errorf("exclude = %v", agg.Exclude)
	}
}

func TestCompile_Lifecycle(t *testing.T) {
	c := NewCompiler()
	spec := minimalSpec("Allow", 100)
	spec.Lifecycle = &v1alpha1.PolicyLifecycle{
		Validity: &v1alpha1.PolicyValidity{
			NotBefore: "2025-01-01T00:00:00Z",
			NotAfter:  "2026-12-31T23:59:59Z",
		},
	}
	p, err := c.Compile("test", "ns", spec)
	if err != nil {
		t.Fatal(err)
	}
	if p.NotBefore == nil || *p.NotBefore != "2025-01-01T00:00:00Z" {
		t.Errorf("NotBefore = %v", p.NotBefore)
	}
	if p.NotAfter == nil || *p.NotAfter != "2026-12-31T23:59:59Z" {
		t.Errorf("NotAfter = %v", p.NotAfter)
	}
}

func TestCompile_NilLifecycle(t *testing.T) {
	c := NewCompiler()
	p, err := c.Compile("test", "ns", minimalSpec("Allow", 100))
	if err != nil {
		t.Fatal(err)
	}
	if p.NotBefore != nil || p.NotAfter != nil {
		t.Error("nil lifecycle should produce nil NotBefore/NotAfter")
	}
}

func TestCompile_Disabled(t *testing.T) {
	c := NewCompiler()
	spec := minimalSpec("Allow", 100)
	spec.Access.Enabled = boolPtr(false)
	p, err := c.Compile("test", "ns", spec)
	if err != nil {
		t.Fatal(err)
	}
	if p.Enabled {
		t.Error("should be disabled")
	}
}

func TestPermissionsToMap_Nil(t *testing.T) {
	m := permissionsToMap(nil)
	if !m["view"] {
		t.Error("nil permissions should default to view:true")
	}
}

func TestPermissionsToMap_Explicit(t *testing.T) {
	p := &v1alpha1.PolicyPermissions{View: boolPtr(true), ViewMetrics: boolPtr(false)}
	m := permissionsToMap(p)
	if !m["view"] {
		t.Error("view should be true")
	}
	if m["viewMetrics"] {
		t.Error("viewMetrics should be false")
	}
}

func TestPermissionsToMap_Empty(t *testing.T) {
	p := &v1alpha1.PolicyPermissions{}
	m := permissionsToMap(p)
	if !m["view"] {
		t.Error("empty permissions should default to view:true")
	}
}

func TestEnsureStringSlice_Nil(t *testing.T) {
	got := ensureStringSlice(nil)
	if got == nil || len(got) != 0 {
		t.Errorf("nil should return empty slice, got %v", got)
	}
}

func TestEnsureStringSlice_NonNil(t *testing.T) {
	input := []string{"a", "b"}
	got := ensureStringSlice(input)
	if len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
}
