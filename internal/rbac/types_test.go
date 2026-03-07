package rbac

import (
	"strings"
	"testing"
)

func TestPrincipal_CacheKey(t *testing.T) {
	t.Run("sorted groups", func(t *testing.T) {
		p := &Principal{Username: "alice", Groups: []string{"z-team", "a-team", "m-team"}}
		key := p.CacheKey()
		if key != "alice:a-team,m-team,z-team" {
			t.Errorf("CacheKey() = %q, want %q", key, "alice:a-team,m-team,z-team")
		}
	})

	t.Run("no groups", func(t *testing.T) {
		p := &Principal{Username: "bob", Groups: []string{}}
		key := p.CacheKey()
		if key != "bob:" {
			t.Errorf("CacheKey() = %q, want %q", key, "bob:")
		}
	})

	t.Run("single group", func(t *testing.T) {
		p := &Principal{Username: "carol", Groups: []string{"admins"}}
		key := p.CacheKey()
		if key != "carol:admins" {
			t.Errorf("CacheKey() = %q, want %q", key, "carol:admins")
		}
	})
}

func TestResource_ID(t *testing.T) {
	tests := []struct {
		name     string
		resource Resource
		want     string
	}{
		{
			"cluster only",
			Resource{Type: ResourceCluster, Name: "prod", Cluster: "prod"},
			"cluster:prod:prod",
		},
		{
			"with namespace",
			Resource{Type: ResourcePod, Name: "my-pod", Namespace: "default", Cluster: "prod"},
			"pod:prod:default:my-pod",
		},
		{
			"name only",
			Resource{Type: ResourceNode, Name: "worker-1"},
			"node:worker-1",
		},
		{
			"cluster and namespace",
			Resource{Type: ResourceNamespace, Name: "kube-system", Cluster: "dev"},
			"namespace:dev:kube-system",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.resource.ID()
			if got != tt.want {
				t.Errorf("ID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRequest_CacheKey(t *testing.T) {
	r := &Request{
		Principal: &Principal{Username: "alice", Groups: []string{"b", "a"}},
		Action:    ActionView,
		Resource:  &Resource{Type: ResourceCluster, Name: "prod", Cluster: "prod"},
	}
	key := r.CacheKey()
	if !strings.HasPrefix(key, "alice:a,b:view:cluster:prod:prod") {
		t.Errorf("CacheKey() = %q, unexpected format", key)
	}
}

func TestMatchSpec_IncludeExact(t *testing.T) {
	ms := &MatchSpec{
		Include: map[string]struct{}{"kube-system": {}},
		Exclude: make(map[string]struct{}),
	}
	if !ms.Matches("kube-system") {
		t.Error("expected kube-system to match include")
	}
	if ms.Matches("default") {
		t.Error("expected default to not match")
	}
}

func TestMatchSpec_ExcludeExact(t *testing.T) {
	ms := &MatchSpec{
		Include: make(map[string]struct{}),
		Exclude: map[string]struct{}{"kube-system": {}},
	}
	if ms.Matches("kube-system") {
		t.Error("expected kube-system to be excluded")
	}
	// No includes means allow all non-excluded
	if !ms.Matches("default") {
		t.Error("expected default to pass (no include filter)")
	}
}

func TestMatchSpec_NoIncludes_AllowAll(t *testing.T) {
	ms := &MatchSpec{
		Include: make(map[string]struct{}),
		Exclude: make(map[string]struct{}),
	}
	if !ms.Matches("anything") {
		t.Error("expected any item to pass when no includes set")
	}
}

func TestMatchSpec_ExcludeOverridesInclude(t *testing.T) {
	ms := &MatchSpec{
		Include: map[string]struct{}{"test": {}},
		Exclude: map[string]struct{}{"test": {}},
	}
	if ms.Matches("test") {
		t.Error("expected exclude to override include for same item")
	}
}

func TestResourceMatcher_IsUnrestricted(t *testing.T) {
	t.Run("true when all empty", func(t *testing.T) {
		m := &ResourceMatcher{Visibility: VisibilityAll}
		if !m.IsUnrestricted() {
			t.Error("expected unrestricted")
		}
	})

	t.Run("false with names", func(t *testing.T) {
		m := &ResourceMatcher{
			Visibility: VisibilityAll,
			Names:      &MatchSpec{},
		}
		if m.IsUnrestricted() {
			t.Error("expected restricted with Names set")
		}
	})

	t.Run("false with namespaces", func(t *testing.T) {
		m := &ResourceMatcher{
			Visibility: VisibilityAll,
			Namespaces: &MatchSpec{},
		}
		if m.IsUnrestricted() {
			t.Error("expected restricted with Namespaces set")
		}
	})

	t.Run("false with labels", func(t *testing.T) {
		m := &ResourceMatcher{
			Visibility: VisibilityAll,
			Labels:     map[string]string{"env": "prod"},
		}
		if m.IsUnrestricted() {
			t.Error("expected restricted with Labels set")
		}
	})

	t.Run("false with field filters", func(t *testing.T) {
		m := &ResourceMatcher{
			Visibility:   VisibilityAll,
			FieldFilters: map[string]*MatchSpec{"status": {}},
		}
		if m.IsUnrestricted() {
			t.Error("expected restricted with FieldFilters set")
		}
	})

	t.Run("false with non-all visibility", func(t *testing.T) {
		m := &ResourceMatcher{Visibility: VisibilityFiltered}
		if m.IsUnrestricted() {
			t.Error("expected restricted with non-all visibility")
		}
	})
}

func TestRBACDecision_Allowed(t *testing.T) {
	tests := []struct {
		decision Decision
		want     bool
	}{
		{DecisionAllow, true},
		{DecisionPartial, true},
		{DecisionDeny, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.decision), func(t *testing.T) {
			d := &RBACDecision{Decision: tt.decision}
			if d.Allowed() != tt.want {
				t.Errorf("Allowed() = %v, want %v", d.Allowed(), tt.want)
			}
		})
	}
}

func TestRBACDecision_Denied(t *testing.T) {
	tests := []struct {
		decision Decision
		want     bool
	}{
		{DecisionDeny, true},
		{DecisionAllow, false},
		{DecisionPartial, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.decision), func(t *testing.T) {
			d := &RBACDecision{Decision: tt.decision}
			if d.Denied() != tt.want {
				t.Errorf("Denied() = %v, want %v", d.Denied(), tt.want)
			}
		})
	}
}

func TestRBACDecision_Can(t *testing.T) {
	d := &RBACDecision{
		Permissions: map[Action]struct{}{
			ActionView: {},
		},
	}
	if !d.Can(ActionView) {
		t.Error("expected Can(ActionView) = true")
	}
	if d.Can(ActionViewMetrics) {
		t.Error("expected Can(ActionViewMetrics) = false")
	}
}

func TestRBACDecision_Can_NilPermissions(t *testing.T) {
	d := &RBACDecision{}
	if d.Can(ActionView) {
		t.Error("expected Can() = false with nil Permissions")
	}
}

func TestCustomResourceDecision_IsAggregationAllowed(t *testing.T) {
	t.Run("nil AllowedAggregations allows all", func(t *testing.T) {
		d := &CustomResourceDecision{}
		if !d.IsAggregationAllowed("any_agg") {
			t.Error("expected all allowed when AllowedAggregations is nil")
		}
	})

	t.Run("denied set blocks", func(t *testing.T) {
		d := &CustomResourceDecision{
			DeniedAggregations: map[string]struct{}{"blocked": {}},
		}
		if d.IsAggregationAllowed("blocked") {
			t.Error("expected denied aggregation to be blocked")
		}
		if !d.IsAggregationAllowed("allowed") {
			t.Error("expected non-denied aggregation to be allowed")
		}
	})

	t.Run("allow list restricts", func(t *testing.T) {
		allowed := map[string]struct{}{"sum": {}, "count": {}}
		d := &CustomResourceDecision{
			AllowedAggregations: &allowed,
		}
		if !d.IsAggregationAllowed("sum") {
			t.Error("expected 'sum' to be allowed")
		}
		if d.IsAggregationAllowed("avg") {
			t.Error("expected 'avg' to be blocked by allow list")
		}
	})

	t.Run("denied takes precedence over allowed", func(t *testing.T) {
		allowed := map[string]struct{}{"sum": {}}
		d := &CustomResourceDecision{
			AllowedAggregations: &allowed,
			DeniedAggregations:  map[string]struct{}{"sum": {}},
		}
		if d.IsAggregationAllowed("sum") {
			t.Error("expected denied to override allowed")
		}
	})
}

func TestCustomResourceDecision_Denied(t *testing.T) {
	d := &CustomResourceDecision{Decision: DecisionDeny}
	if !d.Denied() {
		t.Error("expected Denied() = true")
	}
	d.Decision = DecisionAllow
	if d.Denied() {
		t.Error("expected Denied() = false")
	}
}
