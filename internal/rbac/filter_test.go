package rbac

import (
	"testing"

	"github.com/clusterpulse/cluster-controller/pkg/types"
)

func TestBuildMatcherFromCompiled_AllFields(t *testing.T) {
	crf := &types.CompiledResourceFilter{
		Visibility:   "filtered",
		Labels:       map[string]string{"env": "prod"},
		AllowedNames: []string{"node-1"},
		DeniedNames:  []string{"node-2"},
		AllowedNS:    []string{"default"},
		DeniedNS:     []string{"kube-system"},
		FieldFilters: map[string]*types.CompiledFieldFilter{
			"status": {AllowedLiterals: []string{"running"}},
		},
	}

	m := buildMatcherFromCompiled(crf)
	if m.Visibility != Visibility("filtered") {
		t.Errorf("Visibility = %q, want %q", m.Visibility, "filtered")
	}
	if m.Labels["env"] != "prod" {
		t.Error("Labels not propagated")
	}
	if m.Names == nil {
		t.Fatal("Names should be set when name filters exist")
	}
	if _, ok := m.Names.Include["node-1"]; !ok {
		t.Error("Names.Include missing node-1")
	}
	if _, ok := m.Names.Exclude["node-2"]; !ok {
		t.Error("Names.Exclude missing node-2")
	}
	if m.Namespaces == nil {
		t.Fatal("Namespaces should be set when NS filters exist")
	}
	if _, ok := m.Namespaces.Include["default"]; !ok {
		t.Error("Namespaces.Include missing default")
	}
	if m.FieldFilters == nil || m.FieldFilters["status"] == nil {
		t.Fatal("FieldFilters should be set")
	}
	if _, ok := m.FieldFilters["status"].Include["running"]; !ok {
		t.Error("FieldFilters[status].Include missing running")
	}
}

func TestBuildMatcherFromCompiled_NoFilters(t *testing.T) {
	crf := &types.CompiledResourceFilter{Visibility: "all"}
	m := buildMatcherFromCompiled(crf)
	if m.Names != nil {
		t.Error("Names should be nil when no name filters")
	}
	if m.Namespaces != nil {
		t.Error("Namespaces should be nil when no NS filters")
	}
	if m.FieldFilters != nil {
		t.Error("FieldFilters should be nil when empty")
	}
}

func TestBuildMatcherFromCompiled_DefaultVisibility(t *testing.T) {
	crf := &types.CompiledResourceFilter{}
	m := buildMatcherFromCompiled(crf)
	if m.Visibility != "" {
		t.Errorf("Visibility = %q, want empty (inherits from crf)", m.Visibility)
	}
}

func TestHasNameFilters(t *testing.T) {
	tests := []struct {
		name string
		crf  types.CompiledResourceFilter
		want bool
	}{
		{"empty", types.CompiledResourceFilter{}, false},
		{"allowedNames", types.CompiledResourceFilter{AllowedNames: []string{"a"}}, true},
		{"deniedNames", types.CompiledResourceFilter{DeniedNames: []string{"b"}}, true},
		{"namePatterns", types.CompiledResourceFilter{NamePatterns: [][2]string{{"*", ".*"}}}, true},
		{"denyNamePatterns", types.CompiledResourceFilter{DenyNamePatterns: [][2]string{{"x*", "x.*"}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasNameFilters(&tt.crf); got != tt.want {
				t.Errorf("hasNameFilters() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasNSFilters(t *testing.T) {
	tests := []struct {
		name string
		crf  types.CompiledResourceFilter
		want bool
	}{
		{"empty", types.CompiledResourceFilter{}, false},
		{"allowedNS", types.CompiledResourceFilter{AllowedNS: []string{"ns1"}}, true},
		{"deniedNS", types.CompiledResourceFilter{DeniedNS: []string{"ns2"}}, true},
		{"nsPatterns", types.CompiledResourceFilter{NSPatterns: [][2]string{{"dev-*", "dev-.*"}}}, true},
		{"denyNSPatterns", types.CompiledResourceFilter{DenyNSPatterns: [][2]string{{"kube-*", "kube-.*"}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasNSFilters(&tt.crf); got != tt.want {
				t.Errorf("hasNSFilters() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildMatchSpec(t *testing.T) {
	ms := buildMatchSpec(
		[]string{"a", "b"},
		[]string{"c"},
		[][2]string{{"d*", "d.*"}},
		[][2]string{{"e?", "e."}},
	)
	if len(ms.Include) != 2 {
		t.Errorf("Include len = %d, want 2", len(ms.Include))
	}
	if len(ms.Exclude) != 1 {
		t.Errorf("Exclude len = %d, want 1", len(ms.Exclude))
	}
	if len(ms.IncludePatterns) != 1 {
		t.Errorf("IncludePatterns len = %d, want 1", len(ms.IncludePatterns))
	}
	if len(ms.ExcludePatterns) != 1 {
		t.Errorf("ExcludePatterns len = %d, want 1", len(ms.ExcludePatterns))
	}
}

func TestCompilePatternPairs_Valid(t *testing.T) {
	pairs := [][2]string{{"test-*", "test-.*"}, {"prod-?", "prod-."}}
	compiled := compilePatternPairs(pairs)
	if len(compiled) != 2 {
		t.Fatalf("compiled len = %d, want 2", len(compiled))
	}
	if compiled[0].Original != "test-*" {
		t.Errorf("Original = %q, want %q", compiled[0].Original, "test-*")
	}
	if !compiled[0].Regexp.MatchString("test-abc") {
		t.Error("Pattern should match test-abc")
	}
}

func TestCompilePatternPairs_Invalid(t *testing.T) {
	pairs := [][2]string{{"bad", "[invalid"}}
	compiled := compilePatternPairs(pairs)
	if len(compiled) != 0 {
		t.Errorf("invalid regex should be skipped, got %d patterns", len(compiled))
	}
}

func TestCompilePatternPairs_Empty(t *testing.T) {
	compiled := compilePatternPairs(nil)
	if compiled != nil {
		t.Error("nil input should return nil")
	}
}

func TestBuildFieldMatchSpec(t *testing.T) {
	ff := &types.CompiledFieldFilter{
		AllowedLiterals: []string{"running"},
		DeniedLiterals:  []string{"failed"},
		AllowedPatterns: [][2]string{{"run*", "run.*"}},
		DeniedPatterns:  [][2]string{{"err*", "err.*"}},
	}
	ms := buildFieldMatchSpec(ff)
	if _, ok := ms.Include["running"]; !ok {
		t.Error("Include missing running")
	}
	if _, ok := ms.Exclude["failed"]; !ok {
		t.Error("Exclude missing failed")
	}
	if len(ms.IncludePatterns) != 1 {
		t.Errorf("IncludePatterns len = %d, want 1", len(ms.IncludePatterns))
	}
}
