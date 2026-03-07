package compiler

import (
	"testing"

	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
	"github.com/clusterpulse/cluster-controller/internal/metricsource/expression"
	"github.com/clusterpulse/cluster-controller/pkg/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// --- parseAPIVersion ---

func TestParseAPIVersion(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantGroup string
		wantVer   string
	}{
		{"core v1", "v1", "", "v1"},
		{"apps/v1", "apps/v1", "apps", "v1"},
		{"custom", "custom.io/v1beta1", "custom.io", "v1beta1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group, ver := parseAPIVersion(tt.input)
			if group != tt.wantGroup || ver != tt.wantVer {
				t.Errorf("parseAPIVersion(%q) = (%q, %q), want (%q, %q)",
					tt.input, group, ver, tt.wantGroup, tt.wantVer)
			}
		})
	}
}

// --- parseJSONPath ---

func TestParseJSONPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want []string
	}{
		{"simple", ".metadata.name", []string{"metadata", "name"}},
		{"no leading dot", "metadata.name", []string{"metadata", "name"}},
		{"array index", ".spec.containers[0].name", []string{"spec", "containers", "[0]", "name"}},
		{"multiple arrays", ".a[0].b[1]", []string{"a", "[0]", "b", "[1]"}},
		{"empty", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseJSONPath(tt.path)
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d: %v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("segment[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// --- wildcardToRegex ---

func TestWildcardToRegex(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		match   string
		want    bool
	}{
		{"star", "prod-*", "prod-east", true},
		{"star no match", "prod-*", "dev-east", false},
		{"question mark", "pod-?", "pod-1", true},
		{"question mark no match", "pod-?", "pod-12", false},
		{"no wildcard", "exact", "exact", true},
		{"no wildcard mismatch", "exact", "other", false},
		{"special chars escaped", "test.io", "test.io", true},
		{"special chars dot not wildcard", "test.io", "testXio", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re, err := wildcardToRegex(tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			got := re.MatchString(tt.match)
			if got != tt.want {
				t.Errorf("wildcardToRegex(%q).Match(%q) = %v, want %v",
					tt.pattern, tt.match, got, tt.want)
			}
		})
	}
}

// --- pluralize ---

func TestPluralize(t *testing.T) {
	tests := []struct {
		singular string
		want     string
	}{
		{"pod", "pods"},
		{"deployment", "deployments"},
		{"ingress", "ingresses"},
		{"policy", "policies"},
		{"endpoints", "endpoints"},
		{"storageclass", "storageclasses"},
		{"service", "services"},
		{"configmap", "configmaps"},
		{"networkpolicy", "networkpolicies"},
		{"persistentvolumeclaim", "persistentvolumeclaims"},
	}
	for _, tt := range tests {
		t.Run(tt.singular, func(t *testing.T) {
			got := pluralize(tt.singular)
			if got != tt.want {
				t.Errorf("pluralize(%q) = %q, want %q", tt.singular, got, tt.want)
			}
		})
	}
}

// --- labelSelectorToString ---

func TestLabelSelectorToString_Nil(t *testing.T) {
	if got := labelSelectorToString(nil); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestLabelSelectorToString_MatchLabels(t *testing.T) {
	sel := &metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "web"},
	}
	got := labelSelectorToString(sel)
	if got != "app=web" {
		t.Errorf("got %q, want %q", got, "app=web")
	}
}

func TestLabelSelectorToString_MatchExpressions(t *testing.T) {
	tests := []struct {
		name string
		expr metav1.LabelSelectorRequirement
		want string
	}{
		{
			"In",
			metav1.LabelSelectorRequirement{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod", "staging"}},
			"env in (prod,staging)",
		},
		{
			"NotIn",
			metav1.LabelSelectorRequirement{Key: "env", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"dev"}},
			"env notin (dev)",
		},
		{
			"Exists",
			metav1.LabelSelectorRequirement{Key: "app", Operator: metav1.LabelSelectorOpExists},
			"app",
		},
		{
			"DoesNotExist",
			metav1.LabelSelectorRequirement{Key: "debug", Operator: metav1.LabelSelectorOpDoesNotExist},
			"!debug",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sel := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{tt.expr}}
			got := labelSelectorToString(sel)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// --- validate ---

func TestValidate_ValidSpec(t *testing.T) {
	c := NewCompiler()
	ms := &v1alpha1.MetricSource{
		Spec: v1alpha1.MetricSourceSpec{
			Source: v1alpha1.MetricSourceTarget{APIVersion: "v1", Kind: "Pod"},
			Fields: []v1alpha1.FieldExtraction{
				{Name: "name", Path: ".metadata.name"},
			},
		},
	}
	if err := c.validate(ms); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_MissingAPIVersion(t *testing.T) {
	c := NewCompiler()
	ms := &v1alpha1.MetricSource{
		Spec: v1alpha1.MetricSourceSpec{
			Source: v1alpha1.MetricSourceTarget{Kind: "Pod"},
			Fields: []v1alpha1.FieldExtraction{{Name: "n", Path: ".p"}},
		},
	}
	if err := c.validate(ms); err == nil {
		t.Error("expected error for missing apiVersion")
	}
}

func TestValidate_MissingKind(t *testing.T) {
	c := NewCompiler()
	ms := &v1alpha1.MetricSource{
		Spec: v1alpha1.MetricSourceSpec{
			Source: v1alpha1.MetricSourceTarget{APIVersion: "v1"},
			Fields: []v1alpha1.FieldExtraction{{Name: "n", Path: ".p"}},
		},
	}
	if err := c.validate(ms); err == nil {
		t.Error("expected error for missing kind")
	}
}

func TestValidate_NoFields(t *testing.T) {
	c := NewCompiler()
	ms := &v1alpha1.MetricSource{
		Spec: v1alpha1.MetricSourceSpec{
			Source: v1alpha1.MetricSourceTarget{APIVersion: "v1", Kind: "Pod"},
		},
	}
	if err := c.validate(ms); err == nil {
		t.Error("expected error for no fields")
	}
}

func TestValidate_EmptyFieldName(t *testing.T) {
	c := NewCompiler()
	ms := &v1alpha1.MetricSource{
		Spec: v1alpha1.MetricSourceSpec{
			Source: v1alpha1.MetricSourceTarget{APIVersion: "v1", Kind: "Pod"},
			Fields: []v1alpha1.FieldExtraction{{Name: "", Path: ".p"}},
		},
	}
	if err := c.validate(ms); err == nil {
		t.Error("expected error for empty field name")
	}
}

func TestValidate_EmptyFieldPath(t *testing.T) {
	c := NewCompiler()
	ms := &v1alpha1.MetricSource{
		Spec: v1alpha1.MetricSourceSpec{
			Source: v1alpha1.MetricSourceTarget{APIVersion: "v1", Kind: "Pod"},
			Fields: []v1alpha1.FieldExtraction{{Name: "n", Path: ""}},
		},
	}
	if err := c.validate(ms); err == nil {
		t.Error("expected error for empty field path")
	}
}

func TestValidate_DuplicateFieldName(t *testing.T) {
	c := NewCompiler()
	ms := &v1alpha1.MetricSource{
		Spec: v1alpha1.MetricSourceSpec{
			Source: v1alpha1.MetricSourceTarget{APIVersion: "v1", Kind: "Pod"},
			Fields: []v1alpha1.FieldExtraction{
				{Name: "dup", Path: ".a"},
				{Name: "dup", Path: ".b"},
			},
		},
	}
	if err := c.validate(ms); err == nil {
		t.Error("expected error for duplicate field name")
	}
}

func TestValidate_ComputedConflictsWithExtracted(t *testing.T) {
	c := NewCompiler()
	ms := &v1alpha1.MetricSource{
		Spec: v1alpha1.MetricSourceSpec{
			Source: v1alpha1.MetricSourceTarget{APIVersion: "v1", Kind: "Pod"},
			Fields: []v1alpha1.FieldExtraction{
				{Name: "cpu", Path: ".spec.cpu"},
			},
			Computed: []v1alpha1.ComputedField{
				{Name: "cpu", Expression: "1 + 1"},
			},
		},
	}
	if err := c.validate(ms); err == nil {
		t.Error("expected error for computed field conflicting with extracted")
	}
}

// --- compileCollectionConfig ---

func TestCompileCollectionConfig_Defaults(t *testing.T) {
	c := NewCompiler()
	cfg := c.compileCollectionConfig(&v1alpha1.CollectionConfig{})
	if cfg.IntervalSeconds != 60 {
		t.Errorf("IntervalSeconds = %d, want 60", cfg.IntervalSeconds)
	}
	if cfg.TimeoutSeconds != 30 {
		t.Errorf("TimeoutSeconds = %d, want 30", cfg.TimeoutSeconds)
	}
	if cfg.MaxResources != 5000 {
		t.Errorf("MaxResources = %d, want 5000", cfg.MaxResources)
	}
	if cfg.BatchSize != 500 {
		t.Errorf("BatchSize = %d, want 500", cfg.BatchSize)
	}
	// RetryAttempts uses >= 0 check, so zero-value int32 (0) is a valid override.
	// Default only applies when no CollectionConfig is provided at a higher level.
	if cfg.RetryAttempts != 0 {
		t.Errorf("RetryAttempts = %d, want 0 (zero-value passes >= 0 check)", cfg.RetryAttempts)
	}
	if cfg.Parallelism != 3 {
		t.Errorf("Parallelism = %d, want 3", cfg.Parallelism)
	}
}

func TestCompileCollectionConfig_CustomValues(t *testing.T) {
	c := NewCompiler()
	cfg := c.compileCollectionConfig(&v1alpha1.CollectionConfig{
		IntervalSeconds: 120,
		TimeoutSeconds:  60,
		MaxResources:    10000,
		BatchSize:       1000,
		RetryAttempts:   5,
		Parallelism:     10,
	})
	if cfg.IntervalSeconds != 120 {
		t.Errorf("IntervalSeconds = %d, want 120", cfg.IntervalSeconds)
	}
	if cfg.TimeoutSeconds != 60 {
		t.Errorf("TimeoutSeconds = %d, want 60", cfg.TimeoutSeconds)
	}
	if cfg.MaxResources != 10000 {
		t.Errorf("MaxResources = %d, want 10000", cfg.MaxResources)
	}
}

func TestCompileCollectionConfig_RetryAttemptsZero(t *testing.T) {
	c := NewCompiler()
	// RetryAttempts >= 0 is valid, so 0 should override the default
	cfg := c.compileCollectionConfig(&v1alpha1.CollectionConfig{RetryAttempts: 0})
	if cfg.RetryAttempts != 0 {
		t.Errorf("RetryAttempts = %d, want 0", cfg.RetryAttempts)
	}
}

// --- detectCircularDependencies ---

func TestDetectCircularDeps_NoCycle(t *testing.T) {
	c := NewCompiler()
	compiled := []types.CompiledComputation{
		{Name: "a", Compiled: &expression.CompiledExpression{References: []string{"x"}}},
		{Name: "b", Compiled: &expression.CompiledExpression{References: []string{"a"}}},
	}
	if err := c.detectCircularDependencies(compiled); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDetectCircularDeps_Cycle(t *testing.T) {
	c := NewCompiler()
	compiled := []types.CompiledComputation{
		{Name: "a", Compiled: &expression.CompiledExpression{References: []string{"b"}}},
		{Name: "b", Compiled: &expression.CompiledExpression{References: []string{"a"}}},
	}
	if err := c.detectCircularDependencies(compiled); err == nil {
		t.Error("expected error for circular dependency")
	}
}

// --- compileFields ---

func TestCompileFields_DefaultType(t *testing.T) {
	c := NewCompiler()
	fields, index, err := c.compileFields([]v1alpha1.FieldExtraction{
		{Name: "f1", Path: ".metadata.name"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fields[0].Type != types.FieldTypeString {
		t.Errorf("default type = %q, want %q", fields[0].Type, types.FieldTypeString)
	}
	if index["f1"] != 0 {
		t.Errorf("index[f1] = %d, want 0", index["f1"])
	}
}

// --- compileAggregations ---

func TestCompileAggregations(t *testing.T) {
	c := NewCompiler()
	p := 50
	aggs := c.compileAggregations([]v1alpha1.Aggregation{
		{Name: "count", Function: "count"},
		{
			Name:       "p50",
			Field:      "cpu",
			Function:   "percentile",
			Percentile: &p,
			Filter:     &v1alpha1.AggregationFilter{Field: "status", Operator: "equals", Value: "running"},
		},
	})
	if len(aggs) != 2 {
		t.Fatalf("len = %d, want 2", len(aggs))
	}
	if aggs[1].Percentile != 50 {
		t.Errorf("percentile = %d, want 50", aggs[1].Percentile)
	}
	if aggs[1].Filter == nil {
		t.Fatal("expected non-nil filter")
	}
	if aggs[1].Filter.Field != "status" {
		t.Errorf("filter field = %q, want %q", aggs[1].Filter.Field, "status")
	}
}
