package aggregator

import (
	"testing"

	"github.com/clusterpulse/cluster-controller/pkg/types"
)

func resource(vals map[string]any) *types.CustomCollectedResource {
	return &types.CustomCollectedResource{Values: vals}
}

func TestFilter_NilFilter(t *testing.T) {
	f := NewFilterEvaluator()
	if !f.Matches(resource(map[string]any{"x": 1}), nil) {
		t.Error("nil filter should match everything")
	}
}

func TestFilter_MissingField(t *testing.T) {
	f := NewFilterEvaluator()
	filter := &types.CompiledAggFilter{Field: "status", Operator: "equals", Value: "running"}
	if f.Matches(resource(map[string]any{"other": "x"}), filter) {
		t.Error("missing field should not match")
	}
}

func TestFilter_NilFieldValue(t *testing.T) {
	f := NewFilterEvaluator()
	filter := &types.CompiledAggFilter{Field: "status", Operator: "equals", Value: "running"}
	if f.Matches(resource(map[string]any{"status": nil}), filter) {
		t.Error("nil field value should not match")
	}
}

func TestFilter_Equals(t *testing.T) {
	f := NewFilterEvaluator()
	tests := []struct {
		name  string
		val   any
		match string
		want  bool
	}{
		{"string match", "running", "running", true},
		{"string mismatch", "stopped", "running", false},
		{"float match", 42.0, "42", true},
		{"float mismatch", 42.0, "43", false},
		{"int64 match", int64(10), "10", true},
		{"bool match", true, "true", true},
		{"bool mismatch", true, "false", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := &types.CompiledAggFilter{Field: "f", Operator: "equals", Value: tt.match}
			got := f.Matches(resource(map[string]any{"f": tt.val}), filter)
			if got != tt.want {
				t.Errorf("equals(%v, %q) = %v, want %v", tt.val, tt.match, got, tt.want)
			}
		})
	}
}

func TestFilter_NotEquals(t *testing.T) {
	f := NewFilterEvaluator()
	filter := &types.CompiledAggFilter{Field: "status", Operator: "notEquals", Value: "running"}
	if !f.Matches(resource(map[string]any{"status": "stopped"}), filter) {
		t.Error("notEquals should match different values")
	}
	if f.Matches(resource(map[string]any{"status": "running"}), filter) {
		t.Error("notEquals should not match same value")
	}
}

func TestFilter_Contains(t *testing.T) {
	f := NewFilterEvaluator()
	filter := &types.CompiledAggFilter{Field: "name", Operator: "contains", Value: "prod"}
	if !f.Matches(resource(map[string]any{"name": "my-prod-app"}), filter) {
		t.Error("contains should match substring")
	}
	if f.Matches(resource(map[string]any{"name": "dev-app"}), filter) {
		t.Error("contains should not match missing substring")
	}
}

func TestFilter_StartsWith(t *testing.T) {
	f := NewFilterEvaluator()
	filter := &types.CompiledAggFilter{Field: "name", Operator: "startsWith", Value: "prod"}
	if !f.Matches(resource(map[string]any{"name": "prod-app"}), filter) {
		t.Error("startsWith should match prefix")
	}
	if f.Matches(resource(map[string]any{"name": "dev-prod"}), filter) {
		t.Error("startsWith should not match non-prefix")
	}
}

func TestFilter_EndsWith(t *testing.T) {
	f := NewFilterEvaluator()
	filter := &types.CompiledAggFilter{Field: "name", Operator: "endsWith", Value: "-app"}
	if !f.Matches(resource(map[string]any{"name": "prod-app"}), filter) {
		t.Error("endsWith should match suffix")
	}
	if f.Matches(resource(map[string]any{"name": "prod-svc"}), filter) {
		t.Error("endsWith should not match non-suffix")
	}
}

func TestFilter_GreaterThan(t *testing.T) {
	f := NewFilterEvaluator()
	filter := &types.CompiledAggFilter{Field: "cpu", Operator: "greaterThan", Value: "5"}
	if !f.Matches(resource(map[string]any{"cpu": 10.0}), filter) {
		t.Error("10 > 5 should be true")
	}
	if f.Matches(resource(map[string]any{"cpu": 3.0}), filter) {
		t.Error("3 > 5 should be false")
	}
}

func TestFilter_LessThan(t *testing.T) {
	f := NewFilterEvaluator()
	filter := &types.CompiledAggFilter{Field: "cpu", Operator: "lessThan", Value: "5"}
	if !f.Matches(resource(map[string]any{"cpu": 3.0}), filter) {
		t.Error("3 < 5 should be true")
	}
	if f.Matches(resource(map[string]any{"cpu": 10.0}), filter) {
		t.Error("10 < 5 should be false")
	}
}

func TestFilter_In(t *testing.T) {
	f := NewFilterEvaluator()
	filter := &types.CompiledAggFilter{Field: "status", Operator: "in", Value: "[running, pending]"}
	if !f.Matches(resource(map[string]any{"status": "running"}), filter) {
		t.Error("running should be in list")
	}
	if !f.Matches(resource(map[string]any{"status": "pending"}), filter) {
		t.Error("pending should be in list")
	}
	if f.Matches(resource(map[string]any{"status": "stopped"}), filter) {
		t.Error("stopped should not be in list")
	}
}

func TestFilter_In_SpaceTrimming(t *testing.T) {
	f := NewFilterEvaluator()
	filter := &types.CompiledAggFilter{Field: "s", Operator: "in", Value: "[ a , b , c ]"}
	if !f.Matches(resource(map[string]any{"s": "b"}), filter) {
		t.Error("should match after trimming spaces")
	}
}

func TestFilter_Matches(t *testing.T) {
	f := NewFilterEvaluator()
	filter := &types.CompiledAggFilter{Field: "name", Operator: "matches", Value: "^prod-.*"}
	if !f.Matches(resource(map[string]any{"name": "prod-app"}), filter) {
		t.Error("should match regex")
	}
	if f.Matches(resource(map[string]any{"name": "dev-app"}), filter) {
		t.Error("should not match regex")
	}
}

func TestFilter_Matches_InvalidRegex(t *testing.T) {
	f := NewFilterEvaluator()
	filter := &types.CompiledAggFilter{Field: "name", Operator: "matches", Value: "[invalid"}
	if f.Matches(resource(map[string]any{"name": "anything"}), filter) {
		t.Error("invalid regex should return false")
	}
}

func TestFilter_Matches_RegexCaching(t *testing.T) {
	f := NewFilterEvaluator()
	filter := &types.CompiledAggFilter{Field: "name", Operator: "matches", Value: "^test-.*"}
	f.Matches(resource(map[string]any{"name": "test-1"}), filter)
	// Second call should use cache
	if _, ok := f.compiledPatterns["^test-.*"]; !ok {
		t.Error("regex should be cached after first use")
	}
	// Verify cached regex still works
	if !f.Matches(resource(map[string]any{"name": "test-2"}), filter) {
		t.Error("cached regex should still match")
	}
}

func TestFilter_UnknownOperator(t *testing.T) {
	f := NewFilterEvaluator()
	filter := &types.CompiledAggFilter{Field: "x", Operator: "unknownOp", Value: "y"}
	if f.Matches(resource(map[string]any{"x": "y"}), filter) {
		t.Error("unknown operator should return false")
	}
}
