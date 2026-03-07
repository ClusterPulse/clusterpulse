package aggregator

import (
	"math"
	"testing"

	"github.com/clusterpulse/cluster-controller/pkg/types"
)

func makeResources(field string, values ...any) []types.CustomCollectedResource {
	resources := make([]types.CustomCollectedResource, len(values))
	for i, v := range values {
		resources[i] = types.CustomCollectedResource{
			Values: map[string]any{field: v},
		}
	}
	return resources
}

func TestAgg_Count(t *testing.T) {
	a := NewAggregator()
	input := &AggregationInput{
		Resources: makeResources("x", 1.0, 2.0, 3.0),
		Aggregations: []types.CompiledAggregation{
			{Name: "total", Function: types.AggFunctionCount},
		},
	}
	results := a.Compute(input)
	if results.Values["total"] != 3.0 {
		t.Errorf("count = %v, want 3", results.Values["total"])
	}
}

func TestAgg_Count_Empty(t *testing.T) {
	a := NewAggregator()
	input := &AggregationInput{
		Resources: nil,
		Aggregations: []types.CompiledAggregation{
			{Name: "total", Function: types.AggFunctionCount},
		},
	}
	results := a.Compute(input)
	if results.Values["total"] != 0.0 {
		t.Errorf("count = %v, want 0", results.Values["total"])
	}
}

func TestAgg_Sum(t *testing.T) {
	a := NewAggregator()
	input := &AggregationInput{
		Resources: makeResources("cpu", 1.0, 2.5, 3.5),
		Aggregations: []types.CompiledAggregation{
			{Name: "total_cpu", Field: "cpu", Function: types.AggFunctionSum},
		},
	}
	results := a.Compute(input)
	if results.Values["total_cpu"] != 7.0 {
		t.Errorf("sum = %v, want 7", results.Values["total_cpu"])
	}
}

func TestAgg_Sum_MixedTypes(t *testing.T) {
	a := NewAggregator()
	resources := []types.CustomCollectedResource{
		{Values: map[string]any{"val": 1.0}},
		{Values: map[string]any{"val": int64(2)}},
		{Values: map[string]any{"val": int(3)}},
	}
	input := &AggregationInput{
		Resources: resources,
		Aggregations: []types.CompiledAggregation{
			{Name: "s", Field: "val", Function: types.AggFunctionSum},
		},
	}
	results := a.Compute(input)
	if results.Values["s"] != 6.0 {
		t.Errorf("sum mixed = %v, want 6", results.Values["s"])
	}
}

func TestAgg_Sum_NilSkipped(t *testing.T) {
	a := NewAggregator()
	resources := []types.CustomCollectedResource{
		{Values: map[string]any{"val": 5.0}},
		{Values: map[string]any{"val": nil}},
		{Values: map[string]any{"val": 3.0}},
	}
	input := &AggregationInput{
		Resources: resources,
		Aggregations: []types.CompiledAggregation{
			{Name: "s", Field: "val", Function: types.AggFunctionSum},
		},
	}
	results := a.Compute(input)
	if results.Values["s"] != 8.0 {
		t.Errorf("sum = %v, want 8 (nil skipped)", results.Values["s"])
	}
}

func TestAgg_Avg(t *testing.T) {
	a := NewAggregator()
	input := &AggregationInput{
		Resources: makeResources("cpu", 2.0, 4.0, 6.0),
		Aggregations: []types.CompiledAggregation{
			{Name: "avg_cpu", Field: "cpu", Function: types.AggFunctionAvg},
		},
	}
	results := a.Compute(input)
	if results.Values["avg_cpu"] != 4.0 {
		t.Errorf("avg = %v, want 4", results.Values["avg_cpu"])
	}
}

func TestAgg_Avg_Empty(t *testing.T) {
	a := NewAggregator()
	input := &AggregationInput{
		Resources: nil,
		Aggregations: []types.CompiledAggregation{
			{Name: "avg", Field: "cpu", Function: types.AggFunctionAvg},
		},
	}
	results := a.Compute(input)
	if results.Values["avg"] != nil {
		t.Errorf("avg empty = %v, want nil", results.Values["avg"])
	}
}

func TestAgg_Min(t *testing.T) {
	a := NewAggregator()
	input := &AggregationInput{
		Resources: makeResources("cpu", 5.0, 2.0, 8.0),
		Aggregations: []types.CompiledAggregation{
			{Name: "min_cpu", Field: "cpu", Function: types.AggFunctionMin},
		},
	}
	results := a.Compute(input)
	if results.Values["min_cpu"] != 2.0 {
		t.Errorf("min = %v, want 2", results.Values["min_cpu"])
	}
}

func TestAgg_Min_Empty(t *testing.T) {
	a := NewAggregator()
	input := &AggregationInput{
		Resources: nil,
		Aggregations: []types.CompiledAggregation{
			{Name: "min", Field: "cpu", Function: types.AggFunctionMin},
		},
	}
	results := a.Compute(input)
	if results.Values["min"] != nil {
		t.Errorf("min empty = %v, want nil", results.Values["min"])
	}
}

func TestAgg_Max(t *testing.T) {
	a := NewAggregator()
	input := &AggregationInput{
		Resources: makeResources("cpu", 5.0, 2.0, 8.0),
		Aggregations: []types.CompiledAggregation{
			{Name: "max_cpu", Field: "cpu", Function: types.AggFunctionMax},
		},
	}
	results := a.Compute(input)
	if results.Values["max_cpu"] != 8.0 {
		t.Errorf("max = %v, want 8", results.Values["max_cpu"])
	}
}

func TestAgg_Max_Empty(t *testing.T) {
	a := NewAggregator()
	input := &AggregationInput{
		Resources: nil,
		Aggregations: []types.CompiledAggregation{
			{Name: "max", Field: "cpu", Function: types.AggFunctionMax},
		},
	}
	results := a.Compute(input)
	if results.Values["max"] != nil {
		t.Errorf("max empty = %v, want nil", results.Values["max"])
	}
}

func TestAgg_Percentile_P50(t *testing.T) {
	a := NewAggregator()
	input := &AggregationInput{
		Resources: makeResources("val", 10.0, 20.0, 30.0, 40.0, 50.0),
		Aggregations: []types.CompiledAggregation{
			{Name: "p50", Field: "val", Function: types.AggFunctionPercentile, Percentile: 50},
		},
	}
	results := a.Compute(input)
	if results.Values["p50"] != 30.0 {
		t.Errorf("p50 = %v, want 30", results.Values["p50"])
	}
}

func TestAgg_Percentile_P0(t *testing.T) {
	a := NewAggregator()
	input := &AggregationInput{
		Resources: makeResources("val", 10.0, 20.0, 30.0),
		Aggregations: []types.CompiledAggregation{
			{Name: "p0", Field: "val", Function: types.AggFunctionPercentile, Percentile: 0},
		},
	}
	results := a.Compute(input)
	if results.Values["p0"] != 10.0 {
		t.Errorf("p0 = %v, want 10", results.Values["p0"])
	}
}

func TestAgg_Percentile_P100(t *testing.T) {
	a := NewAggregator()
	input := &AggregationInput{
		Resources: makeResources("val", 10.0, 20.0, 30.0),
		Aggregations: []types.CompiledAggregation{
			{Name: "p100", Field: "val", Function: types.AggFunctionPercentile, Percentile: 100},
		},
	}
	results := a.Compute(input)
	if results.Values["p100"] != 30.0 {
		t.Errorf("p100 = %v, want 30", results.Values["p100"])
	}
}

func TestAgg_Percentile_Empty(t *testing.T) {
	a := NewAggregator()
	input := &AggregationInput{
		Resources: nil,
		Aggregations: []types.CompiledAggregation{
			{Name: "p50", Field: "val", Function: types.AggFunctionPercentile, Percentile: 50},
		},
	}
	results := a.Compute(input)
	if results.Values["p50"] != nil {
		t.Errorf("percentile empty = %v, want nil", results.Values["p50"])
	}
}

func TestAgg_Percentile_SingleValue(t *testing.T) {
	a := NewAggregator()
	input := &AggregationInput{
		Resources: makeResources("val", 42.0),
		Aggregations: []types.CompiledAggregation{
			{Name: "p50", Field: "val", Function: types.AggFunctionPercentile, Percentile: 50},
		},
	}
	results := a.Compute(input)
	if results.Values["p50"] != 42.0 {
		t.Errorf("p50 single = %v, want 42", results.Values["p50"])
	}
}

func TestAgg_Distinct(t *testing.T) {
	a := NewAggregator()
	resources := []types.CustomCollectedResource{
		{Values: map[string]any{"status": "running"}},
		{Values: map[string]any{"status": "running"}},
		{Values: map[string]any{"status": "pending"}},
		{Values: map[string]any{"status": "stopped"}},
	}
	input := &AggregationInput{
		Resources: resources,
		Aggregations: []types.CompiledAggregation{
			{Name: "unique", Field: "status", Function: types.AggFunctionDistinct},
		},
	}
	results := a.Compute(input)
	if results.Values["unique"] != 3.0 {
		t.Errorf("distinct = %v, want 3", results.Values["unique"])
	}
}

func TestAgg_Distinct_NilSkipped(t *testing.T) {
	a := NewAggregator()
	resources := []types.CustomCollectedResource{
		{Values: map[string]any{"s": "a"}},
		{Values: map[string]any{"s": nil}},
		{Values: map[string]any{"s": "b"}},
	}
	input := &AggregationInput{
		Resources: resources,
		Aggregations: []types.CompiledAggregation{
			{Name: "d", Field: "s", Function: types.AggFunctionDistinct},
		},
	}
	results := a.Compute(input)
	if results.Values["d"] != 2.0 {
		t.Errorf("distinct = %v, want 2 (nil skipped)", results.Values["d"])
	}
}

func TestAgg_UnknownFunction(t *testing.T) {
	a := NewAggregator()
	input := &AggregationInput{
		Resources: makeResources("x", 1.0),
		Aggregations: []types.CompiledAggregation{
			{Name: "bad", Field: "x", Function: "unknownFunc"},
		},
	}
	results := a.Compute(input)
	if results.Values["bad"] != nil {
		t.Errorf("unknown func = %v, want nil", results.Values["bad"])
	}
}

func TestAgg_Grouped(t *testing.T) {
	a := NewAggregator()
	resources := []types.CustomCollectedResource{
		{Values: map[string]any{"ns": "prod", "cpu": 4.0}},
		{Values: map[string]any{"ns": "prod", "cpu": 6.0}},
		{Values: map[string]any{"ns": "dev", "cpu": 2.0}},
	}
	input := &AggregationInput{
		Resources: resources,
		Aggregations: []types.CompiledAggregation{
			{Name: "cpu_by_ns", Field: "cpu", Function: types.AggFunctionSum, GroupBy: "ns"},
		},
	}
	results := a.Compute(input)
	grouped, ok := results.Values["cpu_by_ns"].(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T", results.Values["cpu_by_ns"])
	}
	if grouped["prod"] != 10.0 {
		t.Errorf("prod sum = %v, want 10", grouped["prod"])
	}
	if grouped["dev"] != 2.0 {
		t.Errorf("dev sum = %v, want 2", grouped["dev"])
	}
}

func TestAgg_Grouped_MissingField(t *testing.T) {
	a := NewAggregator()
	resources := []types.CustomCollectedResource{
		{Values: map[string]any{"cpu": 4.0}},
	}
	input := &AggregationInput{
		Resources: resources,
		Aggregations: []types.CompiledAggregation{
			{Name: "g", Field: "cpu", Function: types.AggFunctionSum, GroupBy: "ns"},
		},
	}
	results := a.Compute(input)
	grouped := results.Values["g"].(map[string]any)
	if _, ok := grouped["_unknown_"]; !ok {
		t.Error("missing group field should use '_unknown_' key")
	}
}

func TestAgg_WithFilter(t *testing.T) {
	a := NewAggregator()
	resources := []types.CustomCollectedResource{
		{Values: map[string]any{"status": "running", "cpu": 4.0}},
		{Values: map[string]any{"status": "stopped", "cpu": 6.0}},
		{Values: map[string]any{"status": "running", "cpu": 2.0}},
	}
	input := &AggregationInput{
		Resources: resources,
		Aggregations: []types.CompiledAggregation{
			{
				Name:     "running_cpu",
				Field:    "cpu",
				Function: types.AggFunctionSum,
				Filter:   &types.CompiledAggFilter{Field: "status", Operator: "equals", Value: "running"},
			},
		},
	}
	results := a.Compute(input)
	if results.Values["running_cpu"] != 6.0 {
		t.Errorf("filtered sum = %v, want 6", results.Values["running_cpu"])
	}
}

func TestAgg_GetNumericValue(t *testing.T) {
	a := NewAggregator()
	tests := []struct {
		name string
		val  any
		want *float64
	}{
		{"float64", 3.14, ptr(3.14)},
		{"int64", int64(42), ptr(42.0)},
		{"int", int(10), ptr(10.0)},
		{"string", "nope", nil},
		{"nil", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &types.CustomCollectedResource{Values: map[string]any{"v": tt.val}}
			got := a.getNumericValue(r, "v")
			if tt.want == nil {
				if got != nil {
					t.Errorf("got %v, want nil", *got)
				}
			} else {
				if got == nil {
					t.Fatalf("got nil, want %v", *tt.want)
				}
				if math.Abs(*got-*tt.want) > 1e-9 {
					t.Errorf("got %v, want %v", *got, *tt.want)
				}
			}
		})
	}
}

func ptr(f float64) *float64 { return &f }
