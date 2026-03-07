package api

import (
	"encoding/json"
	"testing"
)

func TestGetFieldValue_ValuesDict(t *testing.T) {
	r := map[string]any{"values": map[string]any{"cpu": 4.0}}
	if v := getFieldValue(r, "cpu"); v != 4.0 {
		t.Errorf("got %v, want 4.0", v)
	}
}

func TestGetFieldValue_RootLevel(t *testing.T) {
	r := map[string]any{"status": "running"}
	if v := getFieldValue(r, "status"); v != "running" {
		t.Errorf("got %v, want running", v)
	}
}

func TestGetFieldValue_UnderscorePrefix(t *testing.T) {
	tests := []struct {
		field string
		key   string
	}{
		{"namespace", "_namespace"},
		{"name", "_name"},
		{"id", "_id"},
		{"labels", "_labels"},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			r := map[string]any{tt.key: "val"}
			if v := getFieldValue(r, tt.field); v != "val" {
				t.Errorf("got %v, want val", v)
			}
		})
	}
}

func TestGetFieldValue_DotNotation(t *testing.T) {
	r := map[string]any{"spec": map[string]any{"replicas": 3}}
	if v := getFieldValue(r, "spec.replicas"); v != 3 {
		t.Errorf("got %v, want 3", v)
	}
}

func TestGetFieldValue_Missing(t *testing.T) {
	r := map[string]any{}
	if v := getFieldValue(r, "nonexistent"); v != nil {
		t.Errorf("got %v, want nil", v)
	}
}

func TestMatchesFilter_Nil(t *testing.T) {
	if !matchesFilter(map[string]any{}, nil) {
		t.Error("nil filter should return true")
	}
}

func TestMatchesFilter_Operators(t *testing.T) {
	tests := []struct {
		name     string
		resource map[string]any
		filter   map[string]any
		want     bool
	}{
		{
			"equals_match",
			map[string]any{"status": "running"},
			map[string]any{"field": "status", "operator": "equals", "value": "running"},
			true,
		},
		{
			"equals_no_match",
			map[string]any{"status": "failed"},
			map[string]any{"field": "status", "operator": "equals", "value": "running"},
			false,
		},
		{
			"notEquals",
			map[string]any{"status": "failed"},
			map[string]any{"field": "status", "operator": "notEquals", "value": "running"},
			true,
		},
		{
			"greaterThan",
			map[string]any{"values": map[string]any{"cpu": 10.0}},
			map[string]any{"field": "cpu", "operator": "greaterThan", "value": 5.0},
			true,
		},
		{
			"lessThan",
			map[string]any{"values": map[string]any{"cpu": 2.0}},
			map[string]any{"field": "cpu", "operator": "lessThan", "value": 5.0},
			true,
		},
		{
			"contains",
			map[string]any{"message": "hello world"},
			map[string]any{"field": "message", "operator": "contains", "value": "world"},
			true,
		},
		{
			"contains_nil_field",
			map[string]any{},
			map[string]any{"field": "message", "operator": "contains", "value": "x"},
			false,
		},
		{
			"in_match",
			map[string]any{"status": "running"},
			map[string]any{"field": "status", "operator": "in", "value": []any{"running", "pending"}},
			true,
		},
		{
			"in_no_match",
			map[string]any{"status": "failed"},
			map[string]any{"field": "status", "operator": "in", "value": []any{"running", "pending"}},
			false,
		},
		{
			"unknown_operator",
			map[string]any{"x": 1},
			map[string]any{"field": "x", "operator": "unknownOp", "value": 1},
			true,
		},
		{
			"default_equals",
			map[string]any{"status": "ok"},
			map[string]any{"field": "status", "value": "ok"},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesFilter(tt.resource, tt.filter); got != tt.want {
				t.Errorf("matchesFilter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestComputeSingle_Count(t *testing.T) {
	resources := []map[string]any{{"a": 1}, {"a": 2}, {"a": 3}}
	v, err := computeSingle(resources, "count", "", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if v != 3 {
		t.Errorf("count = %v, want 3", v)
	}
}

func TestComputeSingle_Sum(t *testing.T) {
	resources := []map[string]any{
		{"values": map[string]any{"cpu": 1.0}},
		{"values": map[string]any{"cpu": 2.0}},
		{"values": map[string]any{"cpu": 3.0}},
	}
	v, err := computeSingle(resources, "sum", "cpu", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if v != 6.0 {
		t.Errorf("sum = %v, want 6.0", v)
	}
}

func TestComputeSingle_Avg(t *testing.T) {
	resources := []map[string]any{
		{"values": map[string]any{"x": 10.0}},
		{"values": map[string]any{"x": 20.0}},
	}
	v, err := computeSingle(resources, "avg", "x", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if v != 15.0 {
		t.Errorf("avg = %v, want 15.0", v)
	}
}

func TestComputeSingle_Min(t *testing.T) {
	resources := []map[string]any{
		{"values": map[string]any{"x": 5.0}},
		{"values": map[string]any{"x": 2.0}},
		{"values": map[string]any{"x": 8.0}},
	}
	v, _ := computeSingle(resources, "min", "x", map[string]any{})
	if v != 2.0 {
		t.Errorf("min = %v, want 2.0", v)
	}
}

func TestComputeSingle_Max(t *testing.T) {
	resources := []map[string]any{
		{"values": map[string]any{"x": 5.0}},
		{"values": map[string]any{"x": 2.0}},
		{"values": map[string]any{"x": 8.0}},
	}
	v, _ := computeSingle(resources, "max", "x", map[string]any{})
	if v != 8.0 {
		t.Errorf("max = %v, want 8.0", v)
	}
}

func TestComputeSingle_Percentile(t *testing.T) {
	resources := make([]map[string]any, 100)
	for i := range resources {
		resources[i] = map[string]any{"values": map[string]any{"x": float64(i + 1)}}
	}
	v, _ := computeSingle(resources, "percentile", "x", map[string]any{"percentile": 50.0})
	f, ok := v.(float64)
	// idx = int(100 * 50 / 100) = 50, values[50] = 51 (1-indexed data)
	if !ok || f != 51.0 {
		t.Errorf("percentile(50) = %v, want 51.0", v)
	}
}

func TestComputeSingle_Distinct(t *testing.T) {
	resources := []map[string]any{
		{"values": map[string]any{"x": 1.0}},
		{"values": map[string]any{"x": 2.0}},
		{"values": map[string]any{"x": 1.0}},
	}
	v, _ := computeSingle(resources, "distinct", "x", map[string]any{})
	if v != 2 {
		t.Errorf("distinct = %v, want 2", v)
	}
}

func TestComputeSingle_EmptySum(t *testing.T) {
	v, _ := computeSingle(nil, "sum", "x", map[string]any{})
	if v != 0 {
		t.Errorf("empty sum = %v, want 0", v)
	}
}

func TestComputeSingle_EmptyAvg(t *testing.T) {
	v, _ := computeSingle(nil, "avg", "x", map[string]any{})
	if v != nil {
		t.Errorf("empty avg = %v, want nil", v)
	}
}

func TestComputeSingle_NoField(t *testing.T) {
	v, _ := computeSingle([]map[string]any{{"a": 1}}, "sum", "", map[string]any{})
	if v != nil {
		t.Errorf("no field = %v, want nil", v)
	}
}

func TestComputeGrouped(t *testing.T) {
	resources := []map[string]any{
		{"values": map[string]any{"x": 10.0}, "_namespace": "ns1"},
		{"values": map[string]any{"x": 20.0}, "_namespace": "ns1"},
		{"values": map[string]any{"x": 5.0}, "_namespace": "ns2"},
	}
	v, err := computeGrouped(resources, "sum", "x", "_namespace")
	if err != nil {
		t.Fatal(err)
	}
	if v["ns1"] != 30.0 {
		t.Errorf("ns1 sum = %v, want 30.0", v["ns1"])
	}
	if v["ns2"] != 5.0 {
		t.Errorf("ns2 sum = %v, want 5.0", v["ns2"])
	}
}

func TestComputeGrouped_UnknownKey(t *testing.T) {
	resources := []map[string]any{{"values": map[string]any{"x": 1.0}}}
	v, _ := computeGrouped(resources, "count", "", "missing")
	if _, ok := v["unknown"]; !ok {
		t.Error("missing group key should map to 'unknown'")
	}
}

func TestRecomputeAggregations(t *testing.T) {
	resources := []map[string]any{
		{"values": map[string]any{"cpu": 10.0}},
		{"values": map[string]any{"cpu": 20.0}},
	}
	specs := []map[string]any{
		{"name": "total_cpu", "function": "sum", "field": "cpu"},
		{"name": "count", "function": "count"},
	}
	result := recomputeAggregations(resources, specs)
	if result["total_cpu"] != 30.0 {
		t.Errorf("total_cpu = %v, want 30.0", result["total_cpu"])
	}
	if result["count"] != 2 {
		t.Errorf("count = %v, want 2", result["count"])
	}
}

func TestRecomputeAggregations_WithFilter(t *testing.T) {
	resources := []map[string]any{
		{"values": map[string]any{"cpu": 10.0}, "status": "running"},
		{"values": map[string]any{"cpu": 20.0}, "status": "failed"},
	}
	specs := []map[string]any{
		{
			"name":     "running_cpu",
			"function": "sum",
			"field":    "cpu",
			"filter":   map[string]any{"field": "status", "operator": "equals", "value": "running"},
		},
	}
	result := recomputeAggregations(resources, specs)
	if result["running_cpu"] != 10.0 {
		t.Errorf("running_cpu = %v, want 10.0", result["running_cpu"])
	}
}

func TestToFloat(t *testing.T) {
	tests := []struct {
		name string
		v    any
		want float64
	}{
		{"float64", float64(3.14), 3.14},
		{"float32", float32(2.5), 2.5},
		{"int", int(42), 42},
		{"int64", int64(100), 100},
		{"int32", int32(50), 50},
		{"json.Number", json.Number("7.5"), 7.5},
		{"string", "3.0", 3.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toFloat(tt.v)
			if got != tt.want {
				t.Errorf("toFloat(%v) = %v, want %v", tt.v, got, tt.want)
			}
		})
	}
}
