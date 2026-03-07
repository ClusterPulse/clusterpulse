package extractor

import (
	"testing"

	"github.com/clusterpulse/cluster-controller/pkg/types"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// --- navigatePath ---

func TestNavigatePath_SimpleField(t *testing.T) {
	e := NewExtractor()
	obj := map[string]any{"name": "test"}
	val, found, err := e.navigatePath(obj, []string{"name"})
	if err != nil || !found || val != "test" {
		t.Errorf("got (%v, %v, %v), want (test, true, nil)", val, found, err)
	}
}

func TestNavigatePath_Nested(t *testing.T) {
	e := NewExtractor()
	obj := map[string]any{"metadata": map[string]any{"name": "pod-1"}}
	val, found, err := e.navigatePath(obj, []string{"metadata", "name"})
	if err != nil || !found || val != "pod-1" {
		t.Errorf("got (%v, %v, %v)", val, found, err)
	}
}

func TestNavigatePath_ArrayIndex(t *testing.T) {
	e := NewExtractor()
	obj := map[string]any{"items": []any{"a", "b", "c"}}
	val, found, err := e.navigatePath(obj, []string{"items", "[1]"})
	if err != nil || !found || val != "b" {
		t.Errorf("got (%v, %v, %v)", val, found, err)
	}
}

func TestNavigatePath_ArrayOutOfBounds(t *testing.T) {
	e := NewExtractor()
	obj := map[string]any{"items": []any{"a"}}
	_, found, err := e.navigatePath(obj, []string{"items", "[5]"})
	if err != nil || found {
		t.Errorf("out of bounds: got (found=%v, err=%v), want (false, nil)", found, err)
	}
}

func TestNavigatePath_NegativeIndex(t *testing.T) {
	e := NewExtractor()
	obj := map[string]any{"items": []any{"a"}}
	_, found, err := e.navigatePath(obj, []string{"items", "[-1]"})
	if err != nil || found {
		t.Errorf("negative index: got (found=%v, err=%v), want (false, nil)", found, err)
	}
}

func TestNavigatePath_InvalidIndexString(t *testing.T) {
	e := NewExtractor()
	obj := map[string]any{"items": []any{"a"}}
	_, _, err := e.navigatePath(obj, []string{"items", "[abc]"})
	if err == nil {
		t.Error("expected error for invalid array index")
	}
}

func TestNavigatePath_NonMapSegment(t *testing.T) {
	e := NewExtractor()
	obj := map[string]any{"val": "just a string"}
	_, found, err := e.navigatePath(obj, []string{"val", "nested"})
	if err != nil || found {
		t.Errorf("non-map: got (found=%v, err=%v), want (false, nil)", found, err)
	}
}

func TestNavigatePath_NilIntermediate(t *testing.T) {
	e := NewExtractor()
	_, found, err := e.navigatePath(nil, []string{"any"})
	if err != nil || found {
		t.Errorf("nil obj: got (found=%v, err=%v)", found, err)
	}
}

func TestNavigatePath_MissingKey(t *testing.T) {
	e := NewExtractor()
	obj := map[string]any{"a": 1}
	_, found, err := e.navigatePath(obj, []string{"b"})
	if err != nil || found {
		t.Errorf("missing key: got (found=%v, err=%v)", found, err)
	}
}

// --- convertValue ---

func TestConvertValue_String(t *testing.T) {
	e := NewExtractor()
	val, err := e.convertValue("hello", types.FieldTypeString)
	if err != nil || val != "hello" {
		t.Errorf("got (%v, %v)", val, err)
	}
}

func TestConvertValue_Integer(t *testing.T) {
	e := NewExtractor()
	val, err := e.convertValue(float64(42), types.FieldTypeInteger)
	if err != nil || val != int64(42) {
		t.Errorf("got (%v, %v)", val, err)
	}
}

func TestConvertValue_Float(t *testing.T) {
	e := NewExtractor()
	val, err := e.convertValue(3.14, types.FieldTypeFloat)
	if err != nil || val != 3.14 {
		t.Errorf("got (%v, %v)", val, err)
	}
}

func TestConvertValue_Boolean(t *testing.T) {
	e := NewExtractor()
	val, err := e.convertValue(true, types.FieldTypeBoolean)
	if err != nil || val != true {
		t.Errorf("got (%v, %v)", val, err)
	}
}

func TestConvertValue_Timestamp(t *testing.T) {
	e := NewExtractor()
	val, err := e.convertValue("2024-01-01T00:00:00Z", types.FieldTypeTimestamp)
	if err != nil || val != "2024-01-01T00:00:00Z" {
		t.Errorf("got (%v, %v)", val, err)
	}
}

func TestConvertValue_ArrayLength(t *testing.T) {
	e := NewExtractor()
	val, err := e.convertValue([]any{"a", "b", "c"}, types.FieldTypeArrayLength)
	if err != nil || val != int64(3) {
		t.Errorf("got (%v, %v)", val, err)
	}
}

func TestConvertValue_Nil(t *testing.T) {
	e := NewExtractor()
	val, err := e.convertValue(nil, types.FieldTypeString)
	if err != nil || val != nil {
		t.Errorf("got (%v, %v)", val, err)
	}
}

func TestConvertValue_UnknownType(t *testing.T) {
	e := NewExtractor()
	val, err := e.convertValue(42.0, "unknown_type")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Should fallback to toString
	if val != "42" {
		t.Errorf("got %v, want %q", val, "42")
	}
}

func TestConvertValue_Quantity(t *testing.T) {
	e := NewExtractor()
	val, err := e.convertValue("1Gi", types.FieldTypeQuantity)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if val != int64(1024*1024*1024) {
		t.Errorf("got %v, want %d", val, 1024*1024*1024)
	}
}

func TestConvertValue_Integer_Error(t *testing.T) {
	e := NewExtractor()
	_, err := e.convertValue(struct{}{}, types.FieldTypeInteger)
	if err == nil {
		t.Error("expected error converting struct to integer")
	}
}

func TestConvertValue_Float_Error(t *testing.T) {
	e := NewExtractor()
	_, err := e.convertValue(struct{}{}, types.FieldTypeFloat)
	if err == nil {
		t.Error("expected error converting struct to float")
	}
}

// --- convertType ---

func TestConvertType_Integer(t *testing.T) {
	e := NewExtractor()
	tests := []struct {
		name string
		val  string
		want any
	}{
		{"valid", "42", int64(42)},
		{"invalid", "abc", int64(0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.convertType(tt.val, types.FieldTypeInteger)
			if got != tt.want {
				t.Errorf("convertType(%q, integer) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

func TestConvertType_Float(t *testing.T) {
	e := NewExtractor()
	tests := []struct {
		name string
		val  string
		want any
	}{
		{"valid", "3.14", 3.14},
		{"invalid", "abc", 0.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.convertType(tt.val, types.FieldTypeFloat)
			if got != tt.want {
				t.Errorf("convertType(%q, float) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

func TestConvertType_Boolean(t *testing.T) {
	e := NewExtractor()
	if got := e.convertType("true", types.FieldTypeBoolean); got != true {
		t.Errorf("got %v, want true", got)
	}
	if got := e.convertType("false", types.FieldTypeBoolean); got != false {
		t.Errorf("got %v, want false", got)
	}
}

func TestConvertType_Default(t *testing.T) {
	e := NewExtractor()
	got := e.convertType("hello", types.FieldTypeString)
	if got != "hello" {
		t.Errorf("got %v, want %q", got, "hello")
	}
}

// --- BuildResourceID ---

func TestBuildResourceID_WithNamespace(t *testing.T) {
	e := NewExtractor()
	id := e.BuildResourceID("default", "pod-1")
	if id != "default/pod-1" {
		t.Errorf("got %q, want %q", id, "default/pod-1")
	}
}

func TestBuildResourceID_WithoutNamespace(t *testing.T) {
	e := NewExtractor()
	id := e.BuildResourceID("", "node-1")
	if id != "node-1" {
		t.Errorf("got %q, want %q", id, "node-1")
	}
}

// --- ExtractFields integration ---

func TestExtractFields_Integration(t *testing.T) {
	e := NewExtractor()
	obj := &unstructured.Unstructured{
		Object: map[string]any{
			"metadata": map[string]any{
				"name":      "test-pod",
				"namespace": "default",
			},
			"spec": map[string]any{
				"replicas": float64(3),
			},
		},
	}

	fields := []types.CompiledField{
		{Name: "name", PathSegments: []string{"metadata", "name"}, Type: types.FieldTypeString},
		{Name: "replicas", PathSegments: []string{"spec", "replicas"}, Type: types.FieldTypeInteger},
	}

	result, err := e.ExtractFields(obj, fields)
	if err != nil {
		t.Fatal(err)
	}
	if result["name"] != "test-pod" {
		t.Errorf("name = %v, want %q", result["name"], "test-pod")
	}
	if result["replicas"] != int64(3) {
		t.Errorf("replicas = %v, want 3", result["replicas"])
	}
}

func TestExtractFields_DefaultApplied(t *testing.T) {
	e := NewExtractor()
	obj := &unstructured.Unstructured{
		Object: map[string]any{
			"metadata": map[string]any{"name": "test"},
		},
	}

	defaultVal := "unknown"
	fields := []types.CompiledField{
		{Name: "missing", PathSegments: []string{"spec", "nonexistent"}, Type: types.FieldTypeString, Default: &defaultVal},
	}

	result, err := e.ExtractFields(obj, fields)
	if err != nil {
		t.Fatal(err)
	}
	if result["missing"] != "unknown" {
		t.Errorf("missing = %v, want %q (default)", result["missing"], "unknown")
	}
}

// --- toTimestamp ---

func TestToTimestamp_Valid(t *testing.T) {
	e := NewExtractor()
	val, err := e.toTimestamp("2024-01-15T10:30:00Z")
	if err != nil || val != "2024-01-15T10:30:00Z" {
		t.Errorf("got (%v, %v)", val, err)
	}
}

func TestToTimestamp_Invalid(t *testing.T) {
	e := NewExtractor()
	_, err := e.toTimestamp("not-a-date")
	if err == nil {
		t.Error("expected error for invalid timestamp")
	}
}

func TestToTimestamp_Empty(t *testing.T) {
	e := NewExtractor()
	val, err := e.toTimestamp("")
	if err != nil || val != "" {
		t.Errorf("got (%v, %v), want (\"\", nil)", val, err)
	}
}

// --- toArrayLength ---

func TestToArrayLength_Map(t *testing.T) {
	e := NewExtractor()
	val, err := e.toArrayLength(map[string]any{"a": 1, "b": 2})
	if err != nil || val != 2 {
		t.Errorf("got (%v, %v)", val, err)
	}
}

func TestToArrayLength_Nil(t *testing.T) {
	e := NewExtractor()
	val, err := e.toArrayLength(nil)
	if err != nil || val != 0 {
		t.Errorf("got (%v, %v)", val, err)
	}
}

func TestToArrayLength_NotCollection(t *testing.T) {
	e := NewExtractor()
	_, err := e.toArrayLength("string")
	if err == nil {
		t.Error("expected error for non-collection type")
	}
}
