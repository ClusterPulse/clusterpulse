package expression

import (
	"math"
	"strings"
	"testing"
	"time"
)

func callFn(t *testing.T, name string, args []any) any {
	t.Helper()
	fn, ok := BuiltinFunctions[name]
	if !ok {
		t.Fatalf("unknown function: %s", name)
	}
	result, err := fn.Fn(args)
	if err != nil {
		t.Fatalf("%s() error: %v", name, err)
	}
	return result
}

// --- String functions ---

func TestFnConcat(t *testing.T) {
	result := callFn(t, "concat", []any{"hello", " ", "world"})
	if result != "hello world" {
		t.Errorf("got %v, want %q", result, "hello world")
	}
}

func TestFnConcat_NilArg(t *testing.T) {
	result := callFn(t, "concat", []any{"a", nil, "b"})
	if result != "ab" {
		t.Errorf("got %v, want %q", result, "ab")
	}
}

func TestFnLower(t *testing.T) {
	result := callFn(t, "lower", []any{"HELLO"})
	if result != "hello" {
		t.Errorf("got %v, want %q", result, "hello")
	}
}

func TestFnUpper(t *testing.T) {
	result := callFn(t, "upper", []any{"hello"})
	if result != "HELLO" {
		t.Errorf("got %v, want %q", result, "HELLO")
	}
}

func TestFnLen(t *testing.T) {
	result := callFn(t, "len", []any{"hello"})
	if result != 5.0 {
		t.Errorf("got %v, want 5", result)
	}
}

func TestFnLen_Empty(t *testing.T) {
	result := callFn(t, "len", []any{""})
	if result != 0.0 {
		t.Errorf("got %v, want 0", result)
	}
}

func TestFnLen_Nil(t *testing.T) {
	result := callFn(t, "len", []any{nil})
	if result != 0.0 {
		t.Errorf("got %v, want 0 (nil -> empty string)", result)
	}
}

func TestFnSubstr_TwoArgs(t *testing.T) {
	result := callFn(t, "substr", []any{"hello", 2.0})
	if result != "llo" {
		t.Errorf("got %v, want %q", result, "llo")
	}
}

func TestFnSubstr_ThreeArgs(t *testing.T) {
	result := callFn(t, "substr", []any{"hello", 1.0, 3.0})
	if result != "ell" {
		t.Errorf("got %v, want %q", result, "ell")
	}
}

func TestFnSubstr_OutOfRange(t *testing.T) {
	result := callFn(t, "substr", []any{"hi", 10.0})
	if result != "" {
		t.Errorf("got %v, want %q", result, "")
	}
}

func TestFnSubstr_ClampedLength(t *testing.T) {
	result := callFn(t, "substr", []any{"hello", 3.0, 100.0})
	if result != "lo" {
		t.Errorf("got %v, want %q", result, "lo")
	}
}

func TestFnContains(t *testing.T) {
	result := callFn(t, "contains", []any{"hello world", "world"})
	if result != true {
		t.Errorf("got %v, want true", result)
	}
}

func TestFnStartsWith(t *testing.T) {
	result := callFn(t, "startsWith", []any{"hello", "hel"})
	if result != true {
		t.Errorf("got %v, want true", result)
	}
}

func TestFnEndsWith(t *testing.T) {
	result := callFn(t, "endsWith", []any{"hello", "llo"})
	if result != true {
		t.Errorf("got %v, want true", result)
	}
}

func TestFnToString(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
	}{
		{"nil", nil, ""},
		{"string", "hello", "hello"},
		{"float whole", 42.0, "42"},
		{"float decimal", 3.14, "3.14"},
		{"int64", int64(99), "99"},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
		{"other", []int{1, 2}, "[1 2]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toString(tt.in)
			if got != tt.want {
				t.Errorf("toString(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestFnToNumber(t *testing.T) {
	result := callFn(t, "toNumber", []any{3.14})
	if result != 3.14 {
		t.Errorf("got %v, want 3.14", result)
	}
}

// --- Math functions ---

func TestFnRound_ZeroDecimals(t *testing.T) {
	result := callFn(t, "round", []any{3.7})
	if result != 4.0 {
		t.Errorf("got %v, want 4", result)
	}
}

func TestFnRound_TwoDecimals(t *testing.T) {
	result := callFn(t, "round", []any{3.14159, 2.0})
	if result != 3.14 {
		t.Errorf("got %v, want 3.14", result)
	}
}

func TestFnFloor(t *testing.T) {
	result := callFn(t, "floor", []any{3.9})
	if result != 3.0 {
		t.Errorf("got %v, want 3", result)
	}
}

func TestFnCeil(t *testing.T) {
	result := callFn(t, "ceil", []any{3.1})
	if result != 4.0 {
		t.Errorf("got %v, want 4", result)
	}
}

func TestFnAbs(t *testing.T) {
	result := callFn(t, "abs", []any{-5.0})
	if result != 5.0 {
		t.Errorf("got %v, want 5", result)
	}
}

func TestFnMin(t *testing.T) {
	result := callFn(t, "min", []any{3.0, 7.0})
	if result != 3.0 {
		t.Errorf("got %v, want 3", result)
	}
}

func TestFnMax(t *testing.T) {
	result := callFn(t, "max", []any{3.0, 7.0})
	if result != 7.0 {
		t.Errorf("got %v, want 7", result)
	}
}

// --- Utility functions ---

func TestFnCoalesce_FirstNonNil(t *testing.T) {
	result := callFn(t, "coalesce", []any{nil, nil, "found", "other"})
	if result != "found" {
		t.Errorf("got %v, want %q", result, "found")
	}
}

func TestFnCoalesce_AllNil(t *testing.T) {
	result := callFn(t, "coalesce", []any{nil, nil})
	if result != nil {
		t.Errorf("got %v, want nil", result)
	}
}

func TestFnNow(t *testing.T) {
	result := callFn(t, "now", []any{})
	str, ok := result.(string)
	if !ok {
		t.Fatalf("expected string, got %T", result)
	}
	_, err := time.Parse(time.RFC3339, str)
	if err != nil {
		t.Errorf("now() = %q, not valid RFC3339: %v", str, err)
	}
}

func TestFnAge_PastTimestamp(t *testing.T) {
	ts := time.Now().UTC().Add(-60 * time.Second).Format(time.RFC3339)
	result := callFn(t, "age", []any{ts})
	seconds, ok := result.(float64)
	if !ok {
		t.Fatalf("expected float64, got %T", result)
	}
	if seconds < 55 || seconds > 65 {
		t.Errorf("age() = %v, expected ~60 seconds", seconds)
	}
}

func TestFnAge_Empty(t *testing.T) {
	result := callFn(t, "age", []any{""})
	if result != nil {
		t.Errorf("got %v, want nil for empty timestamp", result)
	}
}

func TestFnAge_Invalid(t *testing.T) {
	result := callFn(t, "age", []any{"not-a-date"})
	if result != nil {
		t.Errorf("got %v, want nil for invalid timestamp", result)
	}
}

func TestFnFormatBytes(t *testing.T) {
	tests := []struct {
		name string
		in   float64
		want string
	}{
		{"zero", 0, "0.00B"},
		{"bytes", 500, "500.00B"},
		{"1Ki", 1024, "1.00Ki"},
		{"1Mi", 1024 * 1024, "1.00Mi"},
		{"1Gi", 1024 * 1024 * 1024, "1.00Gi"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := callFn(t, "formatBytes", []any{tt.in})
			if result != tt.want {
				t.Errorf("formatBytes(%v) = %v, want %q", tt.in, result, tt.want)
			}
		})
	}
}

// --- toFloat helper ---

func TestToFloat_AllTypes(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want float64
	}{
		{"nil", nil, 0},
		{"float64", 3.14, 3.14},
		{"int64", int64(42), 42},
		{"int", int(10), 10},
		{"bool true", true, 1},
		{"bool false", false, 0},
		{"default", "string", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toFloat(tt.in)
			if math.Abs(got-tt.want) > 1e-9 {
				t.Errorf("toFloat(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// --- Built-in function registration ---

func TestBuiltinFunctions_AllRegistered(t *testing.T) {
	expected := []string{
		"concat", "lower", "upper", "len", "substr",
		"round", "floor", "ceil", "abs", "min", "max",
		"coalesce", "now", "age", "formatBytes",
		"contains", "startsWith", "endsWith", "toString", "toNumber",
	}
	for _, name := range expected {
		if _, ok := BuiltinFunctions[name]; !ok {
			t.Errorf("missing built-in function: %s", name)
		}
	}
}

func TestFnContains_False(t *testing.T) {
	result := callFn(t, "contains", []any{"hello", "xyz"})
	if result != false {
		t.Errorf("got %v, want false", result)
	}
}

func TestFnStartsWith_False(t *testing.T) {
	result := callFn(t, "startsWith", []any{"hello", "xyz"})
	if result != false {
		t.Errorf("got %v, want false", result)
	}
}

func TestFnEndsWith_False(t *testing.T) {
	result := callFn(t, "endsWith", []any{"hello", "xyz"})
	if result != false {
		t.Errorf("got %v, want false", result)
	}
}

func TestFnToString_ViaBuiltin(t *testing.T) {
	result := callFn(t, "toString", []any{42.0})
	if result != "42" {
		t.Errorf("got %v, want %q", result, "42")
	}
}

func TestFnNow_Format(t *testing.T) {
	result := callFn(t, "now", []any{})
	str := result.(string)
	if !strings.Contains(str, "T") {
		t.Errorf("now() = %q, doesn't look like RFC3339", str)
	}
}
