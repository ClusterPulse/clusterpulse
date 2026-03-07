package expression

import (
	"math"
	"testing"
)

func compileExpr(t *testing.T, expr, resultType string) *CompiledExpression {
	t.Helper()
	c, err := Compile(expr, resultType)
	if err != nil {
		t.Fatalf("Compile(%q) error: %v", expr, err)
	}
	return c
}

func evalExpr(t *testing.T, expr string, ctx *Context) any {
	t.Helper()
	e := NewEvaluator()
	c := compileExpr(t, expr, "")
	result, err := e.Evaluate(c, ctx)
	if err != nil {
		t.Fatalf("Evaluate(%q) error: %v", expr, err)
	}
	return result
}

func TestEval_NilExpression(t *testing.T) {
	e := NewEvaluator()
	result, err := e.Evaluate(nil, nil)
	if err != nil || result != nil {
		t.Errorf("expected (nil, nil), got (%v, %v)", result, err)
	}
}

func TestEval_NilAST(t *testing.T) {
	e := NewEvaluator()
	result, err := e.Evaluate(&CompiledExpression{}, nil)
	if err != nil || result != nil {
		t.Errorf("expected (nil, nil), got (%v, %v)", result, err)
	}
}

func TestEval_Literal(t *testing.T) {
	result := evalExpr(t, "42", nil)
	if result != 42.0 {
		t.Errorf("got %v, want 42", result)
	}
}

func TestEval_Identifier_WithContext(t *testing.T) {
	ctx := &Context{Values: map[string]any{"x": 10.0}}
	result := evalExpr(t, "x", ctx)
	if result != 10.0 {
		t.Errorf("got %v, want 10", result)
	}
}

func TestEval_Identifier_NilContext(t *testing.T) {
	result := evalExpr(t, "x", nil)
	if result != nil {
		t.Errorf("got %v, want nil", result)
	}
}

func TestEval_Identifier_NilValues(t *testing.T) {
	result := evalExpr(t, "x", &Context{})
	if result != nil {
		t.Errorf("got %v, want nil", result)
	}
}

func TestEval_Identifier_MissingKey(t *testing.T) {
	ctx := &Context{Values: map[string]any{"y": 1.0}}
	result := evalExpr(t, "x", ctx)
	if result != nil {
		t.Errorf("got %v, want nil", result)
	}
}

func TestEval_BinaryAdd_Numbers(t *testing.T) {
	ctx := &Context{Values: map[string]any{"a": 3.0, "b": 7.0}}
	result := evalExpr(t, "a + b", ctx)
	if result != 10.0 {
		t.Errorf("got %v, want 10", result)
	}
}

func TestEval_BinaryAdd_StringConcat(t *testing.T) {
	ctx := &Context{Values: map[string]any{"a": "hello", "b": " world"}}
	result := evalExpr(t, "a + b", ctx)
	if result != "hello world" {
		t.Errorf("got %v, want %q", result, "hello world")
	}
}

func TestEval_BinarySub(t *testing.T) {
	ctx := &Context{Values: map[string]any{"a": 10.0, "b": 3.0}}
	result := evalExpr(t, "a - b", ctx)
	if result != 7.0 {
		t.Errorf("got %v, want 7", result)
	}
}

func TestEval_BinaryMul(t *testing.T) {
	ctx := &Context{Values: map[string]any{"a": 4.0, "b": 5.0}}
	result := evalExpr(t, "a * b", ctx)
	if result != 20.0 {
		t.Errorf("got %v, want 20", result)
	}
}

func TestEval_BinaryDiv(t *testing.T) {
	ctx := &Context{Values: map[string]any{"a": 10.0, "b": 4.0}}
	result := evalExpr(t, "a / b", ctx)
	if result != 2.5 {
		t.Errorf("got %v, want 2.5", result)
	}
}

func TestEval_BinaryDiv_ByZero(t *testing.T) {
	ctx := &Context{Values: map[string]any{"a": 10.0, "b": 0.0}}
	result := evalExpr(t, "a / b", ctx)
	if result != nil {
		t.Errorf("got %v, want nil (division by zero)", result)
	}
}

func TestEval_BinaryMod(t *testing.T) {
	ctx := &Context{Values: map[string]any{"a": 10.0, "b": 3.0}}
	result := evalExpr(t, "a % b", ctx)
	if result != 1.0 {
		t.Errorf("got %v, want 1", result)
	}
}

func TestEval_Comparison(t *testing.T) {
	ctx := &Context{Values: map[string]any{"a": 5.0, "b": 10.0}}
	tests := []struct {
		expr string
		want bool
	}{
		{"a == b", false},
		{"a != b", true},
		{"a < b", true},
		{"a <= b", true},
		{"a > b", false},
		{"a >= b", false},
		{"a == a", true},
		{"a <= a", true},
		{"a >= a", true},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			result := evalExpr(t, tt.expr, ctx)
			if result != tt.want {
				t.Errorf("got %v, want %v", result, tt.want)
			}
		})
	}
}

func TestEval_Equality_NilNil(t *testing.T) {
	ctx := &Context{Values: map[string]any{}}
	result := evalExpr(t, "a == b", ctx)
	if result != true {
		t.Errorf("nil == nil should be true, got %v", result)
	}
}

func TestEval_Equality_NilValue(t *testing.T) {
	ctx := &Context{Values: map[string]any{"a": 1.0}}
	result := evalExpr(t, "a == b", ctx)
	if result != false {
		t.Errorf("1 == nil should be false, got %v", result)
	}
}

func TestEval_And_ShortCircuit(t *testing.T) {
	ctx := &Context{Values: map[string]any{"a": false}}
	result := evalExpr(t, "a && b", ctx)
	// b is nil but short-circuits
	if result != false {
		t.Errorf("got %v, want false (short-circuit)", result)
	}
}

func TestEval_Or_ShortCircuit(t *testing.T) {
	ctx := &Context{Values: map[string]any{"a": true}}
	result := evalExpr(t, "a || b", ctx)
	if result != true {
		t.Errorf("got %v, want true (short-circuit)", result)
	}
}

func TestEval_Coalesce(t *testing.T) {
	t.Run("non-nil returns left", func(t *testing.T) {
		ctx := &Context{Values: map[string]any{"a": "hello"}}
		result := evalExpr(t, "a ?? b", ctx)
		if result != "hello" {
			t.Errorf("got %v, want %q", result, "hello")
		}
	})

	t.Run("nil returns right", func(t *testing.T) {
		ctx := &Context{Values: map[string]any{"b": "fallback"}}
		result := evalExpr(t, "a ?? b", ctx)
		if result != "fallback" {
			t.Errorf("got %v, want %q", result, "fallback")
		}
	})
}

func TestEval_UnaryNot(t *testing.T) {
	ctx := &Context{Values: map[string]any{"x": true}}
	result := evalExpr(t, "!x", ctx)
	if result != false {
		t.Errorf("got %v, want false", result)
	}
}

func TestEval_UnaryMinus(t *testing.T) {
	ctx := &Context{Values: map[string]any{"x": 5.0}}
	result := evalExpr(t, "-x", ctx)
	if result != -5.0 {
		t.Errorf("got %v, want -5", result)
	}
}

func TestEval_FunctionUnknown(t *testing.T) {
	e := NewEvaluator()
	c := compileExpr(t, "unknownFn(1)", "")
	_, err := e.Evaluate(c, nil)
	if err == nil {
		t.Error("expected error for unknown function")
	}
}

func TestEval_FunctionTooFewArgs(t *testing.T) {
	e := NewEvaluator()
	// min requires 2 args
	c := compileExpr(t, "min(1)", "")
	_, err := e.Evaluate(c, nil)
	if err == nil {
		t.Error("expected error for too few args")
	}
}

func TestEval_FunctionTooManyArgs(t *testing.T) {
	e := NewEvaluator()
	// lower accepts max 1 arg
	c := compileExpr(t, "lower(1, 2)", "")
	_, err := e.Evaluate(c, nil)
	if err == nil {
		t.Error("expected error for too many args")
	}
}

func TestCoerceResult(t *testing.T) {
	e := NewEvaluator()

	t.Run("string", func(t *testing.T) {
		result := e.coerceResult(42.0, "string")
		if result != "42" {
			t.Errorf("got %v, want %q", result, "42")
		}
	})

	t.Run("integer", func(t *testing.T) {
		result := e.coerceResult(3.7, "integer")
		if result != int64(3) {
			t.Errorf("got %v, want 3", result)
		}
	})

	t.Run("float", func(t *testing.T) {
		result := e.coerceResult(int64(5), "float")
		if result != 5.0 {
			t.Errorf("got %v, want 5.0", result)
		}
	})

	t.Run("boolean", func(t *testing.T) {
		result := e.coerceResult(1.0, "boolean")
		if result != true {
			t.Errorf("got %v, want true", result)
		}
	})

	t.Run("nil", func(t *testing.T) {
		result := e.coerceResult(nil, "string")
		if result != nil {
			t.Errorf("got %v, want nil", result)
		}
	})

	t.Run("unknown type passthrough", func(t *testing.T) {
		result := e.coerceResult(42.0, "unknown")
		if result != 42.0 {
			t.Errorf("got %v, want 42", result)
		}
	})
}

func TestToBool(t *testing.T) {
	tests := []struct {
		name string
		val  any
		want bool
	}{
		{"nil", nil, false},
		{"true", true, true},
		{"false", false, false},
		{"nonzero float", 1.0, true},
		{"zero float", 0.0, false},
		{"nonzero int64", int64(1), true},
		{"zero int64", int64(0), false},
		{"non-empty string", "hello", true},
		{"empty string", "", false},
		{"other type", struct{}{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toBool(tt.val); got != tt.want {
				t.Errorf("toBool(%v) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

func TestToFloat(t *testing.T) {
	tests := []struct {
		name string
		val  any
		want float64
	}{
		{"nil", nil, 0},
		{"float64", 3.14, 3.14},
		{"int64", int64(42), 42},
		{"int", int(10), 10},
		{"bool true", true, 1},
		{"bool false", false, 0},
		{"unknown type", "not a number", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toFloat(tt.val)
			if math.Abs(got-tt.want) > 1e-9 {
				t.Errorf("toFloat(%v) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

func TestIsString(t *testing.T) {
	if !isString("hello") {
		t.Error("isString(string) should be true")
	}
	if isString(42) {
		t.Error("isString(int) should be false")
	}
	if isString(nil) {
		t.Error("isString(nil) should be false")
	}
}
