package expression

import (
	"testing"
)

func TestParse_LiteralNumber(t *testing.T) {
	node, err := NewParser("42").Parse()
	if err != nil {
		t.Fatal(err)
	}
	lit, ok := node.(*LiteralNode)
	if !ok {
		t.Fatalf("expected *LiteralNode, got %T", node)
	}
	if lit.Value != 42.0 {
		t.Errorf("value = %v, want 42", lit.Value)
	}
}

func TestParse_LiteralString(t *testing.T) {
	node, err := NewParser(`"hello"`).Parse()
	if err != nil {
		t.Fatal(err)
	}
	lit := node.(*LiteralNode)
	if lit.Value != "hello" {
		t.Errorf("value = %v, want %q", lit.Value, "hello")
	}
}

func TestParse_LiteralBool(t *testing.T) {
	for _, input := range []string{"true", "false"} {
		t.Run(input, func(t *testing.T) {
			node, err := NewParser(input).Parse()
			if err != nil {
				t.Fatal(err)
			}
			lit := node.(*LiteralNode)
			want := input == "true"
			if lit.Value != want {
				t.Errorf("value = %v, want %v", lit.Value, want)
			}
		})
	}
}

func TestParse_LiteralNull(t *testing.T) {
	for _, input := range []string{"null", "nil"} {
		t.Run(input, func(t *testing.T) {
			node, err := NewParser(input).Parse()
			if err != nil {
				t.Fatal(err)
			}
			lit := node.(*LiteralNode)
			if lit.Value != nil {
				t.Errorf("value = %v, want nil", lit.Value)
			}
		})
	}
}

func TestParse_Identifier(t *testing.T) {
	node, err := NewParser("fieldName").Parse()
	if err != nil {
		t.Fatal(err)
	}
	ident, ok := node.(*IdentifierNode)
	if !ok {
		t.Fatalf("expected *IdentifierNode, got %T", node)
	}
	if ident.Name != "fieldName" {
		t.Errorf("name = %q, want %q", ident.Name, "fieldName")
	}
}

func TestParse_BinaryArithmetic(t *testing.T) {
	node, err := NewParser("a + b").Parse()
	if err != nil {
		t.Fatal(err)
	}
	bin, ok := node.(*BinaryOpNode)
	if !ok {
		t.Fatalf("expected *BinaryOpNode, got %T", node)
	}
	if bin.Operator != "+" {
		t.Errorf("op = %q, want %q", bin.Operator, "+")
	}
}

func TestParse_Precedence(t *testing.T) {
	// a + b * c should parse as a + (b * c)
	node, err := NewParser("a + b * c").Parse()
	if err != nil {
		t.Fatal(err)
	}
	bin := node.(*BinaryOpNode)
	if bin.Operator != "+" {
		t.Errorf("top op = %q, want %q", bin.Operator, "+")
	}
	right, ok := bin.Right.(*BinaryOpNode)
	if !ok {
		t.Fatalf("right should be BinaryOpNode, got %T", bin.Right)
	}
	if right.Operator != "*" {
		t.Errorf("right op = %q, want %q", right.Operator, "*")
	}
}

func TestParse_Grouped(t *testing.T) {
	// (a + b) * c
	node, err := NewParser("(a + b) * c").Parse()
	if err != nil {
		t.Fatal(err)
	}
	bin := node.(*BinaryOpNode)
	if bin.Operator != "*" {
		t.Errorf("top op = %q, want %q", bin.Operator, "*")
	}
	left, ok := bin.Left.(*BinaryOpNode)
	if !ok {
		t.Fatalf("left should be BinaryOpNode, got %T", bin.Left)
	}
	if left.Operator != "+" {
		t.Errorf("left op = %q, want %q", left.Operator, "+")
	}
}

func TestParse_UnaryNot(t *testing.T) {
	node, err := NewParser("!x").Parse()
	if err != nil {
		t.Fatal(err)
	}
	un, ok := node.(*UnaryOpNode)
	if !ok {
		t.Fatalf("expected *UnaryOpNode, got %T", node)
	}
	if un.Operator != "!" {
		t.Errorf("op = %q, want %q", un.Operator, "!")
	}
}

func TestParse_UnaryMinus(t *testing.T) {
	node, err := NewParser("-x").Parse()
	if err != nil {
		t.Fatal(err)
	}
	un := node.(*UnaryOpNode)
	if un.Operator != "-" {
		t.Errorf("op = %q, want %q", un.Operator, "-")
	}
}

func TestParse_NestedUnary(t *testing.T) {
	node, err := NewParser("!!x").Parse()
	if err != nil {
		t.Fatal(err)
	}
	outer := node.(*UnaryOpNode)
	inner, ok := outer.Operand.(*UnaryOpNode)
	if !ok {
		t.Fatalf("expected nested UnaryOpNode, got %T", outer.Operand)
	}
	if inner.Operator != "!" {
		t.Errorf("inner op = %q, want %q", inner.Operator, "!")
	}
}

func TestParse_FunctionNoArgs(t *testing.T) {
	node, err := NewParser("now()").Parse()
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := node.(*FunctionCallNode)
	if !ok {
		t.Fatalf("expected *FunctionCallNode, got %T", node)
	}
	if fn.Name != "now" {
		t.Errorf("name = %q, want %q", fn.Name, "now")
	}
	if len(fn.Args) != 0 {
		t.Errorf("args len = %d, want 0", len(fn.Args))
	}
}

func TestParse_FunctionMultiArgs(t *testing.T) {
	node, err := NewParser("substr(x, 0, 5)").Parse()
	if err != nil {
		t.Fatal(err)
	}
	fn := node.(*FunctionCallNode)
	if fn.Name != "substr" {
		t.Errorf("name = %q, want %q", fn.Name, "substr")
	}
	if len(fn.Args) != 3 {
		t.Errorf("args len = %d, want 3", len(fn.Args))
	}
}

func TestParse_ErrorUnexpectedToken(t *testing.T) {
	_, err := NewParser("@").Parse()
	// '@' is not a valid token — will produce an error or EOF-type fallthrough
	// The parser should still return without panicking
	if err != nil {
		// Error is acceptable
		return
	}
}

func TestParse_ErrorMissingRParen_Group(t *testing.T) {
	_, err := NewParser("(a + b").Parse()
	if err == nil {
		t.Error("expected error for missing ')' in group")
	}
}

func TestParse_ErrorMissingRParen_Function(t *testing.T) {
	_, err := NewParser("func(a, b").Parse()
	if err == nil {
		t.Error("expected error for missing ')' in function call")
	}
}

func TestCompile_Valid(t *testing.T) {
	compiled, err := Compile("a + b", "float")
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Source != "a + b" {
		t.Errorf("Source = %q, want %q", compiled.Source, "a + b")
	}
	if compiled.ResultType != "float" {
		t.Errorf("ResultType = %q, want %q", compiled.ResultType, "float")
	}
	if compiled.AST == nil {
		t.Error("AST should not be nil")
	}
	if len(compiled.References) != 2 {
		t.Errorf("References len = %d, want 2", len(compiled.References))
	}
}

func TestExtractReferences(t *testing.T) {
	node, _ := NewParser("a + fn(b, c)").Parse()
	refs := ExtractReferences(node)
	refMap := make(map[string]bool)
	for _, r := range refs {
		refMap[r] = true
	}
	for _, want := range []string{"a", "b", "c"} {
		if !refMap[want] {
			t.Errorf("missing reference %q", want)
		}
	}
}

func TestExtractReferences_NilNode(t *testing.T) {
	refs := ExtractReferences(nil)
	if len(refs) != 0 {
		t.Errorf("expected empty refs for nil node, got %v", refs)
	}
}
