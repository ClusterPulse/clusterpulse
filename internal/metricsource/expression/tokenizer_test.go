package expression

import "testing"

func TestTokenizer_SingleCharOperators(t *testing.T) {
	tests := []struct {
		input    string
		wantType TokenType
		wantLit  string
	}{
		{"+", TokenPlus, "+"},
		{"-", TokenMinus, "-"},
		{"*", TokenStar, "*"},
		{"/", TokenSlash, "/"},
		{"%", TokenPercent, "%"},
		{"(", TokenLParen, "("},
		{")", TokenRParen, ")"},
		{",", TokenComma, ","},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			tok := NewTokenizer(tt.input).NextToken()
			if tok.Type != tt.wantType {
				t.Errorf("type = %v, want %v", tok.Type, tt.wantType)
			}
			if tok.Literal != tt.wantLit {
				t.Errorf("literal = %q, want %q", tok.Literal, tt.wantLit)
			}
		})
	}
}

func TestTokenizer_TwoCharOperators(t *testing.T) {
	tests := []struct {
		input    string
		wantType TokenType
		wantLit  string
	}{
		{"==", TokenEq, "=="},
		{"!=", TokenNeq, "!="},
		{"<=", TokenLte, "<="},
		{">=", TokenGte, ">="},
		{"&&", TokenAnd, "&&"},
		{"||", TokenOr, "||"},
		{"??", TokenCoalesce, "??"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			tok := NewTokenizer(tt.input).NextToken()
			if tok.Type != tt.wantType {
				t.Errorf("type = %v, want %v", tok.Type, tt.wantType)
			}
			if tok.Literal != tt.wantLit {
				t.Errorf("literal = %q, want %q", tok.Literal, tt.wantLit)
			}
		})
	}
}

func TestTokenizer_SingleComparison(t *testing.T) {
	tests := []struct {
		input    string
		wantType TokenType
		wantLit  string
	}{
		{"<", TokenLt, "<"},
		{">", TokenGt, ">"},
		{"!", TokenNot, "!"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			tok := NewTokenizer(tt.input).NextToken()
			if tok.Type != tt.wantType {
				t.Errorf("type = %v, want %v", tok.Type, tt.wantType)
			}
			if tok.Literal != tt.wantLit {
				t.Errorf("literal = %q, want %q", tok.Literal, tt.wantLit)
			}
		})
	}
}

func TestTokenizer_SingleEquals(t *testing.T) {
	tok := NewTokenizer("=").NextToken()
	if tok.Type != TokenEOF {
		t.Errorf("single '=' type = %v, want TokenEOF", tok.Type)
	}
	if tok.Literal != "=" {
		t.Errorf("literal = %q, want %q", tok.Literal, "=")
	}
}

func TestTokenizer_Numbers(t *testing.T) {
	tests := []struct {
		input   string
		wantLit string
	}{
		{"42", "42"},
		{"3.14", "3.14"},
		{"0", "0"},
		{"100", "100"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			tok := NewTokenizer(tt.input).NextToken()
			if tok.Type != TokenNumber {
				t.Errorf("type = %v, want TokenNumber", tok.Type)
			}
			if tok.Literal != tt.wantLit {
				t.Errorf("literal = %q, want %q", tok.Literal, tt.wantLit)
			}
		})
	}
}

func TestTokenizer_Strings(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLit string
	}{
		{"double quoted", `"hello"`, "hello"},
		{"single quoted", `'hello'`, "hello"},
		{"escaped quote", `"he\"llo"`, `he\"llo`},
		{"empty double", `""`, ""},
		{"empty single", `''`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := NewTokenizer(tt.input).NextToken()
			if tok.Type != TokenString {
				t.Errorf("type = %v, want TokenString", tok.Type)
			}
			if tok.Literal != tt.wantLit {
				t.Errorf("literal = %q, want %q", tok.Literal, tt.wantLit)
			}
		})
	}
}

func TestTokenizer_Keywords(t *testing.T) {
	tests := []struct {
		input    string
		wantType TokenType
	}{
		{"true", TokenBool},
		{"True", TokenBool},
		{"TRUE", TokenBool},
		{"false", TokenBool},
		{"False", TokenBool},
		{"null", TokenNull},
		{"Null", TokenNull},
		{"nil", TokenNull},
		{"NIL", TokenNull},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			tok := NewTokenizer(tt.input).NextToken()
			if tok.Type != tt.wantType {
				t.Errorf("type = %v, want %v", tok.Type, tt.wantType)
			}
		})
	}
}

func TestTokenizer_Identifier(t *testing.T) {
	tok := NewTokenizer("myField").NextToken()
	if tok.Type != TokenIdent {
		t.Errorf("type = %v, want TokenIdent", tok.Type)
	}
	if tok.Literal != "myField" {
		t.Errorf("literal = %q, want %q", tok.Literal, "myField")
	}
}

func TestTokenizer_WhitespaceSkipping(t *testing.T) {
	tok := NewTokenizer("   42   ").NextToken()
	if tok.Type != TokenNumber || tok.Literal != "42" {
		t.Errorf("got type=%v literal=%q, want TokenNumber/42", tok.Type, tok.Literal)
	}
}

func TestTokenizer_EmptyInput(t *testing.T) {
	tok := NewTokenizer("").NextToken()
	if tok.Type != TokenEOF {
		t.Errorf("type = %v, want TokenEOF", tok.Type)
	}
}

func TestTokenizer_ComplexExpression(t *testing.T) {
	input := "a + b * 2"
	tokenizer := NewTokenizer(input)

	expected := []struct {
		typ TokenType
		lit string
	}{
		{TokenIdent, "a"},
		{TokenPlus, "+"},
		{TokenIdent, "b"},
		{TokenStar, "*"},
		{TokenNumber, "2"},
		{TokenEOF, ""},
	}

	for _, want := range expected {
		tok := tokenizer.NextToken()
		if tok.Type != want.typ || tok.Literal != want.lit {
			t.Errorf("got {%v, %q}, want {%v, %q}", tok.Type, tok.Literal, want.typ, want.lit)
		}
	}
}

func TestTokenizer_UnterminatedString(t *testing.T) {
	// Unterminated string reads until EOF
	tok := NewTokenizer(`"hello`).NextToken()
	if tok.Type != TokenString {
		t.Errorf("type = %v, want TokenString", tok.Type)
	}
	if tok.Literal != "hello" {
		t.Errorf("literal = %q, want %q", tok.Literal, "hello")
	}
}

func TestTokenizer_SingleAmpersand(t *testing.T) {
	// Single & doesn't form a token — results in zero-value token
	tokenizer := NewTokenizer("&")
	tok := tokenizer.NextToken()
	// ch is '&' and peek is 0, so it falls through with empty literal
	if tok.Literal != "" {
		t.Errorf("single '&' literal = %q, want empty", tok.Literal)
	}
}

func TestTokenizer_SinglePipe(t *testing.T) {
	tokenizer := NewTokenizer("|")
	tok := tokenizer.NextToken()
	if tok.Literal != "" {
		t.Errorf("single '|' literal = %q, want empty", tok.Literal)
	}
}

func TestTokenizer_SingleQuestion(t *testing.T) {
	tokenizer := NewTokenizer("?")
	tok := tokenizer.NextToken()
	if tok.Literal != "" {
		t.Errorf("single '?' literal = %q, want empty", tok.Literal)
	}
}
