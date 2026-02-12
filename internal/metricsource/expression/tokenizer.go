package expression

import (
	"strings"
	"unicode"
)

// Tokenizer performs lexical analysis on expression strings
type Tokenizer struct {
	input   string
	pos     int
	readPos int
	ch      byte
}

// NewTokenizer creates a tokenizer for the given input
func NewTokenizer(input string) *Tokenizer {
	t := &Tokenizer{input: input}
	t.readChar()
	return t
}

func (t *Tokenizer) readChar() {
	if t.readPos >= len(t.input) {
		t.ch = 0
	} else {
		t.ch = t.input[t.readPos]
	}
	t.pos = t.readPos
	t.readPos++
}

func (t *Tokenizer) peekChar() byte {
	if t.readPos >= len(t.input) {
		return 0
	}
	return t.input[t.readPos]
}

func (t *Tokenizer) skipWhitespace() {
	for t.ch == ' ' || t.ch == '\t' || t.ch == '\n' || t.ch == '\r' {
		t.readChar()
	}
}

// NextToken returns the next token from the input
func (t *Tokenizer) NextToken() Token {
	t.skipWhitespace()

	tok := Token{Pos: t.pos}

	switch t.ch {
	case 0:
		tok.Type = TokenEOF
		tok.Literal = ""
	case '+':
		tok.Type = TokenPlus
		tok.Literal = "+"
	case '-':
		tok.Type = TokenMinus
		tok.Literal = "-"
	case '*':
		tok.Type = TokenStar
		tok.Literal = "*"
	case '/':
		tok.Type = TokenSlash
		tok.Literal = "/"
	case '%':
		tok.Type = TokenPercent
		tok.Literal = "%"
	case '(':
		tok.Type = TokenLParen
		tok.Literal = "("
	case ')':
		tok.Type = TokenRParen
		tok.Literal = ")"
	case ',':
		tok.Type = TokenComma
		tok.Literal = ","
	case '!':
		if t.peekChar() == '=' {
			t.readChar()
			tok.Type = TokenNeq
			tok.Literal = "!="
		} else {
			tok.Type = TokenNot
			tok.Literal = "!"
		}
	case '=':
		if t.peekChar() == '=' {
			t.readChar()
			tok.Type = TokenEq
			tok.Literal = "=="
		} else {
			tok.Type = TokenEOF
			tok.Literal = "="
		}
	case '<':
		if t.peekChar() == '=' {
			t.readChar()
			tok.Type = TokenLte
			tok.Literal = "<="
		} else {
			tok.Type = TokenLt
			tok.Literal = "<"
		}
	case '>':
		if t.peekChar() == '=' {
			t.readChar()
			tok.Type = TokenGte
			tok.Literal = ">="
		} else {
			tok.Type = TokenGt
			tok.Literal = ">"
		}
	case '&':
		if t.peekChar() == '&' {
			t.readChar()
			tok.Type = TokenAnd
			tok.Literal = "&&"
		}
	case '|':
		if t.peekChar() == '|' {
			t.readChar()
			tok.Type = TokenOr
			tok.Literal = "||"
		}
	case '?':
		if t.peekChar() == '?' {
			t.readChar()
			tok.Type = TokenCoalesce
			tok.Literal = "??"
		}
	case '"', '\'':
		tok.Type = TokenString
		tok.Literal = t.readString(t.ch)
		return tok
	default:
		if isDigit(t.ch) {
			tok.Type = TokenNumber
			tok.Literal = t.readNumber()
			return tok
		} else if isLetter(t.ch) {
			literal := t.readIdentifier()
			tok.Literal = literal
			tok.Type = lookupKeyword(literal)
			return tok
		}
	}

	t.readChar()
	return tok
}

func (t *Tokenizer) readString(quote byte) string {
	t.readChar() // consume opening quote
	start := t.pos
	for t.ch != quote && t.ch != 0 {
		if t.ch == '\\' {
			t.readChar() // skip escape char
		}
		t.readChar()
	}
	str := t.input[start:t.pos]
	t.readChar() // consume closing quote
	return str
}

func (t *Tokenizer) readNumber() string {
	start := t.pos
	for isDigit(t.ch) || t.ch == '.' {
		t.readChar()
	}
	return t.input[start:t.pos]
}

func (t *Tokenizer) readIdentifier() string {
	start := t.pos
	for isLetter(t.ch) || isDigit(t.ch) || t.ch == '_' {
		t.readChar()
	}
	return t.input[start:t.pos]
}

func isDigit(ch byte) bool {
	return ch >= '0' && ch <= '9'
}

func isLetter(ch byte) bool {
	return unicode.IsLetter(rune(ch)) || ch == '_'
}

func lookupKeyword(ident string) TokenType {
	switch strings.ToLower(ident) {
	case "true", "false":
		return TokenBool
	case "null", "nil":
		return TokenNull
	default:
		return TokenIdent
	}
}
