package expression

import "fmt"

// TokenType represents the type of a lexical token
type TokenType int

const (
	TokenEOF TokenType = iota
	TokenNumber
	TokenString
	TokenIdent
	TokenBool
	TokenNull

	// Operators
	TokenPlus
	TokenMinus
	TokenStar
	TokenSlash
	TokenPercent
	TokenEq
	TokenNeq
	TokenLt
	TokenLte
	TokenGt
	TokenGte
	TokenAnd
	TokenOr
	TokenNot
	TokenCoalesce

	// Delimiters
	TokenLParen
	TokenRParen
	TokenComma
)

// Token represents a lexical token
type Token struct {
	Type    TokenType
	Literal string
	Pos     int
}

// NodeType represents AST node types
type NodeType int

const (
	NodeLiteral NodeType = iota
	NodeIdentifier
	NodeBinaryOp
	NodeUnaryOp
	NodeFunctionCall
	NodeConditional
)

// Node represents an AST node
type Node interface {
	Type() NodeType
	String() string
}

// LiteralNode represents a literal value (number, string, bool, null)
type LiteralNode struct {
	Value any
}

func (n *LiteralNode) Type() NodeType { return NodeLiteral }
func (n *LiteralNode) String() string { return fmt.Sprintf("%v", n.Value) }

// IdentifierNode represents a field reference
type IdentifierNode struct {
	Name string
}

func (n *IdentifierNode) Type() NodeType { return NodeIdentifier }
func (n *IdentifierNode) String() string { return n.Name }

// BinaryOpNode represents a binary operation
type BinaryOpNode struct {
	Operator string
	Left     Node
	Right    Node
}

func (n *BinaryOpNode) Type() NodeType { return NodeBinaryOp }
func (n *BinaryOpNode) String() string {
	return fmt.Sprintf("(%s %s %s)", n.Left.String(), n.Operator, n.Right.String())
}

// UnaryOpNode represents a unary operation
type UnaryOpNode struct {
	Operator string
	Operand  Node
}

func (n *UnaryOpNode) Type() NodeType { return NodeUnaryOp }
func (n *UnaryOpNode) String() string {
	return fmt.Sprintf("(%s%s)", n.Operator, n.Operand.String())
}

// FunctionCallNode represents a function invocation
type FunctionCallNode struct {
	Name string
	Args []Node
}

func (n *FunctionCallNode) Type() NodeType { return NodeFunctionCall }
func (n *FunctionCallNode) String() string {
	return fmt.Sprintf("%s(...)", n.Name)
}

// ExpressionError represents an error during parsing or evaluation
type ExpressionError struct {
	Message  string
	Position int
}

func (e *ExpressionError) Error() string {
	if e.Position >= 0 {
		return fmt.Sprintf("expression error at position %d: %s", e.Position, e.Message)
	}
	return fmt.Sprintf("expression error: %s", e.Message)
}

// CompiledExpression holds a parsed expression ready for evaluation
type CompiledExpression struct {
	Source     string
	AST        Node
	ResultType string
	References []string // Field names referenced by this expression
}
