package expression

import (
	"fmt"
	"strconv"
	"strings"
)

// Parser builds an AST from tokens
type Parser struct {
	tokenizer *Tokenizer
	curToken  Token
	peekToken Token
	errors    []string
}

// NewParser creates a parser for the given expression
func NewParser(input string) *Parser {
	p := &Parser{tokenizer: NewTokenizer(input)}
	p.nextToken()
	p.nextToken()
	return p
}

func (p *Parser) nextToken() {
	p.curToken = p.peekToken
	p.peekToken = p.tokenizer.NextToken()
}

// Parse parses the expression and returns the AST root
func (p *Parser) Parse() (Node, error) {
	node := p.parseExpression(0)
	if len(p.errors) > 0 {
		return nil, &ExpressionError{Message: strings.Join(p.errors, "; "), Position: -1}
	}
	return node, nil
}

// Operator precedence levels
const (
	precLowest = iota
	precCoalesce
	precOr
	precAnd
	precEquality
	precComparison
	precAdditive
	precMultiplicative
	precUnary
	precCall
)

func (p *Parser) precedence(t TokenType) int {
	switch t {
	case TokenCoalesce:
		return precCoalesce
	case TokenOr:
		return precOr
	case TokenAnd:
		return precAnd
	case TokenEq, TokenNeq:
		return precEquality
	case TokenLt, TokenLte, TokenGt, TokenGte:
		return precComparison
	case TokenPlus, TokenMinus:
		return precAdditive
	case TokenStar, TokenSlash, TokenPercent:
		return precMultiplicative
	case TokenLParen:
		return precCall
	default:
		return -1
	}
}

func (p *Parser) parseExpression(minPrec int) Node {
	left := p.parseUnary()

	for p.curToken.Type != TokenEOF && p.precedence(p.curToken.Type) >= minPrec {
		op := p.curToken
		prec := p.precedence(op.Type)
		p.nextToken()

		right := p.parseExpression(prec + 1)
		left = &BinaryOpNode{
			Operator: op.Literal,
			Left:     left,
			Right:    right,
		}
	}

	return left
}

func (p *Parser) parseUnary() Node {
	if p.curToken.Type == TokenNot || p.curToken.Type == TokenMinus {
		op := p.curToken
		p.nextToken()
		return &UnaryOpNode{
			Operator: op.Literal,
			Operand:  p.parseUnary(),
		}
	}
	return p.parsePrimary()
}

func (p *Parser) parsePrimary() Node {
	switch p.curToken.Type {
	case TokenNumber:
		return p.parseNumber()
	case TokenString:
		return p.parseString()
	case TokenBool:
		return p.parseBool()
	case TokenNull:
		p.nextToken()
		return &LiteralNode{Value: nil}
	case TokenIdent:
		return p.parseIdentifierOrCall()
	case TokenLParen:
		return p.parseGrouped()
	default:
		p.errors = append(p.errors, fmt.Sprintf("unexpected token: %s", p.curToken.Literal))
		p.nextToken()
		return &LiteralNode{Value: nil}
	}
}

func (p *Parser) parseNumber() Node {
	val, err := strconv.ParseFloat(p.curToken.Literal, 64)
	if err != nil {
		p.errors = append(p.errors, fmt.Sprintf("invalid number: %s", p.curToken.Literal))
	}
	p.nextToken()
	return &LiteralNode{Value: val}
}

func (p *Parser) parseString() Node {
	val := p.curToken.Literal
	p.nextToken()
	return &LiteralNode{Value: val}
}

func (p *Parser) parseBool() Node {
	val := strings.ToLower(p.curToken.Literal) == "true"
	p.nextToken()
	return &LiteralNode{Value: val}
}

func (p *Parser) parseIdentifierOrCall() Node {
	name := p.curToken.Literal
	p.nextToken()

	if p.curToken.Type == TokenLParen {
		return p.parseFunctionCall(name)
	}

	return &IdentifierNode{Name: name}
}

func (p *Parser) parseFunctionCall(name string) Node {
	p.nextToken() // consume '('
	args := p.parseCallArgs()
	return &FunctionCallNode{Name: name, Args: args}
}

func (p *Parser) parseCallArgs() []Node {
	var args []Node

	if p.curToken.Type == TokenRParen {
		p.nextToken()
		return args
	}

	args = append(args, p.parseExpression(precLowest))

	for p.curToken.Type == TokenComma {
		p.nextToken()
		args = append(args, p.parseExpression(precLowest))
	}

	if p.curToken.Type != TokenRParen {
		p.errors = append(p.errors, "expected ')' after function arguments")
	}
	p.nextToken()

	return args
}

func (p *Parser) parseGrouped() Node {
	p.nextToken() // consume '('
	node := p.parseExpression(precLowest)
	if p.curToken.Type != TokenRParen {
		p.errors = append(p.errors, "expected ')' after grouped expression")
	}
	p.nextToken()
	return node
}

// ExtractReferences returns all field names referenced in an AST
func ExtractReferences(node Node) []string {
	refs := make(map[string]bool)
	extractRefs(node, refs)
	result := make([]string, 0, len(refs))
	for ref := range refs {
		result = append(result, ref)
	}
	return result
}

func extractRefs(node Node, refs map[string]bool) {
	if node == nil {
		return
	}
	switch n := node.(type) {
	case *IdentifierNode:
		refs[n.Name] = true
	case *BinaryOpNode:
		extractRefs(n.Left, refs)
		extractRefs(n.Right, refs)
	case *UnaryOpNode:
		extractRefs(n.Operand, refs)
	case *FunctionCallNode:
		for _, arg := range n.Args {
			extractRefs(arg, refs)
		}
	}
}

// Compile parses and compiles an expression string
func Compile(expr string, resultType string) (*CompiledExpression, error) {
	parser := NewParser(expr)
	ast, err := parser.Parse()
	if err != nil {
		return nil, err
	}

	return &CompiledExpression{
		Source:     expr,
		AST:        ast,
		ResultType: resultType,
		References: ExtractReferences(ast),
	}, nil
}
