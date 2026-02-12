package expression

import (
	"fmt"
	"math"

	"github.com/sirupsen/logrus"
)

// Evaluator executes compiled expressions against a context
type Evaluator struct {
	log *logrus.Entry
}

// NewEvaluator creates a new expression evaluator
func NewEvaluator() *Evaluator {
	return &Evaluator{
		log: logrus.WithField("component", "expression-evaluator"),
	}
}

// Context holds variable bindings for evaluation
type Context struct {
	Values map[string]interface{}
}

// Evaluate executes a compiled expression and returns the result
func (e *Evaluator) Evaluate(expr *CompiledExpression, ctx *Context) (interface{}, error) {
	if expr == nil || expr.AST == nil {
		return nil, nil
	}

	result, err := e.eval(expr.AST, ctx)
	if err != nil {
		e.log.Debugf("Expression evaluation error: %v", err)
		return nil, err
	}

	return e.coerceResult(result, expr.ResultType), nil
}

func (e *Evaluator) eval(node Node, ctx *Context) (interface{}, error) {
	switch n := node.(type) {
	case *LiteralNode:
		return n.Value, nil

	case *IdentifierNode:
		if ctx == nil || ctx.Values == nil {
			return nil, nil
		}
		return ctx.Values[n.Name], nil

	case *UnaryOpNode:
		return e.evalUnary(n, ctx)

	case *BinaryOpNode:
		return e.evalBinary(n, ctx)

	case *FunctionCallNode:
		return e.evalFunction(n, ctx)

	default:
		return nil, fmt.Errorf("unknown node type: %T", node)
	}
}

func (e *Evaluator) evalUnary(node *UnaryOpNode, ctx *Context) (interface{}, error) {
	operand, err := e.eval(node.Operand, ctx)
	if err != nil {
		return nil, err
	}

	switch node.Operator {
	case "!":
		return !toBool(operand), nil
	case "-":
		return -toFloat(operand), nil
	default:
		return nil, fmt.Errorf("unknown unary operator: %s", node.Operator)
	}
}

func (e *Evaluator) evalBinary(node *BinaryOpNode, ctx *Context) (interface{}, error) {
	// Short-circuit evaluation for logical operators
	if node.Operator == "&&" {
		left, err := e.eval(node.Left, ctx)
		if err != nil {
			return nil, err
		}
		if !toBool(left) {
			return false, nil
		}
		right, err := e.eval(node.Right, ctx)
		if err != nil {
			return nil, err
		}
		return toBool(right), nil
	}

	if node.Operator == "||" {
		left, err := e.eval(node.Left, ctx)
		if err != nil {
			return nil, err
		}
		if toBool(left) {
			return true, nil
		}
		right, err := e.eval(node.Right, ctx)
		if err != nil {
			return nil, err
		}
		return toBool(right), nil
	}

	if node.Operator == "??" {
		left, err := e.eval(node.Left, ctx)
		if err != nil {
			return nil, err
		}
		if left != nil {
			return left, nil
		}
		return e.eval(node.Right, ctx)
	}

	left, err := e.eval(node.Left, ctx)
	if err != nil {
		return nil, err
	}
	right, err := e.eval(node.Right, ctx)
	if err != nil {
		return nil, err
	}

	switch node.Operator {
	case "+":
		if isString(left) || isString(right) {
			return toString(left) + toString(right), nil
		}
		return toFloat(left) + toFloat(right), nil
	case "-":
		return toFloat(left) - toFloat(right), nil
	case "*":
		return toFloat(left) * toFloat(right), nil
	case "/":
		r := toFloat(right)
		if r == 0 {
			return nil, nil // Return nil for division by zero
		}
		return toFloat(left) / r, nil
	case "%":
		return math.Mod(toFloat(left), toFloat(right)), nil
	case "==":
		return e.equals(left, right), nil
	case "!=":
		return !e.equals(left, right), nil
	case "<":
		return toFloat(left) < toFloat(right), nil
	case "<=":
		return toFloat(left) <= toFloat(right), nil
	case ">":
		return toFloat(left) > toFloat(right), nil
	case ">=":
		return toFloat(left) >= toFloat(right), nil
	default:
		return nil, fmt.Errorf("unknown binary operator: %s", node.Operator)
	}
}

func (e *Evaluator) evalFunction(node *FunctionCallNode, ctx *Context) (interface{}, error) {
	fn, ok := BuiltinFunctions[node.Name]
	if !ok {
		return nil, fmt.Errorf("unknown function: %s", node.Name)
	}

	if fn.MinArgs > len(node.Args) {
		return nil, fmt.Errorf("function %s requires at least %d arguments", node.Name, fn.MinArgs)
	}
	if fn.MaxArgs >= 0 && len(node.Args) > fn.MaxArgs {
		return nil, fmt.Errorf("function %s accepts at most %d arguments", node.Name, fn.MaxArgs)
	}

	args := make([]interface{}, len(node.Args))
	for i, arg := range node.Args {
		val, err := e.eval(arg, ctx)
		if err != nil {
			return nil, err
		}
		args[i] = val
	}

	return fn.Fn(args)
}

func (e *Evaluator) equals(a, b interface{}) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	switch va := a.(type) {
	case string:
		return va == toString(b)
	case float64:
		return va == toFloat(b)
	case bool:
		return va == toBool(b)
	default:
		return false
	}
}

func (e *Evaluator) coerceResult(val interface{}, targetType string) interface{} {
	if val == nil {
		return nil
	}

	switch targetType {
	case "string":
		return toString(val)
	case "integer":
		return int64(toFloat(val))
	case "float":
		return toFloat(val)
	case "boolean":
		return toBool(val)
	default:
		return val
	}
}

func toBool(v interface{}) bool {
	if v == nil {
		return false
	}
	switch val := v.(type) {
	case bool:
		return val
	case float64:
		return val != 0
	case int64:
		return val != 0
	case string:
		return val != ""
	default:
		return true
	}
}

func isString(v interface{}) bool {
	_, ok := v.(string)
	return ok
}
