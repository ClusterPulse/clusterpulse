package expression

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// FunctionDef defines a built-in function
type FunctionDef struct {
	MinArgs int
	MaxArgs int
	Fn      func(args []interface{}) (interface{}, error)
}

// BuiltinFunctions contains all available functions
var BuiltinFunctions = map[string]FunctionDef{
	"concat":      {MinArgs: 1, MaxArgs: -1, Fn: fnConcat},
	"lower":       {MinArgs: 1, MaxArgs: 1, Fn: fnLower},
	"upper":       {MinArgs: 1, MaxArgs: 1, Fn: fnUpper},
	"len":         {MinArgs: 1, MaxArgs: 1, Fn: fnLen},
	"substr":      {MinArgs: 2, MaxArgs: 3, Fn: fnSubstr},
	"round":       {MinArgs: 1, MaxArgs: 2, Fn: fnRound},
	"floor":       {MinArgs: 1, MaxArgs: 1, Fn: fnFloor},
	"ceil":        {MinArgs: 1, MaxArgs: 1, Fn: fnCeil},
	"abs":         {MinArgs: 1, MaxArgs: 1, Fn: fnAbs},
	"min":         {MinArgs: 2, MaxArgs: 2, Fn: fnMin},
	"max":         {MinArgs: 2, MaxArgs: 2, Fn: fnMax},
	"coalesce":    {MinArgs: 1, MaxArgs: -1, Fn: fnCoalesce},
	"now":         {MinArgs: 0, MaxArgs: 0, Fn: fnNow},
	"age":         {MinArgs: 1, MaxArgs: 1, Fn: fnAge},
	"formatBytes": {MinArgs: 1, MaxArgs: 1, Fn: fnFormatBytes},
	"contains":    {MinArgs: 2, MaxArgs: 2, Fn: fnContains},
	"startsWith":  {MinArgs: 2, MaxArgs: 2, Fn: fnStartsWith},
	"endsWith":    {MinArgs: 2, MaxArgs: 2, Fn: fnEndsWith},
	"toString":    {MinArgs: 1, MaxArgs: 1, Fn: fnToString},
	"toNumber":    {MinArgs: 1, MaxArgs: 1, Fn: fnToNumber},
}

func fnConcat(args []interface{}) (interface{}, error) {
	var sb strings.Builder
	for _, arg := range args {
		sb.WriteString(toString(arg))
	}
	return sb.String(), nil
}

func fnLower(args []interface{}) (interface{}, error) {
	return strings.ToLower(toString(args[0])), nil
}

func fnUpper(args []interface{}) (interface{}, error) {
	return strings.ToUpper(toString(args[0])), nil
}

func fnLen(args []interface{}) (interface{}, error) {
	return float64(len(toString(args[0]))), nil
}

func fnSubstr(args []interface{}) (interface{}, error) {
	s := toString(args[0])
	start := int(toFloat(args[1]))
	if start < 0 || start >= len(s) {
		return "", nil
	}
	if len(args) == 3 {
		length := int(toFloat(args[2]))
		end := start + length
		if end > len(s) {
			end = len(s)
		}
		return s[start:end], nil
	}
	return s[start:], nil
}

func fnRound(args []interface{}) (interface{}, error) {
	val := toFloat(args[0])
	decimals := 0
	if len(args) == 2 {
		decimals = int(toFloat(args[1]))
	}
	mult := math.Pow(10, float64(decimals))
	return math.Round(val*mult) / mult, nil
}

func fnFloor(args []interface{}) (interface{}, error) {
	return math.Floor(toFloat(args[0])), nil
}

func fnCeil(args []interface{}) (interface{}, error) {
	return math.Ceil(toFloat(args[0])), nil
}

func fnAbs(args []interface{}) (interface{}, error) {
	return math.Abs(toFloat(args[0])), nil
}

func fnMin(args []interface{}) (interface{}, error) {
	a, b := toFloat(args[0]), toFloat(args[1])
	return math.Min(a, b), nil
}

func fnMax(args []interface{}) (interface{}, error) {
	a, b := toFloat(args[0]), toFloat(args[1])
	return math.Max(a, b), nil
}

func fnCoalesce(args []interface{}) (interface{}, error) {
	for _, arg := range args {
		if arg != nil {
			return arg, nil
		}
	}
	return nil, nil
}

func fnNow(args []interface{}) (interface{}, error) {
	return time.Now().UTC().Format(time.RFC3339), nil
}

func fnAge(args []interface{}) (interface{}, error) {
	ts := toString(args[0])
	if ts == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return nil, nil
	}
	return time.Since(t).Seconds(), nil
}

func fnFormatBytes(args []interface{}) (interface{}, error) {
	bytes := toFloat(args[0])
	units := []string{"B", "Ki", "Mi", "Gi", "Ti", "Pi"}
	idx := 0
	for bytes >= 1024 && idx < len(units)-1 {
		bytes /= 1024
		idx++
	}
	return fmt.Sprintf("%.2f%s", bytes, units[idx]), nil
}

func fnContains(args []interface{}) (interface{}, error) {
	return strings.Contains(toString(args[0]), toString(args[1])), nil
}

func fnStartsWith(args []interface{}) (interface{}, error) {
	return strings.HasPrefix(toString(args[0]), toString(args[1])), nil
}

func fnEndsWith(args []interface{}) (interface{}, error) {
	return strings.HasSuffix(toString(args[0]), toString(args[1])), nil
}

func fnToString(args []interface{}) (interface{}, error) {
	return toString(args[0]), nil
}

func fnToNumber(args []interface{}) (interface{}, error) {
	return toFloat(args[0]), nil
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case int64:
		return fmt.Sprintf("%d", val)
	case bool:
		return fmt.Sprintf("%t", val)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func toFloat(v interface{}) float64 {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case float64:
		return val
	case int64:
		return float64(val)
	case int:
		return float64(val)
	case bool:
		if val {
			return 1
		}
		return 0
	default:
		return 0
	}
}
