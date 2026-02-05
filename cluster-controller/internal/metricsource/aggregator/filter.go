package aggregator

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/clusterpulse/cluster-controller/pkg/types"
)

// FilterEvaluator evaluates filter conditions against resource values
type FilterEvaluator struct {
	compiledPatterns map[string]*regexp.Regexp
}

// NewFilterEvaluator creates a new filter evaluator
func NewFilterEvaluator() *FilterEvaluator {
	return &FilterEvaluator{
		compiledPatterns: make(map[string]*regexp.Regexp),
	}
}

// Matches checks if a resource passes the filter condition
func (f *FilterEvaluator) Matches(resource *types.CustomCollectedResource, filter *types.CompiledAggFilter) bool {
	if filter == nil {
		return true
	}

	fieldValue, ok := resource.Values[filter.Field]
	if !ok {
		return false
	}

	return f.evaluate(fieldValue, FilterOperator(filter.Operator), filter.Value)
}

func (f *FilterEvaluator) evaluate(fieldValue interface{}, op FilterOperator, filterValue string) bool {
	if fieldValue == nil {
		return false
	}

	switch op {
	case OpEquals:
		return f.equals(fieldValue, filterValue)
	case OpNotEquals:
		return !f.equals(fieldValue, filterValue)
	case OpContains:
		return strings.Contains(f.toString(fieldValue), filterValue)
	case OpStartsWith:
		return strings.HasPrefix(f.toString(fieldValue), filterValue)
	case OpEndsWith:
		return strings.HasSuffix(f.toString(fieldValue), filterValue)
	case OpGreaterThan:
		return f.toFloat(fieldValue) > f.parseFloat(filterValue)
	case OpLessThan:
		return f.toFloat(fieldValue) < f.parseFloat(filterValue)
	case OpIn:
		return f.inList(fieldValue, filterValue)
	case OpMatches:
		return f.matchesRegex(fieldValue, filterValue)
	default:
		return false
	}
}

func (f *FilterEvaluator) equals(fieldValue interface{}, filterValue string) bool {
	switch v := fieldValue.(type) {
	case string:
		return v == filterValue
	case float64:
		fv, err := strconv.ParseFloat(filterValue, 64)
		return err == nil && v == fv
	case int64:
		iv, err := strconv.ParseInt(filterValue, 10, 64)
		return err == nil && v == iv
	case bool:
		return strconv.FormatBool(v) == filterValue
	default:
		return f.toString(fieldValue) == filterValue
	}
}

func (f *FilterEvaluator) toString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		if val == float64(int64(val)) {
			return strconv.FormatInt(int64(val), 10)
		}
		return strconv.FormatFloat(val, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(val, 10)
	case bool:
		return strconv.FormatBool(val)
	default:
		return ""
	}
}

func (f *FilterEvaluator) toFloat(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case int64:
		return float64(val)
	case string:
		fv, _ := strconv.ParseFloat(val, 64)
		return fv
	default:
		return 0
	}
}

func (f *FilterEvaluator) parseFloat(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

func (f *FilterEvaluator) inList(fieldValue interface{}, filterValue string) bool {
	strVal := f.toString(fieldValue)
	values := strings.Split(strings.Trim(filterValue, "[]"), ",")
	for _, v := range values {
		if strings.TrimSpace(v) == strVal {
			return true
		}
	}
	return false
}

func (f *FilterEvaluator) matchesRegex(fieldValue interface{}, pattern string) bool {
	regex, ok := f.compiledPatterns[pattern]
	if !ok {
		var err error
		regex, err = regexp.Compile(pattern)
		if err != nil {
			return false
		}
		f.compiledPatterns[pattern] = regex
	}
	return regex.MatchString(f.toString(fieldValue))
}
