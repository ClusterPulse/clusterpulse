package aggregator

import "github.com/clusterpulse/cluster-controller/pkg/types"

// FilterOperator defines comparison operators for aggregation filters
type FilterOperator string

const (
	OpEquals      FilterOperator = "equals"
	OpNotEquals   FilterOperator = "notEquals"
	OpContains    FilterOperator = "contains"
	OpStartsWith  FilterOperator = "startsWith"
	OpEndsWith    FilterOperator = "endsWith"
	OpGreaterThan FilterOperator = "greaterThan"
	OpLessThan    FilterOperator = "lessThan"
	OpIn          FilterOperator = "in"
	OpMatches     FilterOperator = "matches"
)

// AggregationInput holds the data needed for aggregation computation
type AggregationInput struct {
	Resources    []types.CustomCollectedResource
	Aggregations []types.CompiledAggregation
}

// AggregationOutput holds computed aggregation results
type AggregationOutput struct {
	Values map[string]interface{}
}
