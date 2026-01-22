package types

import (
	"regexp"
	"time"
)

// CompiledMetricSource is the internal representation optimized for collection
type CompiledMetricSource struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`

	Source            CompiledSourceTarget   `json:"source"`
	Fields            []CompiledField        `json:"fields"`
	Computed          []CompiledComputation  `json:"computed,omitempty"`
	Aggregations      []CompiledAggregation  `json:"aggregations,omitempty"`
	Collection        CompiledCollectionConf `json:"collection"`
	RBAC              CompiledRBAC           `json:"rbac"`
	CompiledAt        string                 `json:"compiledAt"`
	Hash              string                 `json:"hash"`
	FieldNameToIndex  map[string]int         `json:"-"`
	NamespacePatterns *CompiledPatterns      `json:"-"`
}

// CompiledSourceTarget contains the parsed source configuration
type CompiledSourceTarget struct {
	APIVersion    string           `json:"apiVersion"`
	Kind          string           `json:"kind"`
	Scope         string           `json:"scope"`
	Group         string           `json:"group"`
	Version       string           `json:"version"`
	Resource      string           `json:"resource"`
	LabelSelector string           `json:"labelSelector,omitempty"`
	Namespaces    *NamespaceConfig `json:"namespaces,omitempty"`
}

// NamespaceConfig holds namespace include/exclude patterns
type NamespaceConfig struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// CompiledPatterns holds pre-compiled regex patterns for namespace matching
type CompiledPatterns struct {
	Include []*regexp.Regexp
	Exclude []*regexp.Regexp
}

// CompiledField represents a field extraction with parsed path
type CompiledField struct {
	Name         string   `json:"name"`
	Path         string   `json:"path"`
	PathSegments []string `json:"pathSegments"`
	Type         string   `json:"type"`
	Default      *string  `json:"default,omitempty"`
	Index        int      `json:"index"`
}

// CompiledComputation represents a computed field with parsed expression
type CompiledComputation struct {
	Name       string      `json:"name"`
	Expression string      `json:"expression"`
	Type       string      `json:"type"`
	Compiled   interface{} `json:"-"` // *expression.CompiledExpression at runtime
}

// CompiledAggregation represents an aggregation with parsed filter
type CompiledAggregation struct {
	Name       string             `json:"name"`
	Field      string             `json:"field,omitempty"`
	Function   string             `json:"function"`
	Filter     *CompiledAggFilter `json:"filter,omitempty"`
	GroupBy    string             `json:"groupBy,omitempty"`
	Percentile int                `json:"percentile,omitempty"`
}

// CompiledAggFilter represents a pre-processed aggregation filter
type CompiledAggFilter struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// CompiledCollectionConf holds collection parameters with defaults applied
type CompiledCollectionConf struct {
	IntervalSeconds int32 `json:"intervalSeconds"`
	TimeoutSeconds  int32 `json:"timeoutSeconds"`
	MaxResources    int32 `json:"maxResources"`
	BatchSize       int32 `json:"batchSize"`
	RetryAttempts   int32 `json:"retryAttempts"`
	Parallelism     int32 `json:"parallelism"`
}

// CompiledRBAC holds RBAC configuration for policy integration.
// Resource identity (_namespace, _name) is always collected automatically.
type CompiledRBAC struct {
	ResourceTypeName   string   `json:"resourceTypeName"`
	FilterableFields   []string `json:"filterableFields,omitempty"`
	FilterAggregations bool     `json:"filterAggregations"`
}

// CustomCollectedResource represents a single resource instance with extracted values
type CustomCollectedResource struct {
	ID        string                 `json:"_id"`
	Namespace string                 `json:"_namespace,omitempty"`
	Name      string                 `json:"_name"`
	Labels    map[string]string      `json:"_labels,omitempty"`
	Values    map[string]interface{} `json:"values"`
}

// CustomResourceCollection holds all collected resources for a cluster/source combination
type CustomResourceCollection struct {
	CollectedAt   time.Time                 `json:"collectedAt"`
	SourceID      string                    `json:"sourceId"`
	ClusterName   string                    `json:"clusterName"`
	ResourceCount int                       `json:"resourceCount"`
	Truncated     bool                      `json:"truncated"`
	DurationMs    int64                     `json:"durationMs"`
	Resources     []CustomCollectedResource `json:"resources"`
}

// AggregationResults holds computed aggregation values for a cluster/source
type AggregationResults struct {
	ComputedAt time.Time              `json:"computedAt"`
	SourceID   string                 `json:"sourceId"`
	DurationMs int64                  `json:"durationMs"`
	Values     map[string]interface{} `json:"values"`
}

// CollectionMetadata holds metadata about the last collection run
type CollectionMetadata struct {
	SourceID           string    `json:"sourceId"`
	ClusterName        string    `json:"clusterName"`
	LastCollectionTime time.Time `json:"lastCollectionTime"`
	DurationMs         int64     `json:"durationMs"`
	ResourceCount      int       `json:"resourceCount"`
	Truncated          bool      `json:"truncated"`
	ErrorCount         int       `json:"errorCount"`
	LastError          string    `json:"lastError,omitempty"`
}

// FieldType constants
const (
	FieldTypeString      = "string"
	FieldTypeInteger     = "integer"
	FieldTypeFloat       = "float"
	FieldTypeBoolean     = "boolean"
	FieldTypeQuantity    = "quantity"
	FieldTypeTimestamp   = "timestamp"
	FieldTypeArrayLength = "arrayLength"
)

// AggregationFunction constants
const (
	AggFunctionCount      = "count"
	AggFunctionSum        = "sum"
	AggFunctionAvg        = "avg"
	AggFunctionMin        = "min"
	AggFunctionMax        = "max"
	AggFunctionPercentile = "percentile"
	AggFunctionDistinct   = "distinct"
)

// FilterOperator constants
const (
	FilterOpEquals      = "equals"
	FilterOpNotEquals   = "notEquals"
	FilterOpContains    = "contains"
	FilterOpStartsWith  = "startsWith"
	FilterOpEndsWith    = "endsWith"
	FilterOpGreaterThan = "greaterThan"
	FilterOpLessThan    = "lessThan"
	FilterOpIn          = "in"
	FilterOpMatches     = "matches"
)
