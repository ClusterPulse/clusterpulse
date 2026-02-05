// +kubebuilder:object:generate=true
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MetricSourceSpec defines the desired state of MetricSource
type MetricSourceSpec struct {
	// Source defines which Kubernetes resource to collect from
	Source MetricSourceTarget `json:"source"`

	// Fields defines what to extract from each resource instance
	Fields []FieldExtraction `json:"fields"`

	// Computed defines derived values calculated from extracted fields
	// +optional
	Computed []ComputedField `json:"computed,omitempty"`

	// Aggregations defines cluster-wide computations across all collected resources
	// +optional
	Aggregations []Aggregation `json:"aggregations,omitempty"`

	// Collection defines how and when to collect resources
	// +optional
	Collection CollectionConfig `json:"collection,omitempty"`

	// RBAC defines how this resource integrates with access policies
	// +optional
	RBAC MetricSourceRBAC `json:"rbac,omitempty"`
}

// MetricSourceTarget identifies the Kubernetes resource to collect
type MetricSourceTarget struct {
	// APIVersion of the target resource (e.g., "v1", "apps/v1")
	APIVersion string `json:"apiVersion"`

	// Kind of the target resource (e.g., "PersistentVolumeClaim", "Deployment")
	Kind string `json:"kind"`

	// Scope determines collection behavior: Namespaced or Cluster
	// +kubebuilder:validation:Enum=Namespaced;Cluster
	// +kubebuilder:default=Namespaced
	Scope string `json:"scope,omitempty"`

	// Namespaces defines which namespaces to collect from (only for Namespaced scope)
	// +optional
	Namespaces *NamespaceSelector `json:"namespaces,omitempty"`

	// LabelSelector filters resources by labels
	// +optional
	LabelSelector *metav1.LabelSelector `json:"labelSelector,omitempty"`
}

// NamespaceSelector defines namespace inclusion/exclusion patterns
type NamespaceSelector struct {
	// Include specifies namespace patterns to include (supports wildcards)
	// +optional
	Include []string `json:"include,omitempty"`

	// Exclude specifies namespace patterns to exclude (takes precedence over include)
	// +optional
	Exclude []string `json:"exclude,omitempty"`
}

// FieldExtraction defines how to extract a single field from a resource
type FieldExtraction struct {
	// Name is the identifier for this extracted field
	Name string `json:"name"`

	// Path is the JSONPath expression to extract the value
	Path string `json:"path"`

	// Type specifies how to interpret the extracted value
	// +kubebuilder:validation:Enum=string;integer;float;boolean;quantity;timestamp;arrayLength
	// +kubebuilder:default=string
	Type string `json:"type,omitempty"`

	// Default value when the path doesn't exist
	// +optional
	Default *string `json:"default,omitempty"`
}

// ComputedField defines a derived value calculated from extracted fields
type ComputedField struct {
	// Name is the identifier for this computed field
	Name string `json:"name"`

	// Expression defines the computation using the expression language
	Expression string `json:"expression"`

	// Type specifies the result type
	// +kubebuilder:validation:Enum=string;integer;float;boolean
	// +kubebuilder:default=float
	Type string `json:"type,omitempty"`
}

// Aggregation defines a cluster-wide computation across all collected resources
type Aggregation struct {
	// Name is the identifier for this aggregation
	Name string `json:"name"`

	// Field to aggregate (not required for count)
	// +optional
	Field string `json:"field,omitempty"`

	// Function specifies the aggregation operation
	// +kubebuilder:validation:Enum=count;sum;avg;min;max;percentile;distinct
	Function string `json:"function"`

	// Filter applies a condition before aggregating
	// +optional
	Filter *AggregationFilter `json:"filter,omitempty"`

	// GroupBy produces aggregations grouped by this field's values
	// +optional
	GroupBy string `json:"groupBy,omitempty"`

	// Percentile value (only used when function is percentile)
	// +optional
	Percentile *int `json:"percentile,omitempty"`
}

// AggregationFilter defines a condition for filtering before aggregation
type AggregationFilter struct {
	// Field to filter on
	Field string `json:"field"`

	// Operator for comparison
	// +kubebuilder:validation:Enum=equals;notEquals;contains;startsWith;endsWith;greaterThan;lessThan;in;matches
	Operator string `json:"operator"`

	// Value to compare against
	Value string `json:"value"`
}

// CollectionConfig defines collection behavior parameters
type CollectionConfig struct {
	// IntervalSeconds between collection cycles (minimum 30)
	// +kubebuilder:validation:Minimum=30
	// +kubebuilder:default=60
	IntervalSeconds int32 `json:"intervalSeconds,omitempty"`

	// TimeoutSeconds for per-cluster collection
	// +kubebuilder:validation:Minimum=5
	// +kubebuilder:default=30
	TimeoutSeconds int32 `json:"timeoutSeconds,omitempty"`

	// MaxResources limits the number of resources collected per cluster
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=5000
	MaxResources int32 `json:"maxResources,omitempty"`

	// BatchSize for API pagination
	// +kubebuilder:validation:Minimum=10
	// +kubebuilder:default=500
	BatchSize int32 `json:"batchSize,omitempty"`

	// RetryAttempts on transient failures
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=3
	RetryAttempts int32 `json:"retryAttempts,omitempty"`

	// Parallelism for concurrent field extractions
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=3
	Parallelism int32 `json:"parallelism,omitempty"`
}

// MetricSourceRBAC defines how this resource integrates with access policies
type MetricSourceRBAC struct {
	// ResourceTypeName is the unique identifier for policy references
	ResourceTypeName string `json:"resourceTypeName"`

	// FilterableFields lists fields that can be filtered in policies
	// +optional
	FilterableFields []string `json:"filterableFields,omitempty"`

	// FilterAggregations controls whether aggregations respect RBAC filtering
	// +kubebuilder:default=true
	FilterAggregations bool `json:"filterAggregations,omitempty"`
}

// MetricSourceStatus defines the observed state of MetricSource
type MetricSourceStatus struct {
	// Phase indicates the current state
	// +kubebuilder:validation:Enum=Active;Error;Disabled
	Phase string `json:"phase,omitempty"`

	// LastCollectionTime is when collection last completed
	// +optional
	LastCollectionTime *metav1.Time `json:"lastCollectionTime,omitempty"`

	// LastCollectionDuration is how long the last collection took
	// +optional
	LastCollectionDuration string `json:"lastCollectionDuration,omitempty"`

	// ResourcesCollected is the total count from last collection
	ResourcesCollected int `json:"resourcesCollected,omitempty"`

	// ClustersCollected is the number of clusters successfully collected from
	ClustersCollected int `json:"clustersCollected,omitempty"`

	// ErrorsLastRun is the count of errors in the last collection cycle
	ErrorsLastRun int `json:"errorsLastRun,omitempty"`

	// Message provides additional status information
	// +optional
	Message string `json:"message,omitempty"`

	// FieldValidation reports validation status for each field
	// +optional
	FieldValidation []FieldValidationStatus `json:"fieldValidation,omitempty"`

	// Conditions represent the latest observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// FieldValidationStatus reports the validation status of a single field
type FieldValidationStatus struct {
	// Field name
	Field string `json:"field"`

	// Status of validation
	// +kubebuilder:validation:Enum=valid;invalid;warning
	Status string `json:"status"`

	// Message provides details if status is not valid
	// +optional
	Message string `json:"message,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ms;metricsrc
// +kubebuilder:printcolumn:name="Source Kind",type="string",JSONPath=".spec.source.kind"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Resources",type="integer",JSONPath=".status.resourcesCollected"
// +kubebuilder:printcolumn:name="Clusters",type="integer",JSONPath=".status.clustersCollected"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// MetricSource defines a custom resource collection configuration
type MetricSource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MetricSourceSpec   `json:"spec,omitempty"`
	Status MetricSourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MetricSourceList contains a list of MetricSource
type MetricSourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MetricSource `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MetricSource{}, &MetricSourceList{})
}
