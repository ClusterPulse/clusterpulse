// +kubebuilder:object:generate=true
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ResourceMonitorSpec defines a Kubernetes resource type to collect across all connected clusters
type ResourceMonitorSpec struct {
	// DisplayName is a human-friendly name for UI display
	DisplayName string `json:"displayName,omitempty"`

	// Description provides additional context about what this monitor collects
	Description string `json:"description,omitempty"`

	// Category for grouping in UI (e.g., "Configuration", "Workloads", "Networking")
	Category string `json:"category,omitempty"`

	// Target defines the Kubernetes resource to monitor
	Target ResourceTarget `json:"target"`

	// Collection settings control how and when resources are collected
	Collection CollectionSettings `json:"collection,omitempty"`

	// Schema defines which fields to extract from each resource instance
	Schema SchemaDefinition `json:"schema,omitempty"`

	// Health defines how to determine health status from resource fields
	Health *HealthMapping `json:"health,omitempty"`
}

// ResourceTarget identifies the Kubernetes resource type to monitor
type ResourceTarget struct {
	// APIVersion of the resource (e.g., "v1", "apps/v1", "argoproj.io/v1alpha1")
	APIVersion string `json:"apiVersion"`

	// Kind of the resource (e.g., "ConfigMap", "Deployment", "Workflow")
	Kind string `json:"kind"`
}

// CollectionSettings control resource collection behavior
type CollectionSettings struct {
	// Enabled controls whether collection is active (default: true)
	Enabled *bool `json:"enabled,omitempty"`

	// IntervalSeconds between collection runs (minimum: 30, default: 60)
	IntervalSeconds int32 `json:"intervalSeconds,omitempty"`

	// Limits prevent memory issues on large clusters
	Limits CollectionLimits `json:"limits,omitempty"`

	// NamespaceSelector filters which namespaces to collect from
	NamespaceSelector *NamespaceSelector `json:"namespaceSelector,omitempty"`

	// ResourceSelector filters which resources to collect using label selectors
	ResourceSelector *metav1.LabelSelector `json:"resourceSelector,omitempty"`
}

// CollectionLimits define resource collection boundaries
type CollectionLimits struct {
	// PerNamespace limits resources collected per namespace (0 = unlimited)
	PerNamespace int32 `json:"perNamespace,omitempty"`

	// PerCluster limits total resources collected per cluster (0 = unlimited)
	PerCluster int32 `json:"perCluster,omitempty"`
}

// NamespaceSelector defines which namespaces to include or exclude
type NamespaceSelector struct {
	// Include patterns (glob-style) - empty means include all
	Include []string `json:"include,omitempty"`

	// Exclude patterns (glob-style) - takes precedence over include
	Exclude []string `json:"exclude,omitempty"`

	// MatchLabels selects namespaces by labels
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// SchemaDefinition defines fields to extract from resources
type SchemaDefinition struct {
	// IncludeAnnotations controls whether annotations are collected (can be large)
	IncludeAnnotations bool `json:"includeAnnotations,omitempty"`

	// Fields defines custom fields to extract using JSONPath
	Fields []FieldDefinition `json:"fields,omitempty"`
}

// FieldDefinition describes a field to extract from resources
type FieldDefinition struct {
	// Name is the field name in the output (must be unique, cannot be reserved names)
	Name string `json:"name"`

	// Path is a JSONPath expression to extract the value
	Path string `json:"path"`

	// Type hint for storage and display (string, boolean, integer, object, array, timestamp)
	Type string `json:"type,omitempty"`

	// Transform applies a transformation to the extracted value
	// Supported: keys, count, first, last, join, exists
	Transform string `json:"transform,omitempty"`

	// Default value if the path doesn't match
	Default string `json:"default,omitempty"`
}

// HealthMapping defines how to determine resource health from field values
type HealthMapping struct {
	// Field to use for health determination (must be defined in schema or be a standard field)
	Field string `json:"field,omitempty"`

	// Mapping of field values to health states
	Mapping HealthStateMapping `json:"mapping,omitempty"`

	// Expression for complex health evaluation (alternative to field+mapping)
	Expression string `json:"expression,omitempty"`
}

// HealthStateMapping maps field values to health states
type HealthStateMapping struct {
	// Healthy values indicate the resource is functioning correctly
	Healthy []string `json:"healthy,omitempty"`

	// Degraded values indicate the resource has issues but is operational
	Degraded []string `json:"degraded,omitempty"`

	// Unhealthy values indicate the resource is not functioning
	Unhealthy []string `json:"unhealthy,omitempty"`
}

// ResourceMonitorStatus defines the observed state of ResourceMonitor
type ResourceMonitorStatus struct {
	// State indicates the current state of this monitor
	State string `json:"state,omitempty"`

	// LastValidated is when the monitor spec was last validated
	LastValidated *metav1.Time `json:"lastValidated,omitempty"`

	// Message provides additional status information
	Message string `json:"message,omitempty"`

	// Clusters shows per-cluster collection status
	Clusters []ClusterCollectionStatus `json:"clusters,omitempty"`
}

// ClusterCollectionStatus shows collection status for a specific cluster
type ClusterCollectionStatus struct {
	// Name of the cluster
	Name string `json:"name"`

	// LastCollected is when resources were last collected from this cluster
	LastCollected *metav1.Time `json:"lastCollected,omitempty"`

	// ResourceCount is the number of resources collected
	ResourceCount int `json:"resourceCount,omitempty"`

	// Error message if collection failed
	Error string `json:"error,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=rm;resmon
// +kubebuilder:printcolumn:name="Display Name",type="string",JSONPath=".spec.displayName"
// +kubebuilder:printcolumn:name="API Version",type="string",JSONPath=".spec.target.apiVersion"
// +kubebuilder:printcolumn:name="Kind",type="string",JSONPath=".spec.target.kind"
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ResourceMonitor is the Schema for the resourcemonitors API
type ResourceMonitor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ResourceMonitorSpec   `json:"spec,omitempty"`
	Status ResourceMonitorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ResourceMonitorList contains a list of ResourceMonitor
type ResourceMonitorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ResourceMonitor `json:"items"`
}

// IsEnabled returns whether collection is enabled for this monitor
func (r *ResourceMonitor) IsEnabled() bool {
	if r.Spec.Collection.Enabled == nil {
		return true // default to enabled
	}
	return *r.Spec.Collection.Enabled
}

// GetInterval returns the collection interval with minimum enforcement
func (r *ResourceMonitor) GetInterval() int32 {
	interval := r.Spec.Collection.IntervalSeconds
	if interval < 30 {
		return 60 // default
	}
	return interval
}

func init() {
	SchemeBuilder.Register(&ResourceMonitor{}, &ResourceMonitorList{})
}
