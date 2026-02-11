// +kubebuilder:object:generate=true
package v1alpha1

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MonitorAccessPolicySpec defines the desired state of MonitorAccessPolicy
type MonitorAccessPolicySpec struct {
	// Identity defines who this policy applies to
	Identity PolicyIdentity `json:"identity"`

	// Access defines the effect and enablement of this policy
	Access PolicyAccess `json:"access"`

	// Scope defines what resources are accessible
	Scope PolicyScope `json:"scope"`

	// Lifecycle defines validity periods
	// +optional
	Lifecycle *PolicyLifecycle `json:"lifecycle,omitempty"`

	// Operations defines audit and operational settings
	// +optional
	Operations *PolicyOperations `json:"operations,omitempty"`
}

// PolicyIdentity defines who this policy applies to
type PolicyIdentity struct {
	// Subjects specifies the users, groups, and service accounts
	Subjects PolicySubjects `json:"subjects"`

	// Priority determines evaluation order (higher = first)
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10000
	// +kubebuilder:default=100
	Priority int `json:"priority,omitempty"`
}

// PolicySubjects specifies the identities this policy applies to
type PolicySubjects struct {
	// Users is a list of usernames or email addresses
	// +optional
	Users []string `json:"users,omitempty"`

	// Groups is a list of group names
	// +optional
	Groups []string `json:"groups,omitempty"`

	// ServiceAccounts is a list of service account references
	// +optional
	ServiceAccounts []PolicyServiceAccount `json:"serviceAccounts,omitempty"`
}

// PolicyServiceAccount references a Kubernetes service account
type PolicyServiceAccount struct {
	// Name of the service account
	Name string `json:"name"`

	// Namespace of the service account
	// +kubebuilder:default=default
	Namespace string `json:"namespace,omitempty"`
}

// PolicyAccess defines the effect and enablement
type PolicyAccess struct {
	// Effect is Allow or Deny
	// +kubebuilder:validation:Enum=Allow;Deny
	Effect string `json:"effect"`

	// Enabled indicates whether this policy is active
	// +kubebuilder:default=true
	Enabled *bool `json:"enabled,omitempty"`
}

// PolicyScope defines what resources are accessible
type PolicyScope struct {
	// Clusters defines cluster access rules
	Clusters PolicyClusters `json:"clusters"`

	// Restrictions defines global restrictions
	// +optional
	Restrictions *apiextensionsv1.JSON `json:"restrictions,omitempty"`
}

// PolicyClusters defines cluster-level access
type PolicyClusters struct {
	// Default access for clusters not matching any rule
	// +kubebuilder:validation:Enum=allow;deny;none
	// +kubebuilder:default=none
	Default string `json:"default,omitempty"`

	// Rules defines per-cluster access rules
	// +optional
	Rules []PolicyClusterRule `json:"rules,omitempty"`
}

// PolicyClusterRule defines access for a set of clusters
type PolicyClusterRule struct {
	// Selector matches clusters by name, pattern, or labels
	Selector PolicyClusterSelector `json:"selector"`

	// Permissions defines what actions are allowed
	// +optional
	Permissions map[string]bool `json:"permissions,omitempty"`

	// Resources defines resource-level filtering
	// +optional
	Resources *PolicyResources `json:"resources,omitempty"`
}

// PolicyClusterSelector identifies which clusters a rule applies to
type PolicyClusterSelector struct {
	// MatchLabels selects clusters by labels
	// +optional
	MatchLabels map[string]string `json:"matchLabels,omitempty"`

	// MatchNames selects clusters by exact name or wildcard pattern
	// +optional
	MatchNames []string `json:"matchNames,omitempty"`

	// MatchPattern selects clusters by regex
	// +optional
	MatchPattern string `json:"matchPattern,omitempty"`
}

// PolicyResources defines resource-level filtering within a cluster rule
type PolicyResources struct {
	// Nodes defines node visibility and filters
	// +optional
	Nodes *ResourceConfig `json:"nodes,omitempty"`

	// Operators defines operator visibility and filters
	// +optional
	Operators *ResourceConfig `json:"operators,omitempty"`

	// Namespaces defines namespace visibility and filters
	// +optional
	Namespaces *ResourceConfig `json:"namespaces,omitempty"`

	// Pods defines pod visibility and filters
	// +optional
	Pods *ResourceConfig `json:"pods,omitempty"`

	// Custom defines filters for custom resource types keyed by resourceTypeName
	// +optional
	Custom map[string]CustomResourceConfig `json:"custom,omitempty"`
}

// ResourceConfig defines visibility and filters for a built-in resource type
type ResourceConfig struct {
	// Visibility level
	// +kubebuilder:validation:Enum=all;none;filtered
	// +kubebuilder:default=all
	Visibility string `json:"visibility,omitempty"`

	// Filters defines the filter criteria
	// +optional
	Filters *apiextensionsv1.JSON `json:"filters,omitempty"`
}

// CustomResourceConfig defines filter configuration for a custom resource type
type CustomResourceConfig struct {
	// Visibility level for this custom resource type
	// +kubebuilder:validation:Enum=all;none;filtered
	// +kubebuilder:default=all
	Visibility string `json:"visibility,omitempty"`

	// Filters defines filter criteria (namespaces, names, fields)
	// +optional
	Filters *CustomResourceFilters `json:"filters,omitempty"`

	// Aggregations controls which aggregations are visible
	// +optional
	Aggregations *AggregationVisibility `json:"aggregations,omitempty"`
}

// CustomResourceFilters defines filter criteria for custom resources
type CustomResourceFilters struct {
	// Namespaces defines namespace-based filtering
	// +optional
	Namespaces *PatternFilter `json:"namespaces,omitempty"`

	// Names defines resource name filtering
	// +optional
	Names *PatternFilter `json:"names,omitempty"`

	// Fields defines field-based filters keyed by field name
	// +optional
	Fields map[string]FieldFilterConfig `json:"fields,omitempty"`
}

// PatternFilter defines allowed/denied patterns
type PatternFilter struct {
	// Allowed patterns (supports wildcards)
	// +optional
	Allowed []string `json:"allowed,omitempty"`

	// Denied patterns
	// +optional
	Denied []string `json:"denied,omitempty"`
}

// FieldFilterConfig defines a filter for a specific field
type FieldFilterConfig struct {
	// Allowed values or patterns
	// +optional
	Allowed []apiextensionsv1.JSON `json:"allowed,omitempty"`

	// Denied values or patterns
	// +optional
	Denied []apiextensionsv1.JSON `json:"denied,omitempty"`

	// Conditions defines operator-based filter conditions
	// +optional
	Conditions []FieldCondition `json:"conditions,omitempty"`
}

// FieldCondition defines an operator-based filter condition
type FieldCondition struct {
	// Operator for comparison
	// +kubebuilder:validation:Enum=equals;notEquals;contains;startsWith;endsWith;greaterThan;lessThan;in;notIn;matches
	Operator string `json:"operator"`

	// Value to compare against
	Value apiextensionsv1.JSON `json:"value"`
}

// AggregationVisibility controls which aggregations are visible
type AggregationVisibility struct {
	// Include only these aggregations (takes precedence over exclude)
	// +optional
	Include []string `json:"include,omitempty"`

	// Exclude these aggregations
	// +optional
	Exclude []string `json:"exclude,omitempty"`
}

// PolicyLifecycle defines validity periods
type PolicyLifecycle struct {
	// Validity defines time-based validity
	// +optional
	Validity *PolicyValidity `json:"validity,omitempty"`
}

// PolicyValidity defines time bounds for the policy
type PolicyValidity struct {
	// NotBefore - policy is not valid before this time
	// +optional
	NotBefore string `json:"notBefore,omitempty"`

	// NotAfter - policy expires after this time
	// +optional
	NotAfter string `json:"notAfter,omitempty"`
}

// PolicyOperations defines audit and operational settings
type PolicyOperations struct {
	// Audit defines audit configuration
	// +optional
	Audit *PolicyAudit `json:"audit,omitempty"`
}

// PolicyAudit defines audit settings
type PolicyAudit struct {
	// LogAccess logs all access attempts
	// +kubebuilder:default=false
	LogAccess bool `json:"logAccess,omitempty"`

	// RequireReason requires a reason for access
	// +kubebuilder:default=false
	RequireReason bool `json:"requireReason,omitempty"`
}

// MonitorAccessPolicyStatus defines the observed state of MonitorAccessPolicy
type MonitorAccessPolicyStatus struct {
	// State indicates the current policy state
	// +kubebuilder:validation:Enum=Active;Inactive;Error;Pending;Expired
	// +kubebuilder:default=Pending
	State string `json:"state,omitempty"`

	// Message provides additional status information
	// +optional
	Message string `json:"message,omitempty"`

	// CompiledAt is when the policy was last compiled
	// +optional
	CompiledAt string `json:"compiledAt,omitempty"`

	// Hash is the spec hash of the compiled policy
	// +optional
	Hash string `json:"hash,omitempty"`

	// AffectedUsers is the count of users affected by this policy
	AffectedUsers int `json:"affectedUsers,omitempty"`

	// AffectedGroups is the count of groups affected by this policy
	AffectedGroups int `json:"affectedGroups,omitempty"`

	// AffectedServiceAccounts is the count of SAs affected by this policy
	AffectedServiceAccounts int `json:"affectedServiceAccounts,omitempty"`

	// CustomResourceTypes is the count of custom resource types referenced
	CustomResourceTypes int `json:"customResourceTypes,omitempty"`

	// CustomResourceWarnings lists warnings about custom resource references
	// +optional
	CustomResourceWarnings []string `json:"customResourceWarnings,omitempty"`

	// EvaluationCount tracks how many times this policy has been evaluated
	// +kubebuilder:default=0
	EvaluationCount int `json:"evaluationCount,omitempty"`

	// LastEvaluated is when this policy was last evaluated
	// +optional
	LastEvaluated string `json:"lastEvaluated,omitempty"`

	// Conditions represent the latest observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=map;policy
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +kubebuilder:printcolumn:name="Effect",type="string",JSONPath=".spec.access.effect"
// +kubebuilder:printcolumn:name="Priority",type="integer",JSONPath=".spec.identity.priority"
// +kubebuilder:printcolumn:name="Users",type="integer",JSONPath=".status.affectedUsers"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// MonitorAccessPolicy defines an RBAC policy for cluster monitoring access
type MonitorAccessPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MonitorAccessPolicySpec   `json:"spec,omitempty"`
	Status MonitorAccessPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MonitorAccessPolicyList contains a list of MonitorAccessPolicy
type MonitorAccessPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MonitorAccessPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MonitorAccessPolicy{}, &MonitorAccessPolicyList{})
}
