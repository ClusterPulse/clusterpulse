package types

// Policy state constants
const (
	PolicyStateActive   = "Active"
	PolicyStateInactive = "Inactive"
	PolicyStateError    = "Error"
	PolicyStateExpired  = "Expired"
)

// CompiledPolicy is the top-level compiled policy stored in Redis.
// JSON tags use snake_case to match the Python to_dict() format exactly.
type CompiledPolicy struct {
	PolicyName           string                    `json:"policy_name"`
	Namespace            string                    `json:"namespace"`
	Priority             int                       `json:"priority"`
	Effect               string                    `json:"effect"`
	Enabled              bool                      `json:"enabled"`
	Users                []string                  `json:"users"`
	Groups               []string                  `json:"groups"`
	ServiceAccounts      []string                  `json:"service_accounts"`
	DefaultClusterAccess string                    `json:"default_cluster_access"`
	ClusterRules         []CompiledClusterRule     `json:"cluster_rules"`
	NotBefore            *string                   `json:"not_before"`
	NotAfter             *string                   `json:"not_after"`
	AuditConfig          map[string]bool           `json:"audit_config"`
	CompiledAt           string                    `json:"compiled_at"`
	Hash                 string                    `json:"hash"`
	CustomResourceTypes  []string                  `json:"custom_resource_types"`
}

// CompiledClusterRule is a compiled cluster access rule
type CompiledClusterRule struct {
	ClusterSelector map[string]any                `json:"cluster_selector"`
	Permissions     map[string]bool                       `json:"permissions"`
	NodeFilter      *CompiledResourceFilter               `json:"node_filter"`
	OperatorFilter  *CompiledResourceFilter               `json:"operator_filter"`
	NamespaceFilter *CompiledResourceFilter               `json:"namespace_filter"`
	PodFilter       *CompiledResourceFilter               `json:"pod_filter"`
	CustomResources map[string]*CompiledCustomResourceFilter `json:"custom_resources"`
}

// CompiledResourceFilter is a compiled resource filter for efficient evaluation.
// Patterns are stored as [][2]string where [0]=original, [1]=regex.
type CompiledResourceFilter struct {
	Visibility        string                 `json:"visibility"`
	AllowedPatterns   [][2]string            `json:"allowed_patterns"`
	DeniedPatterns    [][2]string            `json:"denied_patterns"`
	AllowedLiterals   []string               `json:"allowed_literals"`
	DeniedLiterals    []string               `json:"denied_literals"`
	LabelSelectors    map[string]string      `json:"label_selectors"`
	AdditionalFilters map[string]any `json:"additional_filters"`
}

// CompiledFieldFilter is a compiled filter for a single custom resource field
type CompiledFieldFilter struct {
	FieldName       string      `json:"field_name"`
	AllowedPatterns [][2]string `json:"allowed_patterns"`
	DeniedPatterns  [][2]string `json:"denied_patterns"`
	AllowedLiterals []string    `json:"allowed_literals"`
	DeniedLiterals  []string    `json:"denied_literals"`
	Conditions      [][2]any `json:"conditions"`
}

// CompiledCustomResourceFilter is a compiled filter for a custom resource type
type CompiledCustomResourceFilter struct {
	ResourceTypeName string                       `json:"resource_type_name"`
	Visibility       string                       `json:"visibility"`
	NamespaceFilter  *CompiledResourceFilter      `json:"namespace_filter"`
	NameFilter       *CompiledResourceFilter      `json:"name_filter"`
	FieldFilters     map[string]*CompiledFieldFilter `json:"field_filters"`
	AggregationRules *CompiledAggregationRules    `json:"aggregation_rules"`
}

// CompiledAggregationRules controls which aggregations are visible
type CompiledAggregationRules struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}
