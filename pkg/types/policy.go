package types

// Policy state constants
const (
	PolicyStateActive   = "Active"
	PolicyStateInactive = "Inactive"
	PolicyStateError    = "Error"
	PolicyStateExpired  = "Expired"
)

// CompiledPolicy is the top-level compiled policy stored in Redis.
type CompiledPolicy struct {
	PolicyName           string                `json:"policy_name"`
	Namespace            string                `json:"namespace"`
	Priority             int                   `json:"priority"`
	Effect               string                `json:"effect"`
	Enabled              bool                  `json:"enabled"`
	Users                []string              `json:"users"`
	Groups               []string              `json:"groups"`
	ServiceAccounts      []string              `json:"service_accounts"`
	DefaultClusterAccess string                `json:"default_cluster_access"`
	ClusterRules         []CompiledClusterRule `json:"cluster_rules"`
	NotBefore            *string               `json:"not_before"`
	NotAfter             *string               `json:"not_after"`
	CompiledAt           string                `json:"compiled_at"`
	Hash                 string                `json:"hash"`
	CustomResourceTypes  []string              `json:"custom_resource_types"`
	RedisKey             string                `json:"-"`
}

// CompiledClusterSelector identifies which clusters a rule applies to
type CompiledClusterSelector struct {
	MatchNames   []string          `json:"matchNames,omitempty"`
	MatchPattern string            `json:"matchPattern,omitempty"`
	MatchLabels  map[string]string `json:"matchLabels,omitempty"`
}

// CompiledClusterRule is a compiled cluster access rule
type CompiledClusterRule struct {
	ClusterSelector CompiledClusterSelector  `json:"cluster_selector"`
	Permissions     map[string]bool          `json:"permissions"`
	Resources       []CompiledResourceFilter `json:"resources"`
}

// CompiledResourceFilter is a compiled resource filter for efficient evaluation.
// Patterns are stored as [][2]string where [0]=original, [1]=regex.
type CompiledResourceFilter struct {
	Type             string                          `json:"type"`
	Visibility       string                          `json:"visibility"`
	AllowedNames     []string                        `json:"allowed_names,omitempty"`
	DeniedNames      []string                        `json:"denied_names,omitempty"`
	NamePatterns     [][2]string                     `json:"name_patterns,omitempty"`
	DenyNamePatterns [][2]string                     `json:"deny_name_patterns,omitempty"`
	AllowedNS        []string                        `json:"allowed_ns,omitempty"`
	DeniedNS         []string                        `json:"denied_ns,omitempty"`
	NSPatterns       [][2]string                     `json:"ns_patterns,omitempty"`
	DenyNSPatterns   [][2]string                     `json:"deny_ns_patterns,omitempty"`
	Labels           map[string]string               `json:"labels,omitempty"`
	FieldFilters     map[string]*CompiledFieldFilter `json:"field_filters,omitempty"`
	AggregationRules *CompiledAggregationRules       `json:"aggregation_rules,omitempty"`
}

// CompiledFieldFilter is a compiled filter for a single custom resource field
type CompiledFieldFilter struct {
	AllowedLiterals []string    `json:"allowed_literals,omitempty"`
	DeniedLiterals  []string    `json:"denied_literals,omitempty"`
	AllowedPatterns [][2]string `json:"allowed_patterns,omitempty"`
	DeniedPatterns  [][2]string `json:"denied_patterns,omitempty"`
}

// CompiledAggregationRules controls which aggregations are visible
type CompiledAggregationRules struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}
