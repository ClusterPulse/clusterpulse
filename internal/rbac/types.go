package rbac

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Action represents system actions.
type Action string

const (
	ActionView        Action = "view"
	ActionViewMetrics Action = "view_metrics"
)

// AllActions returns all valid actions for iteration.
var AllActions = []Action{
	ActionView, ActionViewMetrics,
}

// ResourceType represents resource types.
type ResourceType string

const (
	ResourceCluster   ResourceType = "cluster"
	ResourceNode      ResourceType = "node"
	ResourceOperator  ResourceType = "operator"
	ResourceNamespace ResourceType = "namespace"
	ResourcePod       ResourceType = "pod"
	ResourceAlert     ResourceType = "alert"
	ResourceEvent     ResourceType = "event"
	ResourceMetric    ResourceType = "metric"
	ResourcePolicy    ResourceType = "policy"
	ResourceCustom    ResourceType = "custom"
)

// ResourceTypeToFilterKey maps ResourceType constants to compiled filter type keys.
var ResourceTypeToFilterKey = map[ResourceType]string{
	ResourceNode:      "nodes",
	ResourceOperator:  "operators",
	ResourceNamespace: "namespaces",
	ResourcePod:       "pods",
	ResourceAlert:     "alerts",
	ResourceEvent:     "events",
}

// Decision represents authorization decisions.
type Decision string

const (
	DecisionAllow   Decision = "allow"
	DecisionDeny    Decision = "deny"
	DecisionPartial Decision = "partial"
)

// Visibility represents resource visibility.
type Visibility string

const (
	VisibilityAll      Visibility = "all"
	VisibilityNone     Visibility = "none"
	VisibilityFiltered Visibility = "filtered"
)

// PermissionMapping maps policy JSON keys to Action constants.
var PermissionMapping = map[string]Action{
	"view":        ActionView,
	"viewMetrics": ActionViewMetrics,
}

// Principal represents the entity making the request.
type Principal struct {
	Username         string         `json:"username"`
	Email            string         `json:"email,omitempty"`
	Groups           []string       `json:"groups"`
	IsServiceAccount bool           `json:"is_service_account"`
	Attributes       map[string]any `json:"attributes,omitempty"`
}

// CacheKey returns a stable cache key for the principal.
func (p *Principal) CacheKey() string {
	sorted := make([]string, len(p.Groups))
	copy(sorted, p.Groups)
	slices.Sort(sorted)
	return fmt.Sprintf("%s:%s", p.Username, strings.Join(sorted, ","))
}

// Resource represents the resource being accessed.
type Resource struct {
	Type      ResourceType      `json:"type"`
	Name      string            `json:"name"`
	Namespace string            `json:"namespace,omitempty"`
	Cluster   string            `json:"cluster,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// ID builds a unique resource identifier.
func (r *Resource) ID() string {
	parts := []string{string(r.Type)}
	if r.Cluster != "" {
		parts = append(parts, r.Cluster)
	}
	if r.Namespace != "" {
		parts = append(parts, r.Namespace)
	}
	parts = append(parts, r.Name)
	return strings.Join(parts, ":")
}

// Request represents an authorization request.
type Request struct {
	Principal *Principal
	Action    Action
	Resource  *Resource
}

// CacheKey returns a stable cache key for the request.
func (r *Request) CacheKey() string {
	return fmt.Sprintf("%s:%s:%s", r.Principal.CacheKey(), r.Action, r.Resource.ID())
}

// CompiledPattern wraps a compiled regex with its original string.
type CompiledPattern struct {
	Original string
	Regexp   *regexp.Regexp
}

// MatchSpec defines include/exclude matching for a single dimension (name, namespace, etc.)
type MatchSpec struct {
	Include         map[string]struct{}
	Exclude         map[string]struct{}
	IncludePatterns []CompiledPattern
	ExcludePatterns []CompiledPattern
}

// Matches checks if an item passes the match spec criteria.
func (ms *MatchSpec) Matches(item string) bool {
	// Check exclusions first
	if _, excluded := ms.Exclude[item]; excluded {
		return false
	}
	for _, p := range ms.ExcludePatterns {
		if p.Regexp.MatchString(item) {
			return false
		}
	}

	// If no include criteria, allow all non-excluded
	if len(ms.Include) == 0 && len(ms.IncludePatterns) == 0 {
		return true
	}

	// Check inclusions
	if _, ok := ms.Include[item]; ok {
		return true
	}
	for _, p := range ms.IncludePatterns {
		if p.Regexp.MatchString(item) {
			return true
		}
	}

	return false
}

// ResourceMatcher is the unified filter type for all resource types.
type ResourceMatcher struct {
	Visibility   Visibility
	Names        *MatchSpec
	Namespaces   *MatchSpec
	Labels       map[string]string
	FieldFilters map[string]*MatchSpec
}

// IsUnrestricted checks if matcher imposes no restrictions.
func (m *ResourceMatcher) IsUnrestricted() bool {
	return m.Visibility == VisibilityAll &&
		m.Names == nil &&
		m.Namespaces == nil &&
		len(m.Labels) == 0 &&
		len(m.FieldFilters) == 0
}

// RBACDecision represents an authorization decision result.
type RBACDecision struct {
	Decision        Decision                       `json:"decision"`
	Request         *Request                       `json:"-"`
	Reason          string                         `json:"reason"`
	Matchers        map[string]*ResourceMatcher    `json:"-"`
	Permissions     map[Action]struct{}            `json:"-"`
	Metadata        map[string]any                 `json:"metadata,omitempty"`
	AppliedPolicies []string                       `json:"applied_policies,omitempty"`
	Cached          bool                           `json:"cached,omitempty"`
}

// Allowed returns true if decision allows access.
func (d *RBACDecision) Allowed() bool {
	return d.Decision == DecisionAllow || d.Decision == DecisionPartial
}

// Denied returns true if decision denies access.
func (d *RBACDecision) Denied() bool {
	return d.Decision == DecisionDeny
}

// Can checks if a specific action is permitted.
func (d *RBACDecision) Can(action Action) bool {
	_, ok := d.Permissions[action]
	return ok
}

// GetMatcher returns the matcher for a resource type, or nil.
func (d *RBACDecision) GetMatcher(rt ResourceType) *ResourceMatcher {
	if d.Matchers == nil {
		return nil
	}
	key := ResourceTypeToFilterKey[rt]
	return d.Matchers[key]
}

// CustomResourceDecision is the authorization decision for custom resource access.
type CustomResourceDecision struct {
	Decision            Decision
	ResourceTypeName    string
	Cluster             string
	Reason              string
	Matcher             *ResourceMatcher
	AllowedAggregations *map[string]struct{} // nil means all allowed
	DeniedAggregations  map[string]struct{}
	Permissions         map[Action]struct{}
	AppliedPolicies     []string
	Metadata            map[string]any
	Cached              bool
}

// Denied returns true if decision denies access.
func (d *CustomResourceDecision) Denied() bool {
	return d.Decision == DecisionDeny
}

// IsAggregationAllowed checks if a specific aggregation is visible.
func (d *CustomResourceDecision) IsAggregationAllowed(name string) bool {
	if _, denied := d.DeniedAggregations[name]; denied {
		return false
	}
	if d.AllowedAggregations != nil {
		_, ok := (*d.AllowedAggregations)[name]
		return ok
	}
	return true
}
