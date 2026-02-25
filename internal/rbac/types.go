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
	ActionView          Action = "view"
	ActionViewMetrics   Action = "view_metrics"
	ActionViewSensitive Action = "view_sensitive"
	ActionViewCosts     Action = "view_costs"
	ActionViewSecrets   Action = "view_secrets"
	ActionViewMetadata  Action = "view_metadata"
	ActionViewAudit     Action = "view_audit"
	ActionEdit          Action = "edit"
	ActionDelete        Action = "delete"
	ActionExecute       Action = "execute"
)

// AllActions returns all valid actions for iteration.
var AllActions = []Action{
	ActionView, ActionViewMetrics, ActionViewSensitive, ActionViewCosts,
	ActionViewSecrets, ActionViewMetadata, ActionViewAudit,
	ActionEdit, ActionDelete, ActionExecute,
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
	"view":          ActionView,
	"viewMetrics":   ActionViewMetrics,
	"viewSensitive": ActionViewSensitive,
	"viewCosts":     ActionViewCosts,
	"viewSecrets":   ActionViewSecrets,
	"viewMetadata":  ActionViewMetadata,
	"viewAuditInfo": ActionViewAudit,
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

// Filter represents resource filter configuration.
type Filter struct {
	Visibility Visibility
	Include    map[string]struct{}
	Exclude    map[string]struct{}
	Patterns   []CompiledPattern
	Labels     map[string]string
}

// NewFilter creates a Filter with defaults.
func NewFilter(visibility Visibility) *Filter {
	return &Filter{
		Visibility: visibility,
		Include:    make(map[string]struct{}),
		Exclude:    make(map[string]struct{}),
		Labels:     make(map[string]string),
	}
}

// IsEmpty checks if filter has no restrictions.
func (f *Filter) IsEmpty() bool {
	return f.Visibility == VisibilityAll &&
		len(f.Include) == 0 &&
		len(f.Exclude) == 0 &&
		len(f.Patterns) == 0 &&
		len(f.Labels) == 0
}

// Matches checks if item matches filter criteria.
func (f *Filter) Matches(item string, labels map[string]string) bool {
	if f.Visibility == VisibilityNone {
		return false
	}
	if f.Visibility == VisibilityAll && len(f.Exclude) == 0 && len(f.Include) == 0 {
		return true
	}

	if _, excluded := f.Exclude[item]; excluded {
		return false
	}

	if len(f.Include) > 0 {
		if _, included := f.Include[item]; !included {
			matched := false
			for _, p := range f.Patterns {
				if p.Regexp.MatchString(item) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}

	if len(f.Labels) > 0 && labels != nil {
		for k, v := range f.Labels {
			if labels[k] != v {
				return false
			}
		}
	}

	return true
}

// RBACDecision represents an authorization decision result.
type RBACDecision struct {
	Decision        Decision                 `json:"decision"`
	Request         *Request                 `json:"-"`
	Reason          string                   `json:"reason"`
	Filters         map[ResourceType]*Filter `json:"-"`
	Permissions     map[Action]struct{}      `json:"-"`
	Metadata        map[string]any           `json:"metadata,omitempty"`
	AppliedPolicies []string                 `json:"applied_policies,omitempty"`
	Cached          bool                     `json:"cached,omitempty"`
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

// GetFilter returns the filter for a resource type, or nil.
func (d *RBACDecision) GetFilter(rt ResourceType) *Filter {
	if d.Filters == nil {
		return nil
	}
	return d.Filters[rt]
}

// FieldFilter holds allowed/denied literals and patterns for a single field.
type FieldFilter struct {
	AllowedLiterals map[string]struct{}
	AllowedPatterns []CompiledPattern
	DeniedLiterals  map[string]struct{}
	DeniedPatterns  []CompiledPattern
}

// CustomResourceFilter supports namespace, name, and field-based filtering.
type CustomResourceFilter struct {
	Visibility               Visibility
	NamespaceLiterals        map[string]struct{}
	NamespacePatterns        []CompiledPattern
	NamespaceExcludeLiterals map[string]struct{}
	NamespaceExcludePatterns []CompiledPattern
	NameLiterals             map[string]struct{}
	NamePatterns             []CompiledPattern
	NameExcludeLiterals      map[string]struct{}
	NameExcludePatterns      []CompiledPattern
	FieldFilters             map[string]*FieldFilter
}

// NewCustomResourceFilter creates a CustomResourceFilter with defaults.
func NewCustomResourceFilter() *CustomResourceFilter {
	return &CustomResourceFilter{
		Visibility:               VisibilityAll,
		NamespaceLiterals:        make(map[string]struct{}),
		NamespaceExcludeLiterals: make(map[string]struct{}),
		NameLiterals:             make(map[string]struct{}),
		NameExcludeLiterals:      make(map[string]struct{}),
		FieldFilters:             make(map[string]*FieldFilter),
	}
}

// IsUnrestricted checks if filter imposes no restrictions.
func (f *CustomResourceFilter) IsUnrestricted() bool {
	return f.Visibility == VisibilityAll &&
		len(f.NamespaceLiterals) == 0 && len(f.NamespacePatterns) == 0 &&
		len(f.NamespaceExcludeLiterals) == 0 && len(f.NamespaceExcludePatterns) == 0 &&
		len(f.NameLiterals) == 0 && len(f.NamePatterns) == 0 &&
		len(f.NameExcludeLiterals) == 0 && len(f.NameExcludePatterns) == 0 &&
		len(f.FieldFilters) == 0
}

// MatchesNamespace checks if namespace passes filter criteria.
func (f *CustomResourceFilter) MatchesNamespace(namespace string) bool {
	if f.Visibility == VisibilityNone {
		return false
	}
	// Cluster-scoped resources (empty namespace) pass
	if namespace == "" {
		return true
	}

	// Check exclusions first
	if _, excluded := f.NamespaceExcludeLiterals[namespace]; excluded {
		return false
	}
	for _, p := range f.NamespaceExcludePatterns {
		if p.Regexp.MatchString(namespace) {
			return false
		}
	}

	// If no include filters, allow all non-excluded
	if len(f.NamespaceLiterals) == 0 && len(f.NamespacePatterns) == 0 {
		return true
	}

	// Check inclusions
	if _, included := f.NamespaceLiterals[namespace]; included {
		return true
	}
	for _, p := range f.NamespacePatterns {
		if p.Regexp.MatchString(namespace) {
			return true
		}
	}

	return false
}

// MatchesName checks if resource name passes filter criteria.
func (f *CustomResourceFilter) MatchesName(name string) bool {
	if f.Visibility == VisibilityNone {
		return false
	}

	if _, excluded := f.NameExcludeLiterals[name]; excluded {
		return false
	}
	for _, p := range f.NameExcludePatterns {
		if p.Regexp.MatchString(name) {
			return false
		}
	}

	if len(f.NameLiterals) == 0 && len(f.NamePatterns) == 0 {
		return true
	}

	if _, included := f.NameLiterals[name]; included {
		return true
	}
	for _, p := range f.NamePatterns {
		if p.Regexp.MatchString(name) {
			return true
		}
	}

	return false
}

// MatchesField checks if a field value passes filter criteria.
func (f *CustomResourceFilter) MatchesField(fieldName string, fieldValue any) bool {
	ff, ok := f.FieldFilters[fieldName]
	if !ok {
		return true
	}

	valueStr := ""
	if fieldValue != nil {
		valueStr = fmt.Sprintf("%v", fieldValue)
	}

	// Check exclusions first
	if _, denied := ff.DeniedLiterals[valueStr]; denied {
		return false
	}
	for _, p := range ff.DeniedPatterns {
		if p.Regexp.MatchString(valueStr) {
			return false
		}
	}

	// If no include filters, allow all non-excluded
	if len(ff.AllowedLiterals) == 0 && len(ff.AllowedPatterns) == 0 {
		return true
	}

	// Check inclusions
	if _, allowed := ff.AllowedLiterals[valueStr]; allowed {
		return true
	}
	for _, p := range ff.AllowedPatterns {
		if p.Regexp.MatchString(valueStr) {
			return true
		}
	}

	return false
}

// CustomResourceDecision is the authorization decision for custom resource access.
type CustomResourceDecision struct {
	Decision            Decision
	ResourceTypeName    string
	Cluster             string
	Reason              string
	Filters             *CustomResourceFilter
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
