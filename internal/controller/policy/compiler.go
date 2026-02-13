package policy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
	"github.com/clusterpulse/cluster-controller/pkg/types"
)

// Compiler compiles MonitorAccessPolicy specs into optimized structures
type Compiler struct {
	patternCache map[string]compiledPattern
}

type compiledPattern struct {
	kind    string // "literal" or "regex"
	literal string
	regex   *regexp.Regexp
}

// NewCompiler creates a new policy compiler
func NewCompiler() *Compiler {
	return &Compiler{
		patternCache: make(map[string]compiledPattern),
	}
}

// Compile compiles a MonitorAccessPolicy spec into a CompiledPolicy
func (c *Compiler) Compile(name, namespace string, spec *v1alpha1.MonitorAccessPolicySpec) (*types.CompiledPolicy, error) {
	if err := c.validateSpec(spec); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	subjects := c.extractSubjects(&spec.Identity.Subjects)
	clusterRules, customTypes := c.compileClusterRules(&spec.Scope.Clusters)
	notBefore, notAfter := c.extractValidity(spec.Lifecycle)
	auditConfig := c.extractAuditConfig(spec.Operations)
	hash := c.generateHash(spec)

	enabled := true
	if spec.Access.Enabled != nil {
		enabled = *spec.Access.Enabled
	}

	return &types.CompiledPolicy{
		PolicyName:           name,
		Namespace:            namespace,
		Priority:             spec.Identity.Priority,
		Effect:               spec.Access.Effect,
		Enabled:              enabled,
		Users:                subjects.users,
		Groups:               subjects.groups,
		ServiceAccounts:      subjects.serviceAccounts,
		DefaultClusterAccess: spec.Scope.Clusters.Default,
		ClusterRules:         clusterRules,
		NotBefore:            notBefore,
		NotAfter:             notAfter,
		AuditConfig:          auditConfig,
		CompiledAt:           time.Now().UTC().Format(time.RFC3339),
		Hash:                 hash,
		CustomResourceTypes:  customTypes,
	}, nil
}

func (c *Compiler) validateSpec(spec *v1alpha1.MonitorAccessPolicySpec) error {
	if spec.Access.Effect != "Allow" && spec.Access.Effect != "Deny" {
		return fmt.Errorf("invalid effect: %s", spec.Access.Effect)
	}
	if spec.Identity.Priority < 0 {
		return fmt.Errorf("invalid priority: %d", spec.Identity.Priority)
	}
	return nil
}

type extractedSubjects struct {
	users           []string
	groups          []string
	serviceAccounts []string
}

func (c *Compiler) extractSubjects(subjects *v1alpha1.PolicySubjects) extractedSubjects {
	result := extractedSubjects{
		users:           ensureStringSlice(subjects.Users),
		groups:          ensureStringSlice(subjects.Groups),
		serviceAccounts: make([]string, 0, len(subjects.ServiceAccounts)),
	}

	for _, sa := range subjects.ServiceAccounts {
		ns := sa.Namespace
		if ns == "" {
			ns = "default"
		}
		result.serviceAccounts = append(result.serviceAccounts, fmt.Sprintf("system:serviceaccount:%s:%s", ns, sa.Name))
	}

	return result
}

func (c *Compiler) compileClusterRules(clusters *v1alpha1.PolicyClusters) ([]types.CompiledClusterRule, []string) {
	var rules []types.CompiledClusterRule
	customTypesSet := map[string]bool{}

	for _, rule := range clusters.Rules {
		// Build selector map
		selector := map[string]interface{}{}
		if rule.Selector.MatchLabels != nil {
			selector["matchLabels"] = rule.Selector.MatchLabels
		}
		if rule.Selector.MatchNames != nil {
			selector["matchNames"] = rule.Selector.MatchNames
		}
		if rule.Selector.MatchPattern != "" {
			selector["matchPattern"] = rule.Selector.MatchPattern
		}

		permissions := permissionsToMap(rule.Permissions)

		var nodeFilter, operatorFilter, namespaceFilter, podFilter *types.CompiledResourceFilter
		customResources := map[string]*types.CompiledCustomResourceFilter{}

		if rule.Resources != nil {
			if rule.Resources.Nodes != nil {
				nodeFilter = c.compileNodeFilter(rule.Resources.Nodes)
			}
			if rule.Resources.Operators != nil {
				operatorFilter = c.compileOperatorFilter(rule.Resources.Operators)
			}
			if rule.Resources.Namespaces != nil {
				namespaceFilter = c.compileNamespaceFilter(rule.Resources.Namespaces)
			}
			if rule.Resources.Pods != nil {
				podFilter = c.compilePodFilter(rule.Resources.Pods)
			}
			if rule.Resources.Custom != nil {
				customResources, customTypesSet = c.compileCustomResources(rule.Resources.Custom, customTypesSet)
			}
		}

		rules = append(rules, types.CompiledClusterRule{
			ClusterSelector: selector,
			Permissions:     permissions,
			NodeFilter:      nodeFilter,
			OperatorFilter:  operatorFilter,
			NamespaceFilter: namespaceFilter,
			PodFilter:       podFilter,
			CustomResources: customResources,
		})
	}

	customTypes := make([]string, 0, len(customTypesSet))
	for t := range customTypesSet {
		customTypes = append(customTypes, t)
	}

	return rules, customTypes
}

// permissionsToMap converts typed PolicyPermissions to map[string]bool for the compiled format.
func permissionsToMap(p *v1alpha1.PolicyPermissions) map[string]bool {
	if p == nil {
		return map[string]bool{"view": true}
	}
	m := map[string]bool{}
	if p.View != nil {
		m["view"] = *p.View
	}
	if p.ViewMetrics != nil {
		m["viewMetrics"] = *p.ViewMetrics
	}
	if p.ViewSensitive != nil {
		m["viewSensitive"] = *p.ViewSensitive
	}
	if p.ViewCosts != nil {
		m["viewCosts"] = *p.ViewCosts
	}
	if p.ViewSecrets != nil {
		m["viewSecrets"] = *p.ViewSecrets
	}
	if p.ViewMetadata != nil {
		m["viewMetadata"] = *p.ViewMetadata
	}
	if p.ViewAuditInfo != nil {
		m["viewAuditInfo"] = *p.ViewAuditInfo
	}
	if len(m) == 0 {
		m["view"] = true
	}
	return m
}

func (c *Compiler) compileNodeFilter(cfg *v1alpha1.NodeResourceConfig) *types.CompiledResourceFilter {
	filter := &types.CompiledResourceFilter{
		Visibility:        cfg.Visibility,
		AllowedPatterns:   [][2]string{},
		DeniedPatterns:    [][2]string{},
		AllowedLiterals:   []string{},
		DeniedLiterals:    []string{},
		LabelSelectors:    map[string]string{},
		AdditionalFilters: map[string]interface{}{},
	}

	if cfg.Filters == nil {
		return filter
	}

	for k, v := range cfg.Filters.LabelSelector {
		filter.LabelSelectors[k] = v
	}

	if cfg.Filters.HideMasters {
		filter.AdditionalFilters["hide_masters"] = true
	}

	if cfg.Filters.HideByLabels != nil {
		var val interface{}
		_ = json.Unmarshal(cfg.Filters.HideByLabels.Raw, &val)
		filter.AdditionalFilters["hide_by_labels"] = val
	}

	return filter
}

func (c *Compiler) compileOperatorFilter(cfg *v1alpha1.OperatorResourceConfig) *types.CompiledResourceFilter {
	filter := &types.CompiledResourceFilter{
		Visibility:        cfg.Visibility,
		AllowedPatterns:   [][2]string{},
		DeniedPatterns:    [][2]string{},
		AllowedLiterals:   []string{},
		DeniedLiterals:    []string{},
		LabelSelectors:    map[string]string{},
		AdditionalFilters: map[string]interface{}{},
	}

	if cfg.Filters == nil {
		return filter
	}

	c.addPrefixedPatternsFromSlice(filter, cfg.Filters.AllowedNamespaces, "ns:", true)
	c.addPrefixedPatternsFromSlice(filter, cfg.Filters.DeniedNamespaces, "ns:", false)
	c.addPrefixedPatternsFromSlice(filter, cfg.Filters.AllowedNames, "name:", true)
	c.addPrefixedPatternsFromSlice(filter, cfg.Filters.DeniedNames, "name:", false)

	return filter
}

func (c *Compiler) compileNamespaceFilter(cfg *v1alpha1.NamespaceResourceConfig) *types.CompiledResourceFilter {
	filter := &types.CompiledResourceFilter{
		Visibility:        cfg.Visibility,
		AllowedPatterns:   [][2]string{},
		DeniedPatterns:    [][2]string{},
		AllowedLiterals:   []string{},
		DeniedLiterals:    []string{},
		LabelSelectors:    map[string]string{},
		AdditionalFilters: map[string]interface{}{},
	}

	if cfg.Filters == nil {
		return filter
	}

	c.addPatternsFromSlice(filter, cfg.Filters.Allowed, true)
	c.addPatternsFromSlice(filter, cfg.Filters.Denied, false)

	return filter
}

func (c *Compiler) compilePodFilter(cfg *v1alpha1.PodResourceConfig) *types.CompiledResourceFilter {
	filter := &types.CompiledResourceFilter{
		Visibility:        cfg.Visibility,
		AllowedPatterns:   [][2]string{},
		DeniedPatterns:    [][2]string{},
		AllowedLiterals:   []string{},
		DeniedLiterals:    []string{},
		LabelSelectors:    map[string]string{},
		AdditionalFilters: map[string]interface{}{},
	}

	if cfg.Filters == nil {
		return filter
	}

	c.addPatternsFromSlice(filter, cfg.Filters.AllowedNamespaces, true)

	return filter
}

func (c *Compiler) compileCustomResources(
	custom map[string]v1alpha1.CustomResourceConfig,
	existingTypes map[string]bool,
) (map[string]*types.CompiledCustomResourceFilter, map[string]bool) {
	result := map[string]*types.CompiledCustomResourceFilter{}

	for resourceType, cfg := range custom {
		existingTypes[resourceType] = true

		compiled := &types.CompiledCustomResourceFilter{
			ResourceTypeName: resourceType,
			Visibility:       cfg.Visibility,
			FieldFilters:     map[string]*types.CompiledFieldFilter{},
		}

		if cfg.Visibility == "" {
			compiled.Visibility = "all"
		}

		if cfg.Filters != nil {
			if cfg.Filters.Namespaces != nil {
				compiled.NamespaceFilter = c.compilePatternFilter(cfg.Filters.Namespaces)
			}
			if cfg.Filters.Names != nil {
				compiled.NameFilter = c.compilePatternFilter(cfg.Filters.Names)
			}
			for fieldName, fieldCfg := range cfg.Filters.Fields {
				compiled.FieldFilters[fieldName] = c.compileFieldFilter(fieldName, &fieldCfg)
			}
		}

		if cfg.Aggregations != nil {
			compiled.AggregationRules = &types.CompiledAggregationRules{
				Include: ensureStringSlice(cfg.Aggregations.Include),
				Exclude: ensureStringSlice(cfg.Aggregations.Exclude),
			}
		}

		result[resourceType] = compiled
	}

	return result, existingTypes
}

func (c *Compiler) compilePatternFilter(pf *v1alpha1.PatternFilter) *types.CompiledResourceFilter {
	filter := &types.CompiledResourceFilter{
		Visibility:        "filtered",
		AllowedPatterns:   [][2]string{},
		DeniedPatterns:    [][2]string{},
		AllowedLiterals:   []string{},
		DeniedLiterals:    []string{},
		LabelSelectors:    map[string]string{},
		AdditionalFilters: map[string]interface{}{},
	}

	for _, pattern := range pf.Allowed {
		cp := c.compilePattern(pattern)
		if cp.kind == "literal" {
			filter.AllowedLiterals = append(filter.AllowedLiterals, cp.literal)
		} else {
			filter.AllowedPatterns = append(filter.AllowedPatterns, [2]string{pattern, cp.regex.String()})
		}
	}

	for _, pattern := range pf.Denied {
		cp := c.compilePattern(pattern)
		if cp.kind == "literal" {
			filter.DeniedLiterals = append(filter.DeniedLiterals, cp.literal)
		} else {
			filter.DeniedPatterns = append(filter.DeniedPatterns, [2]string{pattern, cp.regex.String()})
		}
	}

	return filter
}

func (c *Compiler) compileFieldFilter(fieldName string, cfg *v1alpha1.FieldFilterConfig) *types.CompiledFieldFilter {
	filter := &types.CompiledFieldFilter{
		FieldName:       fieldName,
		AllowedPatterns: [][2]string{},
		DeniedPatterns:  [][2]string{},
		AllowedLiterals: []string{},
		DeniedLiterals:  []string{},
		Conditions:      [][2]interface{}{},
	}

	for _, s := range cfg.Allowed {
		cp := c.compilePattern(s)
		if cp.kind == "literal" {
			filter.AllowedLiterals = append(filter.AllowedLiterals, cp.literal)
		} else {
			filter.AllowedPatterns = append(filter.AllowedPatterns, [2]string{s, cp.regex.String()})
		}
	}

	for _, s := range cfg.Denied {
		cp := c.compilePattern(s)
		if cp.kind == "literal" {
			filter.DeniedLiterals = append(filter.DeniedLiterals, cp.literal)
		} else {
			filter.DeniedPatterns = append(filter.DeniedPatterns, [2]string{s, cp.regex.String()})
		}
	}

	for _, cond := range cfg.Conditions {
		var val interface{}
		_ = json.Unmarshal(cond.Value.Raw, &val)
		filter.Conditions = append(filter.Conditions, [2]interface{}{cond.Operator, val})
	}

	return filter
}

func (c *Compiler) compilePattern(pattern string) compiledPattern {
	if cached, ok := c.patternCache[pattern]; ok {
		return cached
	}

	var result compiledPattern
	if strings.ContainsAny(pattern, "*?") {
		regexStr := pattern
		regexStr = strings.ReplaceAll(regexStr, ".", `\.`)
		regexStr = strings.ReplaceAll(regexStr, "*", ".*")
		regexStr = strings.ReplaceAll(regexStr, "?", ".")
		re := regexp.MustCompile("^" + regexStr + "$")
		result = compiledPattern{kind: "regex", regex: re}
	} else {
		result = compiledPattern{kind: "literal", literal: pattern}
	}

	c.patternCache[pattern] = result
	return result
}

func (c *Compiler) addPatternsFromSlice(filter *types.CompiledResourceFilter, patterns []string, allowed bool) {
	for _, s := range patterns {
		cp := c.compilePattern(s)
		if allowed {
			if cp.kind == "literal" {
				filter.AllowedLiterals = append(filter.AllowedLiterals, cp.literal)
			} else {
				filter.AllowedPatterns = append(filter.AllowedPatterns, [2]string{s, cp.regex.String()})
			}
		} else {
			if cp.kind == "literal" {
				filter.DeniedLiterals = append(filter.DeniedLiterals, cp.literal)
			} else {
				filter.DeniedPatterns = append(filter.DeniedPatterns, [2]string{s, cp.regex.String()})
			}
		}
	}
}

func (c *Compiler) addPrefixedPatternsFromSlice(filter *types.CompiledResourceFilter, patterns []string, prefix string, allowed bool) {
	for _, s := range patterns {
		cp := c.compilePattern(s)
		if allowed {
			if cp.kind == "literal" {
				filter.AllowedLiterals = append(filter.AllowedLiterals, prefix+cp.literal)
			} else {
				filter.AllowedPatterns = append(filter.AllowedPatterns, [2]string{prefix + s, cp.regex.String()})
			}
		} else {
			if cp.kind == "literal" {
				filter.DeniedLiterals = append(filter.DeniedLiterals, prefix+cp.literal)
			} else {
				filter.DeniedPatterns = append(filter.DeniedPatterns, [2]string{prefix + s, cp.regex.String()})
			}
		}
	}
}

func (c *Compiler) extractValidity(lifecycle *v1alpha1.PolicyLifecycle) (*string, *string) {
	if lifecycle == nil || lifecycle.Validity == nil {
		return nil, nil
	}

	var notBefore, notAfter *string
	if lifecycle.Validity.NotBefore != "" {
		notBefore = &lifecycle.Validity.NotBefore
	}
	if lifecycle.Validity.NotAfter != "" {
		notAfter = &lifecycle.Validity.NotAfter
	}
	return notBefore, notAfter
}

func (c *Compiler) extractAuditConfig(ops *v1alpha1.PolicyOperations) map[string]bool {
	config := map[string]bool{
		"log_access":     false,
		"require_reason": false,
	}
	if ops != nil && ops.Audit != nil {
		config["log_access"] = ops.Audit.LogAccess
		config["require_reason"] = ops.Audit.RequireReason
	}
	return config
}

func (c *Compiler) generateHash(spec *v1alpha1.MonitorAccessPolicySpec) string {
	data, _ := json.Marshal(spec)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)[:16]
}

func ensureStringSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
