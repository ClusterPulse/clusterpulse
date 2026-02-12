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

	globalRestrictions := map[string]interface{}{}
	if spec.Scope.Restrictions != nil && spec.Scope.Restrictions.Raw != nil {
		_ = json.Unmarshal(spec.Scope.Restrictions.Raw, &globalRestrictions)
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
		GlobalRestrictions:   globalRestrictions,
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

		permissions := rule.Permissions
		if permissions == nil {
			permissions = map[string]bool{"view": true}
		}

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

func (c *Compiler) compileNodeFilter(cfg *v1alpha1.ResourceConfig) *types.CompiledResourceFilter {
	filter := &types.CompiledResourceFilter{
		Visibility:        cfg.Visibility,
		AllowedPatterns:   [][2]string{},
		DeniedPatterns:    [][2]string{},
		AllowedLiterals:   []string{},
		DeniedLiterals:    []string{},
		LabelSelectors:    map[string]string{},
		AdditionalFilters: map[string]interface{}{},
	}

	if cfg.Filters == nil || cfg.Filters.Raw == nil {
		return filter
	}

	var filters map[string]interface{}
	if err := json.Unmarshal(cfg.Filters.Raw, &filters); err != nil {
		return filter
	}

	if ls, ok := filters["labelSelector"].(map[string]interface{}); ok {
		for k, v := range ls {
			if s, ok := v.(string); ok {
				filter.LabelSelectors[k] = s
			}
		}
	}

	if hm, ok := filters["hideMasters"].(bool); ok && hm {
		filter.AdditionalFilters["hide_masters"] = true
	}

	if hbl, ok := filters["hideByLabels"]; ok {
		filter.AdditionalFilters["hide_by_labels"] = hbl
	}

	return filter
}

func (c *Compiler) compileOperatorFilter(cfg *v1alpha1.ResourceConfig) *types.CompiledResourceFilter {
	filter := &types.CompiledResourceFilter{
		Visibility:        cfg.Visibility,
		AllowedPatterns:   [][2]string{},
		DeniedPatterns:    [][2]string{},
		AllowedLiterals:   []string{},
		DeniedLiterals:    []string{},
		LabelSelectors:    map[string]string{},
		AdditionalFilters: map[string]interface{}{},
	}

	if cfg.Filters == nil || cfg.Filters.Raw == nil {
		return filter
	}

	var filters map[string]interface{}
	if err := json.Unmarshal(cfg.Filters.Raw, &filters); err != nil {
		return filter
	}

	// allowedNamespaces → ns: prefix
	c.addPrefixedPatterns(filter, filters, "allowedNamespaces", "ns:", true)
	c.addPrefixedPatterns(filter, filters, "deniedNamespaces", "ns:", false)
	c.addPrefixedPatterns(filter, filters, "allowedNames", "name:", true)
	c.addPrefixedPatterns(filter, filters, "deniedNames", "name:", false)

	return filter
}

func (c *Compiler) compileNamespaceFilter(cfg *v1alpha1.ResourceConfig) *types.CompiledResourceFilter {
	filter := &types.CompiledResourceFilter{
		Visibility:        cfg.Visibility,
		AllowedPatterns:   [][2]string{},
		DeniedPatterns:    [][2]string{},
		AllowedLiterals:   []string{},
		DeniedLiterals:    []string{},
		LabelSelectors:    map[string]string{},
		AdditionalFilters: map[string]interface{}{},
	}

	if cfg.Filters == nil || cfg.Filters.Raw == nil {
		return filter
	}

	var filters map[string]interface{}
	if err := json.Unmarshal(cfg.Filters.Raw, &filters); err != nil {
		return filter
	}

	c.addPatterns(filter, filters, "allowed", true)
	c.addPatterns(filter, filters, "denied", false)

	return filter
}

func (c *Compiler) compilePodFilter(cfg *v1alpha1.ResourceConfig) *types.CompiledResourceFilter {
	filter := &types.CompiledResourceFilter{
		Visibility:        cfg.Visibility,
		AllowedPatterns:   [][2]string{},
		DeniedPatterns:    [][2]string{},
		AllowedLiterals:   []string{},
		DeniedLiterals:    []string{},
		LabelSelectors:    map[string]string{},
		AdditionalFilters: map[string]interface{}{},
	}

	if cfg.Filters == nil || cfg.Filters.Raw == nil {
		return filter
	}

	var filters map[string]interface{}
	if err := json.Unmarshal(cfg.Filters.Raw, &filters); err != nil {
		return filter
	}

	c.addPatterns(filter, filters, "allowedNamespaces", true)

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

	for _, raw := range cfg.Allowed {
		s := jsonRawToString(raw.Raw)
		cp := c.compilePattern(s)
		if cp.kind == "literal" {
			filter.AllowedLiterals = append(filter.AllowedLiterals, cp.literal)
		} else {
			filter.AllowedPatterns = append(filter.AllowedPatterns, [2]string{s, cp.regex.String()})
		}
	}

	for _, raw := range cfg.Denied {
		s := jsonRawToString(raw.Raw)
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

func (c *Compiler) addPatterns(filter *types.CompiledResourceFilter, filters map[string]interface{}, key string, allowed bool) {
	if patterns, ok := filters[key].([]interface{}); ok {
		for _, p := range patterns {
			if s, ok := p.(string); ok {
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
	}
}

func (c *Compiler) addPrefixedPatterns(filter *types.CompiledResourceFilter, filters map[string]interface{}, key, prefix string, allowed bool) {
	if patterns, ok := filters[key].([]interface{}); ok {
		for _, p := range patterns {
			if s, ok := p.(string); ok {
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

// jsonRawToString extracts a string value from JSON raw bytes
func jsonRawToString(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		// Not a string - return raw representation
		return string(raw)
	}
	return s
}

func ensureStringSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
