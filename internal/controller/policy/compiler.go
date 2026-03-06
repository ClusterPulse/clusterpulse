package policy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
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

var standardResourceTypes = map[string]bool{
	"nodes": true, "operators": true, "namespaces": true, "pods": true,
}

// Compile compiles a MonitorAccessPolicy spec into a CompiledPolicy
func (c *Compiler) Compile(name, namespace string, spec *v1alpha1.MonitorAccessPolicySpec) (*types.CompiledPolicy, error) {
	if err := c.validateSpec(spec); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	subjects := c.extractSubjects(&spec.Identity.Subjects)
	clusterRules, customTypes := c.compileClusterRules(&spec.Scope.Clusters)
	notBefore, notAfter := c.extractValidity(spec.Lifecycle)
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
		selector := types.CompiledClusterSelector{
			MatchNames:   rule.Selector.MatchNames,
			MatchPattern: rule.Selector.MatchPattern,
			MatchLabels:  rule.Selector.MatchLabels,
		}

		permissions := permissionsToMap(rule.Permissions)

		var resources []types.CompiledResourceFilter
		for i := range rule.Resources {
			compiled := c.compileResourceFilter(&rule.Resources[i])
			resources = append(resources, compiled)
			if !standardResourceTypes[rule.Resources[i].Type] {
				customTypesSet[rule.Resources[i].Type] = true
			}
		}

		rules = append(rules, types.CompiledClusterRule{
			ClusterSelector: selector,
			Permissions:     permissions,
			Resources:       resources,
		})
	}

	customTypes := slices.Sorted(func(yield func(string) bool) {
		for t := range customTypesSet {
			if !yield(t) {
				return
			}
		}
	})

	return rules, customTypes
}

func (c *Compiler) compileResourceFilter(rf *v1alpha1.ResourceFilter) types.CompiledResourceFilter {
	result := types.CompiledResourceFilter{
		Type:       rf.Type,
		Visibility: rf.Visibility,
	}
	if result.Visibility == "" {
		result.Visibility = "all"
	}

	if rf.Filters != nil {
		if rf.Filters.Names != nil {
			c.addPatterns(&result.AllowedNames, &result.NamePatterns, rf.Filters.Names.Allowed)
			c.addPatterns(&result.DeniedNames, &result.DenyNamePatterns, rf.Filters.Names.Denied)
		}
		if rf.Filters.Namespaces != nil {
			c.addPatterns(&result.AllowedNS, &result.NSPatterns, rf.Filters.Namespaces.Allowed)
			c.addPatterns(&result.DeniedNS, &result.DenyNSPatterns, rf.Filters.Namespaces.Denied)
		}
		result.Labels = rf.Filters.Labels
		if len(rf.Filters.Fields) > 0 {
			result.FieldFilters = make(map[string]*types.CompiledFieldFilter, len(rf.Filters.Fields))
			for name, spec := range rf.Filters.Fields {
				result.FieldFilters[name] = c.compileFieldFilter(&spec)
			}
		}
	}

	if rf.Aggregations != nil {
		result.AggregationRules = &types.CompiledAggregationRules{
			Include: ensureStringSlice(rf.Aggregations.Include),
			Exclude: ensureStringSlice(rf.Aggregations.Exclude),
		}
	}

	return result
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
	if len(m) == 0 {
		m["view"] = true
	}
	return m
}

func (c *Compiler) compileFieldFilter(cfg *v1alpha1.PatternFilter) *types.CompiledFieldFilter {
	filter := &types.CompiledFieldFilter{}

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

func (c *Compiler) addPatterns(literals *[]string, patterns *[][2]string, sources []string) {
	for _, s := range sources {
		cp := c.compilePattern(s)
		if cp.kind == "literal" {
			*literals = append(*literals, cp.literal)
		} else {
			*patterns = append(*patterns, [2]string{s, cp.regex.String()})
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
