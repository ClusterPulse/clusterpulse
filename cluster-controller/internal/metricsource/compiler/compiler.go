package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
	"github.com/clusterpulse/cluster-controller/internal/metricsource/expression"
	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Compiler transforms MetricSource CRD specs into optimized runtime structures
type Compiler struct {
	log *logrus.Entry
}

// NewCompiler creates a new MetricSource compiler
func NewCompiler() *Compiler {
	return &Compiler{
		log: logrus.WithField("component", "metricsource-compiler"),
	}
}

// Compile transforms a MetricSource spec into a CompiledMetricSource
func (c *Compiler) Compile(ms *v1alpha1.MetricSource) (*types.CompiledMetricSource, error) {
	c.log.Debugf("Compiling MetricSource %s/%s", ms.Namespace, ms.Name)

	if err := c.validate(ms); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	compiled := &types.CompiledMetricSource{
		Name:      ms.Name,
		Namespace: ms.Namespace,
	}

	// Compile source target
	source, err := c.compileSource(&ms.Spec.Source)
	if err != nil {
		return nil, fmt.Errorf("failed to compile source: %w", err)
	}
	compiled.Source = *source

	// Compile fields and build field name set
	fields, fieldIndex, err := c.compileFields(ms.Spec.Fields)
	if err != nil {
		return nil, fmt.Errorf("failed to compile fields: %w", err)
	}
	compiled.Fields = fields
	compiled.FieldNameToIndex = fieldIndex

	// Build field name set for computed field validation
	fieldNames := make(map[string]bool)
	for _, f := range ms.Spec.Fields {
		fieldNames[f.Name] = true
	}

	// Compile computed fields with expression parsing
	computedFields, err := c.compileComputed(ms.Spec.Computed, fieldNames)
	if err != nil {
		return nil, fmt.Errorf("failed to compile computed fields: %w", err)
	}
	compiled.Computed = computedFields

	// Compile aggregations
	compiled.Aggregations = c.compileAggregations(ms.Spec.Aggregations)

	// Compile collection config with defaults
	compiled.Collection = c.compileCollectionConfig(&ms.Spec.Collection)

	// Compile RBAC config
	compiled.RBAC = c.compileRBAC(&ms.Spec.RBAC)

	// Compile namespace patterns if present
	if ms.Spec.Source.Namespaces != nil {
		patterns, err := c.compileNamespacePatterns(ms.Spec.Source.Namespaces)
		if err != nil {
			return nil, fmt.Errorf("failed to compile namespace patterns: %w", err)
		}
		compiled.NamespacePatterns = patterns
	}

	// Generate hash and timestamp
	compiled.Hash = c.generateHash(&ms.Spec)
	compiled.CompiledAt = time.Now().UTC().Format(time.RFC3339)

	c.log.Debugf("Successfully compiled MetricSource %s/%s with %d fields, %d computed, %d aggregations",
		ms.Namespace, ms.Name, len(compiled.Fields), len(compiled.Computed), len(compiled.Aggregations))

	return compiled, nil
}

// validate performs basic validation on the MetricSource spec
func (c *Compiler) validate(ms *v1alpha1.MetricSource) error {
	if ms.Spec.Source.APIVersion == "" {
		return fmt.Errorf("source.apiVersion is required")
	}
	if ms.Spec.Source.Kind == "" {
		return fmt.Errorf("source.kind is required")
	}
	if len(ms.Spec.Fields) == 0 {
		return fmt.Errorf("at least one field extraction is required")
	}

	// Validate field names are unique
	fieldNames := make(map[string]bool)
	for _, f := range ms.Spec.Fields {
		if f.Name == "" {
			return fmt.Errorf("field name cannot be empty")
		}
		if f.Path == "" {
			return fmt.Errorf("field %s: path cannot be empty", f.Name)
		}
		if fieldNames[f.Name] {
			return fmt.Errorf("duplicate field name: %s", f.Name)
		}
		fieldNames[f.Name] = true
	}

	// Validate computed field names don't conflict with extracted fields
	for _, comp := range ms.Spec.Computed {
		if comp.Name == "" {
			return fmt.Errorf("computed field name cannot be empty")
		}
		if fieldNames[comp.Name] {
			return fmt.Errorf("computed field name conflicts with extracted field: %s", comp.Name)
		}
		fieldNames[comp.Name] = true
	}

	// Validate RBAC identifiers reference valid fields
	if ms.Spec.RBAC.Identifiers != nil {
		if ns := ms.Spec.RBAC.Identifiers.Namespace; ns != "" && !fieldNames[ns] {
			return fmt.Errorf("RBAC namespace identifier references unknown field: %s", ns)
		}
		if name := ms.Spec.RBAC.Identifiers.Name; name != "" && !fieldNames[name] {
			return fmt.Errorf("RBAC name identifier references unknown field: %s", name)
		}
	}

	return nil
}

// compileSource parses the source target configuration
func (c *Compiler) compileSource(source *v1alpha1.MetricSourceTarget) (*types.CompiledSourceTarget, error) {
	compiled := &types.CompiledSourceTarget{
		APIVersion: source.APIVersion,
		Kind:       source.Kind,
		Scope:      source.Scope,
	}

	// Default scope to Namespaced
	if compiled.Scope == "" {
		compiled.Scope = "Namespaced"
	}

	// Parse group and version from apiVersion
	compiled.Group, compiled.Version = parseAPIVersion(source.APIVersion)

	// Derive resource name (lowercase plural form of kind)
	compiled.Resource = strings.ToLower(source.Kind) + "s"
	// Handle common irregular plurals
	compiled.Resource = pluralize(strings.ToLower(source.Kind))

	// Compile label selector to string format
	if source.LabelSelector != nil {
		compiled.LabelSelector = labelSelectorToString(source.LabelSelector)
	}

	// Copy namespace config
	if source.Namespaces != nil {
		compiled.Namespaces = &types.NamespaceConfig{
			Include: source.Namespaces.Include,
			Exclude: source.Namespaces.Exclude,
		}
	}

	return compiled, nil
}

// compileFields processes field extraction definitions
func (c *Compiler) compileFields(fields []v1alpha1.FieldExtraction) ([]types.CompiledField, map[string]int, error) {
	compiled := make([]types.CompiledField, len(fields))
	index := make(map[string]int)

	for i, f := range fields {
		fieldType := f.Type
		if fieldType == "" {
			fieldType = types.FieldTypeString
		}

		// Parse the JSONPath into segments for efficient extraction
		segments := parseJSONPath(f.Path)

		compiled[i] = types.CompiledField{
			Name:         f.Name,
			Path:         f.Path,
			PathSegments: segments,
			Type:         fieldType,
			Default:      f.Default,
			Index:        i,
		}
		index[f.Name] = i
	}

	return compiled, index, nil
}

// compileComputed processes computed field definitions with expression compilation
func (c *Compiler) compileComputed(computed []v1alpha1.ComputedField, fieldNames map[string]bool) ([]types.CompiledComputation, error) {
	result := make([]types.CompiledComputation, 0, len(computed))

	for _, comp := range computed {
		fieldType := comp.Type
		if fieldType == "" {
			fieldType = types.FieldTypeFloat
		}

		// Compile the expression
		compiled, err := expression.Compile(comp.Expression, fieldType)
		if err != nil {
			return nil, fmt.Errorf("invalid expression for computed field '%s': %w", comp.Name, err)
		}

		// Validate that all referenced fields exist
		for _, ref := range compiled.References {
			if !fieldNames[ref] {
				return nil, fmt.Errorf("computed field '%s' references unknown field '%s'", comp.Name, ref)
			}
		}

		result = append(result, types.CompiledComputation{
			Name:       comp.Name,
			Expression: comp.Expression,
			Type:       fieldType,
			Compiled:   compiled,
		})

		// Add to fieldNames so subsequent computed fields can reference it
		fieldNames[comp.Name] = true
	}

	// Check for circular dependencies
	if err := c.detectCircularDependencies(result); err != nil {
		return nil, err
	}

	return result, nil
}

// detectCircularDependencies checks for circular references in computed fields
func (c *Compiler) detectCircularDependencies(computed []types.CompiledComputation) error {
	// Build dependency graph
	deps := make(map[string][]string)
	for _, comp := range computed {
		if comp.Compiled != nil {
			deps[comp.Name] = comp.Compiled.References
		}
	}

	// DFS to detect cycles
	visited := make(map[string]int) // 0=unvisited, 1=visiting, 2=visited
	var path []string

	var visit func(name string) error
	visit = func(name string) error {
		if visited[name] == 1 {
			return fmt.Errorf("circular dependency detected: %v -> %s", path, name)
		}
		if visited[name] == 2 {
			return nil
		}

		visited[name] = 1
		path = append(path, name)

		for _, dep := range deps[name] {
			if _, isComputed := deps[dep]; isComputed {
				if err := visit(dep); err != nil {
					return err
				}
			}
		}

		visited[name] = 2
		path = path[:len(path)-1]
		return nil
	}

	for name := range deps {
		if err := visit(name); err != nil {
			return err
		}
	}

	return nil
}

// compileAggregations processes aggregation definitions
func (c *Compiler) compileAggregations(aggs []v1alpha1.Aggregation) []types.CompiledAggregation {
	result := make([]types.CompiledAggregation, len(aggs))

	for i, agg := range aggs {
		compiled := types.CompiledAggregation{
			Name:     agg.Name,
			Field:    agg.Field,
			Function: agg.Function,
			GroupBy:  agg.GroupBy,
		}

		if agg.Percentile != nil {
			compiled.Percentile = *agg.Percentile
		}

		if agg.Filter != nil {
			compiled.Filter = &types.CompiledAggFilter{
				Field:    agg.Filter.Field,
				Operator: agg.Filter.Operator,
				Value:    agg.Filter.Value,
			}
		}

		result[i] = compiled
	}

	return result
}

// compileCollectionConfig applies defaults and validates collection parameters
func (c *Compiler) compileCollectionConfig(config *v1alpha1.CollectionConfig) types.CompiledCollectionConf {
	compiled := types.CompiledCollectionConf{
		IntervalSeconds: 60,
		TimeoutSeconds:  30,
		MaxResources:    5000,
		BatchSize:       500,
		RetryAttempts:   3,
		Parallelism:     3,
	}

	if config.IntervalSeconds > 0 {
		compiled.IntervalSeconds = config.IntervalSeconds
	}
	if config.TimeoutSeconds > 0 {
		compiled.TimeoutSeconds = config.TimeoutSeconds
	}
	if config.MaxResources > 0 {
		compiled.MaxResources = config.MaxResources
	}
	if config.BatchSize > 0 {
		compiled.BatchSize = config.BatchSize
	}
	if config.RetryAttempts >= 0 {
		compiled.RetryAttempts = config.RetryAttempts
	}
	if config.Parallelism > 0 {
		compiled.Parallelism = config.Parallelism
	}

	return compiled
}

// compileRBAC processes RBAC configuration
func (c *Compiler) compileRBAC(rbac *v1alpha1.MetricSourceRBAC) types.CompiledRBAC {
	compiled := types.CompiledRBAC{
		ResourceTypeName:   rbac.ResourceTypeName,
		FilterableFields:   rbac.FilterableFields,
		FilterAggregations: rbac.FilterAggregations,
	}

	if rbac.Identifiers != nil {
		compiled.NamespaceField = rbac.Identifiers.Namespace
		compiled.NameField = rbac.Identifiers.Name
	}

	return compiled
}

// compileNamespacePatterns converts wildcard patterns to compiled regex
func (c *Compiler) compileNamespacePatterns(ns *v1alpha1.NamespaceSelector) (*types.CompiledPatterns, error) {
	patterns := &types.CompiledPatterns{
		Include: make([]*regexp.Regexp, 0, len(ns.Include)),
		Exclude: make([]*regexp.Regexp, 0, len(ns.Exclude)),
	}

	for _, pattern := range ns.Include {
		regex, err := wildcardToRegex(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid include pattern '%s': %w", pattern, err)
		}
		patterns.Include = append(patterns.Include, regex)
	}

	for _, pattern := range ns.Exclude {
		regex, err := wildcardToRegex(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude pattern '%s': %w", pattern, err)
		}
		patterns.Exclude = append(patterns.Exclude, regex)
	}

	return patterns, nil
}

// generateHash creates a deterministic hash of the spec for change detection
func (c *Compiler) generateHash(spec *v1alpha1.MetricSourceSpec) string {
	data, _ := json.Marshal(spec)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:8])
}

// parseAPIVersion splits apiVersion into group and version
func parseAPIVersion(apiVersion string) (group, version string) {
	parts := strings.SplitN(apiVersion, "/", 2)
	if len(parts) == 1 {
		// Core API (e.g., "v1")
		return "", parts[0]
	}
	return parts[0], parts[1]
}

// parseJSONPath splits a JSONPath into path segments
func parseJSONPath(path string) []string {
	// Remove leading dot if present
	path = strings.TrimPrefix(path, ".")

	// Split on dots, handling array notation
	var segments []string
	current := ""

	for i := 0; i < len(path); i++ {
		ch := path[i]
		if ch == '.' {
			if current != "" {
				segments = append(segments, current)
				current = ""
			}
		} else if ch == '[' {
			// Handle array index notation
			if current != "" {
				segments = append(segments, current)
				current = ""
			}
			// Find closing bracket
			end := strings.Index(path[i:], "]")
			if end != -1 {
				segments = append(segments, path[i:i+end+1])
				i += end
			}
		} else {
			current += string(ch)
		}
	}

	if current != "" {
		segments = append(segments, current)
	}

	return segments
}

// wildcardToRegex converts a shell-style wildcard pattern to regex
func wildcardToRegex(pattern string) (*regexp.Regexp, error) {
	// Escape regex special characters except * and ?
	escaped := regexp.QuoteMeta(pattern)
	// Convert wildcards
	escaped = strings.ReplaceAll(escaped, `\*`, ".*")
	escaped = strings.ReplaceAll(escaped, `\?`, ".")
	return regexp.Compile("^" + escaped + "$")
}

// pluralize converts a singular resource name to plural
func pluralize(singular string) string {
	// Handle common Kubernetes resource irregulars
	irregulars := map[string]string{
		"endpoints":                "endpoints",
		"ingress":                  "ingresses",
		"networkpolicy":            "networkpolicies",
		"podsecuritypolicy":        "podsecuritypolicies",
		"resourcequota":            "resourcequotas",
		"limitrange":               "limitranges",
		"serviceaccount":           "serviceaccounts",
		"persistentvolume":         "persistentvolumes",
		"persistentvolumeclaim":    "persistentvolumeclaims",
		"storageclass":             "storageclasses",
		"volumeattachment":         "volumeattachments",
		"customresourcedefinition": "customresourcedefinitions",
	}

	if plural, ok := irregulars[singular]; ok {
		return plural
	}

	// Standard English pluralization rules
	switch {
	case strings.HasSuffix(singular, "s"), strings.HasSuffix(singular, "x"),
		strings.HasSuffix(singular, "ch"), strings.HasSuffix(singular, "sh"):
		return singular + "es"
	case strings.HasSuffix(singular, "y"):
		return singular[:len(singular)-1] + "ies"
	default:
		return singular + "s"
	}
}

// labelSelectorToString converts a LabelSelector to a string for API queries
func labelSelectorToString(selector *metav1.LabelSelector) string {
	if selector == nil {
		return ""
	}

	var parts []string

	// Match labels
	for k, v := range selector.MatchLabels {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}

	// Match expressions
	for _, expr := range selector.MatchExpressions {
		switch expr.Operator {
		case metav1.LabelSelectorOpIn:
			parts = append(parts, fmt.Sprintf("%s in (%s)", expr.Key, strings.Join(expr.Values, ",")))
		case metav1.LabelSelectorOpNotIn:
			parts = append(parts, fmt.Sprintf("%s notin (%s)", expr.Key, strings.Join(expr.Values, ",")))
		case metav1.LabelSelectorOpExists:
			parts = append(parts, expr.Key)
		case metav1.LabelSelectorOpDoesNotExist:
			parts = append(parts, "!"+expr.Key)
		}
	}

	return strings.Join(parts, ",")
}
