package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	store "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/sirupsen/logrus"
)

// maxPatternLength is the maximum allowed length for matchPattern regex strings.
const maxPatternLength = 256

// Engine is the RBAC authorization engine.
type Engine struct {
	store        *store.Client
	cache        *Cache
	cacheEnabled bool
	hits         atomic.Int64
	misses       atomic.Int64
	regexCache   sync.Map // string -> *regexp.Regexp
}

// NewEngine creates a new RBAC engine.
func NewEngine(s *store.Client, cacheTTLSeconds int) *Engine {
	return &Engine{
		store:        s,
		cache:        NewCache(s.RedisClient(), cacheTTLSeconds),
		cacheEnabled: cacheTTLSeconds > 0,
	}
}

// compilePattern returns a cached compiled regex, or compiles and caches it.
func (e *Engine) compilePattern(pattern string) *regexp.Regexp {
	if len(pattern) > maxPatternLength {
		logrus.Warnf("Regex pattern exceeds max length (%d > %d), rejecting", len(pattern), maxPatternLength)
		return nil
	}
	if cached, ok := e.regexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		logrus.Warnf("Invalid regex pattern %q: %v", pattern, err)
		return nil
	}
	e.regexCache.Store(pattern, re)
	return re
}

// =========================================================================
// Resource Handlers
// =========================================================================

// ResourceHandler extracts fields from raw resource data for filtering.
type ResourceHandler struct {
	ExtractName       func(map[string]any) string
	ExtractNamespaces func(map[string]any) []string
	ExtractLabels     func(map[string]any) map[string]string
}

var standardHandlers = map[string]*ResourceHandler{
	"nodes":      {extractStr("name"), noNamespaces, extractLabelsFromMap},
	"operators":  {operatorName, operatorNamespaces, extractLabelsFromMap},
	"namespaces": {namespaceName, noNamespaces, extractLabelsFromMap},
	"pods":       {extractStr("name"), singleNamespace("namespace"), extractLabelsFromMap},
	"events":     {extractStr("name"), singleNamespace("namespace"), extractLabelsFromMap},
	"alerts":     {extractStr("name"), noNamespaces, extractLabelsFromMap},
}

var defaultCustomHandler = &ResourceHandler{
	ExtractName:       extractStr("_name"),
	ExtractNamespaces: singleNamespace("_namespace"),
	ExtractLabels:     func(map[string]any) map[string]string { return nil },
}

func extractStr(key string) func(map[string]any) string {
	return func(r map[string]any) string { return getStr(r, key) }
}

func noNamespaces(_ map[string]any) []string { return nil }

func singleNamespace(key string) func(map[string]any) []string {
	return func(r map[string]any) []string {
		ns := getStr(r, key)
		if ns == "" {
			return nil
		}
		return []string{ns}
	}
}

func operatorName(r map[string]any) string {
	if name := getStr(r, "name"); name != "" {
		return name
	}
	return getStr(r, "display_name")
}

func operatorNamespaces(r map[string]any) []string {
	ns := getStringSlice(r, "available_in_namespaces")
	if len(ns) == 1 && ns[0] == "*" {
		return nil // cluster-wide, passes any namespace filter
	}
	return ns
}

func namespaceName(r map[string]any) string {
	if ns := getStr(r, "namespace"); ns != "" {
		return ns
	}
	return getStr(r, "name")
}

func extractLabelsFromMap(r map[string]any) map[string]string {
	if labels, ok := r["labels"].(map[string]string); ok {
		return labels
	}
	if labelsAny, ok := r["labels"].(map[string]any); ok {
		labels := make(map[string]string, len(labelsAny))
		for k, v := range labelsAny {
			if s, ok := v.(string); ok {
				labels[k] = s
			}
		}
		return labels
	}
	return nil
}

func (e *Engine) getHandler(filterKey string) *ResourceHandler {
	if h, ok := standardHandlers[filterKey]; ok {
		return h
	}
	return defaultCustomHandler
}

// =========================================================================
// Standard Resource Authorization
// =========================================================================

// Authorize authorizes a request for standard resources.
func (e *Engine) Authorize(ctx context.Context, request *Request) *RBACDecision {
	if request.Principal == nil {
		return &RBACDecision{
			Decision:    DecisionDeny,
			Request:     request,
			Reason:      "No principal provided",
			Permissions: make(map[Action]struct{}),
			Matchers:    make(map[string]*ResourceMatcher),
			Metadata:    make(map[string]any),
		}
	}

	if e.cacheEnabled {
		cacheKey := fmt.Sprintf("rbac:decision:%s", request.CacheKey())
		if cached := e.cache.GetDecision(ctx, cacheKey); cached != nil {
			e.hits.Add(1)
			cached.Cached = true
			cached.Request = request
			return cached
		}
	}

	e.misses.Add(1)

	policies, err := e.getApplicablePolicies(ctx, request.Principal)
	if err != nil {
		logrus.WithError(err).Warn("Failed to fetch applicable policies, defaulting to deny")
		return &RBACDecision{
			Decision:    DecisionDeny,
			Request:     request,
			Reason:      "Policy fetch failed: " + err.Error(),
			Permissions: make(map[Action]struct{}),
			Matchers:    make(map[string]*ResourceMatcher),
			Metadata:    make(map[string]any),
		}
	}
	decision := e.evaluatePolicies(request, policies)

	if e.cacheEnabled {
		cacheKey := fmt.Sprintf("rbac:decision:%s", request.CacheKey())
		e.cache.SetDecision(ctx, cacheKey, decision)
	}

	if audit, _ := decision.Metadata["audit_required"].(bool); audit {
		e.auditLog(ctx, request, decision)
	}

	return decision
}

// FilterResources filters resources based on RBAC permissions.
func (e *Engine) FilterResources(ctx context.Context, principal *Principal, resources []map[string]any, resourceType ResourceType, cluster string) []map[string]any {
	if len(resources) == 0 {
		return nil
	}

	dummyResource := &Resource{Type: resourceType, Name: "*", Cluster: cluster}
	request := &Request{Principal: principal, Action: ActionView, Resource: dummyResource}
	decision := e.Authorize(ctx, request)

	if decision.Denied() {
		return nil
	}

	filterKey := ResourceTypeToFilterKey[resourceType]
	matcher := decision.Matchers[filterKey]

	if matcher != nil && matcher.Visibility == VisibilityNone {
		return nil
	}
	if decision.Decision == DecisionAllow && (matcher == nil || matcher.IsUnrestricted()) {
		return resources
	}

	handler := e.getHandler(filterKey)

	var filtered []map[string]any
	for _, resource := range resources {
		if e.matchesResource(resource, matcher, handler) {
			filtered = append(filtered, resource)
		}
	}

	return filtered
}

// GetAccessibleClusters returns clusters accessible to principal.
func (e *Engine) GetAccessibleClusters(ctx context.Context, principal *Principal) []string {
	allClusters, err := e.store.GetAllClusterNames(ctx)
	if err != nil {
		return nil
	}

	var accessible []string
	for _, name := range allClusters {
		resource := &Resource{Type: ResourceCluster, Name: name, Cluster: name}
		request := &Request{Principal: principal, Action: ActionView, Resource: resource}
		if e.Authorize(ctx, request).Allowed() {
			accessible = append(accessible, name)
		}
	}

	slices.Sort(accessible)
	return accessible
}

// GetPermissions returns all permissions for principal on resource.
func (e *Engine) GetPermissions(ctx context.Context, principal *Principal, resource *Resource) map[Action]struct{} {
	permissions := make(map[Action]struct{})
	for _, action := range AllActions {
		request := &Request{Principal: principal, Action: action, Resource: resource}
		if e.Authorize(ctx, request).Allowed() {
			permissions[action] = struct{}{}
		}
	}
	return permissions
}

// =========================================================================
// Custom Resource Authorization
// =========================================================================

// AuthorizeCustomResource authorizes access to a custom resource type.
func (e *Engine) AuthorizeCustomResource(ctx context.Context, principal *Principal, typeName, cluster string, action Action) *CustomResourceDecision {
	if e.cacheEnabled {
		cacheKey := CustomResourceCacheKey(principal, typeName, cluster, action)
		if cached := e.cache.GetCustomDecision(ctx, cacheKey); cached != nil {
			e.hits.Add(1)
			cached.Cached = true
			return cached
		}
	}

	e.misses.Add(1)

	if cluster != "" {
		clusterResource := &Resource{Type: ResourceCluster, Name: cluster, Cluster: cluster}
		clusterRequest := &Request{Principal: principal, Action: action, Resource: clusterResource}
		if e.Authorize(ctx, clusterRequest).Denied() {
			return &CustomResourceDecision{
				Decision:           DecisionDeny,
				ResourceTypeName:   typeName,
				Cluster:            cluster,
				Reason:             fmt.Sprintf("Access denied to cluster '%s'", cluster),
				Matcher:            &ResourceMatcher{Visibility: VisibilityNone},
				DeniedAggregations: make(map[string]struct{}),
				Permissions:        make(map[Action]struct{}),
			}
		}
	}

	policies, _ := e.getApplicablePolicies(ctx, principal)
	decision := e.evaluateCustomResourcePolicies(typeName, cluster, action, policies)

	if e.cacheEnabled {
		cacheKey := CustomResourceCacheKey(principal, typeName, cluster, action)
		e.cache.SetCustomDecision(ctx, cacheKey, decision)
	}

	return decision
}

// FilterCustomResources filters custom resources based on RBAC permissions.
func (e *Engine) FilterCustomResources(ctx context.Context, principal *Principal, resources []map[string]any, typeName, cluster string) []map[string]any {
	if len(resources) == 0 {
		return nil
	}

	decision := e.AuthorizeCustomResource(ctx, principal, typeName, cluster, ActionView)
	if decision.Denied() {
		return nil
	}

	if decision.Decision == DecisionAllow && decision.Matcher.IsUnrestricted() {
		return resources
	}

	handler := e.getHandler(typeName)

	var filtered []map[string]any
	for _, resource := range resources {
		if e.matchesResource(resource, decision.Matcher, handler) {
			filtered = append(filtered, resource)
		}
	}

	return filtered
}

// GetAccessibleCustomResourceTypes returns types the principal can access.
func (e *Engine) GetAccessibleCustomResourceTypes(ctx context.Context, principal *Principal) []string {
	policies, _ := e.getApplicablePolicies(ctx, principal)
	accessible := make(map[string]struct{})

	for i := range policies {
		policy := &policies[i]
		if !e.isPolicyValid(policy) {
			continue
		}
		if policy.Effect != "Allow" {
			continue
		}

		for j := range policy.ClusterRules {
			for k := range policy.ClusterRules[j].Resources {
				rf := &policy.ClusterRules[j].Resources[k]
				if !isStandardResourceType(rf.Type) && rf.Visibility != "none" {
					accessible[rf.Type] = struct{}{}
				}
			}
		}
	}

	result := make([]string, 0, len(accessible))
	for t := range accessible {
		result = append(result, t)
	}
	slices.Sort(result)
	return result
}

// FilterAggregations filters aggregations based on RBAC permissions.
func (e *Engine) FilterAggregations(ctx context.Context, principal *Principal, aggregations map[string]any, typeName, cluster string) map[string]any {
	if len(aggregations) == 0 {
		return map[string]any{}
	}

	decision := e.AuthorizeCustomResource(ctx, principal, typeName, cluster, ActionViewMetrics)
	if decision.Denied() {
		return map[string]any{}
	}

	filtered := make(map[string]any, len(aggregations))
	for name, value := range aggregations {
		if decision.IsAggregationAllowed(name) {
			filtered[name] = value
		}
	}
	return filtered
}

// ClearCache clears authorization cache for a principal (or all).
func (e *Engine) ClearCache(ctx context.Context, principal *Principal) int {
	if !e.cacheEnabled {
		return 0
	}
	decisionPattern := "rbac:decision:*"
	customPattern := "rbac:custom:*"
	if principal != nil {
		escaped := escapeRedisGlob(principal.CacheKey())
		decisionPattern = fmt.Sprintf("rbac:decision:%s:*", escaped)
		customPattern = fmt.Sprintf("rbac:custom:%s:*", escaped)
	}
	count := e.cache.ClearDecisions(ctx, decisionPattern)
	count += e.cache.ClearDecisions(ctx, customPattern)
	return count
}

func escapeRedisGlob(s string) string {
	replacer := strings.NewReplacer(
		`*`, `\*`,
		`?`, `\?`,
		`[`, `\[`,
		`]`, `\]`,
	)
	return replacer.Replace(s)
}

// =========================================================================
// Internal Methods
// =========================================================================

func (e *Engine) getApplicablePolicies(ctx context.Context, principal *Principal) ([]types.CompiledPolicy, error) {
	return e.store.GetPoliciesForPrincipal(ctx, principal.Username, principal.Groups, principal.IsServiceAccount)
}

func (e *Engine) evaluatePolicies(request *Request, policies []types.CompiledPolicy) *RBACDecision {
	decision := &RBACDecision{
		Decision:    DecisionDeny,
		Request:     request,
		Reason:      "No matching policies found",
		Permissions: make(map[Action]struct{}),
		Matchers:    make(map[string]*ResourceMatcher),
		Metadata:    make(map[string]any),
	}

	for i := range policies {
		policy := &policies[i]
		if !e.isPolicyValid(policy) {
			continue
		}

		match := e.matchResource(request.Resource, policy)
		if match == nil {
			continue
		}

		policyKey := policy.RedisKey
		if policyKey == "" {
			policyKey = policy.PolicyName
		}
		decision.AppliedPolicies = append(decision.AppliedPolicies, policyKey)

		if policy.Effect == "Deny" {
			decision.Decision = DecisionDeny
			decision.Reason = fmt.Sprintf("Denied by policy %s", policy.PolicyName)
			break
		}

		if policy.Effect == "Allow" {
			permissions, matchers := e.extractPermissionsAndMatchers(match)
			if len(matchers) > 0 {
				decision.Decision = DecisionPartial
			} else {
				decision.Decision = DecisionAllow
			}
			decision.Permissions = permissions
			decision.Matchers = matchers
			decision.Reason = fmt.Sprintf("Allowed by policy %s", policy.PolicyName)

				// First-match-wins
			break
		}
	}

	return decision
}

func (e *Engine) isPolicyValid(policy *types.CompiledPolicy) bool {
	if !policy.Enabled {
		return false
	}

	now := time.Now().UTC()

	if policy.NotBefore != nil && *policy.NotBefore != "" {
		t, err := time.Parse(time.RFC3339, *policy.NotBefore)
		if err != nil {
			logrus.Warnf("Policy %s has invalid not_before %q, treating as invalid", policy.PolicyName, *policy.NotBefore)
			return false
		}
		if now.Before(t) {
			return false
		}
	}

	if policy.NotAfter != nil && *policy.NotAfter != "" {
		t, err := time.Parse(time.RFC3339, *policy.NotAfter)
		if err != nil {
			logrus.Warnf("Policy %s has invalid not_after %q, treating as invalid", policy.PolicyName, *policy.NotAfter)
			return false
		}
		if now.After(t) {
			return false
		}
	}

	return true
}

func (e *Engine) matchResource(resource *Resource, policy *types.CompiledPolicy) *types.CompiledClusterRule {
	if resource.Type == ResourceCluster {
		return e.matchCluster(resource, policy)
	}

	if resource.Cluster != "" {
		if match := e.matchClusterName(resource.Cluster, policy); match != nil {
			return match
		}
	}

	if policy.DefaultClusterAccess == "allow" {
		return &types.CompiledClusterRule{
			Permissions: map[string]bool{"view": true},
		}
	}

	return nil
}

func (e *Engine) matchCluster(resource *Resource, policy *types.CompiledPolicy) *types.CompiledClusterRule {
	for i := range policy.ClusterRules {
		rule := &policy.ClusterRules[i]
		sel := &rule.ClusterSelector

		if slices.Contains(sel.MatchNames, resource.Name) {
			return rule
		}

		if sel.MatchPattern != "" {
			if re := e.compilePattern(sel.MatchPattern); re != nil && re.MatchString(resource.Name) {
				return rule
			}
		}

		if sel.MatchLabels != nil && (resource.Labels != nil || len(sel.MatchLabels) == 0) {
			allMatch := true
			for k, v := range sel.MatchLabels {
				if resource.Labels[k] != v {
					allMatch = false
					break
				}
			}
			if allMatch {
				return rule
			}
		}
	}

	return nil
}

func (e *Engine) clusterMatchesSelector(clusterName string, sel *types.CompiledClusterSelector) bool {
	if slices.Contains(sel.MatchNames, clusterName) {
		return true
	}
	if sel.MatchPattern != "" {
		if re := e.compilePattern(sel.MatchPattern); re != nil && re.MatchString(clusterName) {
			return true
		}
	}
	return false
}

func (e *Engine) matchClusterName(clusterName string, policy *types.CompiledPolicy) *types.CompiledClusterRule {
	for i := range policy.ClusterRules {
		if e.clusterMatchesSelector(clusterName, &policy.ClusterRules[i].ClusterSelector) {
			return &policy.ClusterRules[i]
		}
	}
	return nil
}

func permissionsFromRule(perms map[string]bool) map[Action]struct{} {
	permissions := make(map[Action]struct{})
	if perms == nil {
		permissions[ActionView] = struct{}{}
	} else {
		for key, action := range PermissionMapping {
			if perms[key] {
				permissions[action] = struct{}{}
			}
		}
	}
	return permissions
}

func (e *Engine) extractPermissionsAndMatchers(rule *types.CompiledClusterRule) (map[Action]struct{}, map[string]*ResourceMatcher) {
	permissions := permissionsFromRule(rule.Permissions)

	matchers := make(map[string]*ResourceMatcher, len(rule.Resources))
	for i := range rule.Resources {
		matchers[rule.Resources[i].Type] = buildMatcherFromCompiled(&rule.Resources[i])
	}

	return permissions, matchers
}

// matchesResource checks if a raw resource passes the matcher criteria.
func (e *Engine) matchesResource(resource map[string]any, matcher *ResourceMatcher, handler *ResourceHandler) bool {
	if matcher == nil {
		return true
	}
	if matcher.Visibility == VisibilityNone {
		return false
	}

	name := handler.ExtractName(resource)
	namespaces := handler.ExtractNamespaces(resource)
	labels := handler.ExtractLabels(resource)

	// Name matching
	if matcher.Names != nil {
		if name == "" {
			return false
		}
		if !matcher.Names.Matches(name) {
			return false
		}
	}

	// Namespace matching — any extracted namespace must match
	if matcher.Namespaces != nil && len(namespaces) > 0 {
		anyMatch := false
		for _, ns := range namespaces {
			if matcher.Namespaces.Matches(ns) {
				anyMatch = true
				break
			}
		}
		if !anyMatch {
			return false
		}
	}

	// Label matching
	if len(matcher.Labels) > 0 {
		if labels == nil {
			return false
		}
		for k, v := range matcher.Labels {
			if labels[k] != v {
				return false
			}
		}
	}

	// Field matching (custom resources)
	if len(matcher.FieldFilters) > 0 {
		values, _ := resource["values"].(map[string]any)
		for fieldName, ms := range matcher.FieldFilters {
			var fieldValue any
			if values != nil {
				fieldValue = values[fieldName]
			}
			valueStr := ""
			if fieldValue != nil {
				valueStr = fmt.Sprintf("%v", fieldValue)
			}
			if !ms.Matches(valueStr) {
				return false
			}
		}
	}

	return true
}

// =========================================================================
// Custom Resource Policy Evaluation
// =========================================================================

func (e *Engine) evaluateCustomResourcePolicies(typeName, cluster string, _ Action, policies []types.CompiledPolicy) *CustomResourceDecision {
	decision := &CustomResourceDecision{
		Decision:           DecisionDeny,
		ResourceTypeName:   typeName,
		Cluster:            cluster,
		Reason:             fmt.Sprintf("No policy grants access to custom resource type: %s", typeName),
		Matcher:            &ResourceMatcher{Visibility: VisibilityNone},
		DeniedAggregations: make(map[string]struct{}),
		Permissions:        make(map[Action]struct{}),
	}

	for i := range policies {
		policy := &policies[i]
		if !e.isPolicyValid(policy) {
			continue
		}

		policyKey := policy.RedisKey
		if policyKey == "" {
			policyKey = policy.PolicyName
		}

		if policy.Effect == "Deny" {
			for j := range policy.ClusterRules {
				rule := &policy.ClusterRules[j]
				if cluster != "" && !e.clusterMatchesSelector(cluster, &rule.ClusterSelector) {
					continue
				}
				for k := range rule.Resources {
					if rule.Resources[k].Type == typeName {
						decision.Decision = DecisionDeny
						decision.Reason = fmt.Sprintf("Denied by policy %s", policy.PolicyName)
						decision.AppliedPolicies = append(decision.AppliedPolicies, policyKey)
						return decision
					}
				}
			}
			continue
		}

		if policy.Effect != "Allow" {
			continue
		}

		for j := range policy.ClusterRules {
			rule := &policy.ClusterRules[j]
			if cluster != "" && !e.clusterMatchesSelector(cluster, &rule.ClusterSelector) {
				continue
			}
			for k := range rule.Resources {
				rf := &rule.Resources[k]
				if rf.Type != typeName {
					continue
				}

				decision.AppliedPolicies = append(decision.AppliedPolicies, policyKey)

				if rf.Visibility == "none" {
					continue
				}

				matcher := buildMatcherFromCompiled(rf)
				if rf.Visibility == "all" && matcher.IsUnrestricted() {
					decision.Decision = DecisionAllow
				} else {
					decision.Decision = DecisionPartial
					matcher.Visibility = VisibilityFiltered
				}

				decision.Matcher = matcher
				decision.Reason = fmt.Sprintf("Allowed by policy %s", policy.PolicyName)
				decision.Permissions = permissionsFromRule(rule.Permissions)

				// Aggregation rules
				if rf.AggregationRules != nil {
					if len(rf.AggregationRules.Include) > 0 {
						allowed := make(map[string]struct{}, len(rf.AggregationRules.Include))
						for _, name := range rf.AggregationRules.Include {
							allowed[name] = struct{}{}
						}
						decision.AllowedAggregations = &allowed
					}
					for _, name := range rf.AggregationRules.Exclude {
						decision.DeniedAggregations[name] = struct{}{}
					}
				}

				return decision
			}
		}
	}

	return decision
}

func (e *Engine) auditLog(ctx context.Context, request *Request, decision *RBACDecision) {
	entry := map[string]any{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"principal": request.Principal.Username,
		"groups":    request.Principal.Groups,
		"action":    string(request.Action),
		"resource":  request.Resource.ID(),
		"decision":  string(decision.Decision),
		"reason":    decision.Reason,
		"policies":  decision.AppliedPolicies,
	}

	matcherInfo := make(map[string]any, len(decision.Matchers))
	for rt, m := range decision.Matchers {
		matcherInfo[rt] = map[string]any{
			"visibility":      string(m.Visibility),
			"is_unrestricted": m.IsUnrestricted(),
		}
	}
	entry["filters"] = matcherInfo

	raw, _ := json.Marshal(entry)
	auditKey := fmt.Sprintf("audit:rbac:%s", time.Now().UTC().Format("20060102"))
	e.store.RedisClient().LPush(ctx, auditKey, string(raw))
	e.store.RedisClient().Expire(ctx, auditKey, 30*24*time.Hour)
}

// =========================================================================
// Helpers
// =========================================================================

func isStandardResourceType(t string) bool {
	switch t {
	case "nodes", "operators", "namespaces", "pods":
		return true
	}
	return false
}

func getStr(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getStringSlice(m map[string]any, key string) []string {
	if v, ok := m[key].([]any); ok {
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	if v, ok := m[key].([]string); ok {
		return v
	}
	return nil
}
