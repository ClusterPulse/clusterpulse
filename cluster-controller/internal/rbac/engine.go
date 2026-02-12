package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"sync/atomic"
	"time"

	store "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/sirupsen/logrus"
)

// Engine is the RBAC authorization engine.
type Engine struct {
	store        *store.Client
	cache        *Cache
	cacheEnabled bool
	hits         int64
	misses       int64
}

// NewEngine creates a new RBAC engine.
func NewEngine(s *store.Client, cacheTTLSeconds int) *Engine {
	return &Engine{
		store:        s,
		cache:        NewCache(s.RedisClient(), cacheTTLSeconds),
		cacheEnabled: cacheTTLSeconds > 0,
	}
}

// =========================================================================
// Standard Resource Authorization
// =========================================================================

// Authorize authorizes a request for standard resources.
func (e *Engine) Authorize(ctx context.Context, request *Request) *RBACDecision {
	if e.cacheEnabled {
		cacheKey := fmt.Sprintf("rbac:decision:%s", request.CacheKey())
		if cached := e.cache.GetDecision(ctx, cacheKey); cached != nil {
			atomic.AddInt64(&e.hits, 1)
			cached.Cached = true
			cached.Request = request
			return cached
		}
	}

	atomic.AddInt64(&e.misses, 1)

	policies, _ := e.getApplicablePolicies(ctx, request.Principal)
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

	primaryFilter := decision.GetFilter(resourceType)
	if primaryFilter != nil && primaryFilter.Visibility == VisibilityNone {
		return nil
	}

	if decision.Decision == DecisionAllow && (primaryFilter == nil || (primaryFilter.Visibility == VisibilityAll && primaryFilter.IsEmpty())) {
		return resources
	}

	nsFilter := decision.GetFilter(ResourceNamespace)

	var filtered []map[string]any
	for _, resource := range resources {
		if !e.shouldShowResource(resource, resourceType, primaryFilter, nsFilter) {
			continue
		}
		filtered = append(filtered, e.applyDataFilters(resource, resourceType, decision.Permissions))
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

	sort.Strings(accessible)
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
			atomic.AddInt64(&e.hits, 1)
			cached.Cached = true
			return cached
		}
	}

	atomic.AddInt64(&e.misses, 1)

	// If cluster specified, verify cluster access first
	if cluster != "" {
		clusterResource := &Resource{Type: ResourceCluster, Name: cluster, Cluster: cluster}
		clusterRequest := &Request{Principal: principal, Action: action, Resource: clusterResource}
		if e.Authorize(ctx, clusterRequest).Denied() {
			return &CustomResourceDecision{
				Decision:         DecisionDeny,
				ResourceTypeName: typeName,
				Cluster:          cluster,
				Reason:           fmt.Sprintf("Access denied to cluster '%s'", cluster),
				Filters:          NewCustomResourceFilter(),
				DeniedAggregations: make(map[string]struct{}),
				Permissions:      make(map[Action]struct{}),
			}
		}
	}

	policies, _ := e.getApplicablePolicies(ctx, principal)
	decision := e.evaluateCustomResourcePolicies(principal, typeName, cluster, action, policies)

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

	if decision.Decision == DecisionAllow && decision.Filters.IsUnrestricted() {
		return resources
	}

	var filtered []map[string]any
	for _, resource := range resources {
		if e.customResourceMatchesFilters(resource, decision.Filters) {
			filtered = append(filtered, resource)
		}
	}

	return filtered
}

// GetAccessibleCustomResourceTypes returns types the principal can access (implicit deny).
func (e *Engine) GetAccessibleCustomResourceTypes(ctx context.Context, principal *Principal) []string {
	policies, _ := e.getApplicablePolicies(ctx, principal)
	accessible := make(map[string]struct{})

	for _, policy := range policies {
		if !e.isPolicyValid(policy) {
			continue
		}
		if getStr(policy, "effect") != "Allow" {
			continue
		}

		rules, _ := policy["cluster_rules"].([]any)
		for _, r := range rules {
			rule, _ := r.(map[string]any)
			if rule == nil {
				continue
			}
			customResources, _ := rule["custom_resources"].(map[string]any)
			for typeName, cfg := range customResources {
				cfgMap, _ := cfg.(map[string]any)
				vis := "all"
				if cfgMap != nil {
					if v, ok := cfgMap["visibility"].(string); ok {
						vis = v
					}
				}
				if vis != "none" {
					accessible[typeName] = struct{}{}
				}
			}
		}
	}

	result := make([]string, 0, len(accessible))
	for t := range accessible {
		result = append(result, t)
	}
	sort.Strings(result)
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
	pattern := "rbac:decision:*"
	if principal != nil {
		pattern = fmt.Sprintf("rbac:decision:%s:*", principal.CacheKey())
	}
	return e.cache.ClearDecisions(ctx, pattern)
}

// ClearCustomResourceCache clears custom resource cache.
func (e *Engine) ClearCustomResourceCache(ctx context.Context, principal *Principal, typeName string) int {
	if !e.cacheEnabled {
		return 0
	}
	parts := []string{"rbac:custom"}
	if principal != nil {
		parts = append(parts, principal.CacheKey())
	} else {
		parts = append(parts, "*")
	}
	if typeName != "" {
		parts = append(parts, typeName)
	} else {
		parts = append(parts, "*")
	}
	parts = append(parts, "*", "*") // cluster, action
	pattern := ""
	for i, p := range parts {
		if i > 0 {
			pattern += ":"
		}
		pattern += p
	}
	return e.cache.ClearCustomDecisions(ctx, pattern)
}

// CreateAnonymousPrincipal creates a principal for unauthenticated users.
func (e *Engine) CreateAnonymousPrincipal() *Principal {
	return &Principal{
		Username:   "anonymous",
		Email:      "anonymous@system",
		Groups:     []string{"anonymous", "public"},
		Attributes: map[string]any{"anonymous": true},
	}
}

// AuthorizeAnonymous authorizes anonymous access.
func (e *Engine) AuthorizeAnonymous(action Action, resource *Resource) *RBACDecision {
	principal := e.CreateAnonymousPrincipal()
	request := &Request{Principal: principal, Action: action, Resource: resource}

	if action != ActionView || resource.Type != ResourceCluster {
		return &RBACDecision{
			Decision: DecisionDeny,
			Request:  request,
			Reason:   "Anonymous access only allows viewing cluster health",
		}
	}

	return &RBACDecision{
		Decision:    DecisionAllow,
		Request:     request,
		Reason:      "Anonymous access to public cluster information",
		Permissions: map[Action]struct{}{ActionView: {}},
		Metadata:    map[string]any{"anonymous": true, "restricted": true},
	}
}

// =========================================================================
// Internal Methods
// =========================================================================

func (e *Engine) getApplicablePolicies(ctx context.Context, principal *Principal) ([]map[string]any, error) {
	return e.store.GetPoliciesForPrincipal(ctx, principal.Username, principal.Groups, principal.IsServiceAccount)
}

func (e *Engine) evaluatePolicies(request *Request, policies []map[string]any) *RBACDecision {
	decision := &RBACDecision{
		Decision:    DecisionDeny,
		Request:     request,
		Reason:      "No matching policies found",
		Permissions: make(map[Action]struct{}),
		Filters:     make(map[ResourceType]*Filter),
		Metadata:    make(map[string]any),
	}

	for _, policy := range policies {
		if !e.isPolicyValid(policy) {
			continue
		}

		match := e.matchResource(request.Resource, policy)
		if match == nil {
			continue
		}

		policyKey := getStr(policy, "_key")
		if policyKey == "" {
			policyKey = getStr(policy, "policy_name")
		}
		decision.AppliedPolicies = append(decision.AppliedPolicies, policyKey)

		if getStr(policy, "effect") == "Deny" {
			decision.Decision = DecisionDeny
			decision.Reason = fmt.Sprintf("Denied by policy %s", getStr(policy, "policy_name"))
			break
		}

		if getStr(policy, "effect") == "Allow" {
			permissions, filters := e.extractPermissionsAndFilters(match, policy, request.Resource)
			if len(filters) > 0 {
				decision.Decision = DecisionPartial
			} else {
				decision.Decision = DecisionAllow
			}
			decision.Permissions = permissions
			decision.Filters = filters
			decision.Reason = fmt.Sprintf("Allowed by policy %s", getStr(policy, "policy_name"))

			auditConfig, _ := policy["audit_config"].(map[string]any)
			if logAccess, _ := auditConfig["log_access"].(bool); logAccess {
				decision.Metadata["audit_required"] = true
			}
		}
	}

	return decision
}

func (e *Engine) isPolicyValid(policy map[string]any) bool {
	if enabled, ok := policy["enabled"].(bool); ok && !enabled {
		return false
	}

	now := time.Now().UTC()

	if nb, ok := policy["not_before"].(string); ok && nb != "" {
		t, err := time.Parse(time.RFC3339, nb)
		if err == nil && now.Before(t) {
			return false
		}
	}

	if na, ok := policy["not_after"].(string); ok && na != "" {
		t, err := time.Parse(time.RFC3339, na)
		if err == nil && now.After(t) {
			return false
		}
	}

	return true
}

func (e *Engine) matchResource(resource *Resource, policy map[string]any) map[string]any {
	if resource.Type == ResourceCluster {
		return e.matchCluster(resource, policy)
	}

	if resource.Cluster != "" {
		if match := e.matchClusterName(resource.Cluster, policy); match != nil {
			return match
		}
	}

	if getStr(policy, "default_cluster_access") == "allow" {
		return map[string]any{"permissions": map[string]any{"view": true}, "filters": map[string]any{}}
	}

	return nil
}

func (e *Engine) matchCluster(resource *Resource, policy map[string]any) map[string]any {
	rules, _ := policy["cluster_rules"].([]any)
	for _, r := range rules {
		rule, _ := r.(map[string]any)
		if rule == nil {
			continue
		}

		selector, _ := rule["cluster_selector"].(map[string]any)
		if selector == nil {
			continue
		}

		// matchNames
		if names, ok := selector["matchNames"].([]any); ok {
			for _, n := range names {
				if s, ok := n.(string); ok && s == resource.Name {
					return rule
				}
			}
		}

		// matchPattern
		if pat, ok := selector["matchPattern"].(string); ok {
			if matched, _ := regexp.MatchString(pat, resource.Name); matched {
				return rule
			}
		}

		// matchLabels
		if labels, ok := selector["matchLabels"].(map[string]any); ok && resource.Labels != nil {
			allMatch := true
			for k, v := range labels {
				vs, _ := v.(string)
				if resource.Labels[k] != vs {
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

func (e *Engine) matchClusterName(clusterName string, policy map[string]any) map[string]any {
	rules, _ := policy["cluster_rules"].([]any)
	for _, r := range rules {
		rule, _ := r.(map[string]any)
		if rule == nil {
			continue
		}

		selector, _ := rule["cluster_selector"].(map[string]any)
		if selector == nil {
			continue
		}

		if names, ok := selector["matchNames"].([]any); ok {
			for _, n := range names {
				if s, ok := n.(string); ok && s == clusterName {
					return rule
				}
			}
		}

		if pat, ok := selector["matchPattern"].(string); ok {
			if matched, _ := regexp.MatchString(pat, clusterName); matched {
				return rule
			}
		}
	}

	return nil
}

func (e *Engine) extractPermissionsAndFilters(rule, policy map[string]any, resource *Resource) (map[Action]struct{}, map[ResourceType]*Filter) {
	perms, _ := rule["permissions"].(map[string]any)
	if perms == nil {
		perms = map[string]any{"view": true}
	}

	permissions := make(map[Action]struct{})
	for key, action := range PermissionMapping {
		if v, ok := perms[key].(bool); ok && v {
			permissions[action] = struct{}{}
		}
	}

	filters := make(map[ResourceType]*Filter)
	if nf, ok := rule["node_filter"].(map[string]any); ok {
		filters[ResourceNode] = buildFilter(nf)
	}
	if of, ok := rule["operator_filter"].(map[string]any); ok {
		filters[ResourceOperator] = buildFilter(of)
	}
	if nsf, ok := rule["namespace_filter"].(map[string]any); ok {
		filters[ResourceNamespace] = buildFilter(nsf)
	}
	if pf, ok := rule["pod_filter"].(map[string]any); ok {
		filters[ResourcePod] = buildFilter(pf)
	}

	return permissions, filters
}

func (e *Engine) shouldShowResource(resource map[string]any, resourceType ResourceType, primaryFilter, nsFilter *Filter) bool {
	if primaryFilter != nil {
		if primaryFilter.Visibility == VisibilityNone {
			return false
		}
		if primaryFilter.Visibility == VisibilityAll && primaryFilter.IsEmpty() {
			if resourceType == ResourcePod || resourceType == ResourceOperator || resourceType == ResourceEvent {
				if nsFilter != nil {
					return e.checkNamespaceFilter(resource, resourceType, nsFilter)
				}
			}
			return true
		}
	}

	name := e.extractResourceName(resource, resourceType)
	labels, _ := resource["labels"].(map[string]string)
	if labels == nil {
		if labelsAny, ok := resource["labels"].(map[string]any); ok {
			labels = make(map[string]string, len(labelsAny))
			for k, v := range labelsAny {
				if s, ok := v.(string); ok {
					labels[k] = s
				}
			}
		}
	}

	if resourceType == ResourcePod || resourceType == ResourceOperator || resourceType == ResourceEvent {
		if nsFilter != nil && nsFilter.Visibility == VisibilityNone {
			return false
		}
		if nsFilter != nil && !e.checkNamespaceFilter(resource, resourceType, nsFilter) {
			return false
		}
	}

	if primaryFilter != nil {
		if resourceType == ResourceOperator {
			return e.shouldShowOperator(resource, primaryFilter, nsFilter)
		}
		if !primaryFilter.Matches(name, labels) {
			return false
		}
	}

	return true
}

func (e *Engine) checkNamespaceFilter(resource map[string]any, resourceType ResourceType, nsFilter *Filter) bool {
	if nsFilter.Visibility == VisibilityNone {
		return false
	}
	if nsFilter.Visibility == VisibilityAll && nsFilter.IsEmpty() {
		return true
	}

	if resourceType == ResourceOperator {
		availNS := getStringSlice(resource, "available_in_namespaces")
		if len(availNS) == 1 && availNS[0] == "*" {
			return nsFilter.Visibility != VisibilityNone
		}
		for _, ns := range availNS {
			if nsFilter.Matches(ns, nil) {
				return true
			}
		}
		return false
	}

	ns, _ := resource["namespace"].(string)
	if ns == "" {
		return true
	}
	return nsFilter.Matches(ns, nil)
}

func (e *Engine) shouldShowOperator(operator map[string]any, opFilter, nsFilter *Filter) bool {
	if opFilter.Visibility == VisibilityNone {
		return false
	}
	if opFilter.Visibility == VisibilityAll && opFilter.IsEmpty() {
		if nsFilter != nil {
			return e.checkNamespaceFilter(operator, ResourceOperator, nsFilter)
		}
		return true
	}

	opName, _ := operator["name"].(string)
	displayName, _ := operator["display_name"].(string)

	nameKey := "name:" + opName
	displayNameKey := "name:" + displayName

	// Check exclusions
	for _, key := range []string{opName, nameKey, displayNameKey} {
		if _, excluded := opFilter.Exclude[key]; excluded {
			return false
		}
	}

	// Check inclusions
	if len(opFilter.Include) > 0 {
		nameMatched := false
		for _, key := range []string{opName, nameKey, displayNameKey} {
			if _, ok := opFilter.Include[key]; ok {
				nameMatched = true
				break
			}
		}

		if !nameMatched {
			for _, p := range opFilter.Patterns {
				if p.Original != "" && len(p.Original) > 5 && p.Original[:5] == "name:" {
					if p.Regexp.MatchString(opName) || p.Regexp.MatchString(displayName) {
						nameMatched = true
						break
					}
				}
			}
		}

		if !nameMatched {
			return false
		}
	}

	if nsFilter != nil && nsFilter.Visibility != VisibilityAll {
		availNS := getStringSlice(operator, "available_in_namespaces")
		if len(availNS) == 1 && availNS[0] == "*" {
			return nsFilter.Visibility != VisibilityNone
		}
		for _, ns := range availNS {
			if nsFilter.Matches(ns, nil) {
				nsKey := "ns:" + ns
				if _, excluded := opFilter.Exclude[nsKey]; !excluded {
					return true
				}
			}
		}
		return false
	}

	return true
}

func (e *Engine) extractResourceName(resource map[string]any, resourceType ResourceType) string {
	switch resourceType {
	case ResourceNode:
		return getStr(resource, "name")
	case ResourceOperator:
		if name := getStr(resource, "name"); name != "" {
			return name
		}
		return getStr(resource, "display_name")
	case ResourceNamespace:
		if ns := getStr(resource, "namespace"); ns != "" {
			return ns
		}
		return getStr(resource, "name")
	default:
		return getStr(resource, "name")
	}
}

func (e *Engine) applyDataFilters(resource map[string]any, _ ResourceType, permissions map[Action]struct{}) map[string]any {
	filtered := make(map[string]any, len(resource))
	for k, v := range resource {
		filtered[k] = v
	}

	sensitiveFields := map[Action][]string{
		ActionViewSensitive: {"tokens", "credentials", "secrets", "certificates", "private_keys",
			"service_account_tokens", "kubeconfig", "password", "api_key", "auth_token", "bearer_token"},
		ActionViewCosts: {"cost", "costs", "billing", "price", "prices", "estimated_cost",
			"monthly_cost", "usage_cost", "hourly_rate", "discount", "credits"},
		ActionViewSecrets:  {"secrets", "configmaps"},
		ActionViewMetadata: {"filtered_count", "total_before_filter", "filter_reason", "applied_policies", "access_decision", "permission_source"},
		ActionViewAudit:    {"audit_log", "access_history", "policy_evaluation", "last_accessed_by", "access_count"},
	}

	for action, fields := range sensitiveFields {
		if _, has := permissions[action]; !has {
			for _, field := range fields {
				if _, exists := filtered[field]; exists {
					if action == ActionViewSecrets && (field == "secrets" || field == "configmaps") {
						// Replace with count instead of removing
						if arr, ok := filtered[field].([]any); ok {
							filtered[field] = len(arr)
						} else {
							filtered[field] = 0
						}
					} else {
						delete(filtered, field)
					}
				}
			}
		}
	}

	return filtered
}

// =========================================================================
// Custom Resource Policy Evaluation
// =========================================================================

func (e *Engine) evaluateCustomResourcePolicies(_ *Principal, typeName, cluster string, _ Action, policies []map[string]any) *CustomResourceDecision {
	decision := &CustomResourceDecision{
		Decision:           DecisionDeny,
		ResourceTypeName:   typeName,
		Cluster:            cluster,
		Reason:             fmt.Sprintf("No policy grants access to custom resource type: %s", typeName),
		Filters:            NewCustomResourceFilter(),
		DeniedAggregations: make(map[string]struct{}),
		Permissions:        make(map[Action]struct{}),
	}

	for _, policy := range policies {
		if !e.isPolicyValid(policy) {
			continue
		}

		policyKey := getStr(policy, "_key")
		if policyKey == "" {
			policyKey = getStr(policy, "policy_name")
		}

		if getStr(policy, "effect") == "Deny" {
			rules, _ := policy["cluster_rules"].([]any)
			for _, r := range rules {
				rule, _ := r.(map[string]any)
				if rule == nil {
					continue
				}
				customResources, _ := rule["custom_resources"].(map[string]any)
				if _, ok := customResources[typeName]; ok {
					decision.Decision = DecisionDeny
					decision.Reason = fmt.Sprintf("Denied by policy %s", getStr(policy, "policy_name"))
					decision.AppliedPolicies = append(decision.AppliedPolicies, policyKey)
					return decision
				}
			}
			continue
		}

		if getStr(policy, "effect") != "Allow" {
			continue
		}

		rules, _ := policy["cluster_rules"].([]any)
		for _, r := range rules {
			rule, _ := r.(map[string]any)
			if rule == nil {
				continue
			}
			customResources, _ := rule["custom_resources"].(map[string]any)
			cfg, ok := customResources[typeName]
			if !ok {
				continue
			}

			config, _ := cfg.(map[string]any)
			if config == nil {
				continue
			}

			decision.AppliedPolicies = append(decision.AppliedPolicies, policyKey)

			vis, _ := config["visibility"].(string)
			if vis == "" {
				vis = "all"
			}
			if vis == "none" {
				continue
			}

			filters := e.parseCustomResourceFilters(config)
			if vis == "all" && filters.IsUnrestricted() {
				decision.Decision = DecisionAllow
			} else {
				decision.Decision = DecisionPartial
				filters.Visibility = VisibilityFiltered
			}

			decision.Filters = filters
			decision.Reason = fmt.Sprintf("Allowed by policy %s", getStr(policy, "policy_name"))

			permsConfig, _ := config["permissions"].(map[string]any)
			if permsConfig == nil {
				permsConfig = map[string]any{"view": true}
			}
			decision.Permissions = extractCustomPermissions(permsConfig)

			aggConfig, _ := config["aggregation_rules"].(map[string]any)
			if aggConfig != nil {
				if inc, ok := aggConfig["include"].([]any); ok {
					allowed := make(map[string]struct{}, len(inc))
					for _, i := range inc {
						if s, ok := i.(string); ok {
							allowed[s] = struct{}{}
						}
					}
					decision.AllowedAggregations = &allowed
				}
				if exc, ok := aggConfig["exclude"].([]any); ok {
					for _, e := range exc {
						if s, ok := e.(string); ok {
							decision.DeniedAggregations[s] = struct{}{}
						}
					}
				}
			}

			return decision
		}
	}

	return decision
}

func (e *Engine) parseCustomResourceFilters(config map[string]any) *CustomResourceFilter {
	result := NewCustomResourceFilter()

	// Namespace filter
	if nsConfig, ok := config["namespace_filter"].(map[string]any); ok {
		result.NamespaceLiterals, result.NamespacePatterns = parseFilterSpecsFromAny(
			sliceVal(nsConfig, "allowed_literals"),
			sliceVal(nsConfig, "allowed_patterns"),
		)
		result.NamespaceExcludeLiterals, result.NamespaceExcludePatterns = parseFilterSpecsFromAny(
			sliceVal(nsConfig, "denied_literals"),
			sliceVal(nsConfig, "denied_patterns"),
		)
	}

	// Name filter
	if nameConfig, ok := config["name_filter"].(map[string]any); ok {
		result.NameLiterals, result.NamePatterns = parseFilterSpecsFromAny(
			sliceVal(nameConfig, "allowed_literals"),
			sliceVal(nameConfig, "allowed_patterns"),
		)
		result.NameExcludeLiterals, result.NameExcludePatterns = parseFilterSpecsFromAny(
			sliceVal(nameConfig, "denied_literals"),
			sliceVal(nameConfig, "denied_patterns"),
		)
	}

	// Field filters
	if fieldConfigs, ok := config["field_filters"].(map[string]any); ok {
		for fieldName, spec := range fieldConfigs {
			fieldSpec, _ := spec.(map[string]any)
			if fieldSpec == nil {
				continue
			}
			ff := &FieldFilter{
				AllowedLiterals: make(map[string]struct{}),
				DeniedLiterals:  make(map[string]struct{}),
			}
			ff.AllowedLiterals, ff.AllowedPatterns = parseFilterSpecsFromAny(
				sliceVal(fieldSpec, "allowed_literals"),
				sliceVal(fieldSpec, "allowed_patterns"),
			)
			ff.DeniedLiterals, ff.DeniedPatterns = parseFilterSpecsFromAny(
				sliceVal(fieldSpec, "denied_literals"),
				sliceVal(fieldSpec, "denied_patterns"),
			)
			result.FieldFilters[fieldName] = ff
		}
	}

	if result.IsUnrestricted() {
		result.Visibility = VisibilityAll
	} else {
		result.Visibility = VisibilityFiltered
	}

	return result
}

func extractCustomPermissions(config map[string]any) map[Action]struct{} {
	permissions := make(map[Action]struct{})
	for key, action := range PermissionMapping {
		if v, ok := config[key].(bool); ok && v {
			permissions[action] = struct{}{}
		}
	}
	return permissions
}

func (e *Engine) customResourceMatchesFilters(resource map[string]any, filters *CustomResourceFilter) bool {
	if filters.Visibility == VisibilityNone {
		return false
	}

	ns, _ := resource["_namespace"].(string)
	name, _ := resource["_name"].(string)
	if name == "" {
		logrus.Warn("Resource missing _name field, excluding from results")
		return false
	}

	if !filters.MatchesNamespace(ns) {
		return false
	}
	if !filters.MatchesName(name) {
		return false
	}

	values, _ := resource["values"].(map[string]any)
	for fieldName := range filters.FieldFilters {
		var fieldValue any
		if values != nil {
			fieldValue = values[fieldName]
		}
		if !filters.MatchesField(fieldName, fieldValue) {
			return false
		}
	}

	return true
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

	filterInfo := make(map[string]any, len(decision.Filters))
	for rt, f := range decision.Filters {
		filterInfo[string(rt)] = map[string]any{
			"visibility":  string(f.Visibility),
			"has_filters": !f.IsEmpty(),
		}
	}
	entry["filters"] = filterInfo

	raw, _ := json.Marshal(entry)
	auditKey := fmt.Sprintf("audit:rbac:%s", time.Now().UTC().Format("20060102"))
	e.store.RedisClient().LPush(ctx, auditKey, string(raw))
	e.store.RedisClient().Expire(ctx, auditKey, 30*24*time.Hour)
}

// =========================================================================
// Helpers
// =========================================================================

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
