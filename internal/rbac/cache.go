package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	goredis "github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

// Cache manages RBAC decision caching in Redis.
type Cache struct {
	redis   *goredis.Client
	ttl     time.Duration
	enabled bool
}

// NewCache creates a new RBAC cache. Disabled if ttl <= 0.
func NewCache(redis *goredis.Client, ttlSeconds int) *Cache {
	return &Cache{
		redis:   redis,
		ttl:     time.Duration(ttlSeconds) * time.Second,
		enabled: ttlSeconds > 0,
	}
}

// --- Cache DTOs (JSON-serializable) ---

type cachedDecision struct {
	Decision        string                            `json:"decision"`
	Reason          string                            `json:"reason"`
	Permissions     []string                          `json:"permissions"`
	AppliedPolicies []string                          `json:"applied_policies,omitempty"`
	Metadata        map[string]any                    `json:"metadata,omitempty"`
	Matchers        map[string]*cachedResourceMatcher `json:"matchers,omitempty"`
	Principal       *cachedPrincipal                  `json:"principal,omitempty"`
	Action          string                            `json:"action,omitempty"`
	Resource        *cachedResource                   `json:"resource,omitempty"`
}

type cachedCustomDecision struct {
	Decision            string                 `json:"decision"`
	ResourceTypeName    string                 `json:"resource_type_name"`
	Cluster             string                 `json:"cluster,omitempty"`
	Reason              string                 `json:"reason"`
	Permissions         []string               `json:"permissions"`
	AppliedPolicies     []string               `json:"applied_policies,omitempty"`
	Metadata            map[string]any         `json:"metadata,omitempty"`
	AllowedAggregations *[]string              `json:"allowed_aggregations,omitempty"`
	DeniedAggregations  []string               `json:"denied_aggregations"`
	Matcher             *cachedResourceMatcher `json:"matcher"`
}

type cachedPrincipal struct {
	Username string   `json:"username"`
	Email    string   `json:"email,omitempty"`
	Groups   []string `json:"groups"`
}

type cachedResource struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Cluster   string `json:"cluster,omitempty"`
}

type cachedResourceMatcher struct {
	Visibility   string                      `json:"visibility"`
	Names        *cachedMatchSpec            `json:"names,omitempty"`
	Namespaces   *cachedMatchSpec            `json:"namespaces,omitempty"`
	Labels       map[string]string           `json:"labels,omitempty"`
	FieldFilters map[string]*cachedMatchSpec `json:"field_filters,omitempty"`
}

type cachedMatchSpec struct {
	Include         []string    `json:"include"`
	Exclude         []string    `json:"exclude"`
	IncludePatterns [][2]string `json:"include_patterns,omitempty"`
	ExcludePatterns [][2]string `json:"exclude_patterns,omitempty"`
}

// --- Standard Decision Cache ---

// GetDecision retrieves a cached standard RBAC decision.
func (c *Cache) GetDecision(ctx context.Context, key string) *RBACDecision {
	if !c.enabled {
		return nil
	}
	data, err := c.redis.Get(ctx, key).Result()
	if err != nil {
		return nil
	}

	var cd cachedDecision
	if err := json.Unmarshal([]byte(data), &cd); err != nil {
		return nil
	}

	return &RBACDecision{
		Decision:        Decision(cd.Decision),
		Reason:          cd.Reason,
		Permissions:     stringsToActionSet(cd.Permissions),
		AppliedPolicies: cd.AppliedPolicies,
		Metadata:        cd.Metadata,
		Matchers:        fromCachedMatchers(cd.Matchers),
	}
}

// SetDecision caches a standard RBAC decision.
func (c *Cache) SetDecision(ctx context.Context, key string, d *RBACDecision) {
	if !c.enabled {
		return
	}

	cd := &cachedDecision{
		Decision:        string(d.Decision),
		Reason:          d.Reason,
		Permissions:     actionSetToStrings(d.Permissions),
		AppliedPolicies: d.AppliedPolicies,
		Metadata:        d.Metadata,
		Matchers:        toCachedMatchers(d.Matchers),
	}

	if d.Request != nil {
		cd.Principal = &cachedPrincipal{
			Username: d.Request.Principal.Username,
			Email:    d.Request.Principal.Email,
			Groups:   d.Request.Principal.Groups,
		}
		cd.Action = string(d.Request.Action)
		cd.Resource = &cachedResource{
			Type:      string(d.Request.Resource.Type),
			Name:      d.Request.Resource.Name,
			Namespace: d.Request.Resource.Namespace,
			Cluster:   d.Request.Resource.Cluster,
		}
	}

	raw, err := json.Marshal(cd)
	if err != nil {
		return
	}
	if err := c.redis.SetEX(ctx, key, string(raw), c.ttl).Err(); err != nil {
		logrus.Debugf("Cache storage failed: %v", err)
	}
}

// ClearDecisions clears cached decisions matching a pattern.
func (c *Cache) ClearDecisions(ctx context.Context, pattern string) int {
	return c.scanAndDelete(ctx, pattern)
}

// --- Custom Decision Cache ---

// GetCustomDecision retrieves a cached custom resource decision.
func (c *Cache) GetCustomDecision(ctx context.Context, key string) *CustomResourceDecision {
	if !c.enabled {
		return nil
	}
	data, err := c.redis.Get(ctx, key).Result()
	if err != nil {
		return nil
	}

	var cd cachedCustomDecision
	if err := json.Unmarshal([]byte(data), &cd); err != nil {
		return nil
	}

	d := &CustomResourceDecision{
		Decision:           Decision(cd.Decision),
		ResourceTypeName:   cd.ResourceTypeName,
		Cluster:            cd.Cluster,
		Reason:             cd.Reason,
		Permissions:        stringsToActionSet(cd.Permissions),
		AppliedPolicies:    cd.AppliedPolicies,
		Metadata:           cd.Metadata,
		DeniedAggregations: sliceToStringSet(cd.DeniedAggregations),
	}

	if cd.AllowedAggregations != nil {
		allowed := sliceToStringSet(*cd.AllowedAggregations)
		d.AllowedAggregations = &allowed
	}

	if cd.Matcher != nil {
		d.Matcher = fromCachedMatcher(cd.Matcher)
	} else {
		d.Matcher = &ResourceMatcher{Visibility: VisibilityAll}
	}

	return d
}

// SetCustomDecision caches a custom resource decision.
func (c *Cache) SetCustomDecision(ctx context.Context, key string, d *CustomResourceDecision) {
	if !c.enabled {
		return
	}

	cd := &cachedCustomDecision{
		Decision:           string(d.Decision),
		ResourceTypeName:   d.ResourceTypeName,
		Cluster:            d.Cluster,
		Reason:             d.Reason,
		Permissions:        actionSetToStrings(d.Permissions),
		AppliedPolicies:    d.AppliedPolicies,
		Metadata:           d.Metadata,
		DeniedAggregations: setToSlice(d.DeniedAggregations),
		Matcher:            toCachedMatcher(d.Matcher),
	}

	if d.AllowedAggregations != nil {
		list := setToSlice(*d.AllowedAggregations)
		cd.AllowedAggregations = &list
	}

	raw, err := json.Marshal(cd)
	if err != nil {
		return
	}
	if err := c.redis.SetEX(ctx, key, string(raw), c.ttl).Err(); err != nil {
		logrus.Debugf("Custom cache storage failed: %v", err)
	}
}

// --- DTO Conversion ---

func toCachedMatchers(matchers map[string]*ResourceMatcher) map[string]*cachedResourceMatcher {
	if len(matchers) == 0 {
		return nil
	}
	result := make(map[string]*cachedResourceMatcher, len(matchers))
	for k, m := range matchers {
		result[k] = toCachedMatcher(m)
	}
	return result
}

func toCachedMatcher(m *ResourceMatcher) *cachedResourceMatcher {
	cm := &cachedResourceMatcher{
		Visibility: string(m.Visibility),
		Labels:     m.Labels,
		Names:      toCachedMatchSpec(m.Names),
		Namespaces: toCachedMatchSpec(m.Namespaces),
	}
	if len(m.FieldFilters) > 0 {
		cm.FieldFilters = make(map[string]*cachedMatchSpec, len(m.FieldFilters))
		for name, ms := range m.FieldFilters {
			cm.FieldFilters[name] = toCachedMatchSpec(ms)
		}
	}
	return cm
}

func toCachedMatchSpec(ms *MatchSpec) *cachedMatchSpec {
	if ms == nil {
		return nil
	}
	return &cachedMatchSpec{
		Include:         setToSlice(ms.Include),
		Exclude:         setToSlice(ms.Exclude),
		IncludePatterns: patternsToPairs(ms.IncludePatterns),
		ExcludePatterns: patternsToPairs(ms.ExcludePatterns),
	}
}

func fromCachedMatchers(matchers map[string]*cachedResourceMatcher) map[string]*ResourceMatcher {
	result := make(map[string]*ResourceMatcher, len(matchers))
	for k, cm := range matchers {
		result[k] = fromCachedMatcher(cm)
	}
	return result
}

func fromCachedMatcher(cm *cachedResourceMatcher) *ResourceMatcher {
	m := &ResourceMatcher{
		Visibility: Visibility(cm.Visibility),
		Labels:     cm.Labels,
		Names:      fromCachedMatchSpec(cm.Names),
		Namespaces: fromCachedMatchSpec(cm.Namespaces),
	}
	if m.Visibility == "" {
		m.Visibility = VisibilityAll
	}
	if len(cm.FieldFilters) > 0 {
		m.FieldFilters = make(map[string]*MatchSpec, len(cm.FieldFilters))
		for name, cms := range cm.FieldFilters {
			m.FieldFilters[name] = fromCachedMatchSpec(cms)
		}
	}
	return m
}

func fromCachedMatchSpec(cms *cachedMatchSpec) *MatchSpec {
	if cms == nil {
		return nil
	}
	return &MatchSpec{
		Include:         sliceToStringSet(cms.Include),
		Exclude:         sliceToStringSet(cms.Exclude),
		IncludePatterns: compilePairs(cms.IncludePatterns),
		ExcludePatterns: compilePairs(cms.ExcludePatterns),
	}
}

// --- Internal helpers ---

func (c *Cache) scanAndDelete(ctx context.Context, pattern string) int {
	count := 0
	var cursor uint64
	for {
		keys, nextCursor, err := c.redis.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			break
		}
		if len(keys) > 0 {
			c.redis.Del(ctx, keys...)
			count += len(keys)
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return count
}

func actionSetToStrings(perms map[Action]struct{}) []string {
	result := make([]string, 0, len(perms))
	for a := range perms {
		result = append(result, string(a))
	}
	return result
}

func stringsToActionSet(items []string) map[Action]struct{} {
	result := make(map[Action]struct{}, len(items))
	for _, s := range items {
		result[Action(s)] = struct{}{}
	}
	return result
}

func patternsToPairs(patterns []CompiledPattern) [][2]string {
	if len(patterns) == 0 {
		return nil
	}
	result := make([][2]string, len(patterns))
	for i, p := range patterns {
		result[i] = [2]string{p.Original, p.Regexp.String()}
	}
	return result
}

func compilePairs(pairs [][2]string) []CompiledPattern {
	if len(pairs) == 0 {
		return nil
	}
	compiled := make([]CompiledPattern, 0, len(pairs))
	for _, p := range pairs {
		if p[1] != "" {
			re, err := regexp.Compile(p[1])
			if err == nil {
				compiled = append(compiled, CompiledPattern{Original: p[0], Regexp: re})
			}
		}
	}
	return compiled
}

func setToSlice(s map[string]struct{}) []string {
	result := make([]string, 0, len(s))
	for k := range s {
		result = append(result, k)
	}
	return result
}

func sliceToStringSet(items []string) map[string]struct{} {
	s := make(map[string]struct{}, len(items))
	for _, item := range items {
		s[item] = struct{}{}
	}
	return s
}

// CustomResourceCacheKey generates a cache key for custom resource decisions.
func CustomResourceCacheKey(principal *Principal, typeName, cluster string, action Action) string {
	clusterPart := cluster
	if clusterPart == "" {
		clusterPart = "all"
	}
	return fmt.Sprintf("rbac:custom:%s:%s:%s:%s", principal.CacheKey(), typeName, clusterPart, action)
}
