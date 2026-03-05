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

	var raw map[string]any
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return nil
	}

	decision := &RBACDecision{
		Decision:    Decision(strVal(raw, "decision")),
		Reason:      strVal(raw, "reason"),
		Permissions: make(map[Action]struct{}),
		Matchers:    make(map[string]*ResourceMatcher),
		Metadata:    mapVal(raw, "metadata"),
	}

	if perms, ok := raw["permissions"].([]any); ok {
		for _, p := range perms {
			if s, ok := p.(string); ok {
				decision.Permissions[Action(s)] = struct{}{}
			}
		}
	}

	if policies, ok := raw["applied_policies"].([]any); ok {
		for _, p := range policies {
			if s, ok := p.(string); ok {
				decision.AppliedPolicies = append(decision.AppliedPolicies, s)
			}
		}
	}

	if matchers, ok := raw["matchers"].(map[string]any); ok {
		for typeKey, mData := range matchers {
			if md, ok := mData.(map[string]any); ok {
				decision.Matchers[typeKey] = deserializeResourceMatcher(md)
			}
		}
	}

	return decision
}

// SetDecision caches a standard RBAC decision.
func (c *Cache) SetDecision(ctx context.Context, key string, d *RBACDecision) {
	if !c.enabled {
		return
	}

	perms := make([]string, 0, len(d.Permissions))
	for a := range d.Permissions {
		perms = append(perms, string(a))
	}

	matchers := make(map[string]any, len(d.Matchers))
	for typeKey, m := range d.Matchers {
		matchers[typeKey] = serializeResourceMatcher(m)
	}

	data := map[string]any{
		"decision":         string(d.Decision),
		"reason":           d.Reason,
		"permissions":      perms,
		"metadata":         d.Metadata,
		"applied_policies": d.AppliedPolicies,
		"matchers":         matchers,
	}

	if d.Request != nil {
		data["principal"] = map[string]any{
			"username": d.Request.Principal.Username,
			"email":    d.Request.Principal.Email,
			"groups":   d.Request.Principal.Groups,
		}
		data["action"] = string(d.Request.Action)
		data["resource"] = map[string]any{
			"type":      string(d.Request.Resource.Type),
			"name":      d.Request.Resource.Name,
			"namespace": d.Request.Resource.Namespace,
			"cluster":   d.Request.Resource.Cluster,
		}
	}

	raw, err := json.Marshal(data)
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

	var raw map[string]any
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return nil
	}

	d := &CustomResourceDecision{
		Decision:           Decision(strVal(raw, "decision")),
		ResourceTypeName:   strVal(raw, "resource_type_name"),
		Cluster:            strVal(raw, "cluster"),
		Reason:             strVal(raw, "reason"),
		Permissions:        make(map[Action]struct{}),
		DeniedAggregations: make(map[string]struct{}),
		Metadata:           mapVal(raw, "metadata"),
	}

	if perms, ok := raw["permissions"].([]any); ok {
		for _, p := range perms {
			if s, ok := p.(string); ok {
				d.Permissions[Action(s)] = struct{}{}
			}
		}
	}

	if policies, ok := raw["applied_policies"].([]any); ok {
		for _, p := range policies {
			if s, ok := p.(string); ok {
				d.AppliedPolicies = append(d.AppliedPolicies, s)
			}
		}
	}

	if aa, ok := raw["allowed_aggregations"]; ok && aa != nil {
		if aList, ok := aa.([]any); ok {
			allowed := make(map[string]struct{}, len(aList))
			for _, a := range aList {
				if s, ok := a.(string); ok {
					allowed[s] = struct{}{}
				}
			}
			d.AllowedAggregations = &allowed
		}
	}

	if da, ok := raw["denied_aggregations"].([]any); ok {
		for _, a := range da {
			if s, ok := a.(string); ok {
				d.DeniedAggregations[s] = struct{}{}
			}
		}
	}

	if matcherData, ok := raw["matcher"].(map[string]any); ok {
		d.Matcher = deserializeResourceMatcher(matcherData)
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

	perms := make([]string, 0, len(d.Permissions))
	for a := range d.Permissions {
		perms = append(perms, string(a))
	}

	var allowedAgg any
	if d.AllowedAggregations != nil {
		list := setToSlice(*d.AllowedAggregations)
		allowedAgg = list
	}

	data := map[string]any{
		"decision":             string(d.Decision),
		"resource_type_name":   d.ResourceTypeName,
		"cluster":              d.Cluster,
		"reason":               d.Reason,
		"permissions":          perms,
		"applied_policies":     d.AppliedPolicies,
		"metadata":             d.Metadata,
		"allowed_aggregations": allowedAgg,
		"denied_aggregations":  setToSlice(d.DeniedAggregations),
		"matcher":              serializeResourceMatcher(d.Matcher),
	}

	raw, err := json.Marshal(data)
	if err != nil {
		return
	}
	if err := c.redis.SetEX(ctx, key, string(raw), c.ttl).Err(); err != nil {
		logrus.Debugf("Custom cache storage failed: %v", err)
	}
}

// --- Serialization helpers ---

func serializeResourceMatcher(m *ResourceMatcher) map[string]any {
	result := map[string]any{
		"visibility": string(m.Visibility),
	}
	if m.Names != nil {
		result["names"] = serializeMatchSpec(m.Names)
	}
	if m.Namespaces != nil {
		result["namespaces"] = serializeMatchSpec(m.Namespaces)
	}
	if len(m.Labels) > 0 {
		result["labels"] = m.Labels
	}
	if len(m.FieldFilters) > 0 {
		fields := make(map[string]any, len(m.FieldFilters))
		for name, ms := range m.FieldFilters {
			fields[name] = serializeMatchSpec(ms)
		}
		result["field_filters"] = fields
	}
	return result
}

func serializeMatchSpec(ms *MatchSpec) map[string]any {
	return map[string]any{
		"include":          setToSlice(ms.Include),
		"exclude":          setToSlice(ms.Exclude),
		"include_patterns": patternsToSlice(ms.IncludePatterns),
		"exclude_patterns": patternsToSlice(ms.ExcludePatterns),
	}
}

func deserializeResourceMatcher(data map[string]any) *ResourceMatcher {
	m := &ResourceMatcher{
		Visibility: Visibility(strVal(data, "visibility")),
	}
	if m.Visibility == "" {
		m.Visibility = VisibilityAll
	}

	if nd, ok := data["names"].(map[string]any); ok {
		m.Names = deserializeMatchSpec(nd)
	}
	if nd, ok := data["namespaces"].(map[string]any); ok {
		m.Namespaces = deserializeMatchSpec(nd)
	}
	if labels, ok := data["labels"].(map[string]any); ok {
		m.Labels = make(map[string]string, len(labels))
		for k, v := range labels {
			if s, ok := v.(string); ok {
				m.Labels[k] = s
			}
		}
	}
	if ffData, ok := data["field_filters"].(map[string]any); ok {
		m.FieldFilters = make(map[string]*MatchSpec, len(ffData))
		for name, v := range ffData {
			if md, ok := v.(map[string]any); ok {
				m.FieldFilters[name] = deserializeMatchSpec(md)
			}
		}
	}

	return m
}

func deserializeMatchSpec(data map[string]any) *MatchSpec {
	ms := &MatchSpec{
		Include: anySliceToStringSet(sliceVal(data, "include")),
		Exclude: anySliceToStringSet(sliceVal(data, "exclude")),
	}
	ms.IncludePatterns = deserializePatterns(sliceVal(data, "include_patterns"))
	ms.ExcludePatterns = deserializePatterns(sliceVal(data, "exclude_patterns"))
	return ms
}

func anySliceToStringSet(items []any) map[string]struct{} {
	s := make(map[string]struct{}, len(items))
	for _, item := range items {
		if str, ok := item.(string); ok {
			s[str] = struct{}{}
		}
	}
	return s
}

func deserializePatterns(items []any) []CompiledPattern {
	var compiled []CompiledPattern
	for _, p := range items {
		if pair, ok := p.([]any); ok && len(pair) >= 2 {
			orig, _ := pair[0].(string)
			regex, _ := pair[1].(string)
			if regex != "" {
				re, err := regexp.Compile(regex)
				if err == nil {
					compiled = append(compiled, CompiledPattern{Original: orig, Regexp: re})
				}
			}
		}
	}
	return compiled
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

func patternsToSlice(patterns []CompiledPattern) [][]string {
	result := make([][]string, len(patterns))
	for i, p := range patterns {
		result[i] = []string{p.Original, p.Regexp.String()}
	}
	return result
}

func setToSlice(s map[string]struct{}) []string {
	result := make([]string, 0, len(s))
	for k := range s {
		result = append(result, k)
	}
	return result
}

func strVal(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func mapVal(m map[string]any, key string) map[string]any {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return nil
}

func sliceVal(m map[string]any, key string) []any {
	if v, ok := m[key].([]any); ok {
		return v
	}
	return nil
}

// CustomResourceCacheKey generates a cache key for custom resource decisions.
func CustomResourceCacheKey(principal *Principal, typeName, cluster string, action Action) string {
	clusterPart := cluster
	if clusterPart == "" {
		clusterPart = "all"
	}
	return fmt.Sprintf("rbac:custom:%s:%s:%s:%s", principal.CacheKey(), typeName, clusterPart, action)
}
