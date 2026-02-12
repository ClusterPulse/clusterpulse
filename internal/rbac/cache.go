package rbac

import (
	"context"
	"encoding/json"
	"fmt"
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

// Enabled returns whether caching is active.
func (c *Cache) Enabled() bool { return c.enabled }

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
		Filters:     make(map[ResourceType]*Filter),
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

	if filters, ok := raw["filters"].(map[string]any); ok {
		for rtStr, fData := range filters {
			if fd, ok := fData.(map[string]any); ok {
				f := NewFilter(Visibility(strVal(fd, "visibility")))
				f.Include = toStringSet(sliceVal(fd, "include"))
				f.Exclude = toStringSet(sliceVal(fd, "exclude"))
				if labels, ok := fd["labels"].(map[string]any); ok {
					for k, v := range labels {
						if s, ok := v.(string); ok {
							f.Labels[k] = s
						}
					}
				}
				decision.Filters[ResourceType(rtStr)] = f
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

	filters := make(map[string]any, len(d.Filters))
	for rt, f := range d.Filters {
		filters[string(rt)] = map[string]any{
			"visibility": string(f.Visibility),
			"include":    setToSlice(f.Include),
			"exclude":    setToSlice(f.Exclude),
			"labels":     f.Labels,
		}
	}

	data := map[string]any{
		"decision":         string(d.Decision),
		"reason":           d.Reason,
		"permissions":      perms,
		"metadata":         d.Metadata,
		"applied_policies": d.AppliedPolicies,
		"filters":          filters,
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
		Decision:         Decision(strVal(raw, "decision")),
		ResourceTypeName: strVal(raw, "resource_type_name"),
		Cluster:          strVal(raw, "cluster"),
		Reason:           strVal(raw, "reason"),
		Permissions:      make(map[Action]struct{}),
		DeniedAggregations: make(map[string]struct{}),
		Metadata:         mapVal(raw, "metadata"),
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

	if filtersData, ok := raw["filters"].(map[string]any); ok {
		d.Filters = deserializeCustomFilter(filtersData)
	} else {
		d.Filters = NewCustomResourceFilter()
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
		"decision":              string(d.Decision),
		"resource_type_name":    d.ResourceTypeName,
		"cluster":              d.Cluster,
		"reason":               d.Reason,
		"permissions":          perms,
		"applied_policies":     d.AppliedPolicies,
		"metadata":             d.Metadata,
		"allowed_aggregations": allowedAgg,
		"denied_aggregations":  setToSlice(d.DeniedAggregations),
		"filters":              serializeCustomFilter(d.Filters),
	}

	raw, err := json.Marshal(data)
	if err != nil {
		return
	}
	if err := c.redis.SetEX(ctx, key, string(raw), c.ttl).Err(); err != nil {
		logrus.Debugf("Custom cache storage failed: %v", err)
	}
}

// ClearCustomDecisions clears custom resource cache matching a pattern.
func (c *Cache) ClearCustomDecisions(ctx context.Context, pattern string) int {
	return c.scanAndDelete(ctx, pattern)
}

// --- Internal helpers ---

func serializeCustomFilter(f *CustomResourceFilter) map[string]any {
	fieldFilters := make(map[string]any, len(f.FieldFilters))
	for name, ff := range f.FieldFilters {
		fieldFilters[name] = []any{
			setToSlice(ff.AllowedLiterals),
			patternsToSlice(ff.AllowedPatterns),
			setToSlice(ff.DeniedLiterals),
			patternsToSlice(ff.DeniedPatterns),
		}
	}

	return map[string]any{
		"visibility":                 string(f.Visibility),
		"namespace_literals":         setToSlice(f.NamespaceLiterals),
		"namespace_patterns":         patternsToSlice(f.NamespacePatterns),
		"namespace_exclude_literals": setToSlice(f.NamespaceExcludeLiterals),
		"namespace_exclude_patterns": patternsToSlice(f.NamespaceExcludePatterns),
		"name_literals":              setToSlice(f.NameLiterals),
		"name_patterns":              patternsToSlice(f.NamePatterns),
		"name_exclude_literals":      setToSlice(f.NameExcludeLiterals),
		"name_exclude_patterns":      patternsToSlice(f.NameExcludePatterns),
		"field_filters":              fieldFilters,
	}
}

func deserializeCustomFilter(data map[string]any) *CustomResourceFilter {
	f := NewCustomResourceFilter()

	if v := strVal(data, "visibility"); v != "" {
		f.Visibility = Visibility(v)
	}

	f.NamespaceLiterals = toStringSet(sliceVal(data, "namespace_literals"))
	f.NamespacePatterns = compilePatternList(sliceVal(data, "namespace_patterns"))
	f.NamespaceExcludeLiterals = toStringSet(sliceVal(data, "namespace_exclude_literals"))
	f.NamespaceExcludePatterns = compilePatternList(sliceVal(data, "namespace_exclude_patterns"))

	f.NameLiterals = toStringSet(sliceVal(data, "name_literals"))
	f.NamePatterns = compilePatternList(sliceVal(data, "name_patterns"))
	f.NameExcludeLiterals = toStringSet(sliceVal(data, "name_exclude_literals"))
	f.NameExcludePatterns = compilePatternList(sliceVal(data, "name_exclude_patterns"))

	if ffData, ok := data["field_filters"].(map[string]any); ok {
		for fieldName, v := range ffData {
			if arr, ok := v.([]any); ok && len(arr) >= 4 {
				ff := &FieldFilter{
					AllowedLiterals: make(map[string]struct{}),
					DeniedLiterals:  make(map[string]struct{}),
				}
				if al, ok := arr[0].([]any); ok {
					ff.AllowedLiterals = toStringSet(al)
				}
				if ap, ok := arr[1].([]any); ok {
					ff.AllowedPatterns = compilePatternList(ap)
				}
				if dl, ok := arr[2].([]any); ok {
					ff.DeniedLiterals = toStringSet(dl)
				}
				if dp, ok := arr[3].([]any); ok {
					ff.DeniedPatterns = compilePatternList(dp)
				}
				f.FieldFilters[fieldName] = ff
			}
		}
	}

	return f
}

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
