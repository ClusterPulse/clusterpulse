package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/clusterpulse/cluster-controller/pkg/types"
	goredis "github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

// Policy Redis key patterns (must match Python exactly)
const (
	keyPolicy             = "policy:%s:%s"         // namespace:name
	keyPolicyUser         = "policy:user:%s"       // user
	keyPolicyGroup        = "policy:group:%s"      // group
	keyPolicySA           = "policy:sa:%s"         // sa
	keyPolicyCustomType   = "policy:customtype:%s" // resource_type
	keyUserPermissions    = "user:permissions:%s"  // user
	keyPoliciesAll        = "policies:all"
	keyPoliciesEnabled    = "policies:enabled"
	keyPoliciesByPriority = "policies:by:priority"

	policyScanBatchSize = 100
)

// StorePolicy stores a compiled policy in Redis with all indexes.
//
// On UPDATE, it diffs against the previously-stored compilation and cleans
// stale index entries for subjects that were removed in this revision. The
// effective set of subjects for indexing is empty when the policy is disabled
// (matching the SAdd guards below), so toggling Enabled correctly removes or
// adds subjects from the indexes. Caches are invalidated for the union of old
// and new subjects so removed identities lose stale "allow" decisions.
func (c *Client) StorePolicy(ctx context.Context, policy *types.CompiledPolicy) error {
	policyKey := fmt.Sprintf(keyPolicy, policy.Namespace, policy.PolicyName)

	policyData, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	// Read the previous compilation (if any) so we can clean up stale indexes.
	oldPolicy := c.readPreviousPolicy(ctx, policyKey)

	pipe := c.client.Pipeline()

	pipe.HSet(ctx, policyKey, map[string]any{
		"data":        string(policyData),
		"priority":    policy.Priority,
		"effect":      policy.Effect,
		"enabled":     fmt.Sprintf("%t", policy.Enabled),
		"hash":        policy.Hash,
		"compiled_at": policy.CompiledAt,
	})

	z := func(priority int, member string) *goredis.Z {
		return &goredis.Z{Score: float64(priority), Member: member}
	}

	// Diff-driven index cleanup: drop subjects (and custom resource types) that
	// were indexed under the previous compilation but are no longer present, or
	// drop all of them if the policy is being disabled.
	oldUsers, oldGroups, oldSAs, oldTypes := indexedSubjects(oldPolicy)
	newUsers, newGroups, newSAs, newTypes := indexedSubjects(policy)
	for _, u := range diffStrings(oldUsers, newUsers) {
		k := fmt.Sprintf(keyPolicyUser, u)
		pipe.SRem(ctx, k, policyKey)
		pipe.ZRem(ctx, k+":sorted", policyKey)
	}
	for _, g := range diffStrings(oldGroups, newGroups) {
		k := fmt.Sprintf(keyPolicyGroup, g)
		pipe.SRem(ctx, k, policyKey)
		pipe.ZRem(ctx, k+":sorted", policyKey)
	}
	for _, sa := range diffStrings(oldSAs, newSAs) {
		k := fmt.Sprintf(keyPolicySA, sa)
		pipe.SRem(ctx, k, policyKey)
		pipe.ZRem(ctx, k+":sorted", policyKey)
	}
	for _, rt := range diffStrings(oldTypes, newTypes) {
		k := fmt.Sprintf(keyPolicyCustomType, rt)
		pipe.SRem(ctx, k, policyKey)
		pipe.ZRem(ctx, k+":sorted", policyKey)
	}

	// Index by users / groups / SAs / custom resource types (enabled only).
	if policy.Enabled {
		for _, user := range policy.Users {
			userKey := fmt.Sprintf(keyPolicyUser, user)
			pipe.SAdd(ctx, userKey, policyKey)
			pipe.ZAdd(ctx, userKey+":sorted", z(policy.Priority, policyKey))
		}
		for _, group := range policy.Groups {
			groupKey := fmt.Sprintf(keyPolicyGroup, group)
			pipe.SAdd(ctx, groupKey, policyKey)
			pipe.ZAdd(ctx, groupKey+":sorted", z(policy.Priority, policyKey))
		}
		for _, sa := range policy.ServiceAccounts {
			saKey := fmt.Sprintf(keyPolicySA, sa)
			pipe.SAdd(ctx, saKey, policyKey)
			pipe.ZAdd(ctx, saKey+":sorted", z(policy.Priority, policyKey))
		}
		for _, resourceType := range policy.CustomResourceTypes {
			typeKey := fmt.Sprintf(keyPolicyCustomType, resourceType)
			pipe.SAdd(ctx, typeKey, policyKey)
			pipe.ZAdd(ctx, typeKey+":sorted", z(policy.Priority, policyKey))
		}
	}

	// Global indexes
	pipe.SAdd(ctx, keyPoliciesAll, policyKey)
	pipe.ZAdd(ctx, keyPoliciesByPriority, z(policy.Priority, policyKey))

	if policy.Enabled {
		pipe.SAdd(ctx, keyPoliciesEnabled, policyKey)
	} else {
		pipe.SRem(ctx, keyPoliciesEnabled, policyKey)
	}

	newEffectKey := fmt.Sprintf("policies:effect:%s", strings.ToLower(policy.Effect))
	pipe.SAdd(ctx, newEffectKey, policyKey)
	if oldPolicy != nil && !strings.EqualFold(oldPolicy.Effect, policy.Effect) && oldPolicy.Effect != "" {
		pipe.SRem(ctx, fmt.Sprintf("policies:effect:%s", strings.ToLower(oldPolicy.Effect)), policyKey)
	}

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to store policy: %w", err)
	}

	// Invalidate caches for the UNION of old and new subjects: identities that
	// were removed in this update need stale "allow" decisions cleared, and
	// identities just granted need stale "deny" decisions cleared.
	c.InvalidateEvaluationCaches(
		ctx,
		unionStrings(oldUsersAll(oldPolicy), policy.Users),
		unionStrings(oldGroupsAll(oldPolicy), policy.Groups),
		unionStrings(oldSAsAll(oldPolicy), policy.ServiceAccounts),
	)

	logrus.Infof("Stored policy %s with %d custom resource types", policyKey, len(policy.CustomResourceTypes))
	return nil
}

// readPreviousPolicy fetches the previously-stored compiled policy at policyKey.
// Returns nil if the policy doesn't exist or can't be unmarshaled.
func (c *Client) readPreviousPolicy(ctx context.Context, policyKey string) *types.CompiledPolicy {
	data, err := c.client.HGet(ctx, policyKey, "data").Result()
	if err != nil {
		return nil
	}
	var p types.CompiledPolicy
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		logrus.WithError(err).Warnf("Failed to unmarshal previous policy %s; stale indexes may remain", policyKey)
		return nil
	}
	return &p
}

// indexedSubjects returns the subject and custom-resource-type slices that
// are currently expected to be present in the per-subject Redis indexes for
// the given policy. When the policy is nil or disabled the policy's subjects
// were never written to indexes, so all returned slices are empty.
func indexedSubjects(p *types.CompiledPolicy) (users, groups, sas, types []string) {
	if p == nil || !p.Enabled {
		return nil, nil, nil, nil
	}
	return p.Users, p.Groups, p.ServiceAccounts, p.CustomResourceTypes
}

// oldUsersAll / oldGroupsAll / oldSAsAll return the raw subject slices from a
// previous policy regardless of its enabled state. Used for cache invalidation,
// where we want to clear decisions for *any* identity ever named by the policy.
func oldUsersAll(p *types.CompiledPolicy) []string {
	if p == nil {
		return nil
	}
	return p.Users
}

func oldGroupsAll(p *types.CompiledPolicy) []string {
	if p == nil {
		return nil
	}
	return p.Groups
}

func oldSAsAll(p *types.CompiledPolicy) []string {
	if p == nil {
		return nil
	}
	return p.ServiceAccounts
}

// diffStrings returns elements present in `a` but not in `b`.
func diffStrings(a, b []string) []string {
	if len(a) == 0 {
		return nil
	}
	bset := make(map[string]struct{}, len(b))
	for _, x := range b {
		bset[x] = struct{}{}
	}
	out := make([]string, 0, len(a))
	for _, x := range a {
		if _, ok := bset[x]; !ok {
			out = append(out, x)
		}
	}
	return out
}

// unionStrings returns the set-union of `a` and `b`, deduplicated, order undefined.
func unionStrings(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	s := make(map[string]struct{}, len(a)+len(b))
	for _, x := range a {
		s[x] = struct{}{}
	}
	for _, x := range b {
		s[x] = struct{}{}
	}
	out := make([]string, 0, len(s))
	for x := range s {
		out = append(out, x)
	}
	return out
}

// RemovePolicy removes a policy and all its indexes from Redis
func (c *Client) RemovePolicy(ctx context.Context, namespace, name string) error {
	policyKey := fmt.Sprintf(keyPolicy, namespace, name)

	data, err := c.client.HGet(ctx, policyKey, "data").Result()
	if err != nil {
		logrus.Warnf("Policy %s not found for removal", policyKey)
		return nil
	}

	var policy types.CompiledPolicy
	if err := json.Unmarshal([]byte(data), &policy); err != nil {
		logrus.WithError(err).Warnf("Failed to unmarshal policy %s for cleanup", policyKey)
	}

	pipe := c.client.Pipeline()

	for _, user := range policy.Users {
		userKey := fmt.Sprintf(keyPolicyUser, user)
		pipe.SRem(ctx, userKey, policyKey)
		pipe.ZRem(ctx, userKey+":sorted", policyKey)
	}

	for _, group := range policy.Groups {
		groupKey := fmt.Sprintf(keyPolicyGroup, group)
		pipe.SRem(ctx, groupKey, policyKey)
		pipe.ZRem(ctx, groupKey+":sorted", policyKey)
	}

	for _, sa := range policy.ServiceAccounts {
		saKey := fmt.Sprintf(keyPolicySA, sa)
		pipe.SRem(ctx, saKey, policyKey)
		pipe.ZRem(ctx, saKey+":sorted", policyKey)
	}

	for _, resourceType := range policy.CustomResourceTypes {
		typeKey := fmt.Sprintf(keyPolicyCustomType, resourceType)
		pipe.SRem(ctx, typeKey, policyKey)
		pipe.ZRem(ctx, typeKey+":sorted", policyKey)
	}

	pipe.SRem(ctx, keyPoliciesAll, policyKey)
	pipe.ZRem(ctx, keyPoliciesByPriority, policyKey)
	pipe.SRem(ctx, keyPoliciesEnabled, policyKey)
	pipe.SRem(ctx, fmt.Sprintf("policies:effect:%s", strings.ToLower(policy.Effect)), policyKey)
	pipe.Del(ctx, policyKey)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to remove policy: %w", err)
	}

	c.InvalidateEvaluationCaches(ctx, policy.Users, policy.Groups, policy.ServiceAccounts)
	c.PublishPolicyEvent("deleted", namespace, name)

	logrus.Infof("Removed policy %s", policyKey)
	return nil
}

// GetPolicy retrieves a compiled policy from Redis
func (c *Client) GetPolicy(ctx context.Context, namespace, name string) (*types.CompiledPolicy, error) {
	policyKey := fmt.Sprintf(keyPolicy, namespace, name)

	data, err := c.client.HGet(ctx, policyKey, "data").Result()
	if err != nil {
		return nil, err
	}

	var policy types.CompiledPolicy
	if err := json.Unmarshal([]byte(data), &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy: %w", err)
	}

	return &policy, nil
}

// ListPolicies returns all policy keys or only enabled ones
func (c *Client) ListPolicies(ctx context.Context, enabledOnly bool) ([]string, error) {
	key := keyPoliciesAll
	if enabledOnly {
		key = keyPoliciesEnabled
	}
	return c.client.SMembers(ctx, key).Result()
}

// UpdatePolicyStatus updates the status field in a policy's Redis hash
func (c *Client) UpdatePolicyStatus(ctx context.Context, namespace, name string, status map[string]any) error {
	policyKey := fmt.Sprintf(keyPolicy, namespace, name)
	statusData, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("failed to marshal status: %w", err)
	}
	return c.client.HSet(ctx, policyKey, "status", string(statusData)).Err()
}

// InvalidateEvaluationCaches clears evaluation caches for affected identities.
// Also clears rbac:decision:* and rbac:custom:* caches so stale
// authorization decisions don't persist after policy changes.
//
// Group invalidation walks the RBAC decision keyspace directly rather than
// consulting a separately-maintained group-membership index: the cache itself
// is the truth source, so we scan keys and delete those whose groups CSV
// (encoded in the cache key by Principal.CacheKey) intersects with the
// changed group set. This costs an O(keyspace) scan, which is acceptable
// because policy changes are rare.
func (c *Client) InvalidateEvaluationCaches(ctx context.Context, users, groups, serviceAccounts []string) {
	count := 0
	pipe := c.client.Pipeline()

	for _, user := range users {
		count += c.scanAndDeletePolicy(ctx, pipe, fmt.Sprintf("policy:eval:%s:*", user))
		pipe.Del(ctx, fmt.Sprintf(keyUserPermissions, user))
		// Clear RBAC engine decision caches for this user
		count += c.scanAndDeletePolicy(ctx, pipe, fmt.Sprintf("rbac:decision:%s:*", escapeRedisGlobChars(user)))
		count += c.scanAndDeletePolicy(ctx, pipe, fmt.Sprintf("rbac:custom:%s:*", escapeRedisGlobChars(user)))
	}

	if len(groups) > 0 {
		count += c.invalidateRBACDecisionsForGroups(ctx, pipe, groups)
		for _, group := range groups {
			count += c.scanAndDeletePolicy(ctx, pipe, fmt.Sprintf("policy:eval:*:group:%s:*", group))
		}
	}

	for _, sa := range serviceAccounts {
		count += c.scanAndDeletePolicy(ctx, pipe, fmt.Sprintf("policy:eval:%s:*", sa))
		count += c.scanAndDeletePolicy(ctx, pipe, fmt.Sprintf("rbac:decision:%s:*", escapeRedisGlobChars(sa)))
		count += c.scanAndDeletePolicy(ctx, pipe, fmt.Sprintf("rbac:custom:%s:*", escapeRedisGlobChars(sa)))
	}

	if _, err := pipe.Exec(ctx); err != nil {
		logrus.WithError(err).Debug("Error executing cache invalidation pipeline")
	}

	logrus.Debugf("Cleared %d evaluation cache entries", count)
}

// invalidateRBACDecisionsForGroups scans rbac:decision:* and rbac:custom:* keys
// and queues for deletion any entry whose Principal.CacheKey groups CSV
// contains one of the changed groups. The cache key format is
// "rbac:{decision|custom}:{username}:{sorted_groups_csv}:..." where the CSV
// is comma-joined. We scan each `:`-delimited segment of the suffix and look
// for any element matching a changed group, which tolerates usernames that
// themselves contain colons (e.g. service accounts).
func (c *Client) invalidateRBACDecisionsForGroups(ctx context.Context, pipe goredis.Pipeliner, groups []string) int {
	changed := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		if g != "" {
			changed[g] = struct{}{}
		}
	}
	if len(changed) == 0 {
		return 0
	}

	count := 0
	for _, prefix := range []string{"rbac:decision:", "rbac:custom:"} {
		pattern := prefix + "*"
		var cursor uint64
		for {
			keys, next, err := c.client.Scan(ctx, cursor, pattern, policyScanBatchSize).Result()
			if err != nil {
				break
			}
			for _, key := range keys {
				suffix, ok := strings.CutPrefix(key, prefix)
				if !ok {
					continue
				}
				if cacheKeyMatchesGroup(suffix, changed) {
					pipe.Del(ctx, key)
					count++
				}
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
	}
	return count
}

// cacheKeyMatchesGroup reports whether any `:`-delimited segment of the
// supplied cache-key suffix contains a CSV element present in `changed`.
func cacheKeyMatchesGroup(suffix string, changed map[string]struct{}) bool {
	for segment := range strings.SplitSeq(suffix, ":") {
		if segment == "" {
			continue
		}
		for elem := range strings.SplitSeq(segment, ",") {
			if elem == "" {
				continue
			}
			if _, hit := changed[elem]; hit {
				return true
			}
		}
	}
	return false
}

// escapeRedisGlobChars escapes Redis glob metacharacters to prevent pattern injection.
func escapeRedisGlobChars(s string) string {
	return strings.NewReplacer(
		`*`, `\*`,
		`?`, `\?`,
		`[`, `\[`,
		`]`, `\]`,
	).Replace(s)
}

// PublishPolicyEvent publishes a policy change event
func (c *Client) PublishPolicyEvent(action, namespace, name string) {
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	policyRef := fmt.Sprintf("%s/%s", namespace, name)

	changeEvent, _ := json.Marshal(map[string]string{
		"action":    action,
		"policy":    policyRef,
		"timestamp": now,
	})
	c.client.Publish(ctx, "policy-changes", string(changeEvent))

	detailEvent, _ := json.Marshal(map[string]string{
		"type":      fmt.Sprintf("policy.%s", action),
		"policy":    policyRef,
		"timestamp": now,
	})
	c.client.Publish(ctx, "policy-events", string(detailEvent))
}

// ClearStaleEvalCaches removes all policy:eval:* keys on startup
func (c *Client) ClearStaleEvalCaches(ctx context.Context) (int, error) {
	count := 0
	var cursor uint64

	for {
		keys, nextCursor, err := c.client.Scan(ctx, cursor, "policy:eval:*", policyScanBatchSize).Result()
		if err != nil {
			return count, err
		}

		if len(keys) > 0 {
			if err := c.client.Del(ctx, keys...).Err(); err != nil {
				logrus.WithError(err).Debug("Error clearing stale eval caches")
			}
			count += len(keys)
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return count, nil
}

// GetPoliciesForCustomType returns policy keys that reference a custom resource type
func (c *Client) GetPoliciesForCustomType(ctx context.Context, resourceType string) ([]string, error) {
	key := fmt.Sprintf(keyPolicyCustomType+":sorted", resourceType)
	return c.client.ZRevRange(ctx, key, 0, -1).Result()
}

// GetCustomResourceTypes returns all custom resource types with policies
func (c *Client) GetCustomResourceTypes(ctx context.Context) ([]string, error) {
	var result []string
	var cursor uint64

	for {
		keys, nextCursor, err := c.client.Scan(ctx, cursor, "policy:customtype:*", policyScanBatchSize).Result()
		if err != nil {
			return nil, err
		}

		for _, key := range keys {
			if strings.HasSuffix(key, ":sorted") {
				continue
			}
			// Extract type from "policy:customtype:{type}"
			parts := strings.SplitN(key, ":", 3)
			if len(parts) == 3 {
				result = append(result, parts[2])
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return result, nil
}

// scanAndDeletePolicy scans for keys matching a pattern and queues them for deletion
func (c *Client) scanAndDeletePolicy(ctx context.Context, pipe goredis.Pipeliner, pattern string) int {
	count := 0
	var cursor uint64

	for {
		keys, nextCursor, err := c.client.Scan(ctx, cursor, pattern, policyScanBatchSize).Result()
		if err != nil {
			break
		}

		for _, key := range keys {
			pipe.Del(ctx, key)
			count++
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return count
}
