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
	keyPolicy             = "policy:%s:%s"           // namespace:name
	keyPolicyUser         = "policy:user:%s"         // user
	keyPolicyGroup        = "policy:group:%s"        // group
	keyPolicySA           = "policy:sa:%s"           // sa
	keyPolicyCustomType   = "policy:customtype:%s"   // resource_type
	keyUserPermissions    = "user:permissions:%s"    // user
	keyGroupMembers       = "group:members:%s"       // group
	keyPoliciesAll        = "policies:all"
	keyPoliciesEnabled    = "policies:enabled"
	keyPoliciesByPriority = "policies:by:priority"

	policyScanBatchSize = 100
)

// StorePolicy stores a compiled policy in Redis with all indexes
func (c *Client) StorePolicy(ctx context.Context, policy *types.CompiledPolicy) error {
	policyKey := fmt.Sprintf(keyPolicy, policy.Namespace, policy.PolicyName)

	policyData, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	pipe := c.client.Pipeline()

	pipe.HSet(ctx, policyKey, map[string]interface{}{
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

	// Index by users
	for _, user := range policy.Users {
		if policy.Enabled {
			userKey := fmt.Sprintf(keyPolicyUser, user)
			pipe.SAdd(ctx, userKey, policyKey)
			pipe.ZAdd(ctx, userKey+":sorted", z(policy.Priority, policyKey))
		}
	}

	// Index by groups
	for _, group := range policy.Groups {
		if policy.Enabled {
			groupKey := fmt.Sprintf(keyPolicyGroup, group)
			pipe.SAdd(ctx, groupKey, policyKey)
			pipe.ZAdd(ctx, groupKey+":sorted", z(policy.Priority, policyKey))
		}
	}

	// Index by service accounts
	for _, sa := range policy.ServiceAccounts {
		if policy.Enabled {
			saKey := fmt.Sprintf(keyPolicySA, sa)
			pipe.SAdd(ctx, saKey, policyKey)
			pipe.ZAdd(ctx, saKey+":sorted", z(policy.Priority, policyKey))
		}
	}

	// Index by custom resource types
	for _, resourceType := range policy.CustomResourceTypes {
		if policy.Enabled {
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
	}

	pipe.SAdd(ctx, fmt.Sprintf("policies:effect:%s", strings.ToLower(policy.Effect)), policyKey)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to store policy: %w", err)
	}

	c.InvalidateEvaluationCaches(ctx, policy.Users, policy.Groups, policy.ServiceAccounts)

	logrus.Infof("Stored policy %s with %d custom resource types", policyKey, len(policy.CustomResourceTypes))
	return nil
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
func (c *Client) UpdatePolicyStatus(ctx context.Context, namespace, name string, status map[string]interface{}) error {
	policyKey := fmt.Sprintf(keyPolicy, namespace, name)
	statusData, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("failed to marshal status: %w", err)
	}
	return c.client.HSet(ctx, policyKey, "status", string(statusData)).Err()
}

// InvalidateEvaluationCaches clears evaluation caches for affected identities
func (c *Client) InvalidateEvaluationCaches(ctx context.Context, users, groups, serviceAccounts []string) {
	count := 0
	pipe := c.client.Pipeline()

	for _, user := range users {
		count += c.scanAndDeletePolicy(ctx, pipe, fmt.Sprintf("policy:eval:%s:*", user))
		pipe.Del(ctx, fmt.Sprintf(keyUserPermissions, user))
	}

	for _, group := range groups {
		members, err := c.client.SMembers(ctx, fmt.Sprintf(keyGroupMembers, group)).Result()
		if err == nil {
			for _, member := range members {
				count += c.scanAndDeletePolicy(ctx, pipe, fmt.Sprintf("policy:eval:%s:*", member))
				pipe.Del(ctx, fmt.Sprintf(keyUserPermissions, member))
			}
		}
		count += c.scanAndDeletePolicy(ctx, pipe, fmt.Sprintf("policy:eval:*:group:%s:*", group))
	}

	for _, sa := range serviceAccounts {
		count += c.scanAndDeletePolicy(ctx, pipe, fmt.Sprintf("policy:eval:%s:*", sa))
	}

	if _, err := pipe.Exec(ctx); err != nil {
		logrus.WithError(err).Debug("Error executing cache invalidation pipeline")
	}

	logrus.Debugf("Cleared %d evaluation cache entries", count)
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
