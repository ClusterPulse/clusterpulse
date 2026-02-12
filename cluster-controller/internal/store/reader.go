package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	goredis "github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

// GetJSON retrieves and unmarshals a JSON string value.
func (c *Client) GetJSON(ctx context.Context, key string, dest any) error {
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(data), dest)
}

// GetJSONList retrieves a JSON array stored as a string.
func (c *Client) GetJSONList(ctx context.Context, key string) ([]map[string]any, error) {
	var result []map[string]any
	if err := c.GetJSON(ctx, key, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetHashJSON retrieves a hash field and unmarshals it.
func (c *Client) GetHashJSON(ctx context.Context, key, field string, dest any) error {
	data, err := c.client.HGet(ctx, key, field).Result()
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(data), dest)
}

// --- Cluster Reads ---

// ClusterBundle holds all data for a single cluster.
type ClusterBundle struct {
	Spec    map[string]any `json:"spec,omitempty"`
	Status  map[string]any `json:"status,omitempty"`
	Metrics map[string]any `json:"metrics,omitempty"`
	Info    map[string]any `json:"info,omitempty"`
}

// GetClusterBundle retrieves spec/status/metrics/info via pipeline.
func (c *Client) GetClusterBundle(ctx context.Context, name string) (*ClusterBundle, error) {
	pipe := c.client.Pipeline()

	specCmd := pipe.Get(ctx, fmt.Sprintf("cluster:%s:spec", name))
	statusCmd := pipe.Get(ctx, fmt.Sprintf("cluster:%s:status", name))
	metricsCmd := pipe.Get(ctx, fmt.Sprintf("cluster:%s:metrics", name))
	infoCmd := pipe.Get(ctx, fmt.Sprintf("cluster:%s:info", name))

	_, _ = pipe.Exec(ctx) // some keys may not exist

	bundle := &ClusterBundle{}
	unmarshalCmd(specCmd, &bundle.Spec)
	unmarshalCmd(statusCmd, &bundle.Status)
	unmarshalCmd(metricsCmd, &bundle.Metrics)
	unmarshalCmd(infoCmd, &bundle.Info)

	return bundle, nil
}

// GetAllClusterNames returns all registered cluster names.
func (c *Client) GetAllClusterNames(ctx context.Context) ([]string, error) {
	return c.client.SMembers(ctx, "clusters:all").Result()
}

// GetClusterNodes returns node data for a cluster.
func (c *Client) GetClusterNodes(ctx context.Context, clusterName string) ([]map[string]any, error) {
	nodeNames, err := c.client.SMembers(ctx, fmt.Sprintf("cluster:%s:nodes", clusterName)).Result()
	if err != nil {
		return nil, err
	}
	if len(nodeNames) == 0 {
		return nil, nil
	}

	pipe := c.client.Pipeline()
	cmds := make(map[string]*goredis.StringCmd, len(nodeNames))
	for _, name := range nodeNames {
		key := fmt.Sprintf("cluster:%s:node:%s", clusterName, name)
		cmds[name] = pipe.HGet(ctx, key, "current")
	}
	_, _ = pipe.Exec(ctx)

	var nodes []map[string]any
	for _, name := range nodeNames {
		cmd := cmds[name]
		if cmd.Err() != nil {
			continue
		}
		var node map[string]any
		if err := json.Unmarshal([]byte(cmd.Val()), &node); err == nil {
			nodes = append(nodes, node)
		}
	}
	return nodes, nil
}

// GetClusterNode returns a single node's current data.
func (c *Client) GetClusterNode(ctx context.Context, clusterName, nodeName string) (map[string]any, error) {
	var node map[string]any
	err := c.GetHashJSON(ctx, fmt.Sprintf("cluster:%s:node:%s", clusterName, nodeName), "current", &node)
	return node, err
}

// GetClusterNamespaces returns the namespace list for a cluster.
func (c *Client) GetClusterNamespaces(ctx context.Context, clusterName string) ([]string, error) {
	key := fmt.Sprintf("cluster:%s:namespaces", clusterName)
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		// Fallback to set
		return c.client.SMembers(ctx, fmt.Sprintf("cluster:%s:namespaces:set", clusterName)).Result()
	}

	var nsData struct {
		Namespaces []string `json:"namespaces"`
	}
	if err := json.Unmarshal([]byte(data), &nsData); err != nil {
		return nil, err
	}
	return nsData.Namespaces, nil
}

// GetNodeMetricsHistory returns time-series node metrics.
func (c *Client) GetNodeMetricsHistory(ctx context.Context, clusterName, nodeName string, limit int64) ([]map[string]any, error) {
	key := fmt.Sprintf("cluster:%s:node:%s:metrics", clusterName, nodeName)
	results, err := c.client.ZRevRange(ctx, key, 0, limit-1).Result()
	if err != nil {
		return nil, err
	}

	var metrics []map[string]any
	for _, raw := range results {
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err == nil {
			metrics = append(metrics, m)
		}
	}
	return metrics, nil
}

// GetNodeConditions returns conditions for a node.
func (c *Client) GetNodeConditions(ctx context.Context, clusterName, nodeName string) (map[string]string, error) {
	key := fmt.Sprintf("cluster:%s:node:%s:conditions", clusterName, nodeName)
	return c.client.HGetAll(ctx, key).Result()
}

// GetClusterAlerts returns alerts for a cluster.
func (c *Client) GetClusterAlerts(ctx context.Context, clusterName string) ([]map[string]any, error) {
	pattern := fmt.Sprintf("alerts:%s:*", clusterName)
	var alerts []map[string]any

	iter := c.client.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		data, err := c.client.HGetAll(ctx, iter.Val()).Result()
		if err != nil || len(data) == 0 {
			continue
		}
		alert := make(map[string]any, len(data))
		for k, v := range data {
			alert[k] = v
		}
		alerts = append(alerts, alert)
	}
	return alerts, iter.Err()
}

// GetClusterEvents returns recent events for a cluster.
func (c *Client) GetClusterEvents(ctx context.Context, clusterName string, limit int64) ([]map[string]any, error) {
	key := fmt.Sprintf("events:%s", clusterName)
	results, err := c.client.LRange(ctx, key, 0, limit-1).Result()
	if err != nil {
		return nil, err
	}

	var events []map[string]any
	for _, raw := range results {
		var e map[string]any
		if err := json.Unmarshal([]byte(raw), &e); err == nil {
			events = append(events, e)
		}
	}
	return events, nil
}

// GetClusterOperatorsList returns OLM operators as a list of maps.
func (c *Client) GetClusterOperatorsList(ctx context.Context, clusterName string) ([]map[string]any, error) {
	return c.GetJSONList(ctx, fmt.Sprintf("cluster:%s:operators", clusterName))
}

// GetClusterResourceMetadata returns resource_metadata for a cluster.
func (c *Client) GetClusterResourceMetadata(ctx context.Context, clusterName string) (map[string]any, error) {
	var meta map[string]any
	err := c.GetJSON(ctx, fmt.Sprintf("cluster:%s:resource_metadata", clusterName), &meta)
	return meta, err
}

// GetClusterResourcesByType returns a specific resource type list (pods, deployments, etc).
func (c *Client) GetClusterResourcesByType(ctx context.Context, clusterName, resourceType string) ([]map[string]any, error) {
	return c.GetJSONList(ctx, fmt.Sprintf("cluster:%s:%s", clusterName, resourceType))
}

// --- Registry Reads ---

// RegistryBundle holds spec and status for a registry.
type RegistryBundle struct {
	Spec   map[string]any `json:"spec,omitempty"`
	Status map[string]any `json:"status,omitempty"`
}

// GetAllRegistryNames returns all registered registry names.
func (c *Client) GetAllRegistryNames(ctx context.Context) ([]string, error) {
	return c.client.SMembers(ctx, "registries:all").Result()
}

// BatchGetRegistryBundles retrieves spec+status for multiple registries via pipeline.
func (c *Client) BatchGetRegistryBundles(ctx context.Context, names []string) (map[string]*RegistryBundle, error) {
	if len(names) == 0 {
		return nil, nil
	}

	pipe := c.client.Pipeline()
	specCmds := make(map[string]*goredis.StringCmd, len(names))
	statusCmds := make(map[string]*goredis.StringCmd, len(names))

	for _, name := range names {
		specCmds[name] = pipe.Get(ctx, fmt.Sprintf("registry:%s:spec", name))
		statusCmds[name] = pipe.Get(ctx, fmt.Sprintf("registry:%s:status", name))
	}
	_, _ = pipe.Exec(ctx)

	result := make(map[string]*RegistryBundle, len(names))
	for _, name := range names {
		b := &RegistryBundle{}
		unmarshalCmd(specCmds[name], &b.Spec)
		unmarshalCmd(statusCmds[name], &b.Status)
		result[name] = b
	}
	return result, nil
}

// --- MetricSource Reads ---

// GetSourceIDForType returns MetricSource IDs that provide a given resource type.
func (c *Client) GetSourceIDForType(ctx context.Context, typeName string) ([]string, error) {
	key := fmt.Sprintf("metricsources:by:resourcetype:%s", typeName)
	return c.client.SMembers(ctx, key).Result()
}

// GetMetricSourceDef retrieves a MetricSource definition by sourceID (namespace/name).
func (c *Client) GetMetricSourceDef(ctx context.Context, sourceID string) (map[string]any, error) {
	parts := strings.SplitN(sourceID, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid sourceID: %s", sourceID)
	}
	key := fmt.Sprintf("metricsource:%s:%s", parts[0], parts[1])
	var result map[string]any
	err := c.GetJSON(ctx, key, &result)
	return result, err
}

// GetCustomResourcesRaw retrieves custom resource collection data for a cluster/source.
func (c *Client) GetCustomResourcesRaw(ctx context.Context, clusterName, sourceID string) (map[string]any, error) {
	key := fmt.Sprintf("cluster:%s:custom:%s:resources", clusterName, sourceID)
	var result map[string]any
	err := c.GetJSON(ctx, key, &result)
	return result, err
}

// GetCustomAggregationsRaw retrieves aggregation data for a cluster/source.
func (c *Client) GetCustomAggregationsRaw(ctx context.Context, clusterName, sourceID string) (map[string]any, error) {
	key := fmt.Sprintf("cluster:%s:custom:%s:aggregations", clusterName, sourceID)
	var result map[string]any
	err := c.GetJSON(ctx, key, &result)
	return result, err
}

// GetAllMetricSourceIDs returns all enabled MetricSource identifiers.
func (c *Client) GetAllMetricSourceIDs(ctx context.Context) ([]string, error) {
	return c.client.SMembers(ctx, "metricsources:enabled").Result()
}

// GetAllMetricSources returns all enabled MetricSource definitions with _id injected.
func (c *Client) GetAllMetricSources(ctx context.Context) ([]map[string]any, error) {
	ids, err := c.GetAllMetricSourceIDs(ctx)
	if err != nil {
		return nil, err
	}

	var sources []map[string]any
	for _, id := range ids {
		def, err := c.GetMetricSourceDef(ctx, id)
		if err != nil {
			continue
		}
		def["_id"] = id
		sources = append(sources, def)
	}
	return sources, nil
}

// GetSourceIDForTypeSingle returns the first MetricSource ID for a given resource type.
func (c *Client) GetSourceIDForTypeSingle(ctx context.Context, typeName string) (string, error) {
	ids, err := c.GetSourceIDForType(ctx, typeName)
	if err != nil || len(ids) == 0 {
		return "", err
	}
	return ids[0], nil
}

// GetClustersWithData returns cluster names that have data for a resource type.
func (c *Client) GetClustersWithData(ctx context.Context, typeName string) ([]string, error) {
	sourceID, err := c.GetSourceIDForTypeSingle(ctx, typeName)
	if err != nil || sourceID == "" {
		return nil, err
	}

	pattern := fmt.Sprintf("cluster:*:custom:%s:resources", sourceID)
	var clusters []string

	iter := c.client.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		// Extract cluster name from key pattern cluster:{name}:custom:{sourceID}:resources
		parts := strings.SplitN(key, ":", 3)
		if len(parts) >= 2 {
			clusters = append(clusters, parts[1])
		}
	}

	sort.Strings(clusters)
	return clusters, iter.Err()
}

// BatchGetCustomResources retrieves custom resources for multiple clusters via pipeline.
func (c *Client) BatchGetCustomResources(ctx context.Context, sourceID string, clusters []string) (map[string]map[string]any, error) {
	if len(clusters) == 0 {
		return nil, nil
	}

	pipe := c.client.Pipeline()
	cmds := make(map[string]*goredis.StringCmd, len(clusters))
	for _, cluster := range clusters {
		key := fmt.Sprintf("cluster:%s:custom:%s:resources", cluster, sourceID)
		cmds[cluster] = pipe.Get(ctx, key)
	}
	_, _ = pipe.Exec(ctx)

	result := make(map[string]map[string]any, len(clusters))
	for _, cluster := range clusters {
		var data map[string]any
		unmarshalCmd(cmds[cluster], &data)
		if data != nil {
			result[cluster] = data
		}
	}
	return result, nil
}

// BatchGetCustomAggregations retrieves aggregation data for multiple clusters via pipeline.
func (c *Client) BatchGetCustomAggregations(ctx context.Context, sourceID string, clusters []string) (map[string]map[string]any, error) {
	if len(clusters) == 0 {
		return nil, nil
	}

	pipe := c.client.Pipeline()
	cmds := make(map[string]*goredis.StringCmd, len(clusters))
	for _, cluster := range clusters {
		key := fmt.Sprintf("cluster:%s:custom:%s:aggregations", cluster, sourceID)
		cmds[cluster] = pipe.Get(ctx, key)
	}
	_, _ = pipe.Exec(ctx)

	result := make(map[string]map[string]any, len(clusters))
	for _, cluster := range clusters {
		var data map[string]any
		unmarshalCmd(cmds[cluster], &data)
		if data != nil {
			result[cluster] = data
		}
	}
	return result, nil
}

// --- Policy Reads for RBAC Engine ---

// GetPoliciesForPrincipal reads sorted sets, deduplicates, sorts by priority desc, fetches JSON data.
func (c *Client) GetPoliciesForPrincipal(ctx context.Context, username string, groups []string, isServiceAccount bool) ([]map[string]any, error) {
	type keyPriority struct {
		key      string
		priority float64
	}
	seen := make(map[string]float64)

	// User policies
	userKey := fmt.Sprintf("policy:user:%s:sorted", username)
	userPolicies, err := c.client.ZRevRangeWithScores(ctx, userKey, 0, -1).Result()
	if err == nil {
		for _, z := range userPolicies {
			k := z.Member.(string)
			if z.Score > seen[k] {
				seen[k] = z.Score
			}
		}
	}

	// Group policies
	for _, group := range groups {
		groupKey := fmt.Sprintf("policy:group:%s:sorted", group)
		groupPolicies, err := c.client.ZRevRangeWithScores(ctx, groupKey, 0, -1).Result()
		if err != nil {
			continue
		}
		for _, z := range groupPolicies {
			k := z.Member.(string)
			if z.Score > seen[k] {
				seen[k] = z.Score
			}
		}
	}

	// Service account policies
	if isServiceAccount {
		saKey := fmt.Sprintf("policy:sa:%s:sorted", username)
		saPolicies, err := c.client.ZRevRangeWithScores(ctx, saKey, 0, -1).Result()
		if err == nil {
			for _, z := range saPolicies {
				k := z.Member.(string)
				if z.Score > seen[k] {
					seen[k] = z.Score
				}
			}
		}
	}

	if len(seen) == 0 {
		return nil, nil
	}

	// Sort by priority descending
	sorted := make([]keyPriority, 0, len(seen))
	for k, p := range seen {
		sorted = append(sorted, keyPriority{k, p})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].priority > sorted[j].priority
	})

	// Fetch policy data
	policies := make([]map[string]any, 0, len(sorted))
	for _, kp := range sorted {
		data, err := c.client.HGet(ctx, kp.key, "data").Result()
		if err != nil {
			continue
		}
		var policy map[string]any
		if err := json.Unmarshal([]byte(data), &policy); err != nil {
			logrus.WithError(err).Debugf("Failed to unmarshal policy %s", kp.key)
			continue
		}
		policy["_key"] = kp.key
		policies = append(policies, policy)
	}

	return policies, nil
}

// Ping tests Redis connectivity.
func (c *Client) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// unmarshalCmd safely unmarshals a StringCmd result, ignoring errors.
func unmarshalCmd(cmd *goredis.StringCmd, dest any) {
	if cmd.Err() != nil {
		return
	}
	_ = json.Unmarshal([]byte(cmd.Val()), dest)
}
