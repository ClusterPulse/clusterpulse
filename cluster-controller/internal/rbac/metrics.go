package rbac

import (
	"context"
	"sort"
	"strings"
	"time"

	store "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/sirupsen/logrus"
)

// MetricsCalculator computes RBAC-filtered cluster metrics.
type MetricsCalculator struct {
	store  *store.Client
	engine *Engine
}

// NewMetricsCalculator creates a new MetricsCalculator.
func NewMetricsCalculator(s *store.Client, engine *Engine) *MetricsCalculator {
	return &MetricsCalculator{store: s, engine: engine}
}

// GetFilteredClusterMetrics returns cluster metrics filtered by RBAC permissions.
func (mc *MetricsCalculator) GetFilteredClusterMetrics(ctx context.Context, clusterName string, principal *Principal, includeDetails bool) map[string]any {
	// Get base metrics
	var baseMetrics map[string]any
	if err := mc.store.GetJSON(ctx, "cluster:"+clusterName+":metrics", &baseMetrics); err != nil || baseMetrics == nil {
		return map[string]any{}
	}

	// Check for detailed resource data
	_, err := mc.store.GetClusterResourceMetadata(ctx, clusterName)
	if err != nil {
		baseMetrics["filtered"] = false
		baseMetrics["filter_note"] = "Detailed filtering not available - showing total counts"
		return baseMetrics
	}

	return mc.calculateFilteredMetrics(ctx, clusterName, principal, baseMetrics, includeDetails)
}

func (mc *MetricsCalculator) calculateFilteredMetrics(ctx context.Context, clusterName string, principal *Principal, baseMetrics map[string]any, includeDetails bool) map[string]any {
	filtered := make(map[string]any, len(baseMetrics))
	for k, v := range baseMetrics {
		filtered[k] = v
	}

	anyFilteringApplied := false

	// ====== FILTER NODES ======
	allNodes, _ := mc.store.GetClusterNodes(ctx, clusterName)
	if len(allNodes) > 0 {
		filteredNodes := mc.engine.FilterResources(ctx, principal, allNodes, ResourceNode, clusterName)

		if len(filteredNodes) != len(allNodes) {
			anyFilteringApplied = true
		}

		filtered["nodes"] = len(filteredNodes)

		nodesReady := 0
		for _, n := range filteredNodes {
			if getStr(n, "status") == "Ready" {
				nodesReady++
			}
		}
		filtered["nodes_ready"] = nodesReady
		filtered["nodes_not_ready"] = len(filteredNodes) - nodesReady

		if len(filteredNodes) > 0 {
			filtered["cpu_capacity"] = sumFloat(filteredNodes, "cpu_capacity")
			filtered["cpu_allocatable"] = sumFloat(filteredNodes, "cpu_allocatable")
			filtered["cpu_requested"] = sumFloat(filteredNodes, "cpu_requested")
			cpuCap := sumFloat(filteredNodes, "cpu_capacity")
			if cpuCap > 0 {
				filtered["cpu_usage_percent"] = sumFloat(filteredNodes, "cpu_requested") / cpuCap * 100
			} else {
				filtered["cpu_usage_percent"] = float64(0)
			}

			filtered["memory_capacity"] = sumFloat(filteredNodes, "memory_capacity")
			filtered["memory_allocatable"] = sumFloat(filteredNodes, "memory_allocatable")
			filtered["memory_requested"] = sumFloat(filteredNodes, "memory_requested")
			memCap := sumFloat(filteredNodes, "memory_capacity")
			if memCap > 0 {
				filtered["memory_usage_percent"] = sumFloat(filteredNodes, "memory_requested") / memCap * 100
			} else {
				filtered["memory_usage_percent"] = float64(0)
			}

			filtered["storage_capacity"] = sumFloat(filteredNodes, "storage_capacity")
			filtered["storage_used"] = sumFloat(filteredNodes, "storage_used")
		} else {
			for _, key := range []string{"cpu_capacity", "cpu_allocatable", "cpu_requested", "cpu_usage_percent",
				"memory_capacity", "memory_allocatable", "memory_requested", "memory_usage_percent",
				"storage_capacity", "storage_used"} {
				filtered[key] = float64(0)
			}
		}

		if includeDetails && len(filteredNodes) > 0 {
			roles := make(map[string]int)
			var names []string
			for _, n := range filteredNodes {
				for _, role := range getStringSlice(n, "roles") {
					roles[role]++
				}
				if name := getStr(n, "name"); name != "" {
					names = append(names, name)
				}
			}
			filtered["node_roles"] = roles
			if len(names) > 10 {
				names = names[:10]
			}
			filtered["node_names"] = names
		}
	}

	// ====== FILTER NAMESPACES ======
	allNamespaces, _ := mc.store.GetClusterNamespaces(ctx, clusterName)
	nsResources := make([]map[string]any, len(allNamespaces))
	for i, ns := range allNamespaces {
		nsResources[i] = map[string]any{"name": ns, "namespace": ns}
	}

	filteredNSResources := mc.engine.FilterResources(ctx, principal, nsResources, ResourceNamespace, clusterName)
	allowedNamespaces := make(map[string]struct{}, len(filteredNSResources))
	for _, ns := range filteredNSResources {
		if name := getStr(ns, "name"); name != "" {
			allowedNamespaces[name] = struct{}{}
		}
	}

	if len(allowedNamespaces) < len(allNamespaces) {
		anyFilteringApplied = true
	}

	filtered["namespaces"] = len(allowedNamespaces)
	originalNSCount := len(allNamespaces)
	if v, ok := baseMetrics["namespaces"]; ok {
		if n, ok := toInt(v); ok {
			originalNSCount = n
		}
	}

	// ====== FILTER NAMESPACE-SCOPED RESOURCES ======
	nsResourceTypes := []struct {
		key  string
		rtyp ResourceType
	}{
		{"pods", ResourcePod},
		{"deployments", ResourcePod},
		{"services", ResourcePod},
		{"statefulsets", ResourcePod},
		{"daemonsets", ResourcePod},
	}

	for _, nrt := range nsResourceTypes {
		resources, err := mc.store.GetClusterResourcesByType(ctx, clusterName, nrt.key)
		if err != nil || len(resources) == 0 {
			filtered[nrt.key] = 0
			continue
		}

		filteredRes := mc.engine.FilterResources(ctx, principal, resources, nrt.rtyp, clusterName)
		if len(filteredRes) != len(resources) {
			anyFilteringApplied = true
		}

		filtered[nrt.key] = len(filteredRes)

		if nrt.key == "pods" {
			running, pending, failed := 0, 0, 0
			for _, p := range filteredRes {
				switch strings.ToLower(getStr(p, "status")) {
				case "running":
					running++
				case "pending":
					pending++
				case "failed":
					failed++
				}
			}
			filtered["pods_running"] = running
			filtered["pods_pending"] = pending
			filtered["pods_failed"] = failed
		}
	}

	// PVCs
	if anyFilteringApplied {
		filtered["pvcs"] = 0
	}

	// ====== FILTER OPERATORS ======
	operators, _ := mc.store.GetClusterOperatorsList(ctx, clusterName)
	if len(operators) > 0 {
		filteredOps := mc.engine.FilterResources(ctx, principal, operators, ResourceOperator, clusterName)
		if len(filteredOps) != len(operators) {
			anyFilteringApplied = true
		}
		if includeDetails {
			filtered["operators"] = len(filteredOps)
			filtered["operators_total"] = len(operators)
		}
	}

	// ====== SET FILTERING METADATA ======
	filtered["filtered"] = anyFilteringApplied
	if anyFilteringApplied {
		filtered["filter_metadata"] = map[string]any{
			"applied":            true,
			"type":               "rbac-based",
			"allowed_namespaces": len(allowedNamespaces),
			"total_namespaces":   originalNSCount,
			"allowed_nodes":      filtered["nodes"],
			"total_nodes":        len(allNodes),
			"timestamp":          time.Now().UTC().Format(time.RFC3339),
		}
	}

	return filtered
}

// GetAllowedNamespaces returns the set of namespaces accessible to the principal.
func (mc *MetricsCalculator) GetAllowedNamespaces(ctx context.Context, clusterName string, principal *Principal) []string {
	allNamespaces, err := mc.store.GetClusterNamespaces(ctx, clusterName)
	if err != nil {
		return nil
	}

	nsResources := make([]map[string]any, len(allNamespaces))
	for i, ns := range allNamespaces {
		nsResources[i] = map[string]any{"name": ns, "namespace": ns}
	}

	filteredResources := mc.engine.FilterResources(ctx, principal, nsResources, ResourceNamespace, clusterName)
	result := make([]string, 0, len(filteredResources))
	for _, ns := range filteredResources {
		if name := getStr(ns, "name"); name != "" {
			result = append(result, name)
		}
	}

	sort.Strings(result)
	logrus.Debugf("Allowed namespaces for %s in %s: %d/%d", principal.Username, clusterName, len(result), len(allNamespaces))
	return result
}

// sumFloat sums a float64 field across a slice of maps.
func sumFloat(items []map[string]any, key string) float64 {
	var total float64
	for _, item := range items {
		switch v := item[key].(type) {
		case float64:
			total += v
		case int:
			total += float64(v)
		case int64:
			total += float64(v)
		}
	}
	return total
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case float64:
		return int(n), true
	case int64:
		return int(n), true
	}
	return 0, false
}
