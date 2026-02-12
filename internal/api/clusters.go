package api

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"

	"github.com/clusterpulse/cluster-controller/internal/rbac"
	store "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/sirupsen/logrus"
)

// ClusterHandler handles cluster-related API routes.
type ClusterHandler struct {
	store  *store.Client
	engine *rbac.Engine
}

// NewClusterHandler creates a new ClusterHandler.
func NewClusterHandler(s *store.Client, engine *rbac.Engine) *ClusterHandler {
	return &ClusterHandler{store: s, engine: engine}
}

// checkClusterAccess verifies cluster access and returns the decision or writes 403.
func (h *ClusterHandler) checkClusterAccess(w http.ResponseWriter, r *http.Request, principal *rbac.Principal, cluster string, action rbac.Action) *rbac.RBACDecision {
	resource := &rbac.Resource{Type: rbac.ResourceCluster, Name: cluster, Cluster: cluster}
	request := &rbac.Request{Principal: principal, Action: action, Resource: resource}
	decision := h.engine.Authorize(r.Context(), request)

	if decision.Denied() {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": fmt.Sprintf("Access denied to cluster '%s'", cluster),
		})
		return nil
	}
	return decision
}

// ListClusters returns all accessible clusters.
func (h *ClusterHandler) ListClusters(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	if principal == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	ctx := r.Context()
	accessible := h.engine.GetAccessibleClusters(ctx, principal)

	var clusters []map[string]any
	for _, name := range accessible {
		bundle, _ := h.store.GetClusterBundle(ctx, name)

		operators, _ := h.store.GetClusterOperatorsList(ctx, name)
		filteredOps := h.engine.FilterResources(ctx, principal, operators, rbac.ResourceOperator, name)

		cluster := map[string]any{
			"name":           name,
			"accessible":     true,
			"spec":           ensureMap(bundle.Spec),
			"info":           ensureMap(bundle.Info),
			"metrics":        ensureMap(bundle.Metrics),
			"status":         statusWithFallback(bundle.Status),
			"operator_count": len(filteredOps),
		}

		clusters = append(clusters, cluster)
	}

	if clusters == nil {
		clusters = []map[string]any{}
	}

	logrus.Infof("User %s listed %d clusters", principal.Username, len(clusters))
	writeJSON(w, http.StatusOK, clusters)
}

// GetCluster returns detailed cluster information.
func (h *ClusterHandler) GetCluster(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	clusterName := chi.URLParam(r, "name")

	decision := h.checkClusterAccess(w, r, principal, clusterName, rbac.ActionView)
	if decision == nil {
		return
	}

	ctx := r.Context()
	bundle, _ := h.store.GetClusterBundle(ctx, clusterName)
	resourceMeta, _ := h.store.GetClusterResourceMetadata(ctx, clusterName)

	result := map[string]any{
		"name":    clusterName,
		"spec":    ensureMap(bundle.Spec),
		"info":    ensureMap(bundle.Info),
		"metrics": ensureMap(bundle.Metrics),
		"status":  statusWithFallback(bundle.Status),
	}

	if resourceMeta != nil {
		result["resource_collection"] = map[string]any{
			"enabled":             true,
			"last_collection":     resourceMeta["timestamp"],
			"collection_time_ms":  resourceMeta["collection_time_ms"],
			"truncated":           resourceMeta["truncated"],
		}
	}

	operators, _ := h.store.GetClusterOperatorsList(ctx, clusterName)
	filteredOps := h.engine.FilterResources(ctx, principal, operators, rbac.ResourceOperator, clusterName)
	result["operator_count"] = len(filteredOps)

	logrus.Infof("User %s accessed cluster %s", principal.Username, clusterName)
	writeJSON(w, http.StatusOK, result)
}

// GetClusterNodes returns RBAC-filtered nodes for a cluster.
func (h *ClusterHandler) GetClusterNodes(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	clusterName := chi.URLParam(r, "name")

	if h.checkClusterAccess(w, r, principal, clusterName, rbac.ActionView) == nil {
		return
	}

	ctx := r.Context()
	nodes, err := h.store.GetClusterNodes(ctx, clusterName)
	if err != nil {
		writeJSON(w, http.StatusOK, []map[string]any{})
		return
	}

	// Apply query filters
	role := r.URL.Query().Get("role")
	statusFilter := r.URL.Query().Get("status")

	if role != "" {
		var filtered []map[string]any
		for _, node := range nodes {
			for _, r := range getStringSliceFromMap(node, "roles") {
				if r == role {
					filtered = append(filtered, node)
					break
				}
			}
		}
		nodes = filtered
	}

	if statusFilter != "" {
		var filtered []map[string]any
		for _, node := range nodes {
			if s, _ := node["status"].(string); s == statusFilter {
				filtered = append(filtered, node)
			}
		}
		nodes = filtered
	}

	filteredNodes := h.engine.FilterResources(ctx, principal, nodes, rbac.ResourceNode, clusterName)
	if filteredNodes == nil {
		filteredNodes = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, filteredNodes)
}

// GetClusterNode returns detailed information about a specific node.
func (h *ClusterHandler) GetClusterNode(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	clusterName := chi.URLParam(r, "name")
	nodeName := chi.URLParam(r, "node")

	decision := h.checkClusterAccess(w, r, principal, clusterName, rbac.ActionView)
	if decision == nil {
		return
	}

	ctx := r.Context()
	node, err := h.store.GetClusterNode(ctx, clusterName, nodeName)
	if err != nil || node == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": fmt.Sprintf("Node %s not found in cluster %s", nodeName, clusterName),
		})
		return
	}

	filteredNodes := h.engine.FilterResources(ctx, principal, []map[string]any{node}, rbac.ResourceNode, clusterName)
	if len(filteredNodes) == 0 {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": fmt.Sprintf("Access to node %s is not permitted", nodeName),
		})
		return
	}

	result := filteredNodes[0]

	if r.URL.Query().Get("include_metrics") == "true" && decision.Can(rbac.ActionViewMetrics) {
		history, _ := h.store.GetNodeMetricsHistory(ctx, clusterName, nodeName, 100)
		result["metrics_history"] = history
	}

	conditions, _ := h.store.GetNodeConditions(ctx, clusterName, nodeName)
	if len(conditions) > 0 {
		result["current_conditions"] = conditions
	}

	writeJSON(w, http.StatusOK, result)
}

// GetClusterOperators returns RBAC-filtered operators.
func (h *ClusterHandler) GetClusterOperators(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	clusterName := chi.URLParam(r, "name")

	if h.checkClusterAccess(w, r, principal, clusterName, rbac.ActionView) == nil {
		return
	}

	ctx := r.Context()
	operators, _ := h.store.GetClusterOperatorsList(ctx, clusterName)

	// Apply query filters
	ns := r.URL.Query().Get("namespace")
	statusFilter := r.URL.Query().Get("status")

	if ns != "" {
		var filtered []map[string]any
		for _, op := range operators {
			availNS := getStringSliceFromMap(op, "available_in_namespaces")
			if (len(availNS) == 1 && availNS[0] == "*") || contains(availNS, ns) {
				filtered = append(filtered, op)
			}
		}
		operators = filtered
	}

	if statusFilter != "" {
		var filtered []map[string]any
		for _, op := range operators {
			if s, _ := op["status"].(string); s == statusFilter {
				filtered = append(filtered, op)
			}
		}
		operators = filtered
	}

	filteredOps := h.engine.FilterResources(ctx, principal, operators, rbac.ResourceOperator, clusterName)
	if filteredOps == nil {
		filteredOps = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, filteredOps)
}

// GetClusterNamespaces returns RBAC-filtered namespaces.
func (h *ClusterHandler) GetClusterNamespaces(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	clusterName := chi.URLParam(r, "name")

	if h.checkClusterAccess(w, r, principal, clusterName, rbac.ActionView) == nil {
		return
	}

	ctx := r.Context()
	allowed := h.getAllowedNamespaces(ctx, clusterName, principal)

	withOpCount := r.URL.Query().Get("with_operator_count") == "true"
	withResCounts := r.URL.Query().Get("with_resource_counts") == "true"

	if !withOpCount && !withResCounts {
		writeJSON(w, http.StatusOK, allowed)
		return
	}

	var details []map[string]any
	for _, ns := range allowed {
		detail := map[string]any{"name": ns}

		if withOpCount {
			operators, _ := h.store.GetClusterOperatorsList(ctx, clusterName)
			filteredOps := h.engine.FilterResources(ctx, principal, operators, rbac.ResourceOperator, clusterName)
			count := 0
			for _, op := range filteredOps {
				availNS := getStringSliceFromMap(op, "available_in_namespaces")
				if (len(availNS) == 1 && availNS[0] == "*") || contains(availNS, ns) {
					count++
				}
			}
			detail["operator_count"] = count
		}

		if withResCounts {
			counts := map[string]int{}
			total := 0
			for _, rt := range []string{"pods", "deployments", "services", "statefulsets", "daemonsets"} {
				resources, _ := h.store.GetClusterResourcesByType(ctx, clusterName, rt)
				c := 0
				for _, res := range resources {
					if resNS, _ := res["namespace"].(string); resNS == ns {
						c++
					}
				}
				counts[rt] = c
				total += c
			}
			detail["resource_counts"] = counts
			detail["total_resources"] = total
		}

		details = append(details, detail)
	}

	if withResCounts {
		sort.Slice(details, func(i, j int) bool {
			ti, _ := details[i]["total_resources"].(int)
			tj, _ := details[j]["total_resources"].(int)
			return ti > tj
		})
	}

	writeJSON(w, http.StatusOK, details)
}

// GetClusterAlerts returns RBAC-filtered alerts.
func (h *ClusterHandler) GetClusterAlerts(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	clusterName := chi.URLParam(r, "name")

	if h.checkClusterAccess(w, r, principal, clusterName, rbac.ActionView) == nil {
		return
	}

	ctx := r.Context()
	alerts, _ := h.store.GetClusterAlerts(ctx, clusterName)

	if severity := r.URL.Query().Get("severity"); severity != "" {
		var filtered []map[string]any
		for _, a := range alerts {
			if s, _ := a["severity"].(string); s == severity {
				filtered = append(filtered, a)
			}
		}
		alerts = filtered
	}

	filteredAlerts := h.engine.FilterResources(ctx, principal, alerts, rbac.ResourceAlert, clusterName)
	if filteredAlerts == nil {
		filteredAlerts = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, filteredAlerts)
}

// GetClusterEvents returns RBAC-filtered events.
func (h *ClusterHandler) GetClusterEvents(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	clusterName := chi.URLParam(r, "name")

	if h.checkClusterAccess(w, r, principal, clusterName, rbac.ActionView) == nil {
		return
	}

	limit := int64(100)
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.ParseInt(l, 10, 64); err == nil && n > 0 {
			limit = n
		}
	}

	ctx := r.Context()
	events, _ := h.store.GetClusterEvents(ctx, clusterName, limit)

	filteredEvents := h.engine.FilterResources(ctx, principal, events, rbac.ResourceEvent, clusterName)
	if filteredEvents == nil {
		filteredEvents = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, filteredEvents)
}

// GetCustomResources returns RBAC-filtered custom resources with pagination.
func (h *ClusterHandler) GetCustomResources(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	clusterName := chi.URLParam(r, "name")
	typeName := chi.URLParam(r, "type")

	if h.checkClusterAccess(w, r, principal, clusterName, rbac.ActionView) == nil {
		return
	}

	ctx := r.Context()
	crDecision := h.engine.AuthorizeCustomResource(ctx, principal, typeName, clusterName, rbac.ActionView)
	if crDecision.Denied() {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": fmt.Sprintf("Access denied to custom resource type '%s'", typeName),
		})
		return
	}

	// Find source ID
	sourceIDs, _ := h.store.GetSourceIDForType(ctx, typeName)
	if len(sourceIDs) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": fmt.Sprintf("Custom resource type '%s' not found", typeName),
		})
		return
	}
	sourceID := sourceIDs[0]

	// Get source definition for RBAC config
	sourceDef, _ := h.store.GetMetricSourceDef(ctx, sourceID)
	rbacConfig, _ := sourceDef["rbac"].(map[string]any)
	filterAggregations := true
	if rbacConfig != nil {
		if fa, ok := rbacConfig["filterAggregations"].(bool); ok {
			filterAggregations = fa
		}
	}

	// Get resources
	resourceData, _ := h.store.GetCustomResourcesRaw(ctx, clusterName, sourceID)
	if resourceData == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"resourceTypeName": typeName,
			"cluster":          clusterName,
			"items":            []any{},
			"pagination": map[string]any{
				"total": 0, "page": 1, "pageSize": 100,
				"totalPages": 1, "hasNext": false, "hasPrevious": false,
			},
		})
		return
	}

	rawResources, _ := resourceData["resources"].([]any)
	resources := make([]map[string]any, 0, len(rawResources))
	for _, r := range rawResources {
		if m, ok := r.(map[string]any); ok {
			resources = append(resources, m)
		}
	}
	totalBeforeFilter := len(resources)

	// RBAC filter
	filteredResources := h.engine.FilterCustomResources(ctx, principal, resources, typeName, clusterName)

	// Namespace filter
	if ns := r.URL.Query().Get("namespace"); ns != "" {
		var nsFiltered []map[string]any
		for _, res := range filteredResources {
			if resNS, _ := res["_namespace"].(string); resNS == ns {
				nsFiltered = append(nsFiltered, res)
			}
		}
		filteredResources = nsFiltered
	}

	// Sort
	if sortBy := r.URL.Query().Get("sort_by"); sortBy != "" {
		reverse := r.URL.Query().Get("sort_order") == "desc"
		sort.Slice(filteredResources, func(i, j int) bool {
			vi := fmt.Sprintf("%v", filteredResources[i][sortBy])
			vj := fmt.Sprintf("%v", filteredResources[j][sortBy])
			if reverse {
				return vi > vj
			}
			return vi < vj
		})
	}

	// Pagination
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 100)

	paginationInfo := paginate(filteredResources, page, pageSize)
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > len(filteredResources) {
		start = len(filteredResources)
	}
	if end > len(filteredResources) {
		end = len(filteredResources)
	}
	paginatedItems := filteredResources[start:end]

	isFiltered := totalBeforeFilter != len(filteredResources)
	result := map[string]any{
		"resourceTypeName": typeName,
		"cluster":          clusterName,
		"items":            paginatedItems,
		"filtered":         isFiltered,
		"pagination":       paginationInfo,
	}

	if isFiltered {
		result["filterNote"] = "Results filtered based on access policies"
	}

	if collectedAt := resourceData["collectedAt"]; collectedAt != nil {
		result["collectedAt"] = collectedAt
	}
	if truncated, ok := resourceData["truncated"].(bool); ok && truncated {
		result["truncated"] = true
	}

	// Aggregations
	if r.URL.Query().Get("include_aggregations") != "false" {
		aggData, _ := h.store.GetCustomAggregationsRaw(ctx, clusterName, sourceID)
		if aggData != nil {
			values, _ := aggData["values"].(map[string]any)
			if values == nil {
				values = make(map[string]any)
			}

			if filterAggregations && len(filteredResources) < totalBeforeFilter {
				aggSpecs, _ := sourceDef["aggregations"].([]any)
				var specs []map[string]any
				for _, s := range aggSpecs {
					if m, ok := s.(map[string]any); ok {
						specs = append(specs, m)
					}
				}
				if len(specs) > 0 {
					values = recomputeAggregations(filteredResources, specs)
				}
			}

			values = h.engine.FilterAggregations(ctx, principal, values, typeName, clusterName)
			result["aggregations"] = values
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// paginate returns pagination metadata using camelCase keys (Python-compatible).
func paginate(items []map[string]any, page, pageSize int) map[string]any {
	total := len(items)
	totalPages := int(math.Ceil(float64(total) / float64(pageSize)))
	if totalPages < 1 {
		totalPages = 1
	}

	return map[string]any{
		"total":       total,
		"page":        page,
		"pageSize":    pageSize,
		"totalPages":  totalPages,
		"hasNext":     page < totalPages,
		"hasPrevious": page > 1,
	}
}

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func contains(s []string, v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}

func getStringSliceFromMap(m map[string]any, key string) []string {
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

// getAllowedNamespaces returns RBAC-filtered namespaces for a cluster.
func (h *ClusterHandler) getAllowedNamespaces(ctx context.Context, clusterName string, principal *rbac.Principal) []string {
	allNamespaces, err := h.store.GetClusterNamespaces(ctx, clusterName)
	if err != nil {
		return nil
	}

	nsResources := make([]map[string]any, len(allNamespaces))
	for i, ns := range allNamespaces {
		nsResources[i] = map[string]any{"name": ns, "namespace": ns}
	}

	filtered := h.engine.FilterResources(ctx, principal, nsResources, rbac.ResourceNamespace, clusterName)
	result := make([]string, 0, len(filtered))
	for _, ns := range filtered {
		if name, ok := ns["name"].(string); ok && name != "" {
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result
}

// statusWithFallback returns the status or a sensible default.
func statusWithFallback(status map[string]any) map[string]any {
	if status != nil {
		return status
	}
	return map[string]any{
		"health":  "unknown",
		"message": "Status unavailable",
	}
}

// ensureMap returns m if non-nil, otherwise an empty map.
func ensureMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

