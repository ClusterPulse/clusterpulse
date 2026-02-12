package api

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/clusterpulse/cluster-controller/internal/rbac"
	store "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/sirupsen/logrus"
)

// CustomTypeHandler handles custom resource type discovery routes.
type CustomTypeHandler struct {
	store  *store.Client
	engine *rbac.Engine
}

// NewCustomTypeHandler creates a new CustomTypeHandler.
func NewCustomTypeHandler(s *store.Client, engine *rbac.Engine) *CustomTypeHandler {
	return &CustomTypeHandler{store: s, engine: engine}
}

// ListCustomTypes returns all custom resource types the user can access.
func (h *CustomTypeHandler) ListCustomTypes(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	if principal == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	ctx := r.Context()
	includeSource := r.URL.Query().Get("include_source_details") == "true"
	includeAvail := r.URL.Query().Get("include_cluster_availability") == "true"

	allSources, _ := h.store.GetAllMetricSources(ctx)
	typeToSource := make(map[string]map[string]any)
	for _, source := range allSources {
		rbacCfg, _ := source["rbac"].(map[string]any)
		typeName, _ := rbacCfg["resourceTypeName"].(string)
		if typeName != "" {
			typeToSource[typeName] = source
		}
	}

	accessibleTypes := h.engine.GetAccessibleCustomResourceTypes(ctx, principal)

	var result []map[string]any
	for _, typeName := range accessibleTypes {
		source, ok := typeToSource[typeName]
		if !ok {
			continue
		}

		sourceID, _ := source["_id"].(string)
		if sourceID == "" {
			ns, _ := source["namespace"].(string)
			name, _ := source["name"].(string)
			sourceID = fmt.Sprintf("%s/%s", ns, name)
		}

		entry := map[string]any{
			"resourceTypeName": typeName,
			"sourceId":         sourceID,
		}

		if includeSource {
			sourceSpec, _ := source["source"].(map[string]any)
			if sourceSpec == nil {
				sourceSpec = map[string]any{}
			}
			scope, _ := sourceSpec["scope"].(string)
			if scope == "" {
				scope = "Namespaced"
			}
			entry["source"] = map[string]any{
				"apiVersion": sourceSpec["apiVersion"],
				"kind":       sourceSpec["kind"],
				"scope":      scope,
			}

			entry["fields"] = extractNames(source, "fields")
			entry["computedFields"] = extractNames(source, "computed")
			entry["aggregations"] = extractNames(source, "aggregations")
		}

		if includeAvail {
			clusters, _ := h.store.GetClustersWithData(ctx, typeName)
			entry["clustersWithData"] = clusters
		}

		result = append(result, entry)
	}

	if result == nil {
		result = []map[string]any{}
	}

	logrus.Infof("User %s listed %d custom resource types", principal.Username, len(result))
	writeJSON(w, http.StatusOK, result)
}

// GetCustomResourceCounts returns filtered resource counts per type per cluster.
func (h *CustomTypeHandler) GetCustomResourceCounts(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	if principal == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	ctx := r.Context()
	typeNames := r.URL.Query()["type"]
	clusterFilter := r.URL.Query()["clusters"]
	includeAgg := r.URL.Query().Get("include_aggregations") == "true"

	if len(typeNames) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one 'type' query parameter is required"})
		return
	}

	// Validate access to all requested types
	for _, typeName := range typeNames {
		decision := h.engine.AuthorizeCustomResource(ctx, principal, typeName, "", rbac.ActionView)
		if decision.Denied() {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": fmt.Sprintf("Access denied to custom resource type '%s'", typeName),
			})
			return
		}
	}

	accessible := h.engine.GetAccessibleClusters(ctx, principal)
	if len(clusterFilter) > 0 {
		filterSet := make(map[string]struct{}, len(clusterFilter))
		for _, c := range clusterFilter {
			filterSet[c] = struct{}{}
		}
		var filtered []string
		for _, c := range accessible {
			if _, ok := filterSet[c]; ok {
				filtered = append(filtered, c)
			}
		}
		accessible = filtered
	}

	if len(accessible) == 0 {
		writeJSON(w, http.StatusOK, []any{})
		return
	}

	var result []map[string]any
	for _, typeName := range typeNames {
		counts := h.countsForType(r, principal, typeName, accessible, includeAgg)
		result = append(result, counts...)
	}

	if result == nil {
		result = []map[string]any{}
	}

	logrus.Infof("User %s accessed counts for %d resource types across %d clusters",
		principal.Username, len(typeNames), len(accessible))
	writeJSON(w, http.StatusOK, result)
}

// countsForType computes filtered resource counts for a single type across clusters.
func (h *CustomTypeHandler) countsForType(
	r *http.Request,
	principal *rbac.Principal,
	typeName string,
	clusters []string,
	includeAgg bool,
) []map[string]any {
	ctx := r.Context()

	sourceID, err := h.store.GetSourceIDForTypeSingle(ctx, typeName)
	if err != nil || sourceID == "" {
		return nil
	}

	var sourceDef map[string]any
	sourceDef, _ = h.store.GetMetricSourceDef(ctx, sourceID)
	rbacConfig, _ := sourceDef["rbac"].(map[string]any)
	filterAggregations := true
	if rbacConfig != nil {
		if fa, ok := rbacConfig["filterAggregations"].(bool); ok {
			filterAggregations = fa
		}
	}

	resourcesByCluster, _ := h.store.BatchGetCustomResources(ctx, sourceID, clusters)

	var aggsByCluster map[string]map[string]any
	if includeAgg {
		aggsByCluster, _ = h.store.BatchGetCustomAggregations(ctx, sourceID, clusters)
	}

	sort.Strings(clusters)
	var result []map[string]any

	for _, cluster := range clusters {
		resourceData := resourcesByCluster[cluster]
		if resourceData == nil {
			continue
		}

		rawResources, _ := resourceData["resources"].([]any)
		resources := make([]map[string]any, 0, len(rawResources))
		for _, r := range rawResources {
			if m, ok := r.(map[string]any); ok {
				resources = append(resources, m)
			}
		}
		totalCount := len(resources)

		filtered := h.engine.FilterCustomResources(ctx, principal, resources, typeName, cluster)
		filteredCount := len(filtered)

		entry := map[string]any{
			"cluster":          cluster,
			"resourceTypeName": typeName,
			"count":            filteredCount,
		}

		if collectedAt := resourceData["collectedAt"]; collectedAt != nil {
			entry["lastCollection"] = collectedAt
		}

		if includeAgg && aggsByCluster != nil {
			aggData := aggsByCluster[cluster]
			if aggData != nil {
				values, _ := aggData["values"].(map[string]any)
				if values == nil {
					values = make(map[string]any)
				}

				if filterAggregations && filteredCount < totalCount {
					aggSpecs, _ := sourceDef["aggregations"].([]any)
					var specs []map[string]any
					for _, s := range aggSpecs {
						if m, ok := s.(map[string]any); ok {
							specs = append(specs, m)
						}
					}
					if len(specs) > 0 {
						values = recomputeAggregations(filtered, specs)
					}
				}

				values = h.engine.FilterAggregations(ctx, principal, values, typeName, cluster)
				entry["aggregations"] = values
			}
		}

		result = append(result, entry)
	}

	return result
}

// extractNames pulls the "name" field from each item in a source list key.
func extractNames(source map[string]any, key string) []string {
	items, _ := source[key].([]any)
	var names []string
	for _, item := range items {
		m, _ := item.(map[string]any)
		if m == nil {
			continue
		}
		if name, _ := m["name"].(string); name != "" {
			names = append(names, name)
		}
	}
	if names == nil {
		names = []string{}
	}
	return names
}
