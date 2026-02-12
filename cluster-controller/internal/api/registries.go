package api

import (
	"net/http"

	store "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/sirupsen/logrus"
)

// RegistryHandler handles registry-related API routes.
type RegistryHandler struct {
	store *store.Client
}

// NewRegistryHandler creates a new RegistryHandler.
func NewRegistryHandler(s *store.Client) *RegistryHandler {
	return &RegistryHandler{store: s}
}

// ListRegistriesStatus returns availability status for all registries.
func (h *RegistryHandler) ListRegistriesStatus(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	if principal == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	ctx := r.Context()
	includeRT := r.URL.Query().Get("include_response_time") == "true"

	names, err := h.store.GetAllRegistryNames(ctx)
	if err != nil || len(names) == 0 {
		writeJSON(w, http.StatusOK, []any{})
		return
	}

	bundles, _ := h.store.BatchGetRegistryBundles(ctx, names)

	var registries []map[string]any
	for _, name := range names {
		bundle := bundles[name]
		if bundle == nil {
			bundle = &store.RegistryBundle{}
		}

		entry := map[string]any{
			"name":         name,
			"display_name": getMapStr(bundle.Spec, "displayName"),
			"endpoint":     getMapStr(bundle.Spec, "endpoint"),
			"available":    getMapBool(bundle.Status, "available"),
			"error":        getMapStrPtr(bundle.Status, "error"),
		}

		if includeRT {
			entry["response_time"] = getMapVal(bundle.Status, "responseTime")
		}

		registries = append(registries, entry)
	}

	logrus.Infof("User %s listed %d registries", principal.Username, len(registries))
	writeJSON(w, http.StatusOK, registries)
}

func getMapStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return v
}

func getMapBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	v, _ := m[key].(bool)
	return v
}

func getMapStrPtr(m map[string]any, key string) any {
	if m == nil {
		return nil
	}
	v, ok := m[key].(string)
	if !ok || v == "" {
		return nil
	}
	return v
}

func getMapVal(m map[string]any, key string) any {
	if m == nil {
		return nil
	}
	return m[key]
}
