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
			"name":   name,
			"spec":   ensureMap(bundle.Spec),
			"status": ensureMap(bundle.Status),
		}

		registries = append(registries, entry)
	}

	logrus.Infof("User %s listed %d registries", principal.Username, len(registries))
	writeJSON(w, http.StatusOK, registries)
}

