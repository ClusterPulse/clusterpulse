package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	store "github.com/clusterpulse/cluster-controller/internal/store"
)

// HealthHandler returns a simple health check.
// @Summary Health check
// @Description Returns API health status
// @Tags health
// @Produce json
// @Success 200 {object} map[string]string
// @Router /healthz [get]
func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ReadyHandler returns readiness status by pinging Redis.
// @Summary Readiness check
// @Description Returns readiness status by pinging Redis
// @Tags health
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 503 {object} map[string]string
// @Router /readyz [get]
func ReadyHandler(s *store.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if err := s.Ping(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "not ready",
				"error":  "redis unavailable",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
