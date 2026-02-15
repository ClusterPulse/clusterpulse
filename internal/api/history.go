package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/clusterpulse/cluster-controller/internal/rbac"
	"github.com/go-chi/chi/v5"
	"github.com/sirupsen/logrus"
)

// HistoryHandler serves time-series metric history from VictoriaMetrics.
type HistoryHandler struct {
	vmEndpoint string
	engine     *rbac.Engine
	httpClient *http.Client
}

// NewHistoryHandler creates a new history handler.
func NewHistoryHandler(vmEndpoint string, engine *rbac.Engine) *HistoryHandler {
	return &HistoryHandler{
		vmEndpoint: strings.TrimRight(vmEndpoint, "/"),
		engine:     engine,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// GetClusterMetricsHistory returns time-series data for a cluster metric.
// GET /api/v1/clusters/{name}/metrics/history?metric=cpu_usage&range=24h&step=5m
func (h *HistoryHandler) GetClusterMetricsHistory(w http.ResponseWriter, r *http.Request) {
	clusterName := chi.URLParam(r, "name")
	metric := r.URL.Query().Get("metric")
	rangeStr := r.URL.Query().Get("range")
	step := r.URL.Query().Get("step")

	if metric == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "metric parameter required"})
		return
	}

	if !h.checkClusterAccess(w, r, clusterName) {
		return
	}

	query := fmt.Sprintf(`clusterpulse_cluster_%s{cluster="%s"}`, metric, clusterName)
	data, err := h.queryRange(r.Context(), query, rangeStr, step)
	if err != nil {
		logrus.WithError(err).Debug("VictoriaMetrics query failed")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "metrics backend unavailable"})
		return
	}

	writeJSON(w, http.StatusOK, data)
}

// GetNodeMetricsHistory returns time-series data for a specific node metric.
// GET /api/v1/clusters/{name}/nodes/{node}/metrics/history?metric=cpu_usage&range=24h&step=5m
func (h *HistoryHandler) GetNodeMetricsHistory(w http.ResponseWriter, r *http.Request) {
	clusterName := chi.URLParam(r, "name")
	nodeName := chi.URLParam(r, "node")
	metric := r.URL.Query().Get("metric")
	rangeStr := r.URL.Query().Get("range")
	step := r.URL.Query().Get("step")

	if metric == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "metric parameter required"})
		return
	}

	if !h.checkClusterAccess(w, r, clusterName) {
		return
	}

	query := fmt.Sprintf(`clusterpulse_node_%s{cluster="%s",node="%s"}`, metric, clusterName, nodeName)
	data, err := h.queryRange(r.Context(), query, rangeStr, step)
	if err != nil {
		logrus.WithError(err).Debug("VictoriaMetrics query failed")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "metrics backend unavailable"})
		return
	}

	writeJSON(w, http.StatusOK, data)
}

// checkClusterAccess verifies the caller has RBAC access to the given cluster.
// Returns false (and writes an error response) if access is denied.
func (h *HistoryHandler) checkClusterAccess(w http.ResponseWriter, r *http.Request, clusterName string) bool {
	principal := GetPrincipal(r)
	if principal == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return false
	}
	accessible := h.engine.GetAccessibleClusters(r.Context(), principal)
	for _, c := range accessible {
		if c == clusterName {
			return true
		}
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
	return false
}

func (h *HistoryHandler) queryRange(ctx context.Context, query, rangeStr, step string) (interface{}, error) {
	if rangeStr == "" {
		rangeStr = "1h"
	}
	if step == "" {
		step = "1m"
	}

	dur, err := parseDuration(rangeStr)
	if err != nil {
		dur = time.Hour
	}

	end := time.Now()
	start := end.Add(-dur)

	params := url.Values{
		"query": {query},
		"start": {fmt.Sprintf("%d", start.Unix())},
		"end":   {fmt.Sprintf("%d", end.Unix())},
		"step":  {step},
	}

	reqURL := h.vmEndpoint + "/api/v1/query_range?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		s = strings.TrimSuffix(s, "d")
		var days int
		if _, err := fmt.Sscanf(s, "%d", &days); err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
