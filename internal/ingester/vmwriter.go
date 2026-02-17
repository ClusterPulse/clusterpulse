package ingester

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/sirupsen/logrus"
)

// VMWriter writes metrics to VictoriaMetrics via the import/prometheus endpoint.
type VMWriter struct {
	endpoint   string
	httpClient *http.Client
}

// NewVMWriter creates a new VictoriaMetrics writer.
func NewVMWriter(endpoint string) *VMWriter {
	return &VMWriter{
		endpoint: strings.TrimRight(endpoint, "/"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// WriteClusterMetrics sends cluster-level metrics to VictoriaMetrics.
func (w *VMWriter) WriteClusterMetrics(ctx context.Context, cluster string, m *types.ClusterMetrics) {
	ts := time.Now().UnixMilli()
	var lines []string

	lines = append(lines,
		formatLine("clusterpulse_cluster_nodes_total", cluster, "", m.Nodes, ts),
		formatLine("clusterpulse_cluster_nodes_ready", cluster, "", m.NodesReady, ts),
		formatLine("clusterpulse_cluster_pods_total", cluster, "", m.Pods, ts),
		formatLine("clusterpulse_cluster_pods_running", cluster, "", m.PodsRunning, ts),
		formatLine("clusterpulse_cluster_cpu_capacity", cluster, "", m.CPUCapacity, ts),
		formatLine("clusterpulse_cluster_memory_capacity_bytes", cluster, "", m.MemoryCapacity, ts),
		formatLine("clusterpulse_cluster_namespaces_total", cluster, "", m.Namespaces, ts),
		formatLine("clusterpulse_cluster_deployments_total", cluster, "", m.Deployments, ts),
	)

	w.send(ctx, lines)
}

// WriteNodeMetrics sends per-node metrics to VictoriaMetrics.
func (w *VMWriter) WriteNodeMetrics(ctx context.Context, cluster string, nodes []types.NodeMetrics) {
	ts := time.Now().UnixMilli()
	var lines []string

	for _, n := range nodes {
		lines = append(lines,
			formatLine("clusterpulse_node_cpu_usage_percent", cluster, n.Name, n.CPUUsagePercent, ts),
			formatLine("clusterpulse_node_memory_usage_percent", cluster, n.Name, n.MemoryUsagePercent, ts),
			formatLine("clusterpulse_node_pods_total", cluster, n.Name, n.PodsTotal, ts),
			formatLine("clusterpulse_node_pods_running", cluster, n.Name, n.PodsRunning, ts),
			formatLine("clusterpulse_node_cpu_capacity", cluster, n.Name, n.CPUCapacity, ts),
			formatLine("clusterpulse_node_memory_capacity_bytes", cluster, n.Name, n.MemoryCapacity, ts),
		)
	}

	w.send(ctx, lines)
}

// WriteCustomResourceMetrics sends custom resource aggregation values to VictoriaMetrics.
func (w *VMWriter) WriteCustomResourceMetrics(ctx context.Context, cluster, sourceID string, aggregations map[string]float64) {
	ts := time.Now().UnixMilli()
	var lines []string
	for name, value := range aggregations {
		metric := fmt.Sprintf("clusterpulse_custom_resource_%s", name)
		line := fmt.Sprintf(`%s{cluster="%s",source="%s"} %v %d`, metric, cluster, sourceID, value, ts)
		lines = append(lines, line)
	}
	w.send(ctx, lines)
}

func formatLine[T int | int32 | int64 | float64](metric, cluster, node string, value T, ts int64) string {
	labels := fmt.Sprintf(`cluster="%s"`, cluster)
	if node != "" {
		labels += fmt.Sprintf(`,node="%s"`, node)
	}
	return fmt.Sprintf("%s{%s} %v %d", metric, labels, value, ts)
}

func (w *VMWriter) send(ctx context.Context, lines []string) {
	if len(lines) == 0 {
		return
	}

	body := strings.Join(lines, "\n") + "\n"
	url := w.endpoint + "/api/v1/import/prometheus"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(body))
	if err != nil {
		logrus.WithError(err).Debug("Failed to create VM request")
		return
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := w.httpClient.Do(req)
	if err != nil {
		logrus.WithError(err).Debug("Failed to write to VictoriaMetrics")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		logrus.WithField("status", resp.StatusCode).Debug("VictoriaMetrics write returned non-2xx")
		return
	}

	logrus.WithField("lines", len(lines)).Debug("Wrote metrics to VictoriaMetrics")
}
