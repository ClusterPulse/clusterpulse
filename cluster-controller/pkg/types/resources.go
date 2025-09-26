package types

import "time"

// ResourceCollection holds lightweight resource data for RBAC filtering
// Designed to be memory-efficient and fast to serialize
type ResourceCollection struct {
    Timestamp   time.Time              `json:"timestamp"`
    Pods        []PodSummary          `json:"pods,omitempty"`
    Deployments []DeploymentSummary   `json:"deployments,omitempty"`
    Services    []ServiceSummary      `json:"services,omitempty"`
    StatefulSets []StatefulSetSummary `json:"statefulsets,omitempty"`
    DaemonSets  []DaemonSetSummary    `json:"daemonsets,omitempty"`
    
    // Metadata for performance monitoring
    CollectionTimeMs int64 `json:"collection_time_ms"`
    Truncated       bool   `json:"truncated"`
    TotalResources  int    `json:"total_resources"`
}

// PodSummary - minimal pod info for RBAC filtering
type PodSummary struct {
    Name      string            `json:"name"`
    Namespace string            `json:"namespace"`
    Status    string            `json:"status"`
    Node      string            `json:"node,omitempty"`
    Labels    map[string]string `json:"labels,omitempty"` // Only if needed by policy
}

// DeploymentSummary - minimal deployment info
type DeploymentSummary struct {
    Name      string            `json:"name"`
    Namespace string            `json:"namespace"`
    Replicas  int32            `json:"replicas"`
    Ready     int32            `json:"ready"`
    Labels    map[string]string `json:"labels,omitempty"`
}

// ServiceSummary - minimal service info
type ServiceSummary struct {
    Name      string            `json:"name"`
    Namespace string            `json:"namespace"`
    Type      string            `json:"type"`
    ClusterIP string            `json:"cluster_ip,omitempty"`
    Labels    map[string]string `json:"labels,omitempty"`
}

// StatefulSetSummary - minimal statefulset info
type StatefulSetSummary struct {
    Name      string            `json:"name"`
    Namespace string            `json:"namespace"`
    Replicas  int32            `json:"replicas"`
    Ready     int32            `json:"ready"`
    Labels    map[string]string `json:"labels,omitempty"`
}

// DaemonSetSummary - minimal daemonset info
type DaemonSetSummary struct {
    Name           string            `json:"name"`
    Namespace      string            `json:"namespace"`
    DesiredNumber  int32            `json:"desired"`
    CurrentNumber  int32            `json:"current"`
    ReadyNumber    int32            `json:"ready"`
    Labels         map[string]string `json:"labels,omitempty"`
}

// CollectionConfig controls resource collection behavior
type CollectionConfig struct {
    Enabled          bool   `json:"enabled"`
    MaxPodsPerNS     int    `json:"max_pods_per_ns"`      // Limit pods per namespace
    MaxTotalPods     int    `json:"max_total_pods"`       // Global pod limit
    MaxDeployments   int    `json:"max_deployments"`      
    MaxServices      int    `json:"max_services"`
    IncludeLabels    bool   `json:"include_labels"`       // Whether to collect labels
    NamespaceFilter  string `json:"namespace_filter"`     // Regex to filter namespaces
}
