package types

import (
	"time"
)

// ClusterHealth represents the health status of a cluster
type ClusterHealth string

const (
	HealthHealthy   ClusterHealth = "healthy"
	HealthDegraded  ClusterHealth = "degraded"
	HealthUnhealthy ClusterHealth = "unhealthy"
	HealthUnknown   ClusterHealth = "unknown"
)

// NodeStatus represents the status of a node
type NodeStatus string

const (
	NodeReady              NodeStatus = "Ready"
	NodeNotReady           NodeStatus = "NotReady"
	NodeUnknown            NodeStatus = "Unknown"
	NodeSchedulingDisabled NodeStatus = "SchedulingDisabled"
)

// NodeCondition represents a node condition
type NodeCondition struct {
	Type               string    `json:"type"`
	Status             string    `json:"status"`
	Reason             string    `json:"reason"`
	Message            string    `json:"message"`
	LastTransitionTime time.Time `json:"lastTransitionTime"`
}

// NodeMetrics contains detailed metrics for a node
type NodeMetrics struct {
	Name       string          `json:"name"`
	Timestamp  time.Time       `json:"timestamp"`
	Status     string          `json:"status"`
	Roles      []string        `json:"roles"`
	Conditions []NodeCondition `json:"conditions"`

	// Resource capacity
	CPUCapacity     float64 `json:"cpuCapacity"`
	MemoryCapacity  int64   `json:"memoryCapacity"`
	StorageCapacity int64   `json:"storageCapacity"`
	PodsCapacity    int32   `json:"podsCapacity"`

	// Resource allocatable
	CPUAllocatable     float64 `json:"cpuAllocatable"`
	MemoryAllocatable  int64   `json:"memoryAllocatable"`
	StorageAllocatable int64   `json:"storageAllocatable"`
	PodsAllocatable    int32   `json:"podsAllocatable"`

	// Resource usage
	CPURequested       float64 `json:"cpuRequested"`
	MemoryRequested    int64   `json:"memoryRequested"`
	CPUUsagePercent    float64 `json:"cpuUsagePercent"`
	MemoryUsagePercent float64 `json:"memoryUsagePercent"`

	// Pod metrics
	PodsRunning   int32 `json:"podsRunning"`
	PodsPending   int32 `json:"podsPending"`
	PodsFailed    int32 `json:"podsFailed"`
	PodsSucceeded int32 `json:"podsSucceeded"`
	PodsTotal     int32 `json:"podsTotal"`

	// System info
	KernelVersion    string `json:"kernelVersion"`
	OSImage          string `json:"osImage"`
	ContainerRuntime string `json:"containerRuntime"`
	KubeletVersion   string `json:"kubeletVersion"`
	Architecture     string `json:"architecture"`

	// Labels and annotations
	Labels      map[string]string   `json:"labels"`
	Annotations map[string]string   `json:"annotations"`
	Taints      []map[string]string `json:"taints"`

	// Network info
	InternalIP string `json:"internalIP"`
	ExternalIP string `json:"externalIP"`
	Hostname   string `json:"hostname"`

	// Additional metrics
	ImagesCount     int `json:"imagesCount"`
	VolumesAttached int `json:"volumesAttached"`
}

// ClusterMetrics contains cluster-wide metrics
type ClusterMetrics struct {
	Timestamp     time.Time `json:"timestamp"`
	Nodes         int       `json:"nodes"`
	NodesReady    int       `json:"nodesReady"`
	Namespaces    int       `json:"namespaces"`
	NamespaceList []string  `json:"namespace_list"`
	Pods          int       `json:"pods"`
	PodsRunning   int       `json:"podsRunning"`
	CPUCapacity   float64   `json:"cpuCapacity"`
	MemoryCapacity int64   `json:"memoryCapacity"`
	Deployments   int       `json:"deployments"`
}

// OperatorInfo contains information about an installed operator
type OperatorInfo struct {
	Name                  string            `json:"name"`
	DisplayName           string            `json:"displayName"`
	Version               string            `json:"version"`
	Status                string            `json:"status"`
	InstalledNamespace    string            `json:"installedNamespace"`
	InstallModes          []string          `json:"installModes"`
	InstallMode           string            `json:"installMode"`
	Provider              string            `json:"provider"`
	CreatedAt             time.Time         `json:"createdAt"`
	UpdatedAt             time.Time         `json:"updatedAt"`
	IsClusterWide         bool              `json:"isClusterWide"`
	AvailableInNamespaces []string          `json:"availableInNamespaces"`
	AvailableCount        int               `json:"availableCount"`
	Subscription          map[string]string `json:"subscription,omitempty"`
}

// ClusterOperatorInfo contains information about an OpenShift ClusterOperator
type ClusterOperatorInfo struct {
	Name               string                     `json:"name"`
	Version            string                     `json:"version"`
	Available          bool                       `json:"available"`
	Progressing        bool                       `json:"progressing"`
	Degraded           bool                       `json:"degraded"`
	Upgradeable        bool                       `json:"upgradeable"`
	Message            string                     `json:"message,omitempty"`
	Reason             string                     `json:"reason,omitempty"`
	LastTransitionTime time.Time                  `json:"last_transition_time"`
	Conditions         []ClusterOperatorCondition `json:"conditions"`
	Versions           []ClusterOperatorVersion   `json:"versions,omitempty"`
	RelatedObjects     []RelatedObject            `json:"related_objects,omitempty"`
}

// ClusterOperatorCondition represents a condition of a ClusterOperator
type ClusterOperatorCondition struct {
	Type               string    `json:"type"`
	Status             string    `json:"status"`
	LastTransitionTime time.Time `json:"last_transition_time"`
	Reason             string    `json:"reason,omitempty"`
	Message            string    `json:"message,omitempty"`
}

// ClusterOperatorVersion represents version information for a ClusterOperator
type ClusterOperatorVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// RelatedObject represents objects related to a ClusterOperator
type RelatedObject struct {
	Group     string `json:"group"`
	Resource  string `json:"resource"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}
