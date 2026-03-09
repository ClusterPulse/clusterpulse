package cluster

import (
	"slices"
	"testing"
	"time"

	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/clusterpulse/cluster-controller/pkg/utils"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestDeriveConsoleURL(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{
			"standard openshift https",
			"https://api.cluster.example.com:6443",
			"https://console-openshift-console.apps.cluster.example.com",
		},
		{
			"standard openshift http",
			"http://api.cluster.example.com:6443",
			"https://console-openshift-console.apps.cluster.example.com",
		},
		{
			"no port",
			"https://api.cluster.example.com",
			"https://console-openshift-console.apps.cluster.example.com",
		},
		{
			"non-api prefix returns raw endpoint",
			"https://k8s.example.com:6443",
			"https://k8s.example.com:6443",
		},
		{
			"no protocol",
			"api.cluster.example.com:6443",
			"https://console-openshift-console.apps.cluster.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ClusterClient{Endpoint: tt.endpoint}
			got := c.deriveConsoleURL()
			if got != tt.want {
				t.Errorf("deriveConsoleURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetStringValue(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]any
		key  string
		want string
	}{
		{"key present", map[string]any{"a": "hello"}, "a", "hello"},
		{"key missing", map[string]any{"a": "hello"}, "b", ""},
		{"non-string value", map[string]any{"a": 42}, "a", ""},
		{"nil map value", map[string]any{"a": nil}, "a", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getStringValue(tt.m, tt.key)
			if got != tt.want {
				t.Errorf("getStringValue() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractNodeMetrics(t *testing.T) {
	client := &ClusterClient{Name: "test-cluster"}

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "worker-1",
			Labels: map[string]string{
				"node-role.kubernetes.io/worker":  "",
				"node-role.kubernetes.io/infra":   "",
				"kubernetes.io/hostname":          "worker-1",
			},
			Annotations: map[string]string{"note": "test"},
		},
		Spec: corev1.NodeSpec{
			Taints: []corev1.Taint{
				{Key: "dedicated", Value: "gpu", Effect: corev1.TaintEffectNoSchedule},
			},
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue, Reason: "KubeletReady", Message: "kubelet is ready"},
				{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionFalse},
			},
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:              resource.MustParse("16"),
				corev1.ResourceMemory:           resource.MustParse("64Gi"),
				corev1.ResourceEphemeralStorage: resource.MustParse("200Gi"),
				corev1.ResourcePods:             resource.MustParse("250"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:              resource.MustParse("15500m"),
				corev1.ResourceMemory:           resource.MustParse("62Gi"),
				corev1.ResourceEphemeralStorage: resource.MustParse("190Gi"),
				corev1.ResourcePods:             resource.MustParse("250"),
			},
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.1.5"},
				{Type: corev1.NodeExternalIP, Address: "203.0.113.5"},
				{Type: corev1.NodeHostName, Address: "worker-1.local"},
			},
			NodeInfo: corev1.NodeSystemInfo{
				KernelVersion:           "5.14.0-284",
				OSImage:                 "RHCOS 4.14",
				ContainerRuntimeVersion: "cri-o://1.27.1",
				KubeletVersion:          "v1.27.6",
				Architecture:            "amd64",
			},
			Images:          make([]corev1.ContainerImage, 5),
			VolumesAttached: make([]corev1.AttachedVolume, 3),
		},
	}

	pods := []corev1.Pod{
		{
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("1"),
							corev1.ResourceMemory: resource.MustParse("1Gi"),
						},
					}},
					{Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("500m"),
							corev1.ResourceMemory: resource.MustParse("512Mi"),
						},
					}},
				},
			},
		},
		{
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("250m"),
							corev1.ResourceMemory: resource.MustParse("256Mi"),
						},
					}},
				},
			},
		},
		{Status: corev1.PodStatus{Phase: corev1.PodPending}},
		{Status: corev1.PodStatus{Phase: corev1.PodFailed}},
		{Status: corev1.PodStatus{Phase: corev1.PodSucceeded}},
	}

	m := client.extractNodeMetrics(node, pods)

	// Identity
	if m.Name != "worker-1" {
		t.Errorf("Name = %q, want worker-1", m.Name)
	}
	if m.Status != string(types.NodeReady) {
		t.Errorf("Status = %q, want Ready", m.Status)
	}

	// Roles
	roleSet := map[string]bool{}
	for _, r := range m.Roles {
		roleSet[r] = true
	}
	if !roleSet["worker"] || !roleSet["infra"] {
		t.Errorf("Roles = %v, want worker and infra", m.Roles)
	}
	if len(m.Roles) != 2 {
		t.Errorf("Roles count = %d, want 2", len(m.Roles))
	}

	// Conditions
	if len(m.Conditions) != 2 {
		t.Fatalf("Conditions count = %d, want 2", len(m.Conditions))
	}

	// Resources
	if m.CPUCapacity != 16 {
		t.Errorf("CPUCapacity = %v, want 16", m.CPUCapacity)
	}
	if m.PodsCapacity != 250 {
		t.Errorf("PodsCapacity = %d, want 250", m.PodsCapacity)
	}
	if m.PodsAllocatable != 250 {
		t.Errorf("PodsAllocatable = %d, want 250", m.PodsAllocatable)
	}

	// Pod counts
	if m.PodsRunning != 2 {
		t.Errorf("PodsRunning = %d, want 2", m.PodsRunning)
	}
	if m.PodsPending != 1 {
		t.Errorf("PodsPending = %d, want 1", m.PodsPending)
	}
	if m.PodsFailed != 1 {
		t.Errorf("PodsFailed = %d, want 1", m.PodsFailed)
	}
	if m.PodsSucceeded != 1 {
		t.Errorf("PodsSucceeded = %d, want 1", m.PodsSucceeded)
	}
	if m.PodsTotal != 5 {
		t.Errorf("PodsTotal = %d, want 5", m.PodsTotal)
	}

	// CPU usage (1 + 0.5 + 0.25 = 1.75 cores requested from 15.5 allocatable)
	if m.CPUUsagePercent <= 0 {
		t.Error("CPUUsagePercent should be > 0")
	}

	// System info
	if m.KernelVersion != "5.14.0-284" {
		t.Errorf("KernelVersion = %q", m.KernelVersion)
	}
	if m.Architecture != "amd64" {
		t.Errorf("Architecture = %q", m.Architecture)
	}
	if m.KubeletVersion != "v1.27.6" {
		t.Errorf("KubeletVersion = %q", m.KubeletVersion)
	}
	if m.OSImage != "RHCOS 4.14" {
		t.Errorf("OSImage = %q", m.OSImage)
	}
	if m.ContainerRuntime != "cri-o://1.27.1" {
		t.Errorf("ContainerRuntime = %q", m.ContainerRuntime)
	}

	// Network
	if m.InternalIP != "10.0.1.5" {
		t.Errorf("InternalIP = %q", m.InternalIP)
	}
	if m.ExternalIP != "203.0.113.5" {
		t.Errorf("ExternalIP = %q", m.ExternalIP)
	}
	if m.Hostname != "worker-1.local" {
		t.Errorf("Hostname = %q", m.Hostname)
	}

	// Taints
	if len(m.Taints) != 1 {
		t.Fatalf("Taints count = %d, want 1", len(m.Taints))
	}
	if m.Taints[0]["key"] != "dedicated" || m.Taints[0]["effect"] != "NoSchedule" {
		t.Errorf("Taint = %v", m.Taints[0])
	}

	// Additional
	if m.ImagesCount != 5 {
		t.Errorf("ImagesCount = %d, want 5", m.ImagesCount)
	}
	if m.VolumesAttached != 3 {
		t.Errorf("VolumesAttached = %d, want 3", m.VolumesAttached)
	}

	// Labels and annotations preserved
	if m.Labels["kubernetes.io/hostname"] != "worker-1" {
		t.Errorf("Labels missing expected key")
	}
	if m.Annotations["note"] != "test" {
		t.Errorf("Annotations missing expected key")
	}
}

func TestExtractNodeMetrics_Unschedulable(t *testing.T) {
	client := &ClusterClient{Name: "test"}
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-maint"},
		Spec:       corev1.NodeSpec{Unschedulable: true},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
			},
			Capacity:    corev1.ResourceList{},
			Allocatable: corev1.ResourceList{},
		},
	}

	m := client.extractNodeMetrics(node, nil)
	if m.Status != string(types.NodeSchedulingDisabled) {
		t.Errorf("Status = %q, want SchedulingDisabled", m.Status)
	}
}

func TestExtractNodeMetrics_NotReady(t *testing.T) {
	client := &ClusterClient{Name: "test"}
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-sick"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionFalse},
			},
			Capacity:    corev1.ResourceList{},
			Allocatable: corev1.ResourceList{},
		},
	}

	m := client.extractNodeMetrics(node, nil)
	if m.Status != string(types.NodeNotReady) {
		t.Errorf("Status = %q, want NotReady", m.Status)
	}
}

func TestExtractNodeMetrics_NoPods(t *testing.T) {
	client := &ClusterClient{Name: "test"}
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "empty-node"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
			},
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("8Gi"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("8Gi"),
			},
		},
	}

	m := client.extractNodeMetrics(node, nil)
	if m.PodsTotal != 0 {
		t.Errorf("PodsTotal = %d, want 0", m.PodsTotal)
	}
	if m.CPUUsagePercent != 0 {
		t.Errorf("CPUUsagePercent = %v, want 0", m.CPUUsagePercent)
	}
	if m.MemoryUsagePercent != 0 {
		t.Errorf("MemoryUsagePercent = %v, want 0", m.MemoryUsagePercent)
	}
}

func TestExtractClusterOperatorInfo(t *testing.T) {
	client := &ClusterClient{Name: "test"}
	now := time.Now().UTC().Format(time.RFC3339)

	co := &unstructured.Unstructured{
		Object: map[string]any{
			"metadata": map[string]any{"name": "authentication"},
			"status": map[string]any{
				"conditions": []any{
					map[string]any{
						"type":               "Available",
						"status":             "True",
						"reason":             "AsExpected",
						"message":            "All is well",
						"lastTransitionTime": now,
					},
					map[string]any{
						"type":    "Degraded",
						"status":  "False",
						"reason":  "",
						"message": "",
					},
					map[string]any{
						"type":   "Upgradeable",
						"status": "True",
					},
				},
				"versions": []any{
					map[string]any{"name": "operator", "version": "4.14.5"},
					map[string]any{"name": "oauth-apiserver", "version": "4.14.5"},
				},
				"relatedObjects": []any{
					map[string]any{
						"group":     "",
						"resource":  "namespaces",
						"namespace": "",
						"name":      "openshift-authentication",
					},
				},
			},
		},
	}

	op := client.extractClusterOperatorInfo(co)
	if op == nil {
		t.Fatal("expected non-nil operator")
	}
	if op.Name != "authentication" {
		t.Errorf("Name = %q", op.Name)
	}
	if !op.Available {
		t.Error("expected Available = true")
	}
	if op.Degraded {
		t.Error("expected Degraded = false")
	}
	if !op.Upgradeable {
		t.Error("expected Upgradeable = true")
	}
	if op.Version != "4.14.5" {
		t.Errorf("Version = %q, want 4.14.5", op.Version)
	}
	if len(op.Versions) != 2 {
		t.Errorf("Versions count = %d, want 2", len(op.Versions))
	}
	if len(op.RelatedObjects) != 1 {
		t.Errorf("RelatedObjects count = %d, want 1", len(op.RelatedObjects))
	}
	if op.RelatedObjects[0].Name != "openshift-authentication" {
		t.Errorf("RelatedObject name = %q", op.RelatedObjects[0].Name)
	}
}

func TestExtractClusterOperatorInfo_Degraded(t *testing.T) {
	client := &ClusterClient{Name: "test"}

	co := &unstructured.Unstructured{
		Object: map[string]any{
			"metadata": map[string]any{"name": "dns"},
			"status": map[string]any{
				"conditions": []any{
					map[string]any{
						"type":    "Available",
						"status":  "False",
						"message": "not available",
						"reason":  "DNSDown",
					},
					map[string]any{
						"type":    "Degraded",
						"status":  "True",
						"message": "DNS is degraded",
						"reason":  "DNSError",
					},
				},
				"versions": []any{
					map[string]any{"name": "dns", "version": "4.14.3"},
				},
			},
		},
	}

	op := client.extractClusterOperatorInfo(co)
	if !op.Degraded {
		t.Error("expected Degraded = true")
	}
	if op.Available {
		t.Error("expected Available = false")
	}
	// Degraded message takes priority
	if op.Message != "DNS is degraded" {
		t.Errorf("Message = %q, want 'DNS is degraded'", op.Message)
	}
	if op.Reason != "DNSError" {
		t.Errorf("Reason = %q, want DNSError", op.Reason)
	}
	// Version fallback: first version when no "operator" name match
	if op.Version != "4.14.3" {
		t.Errorf("Version = %q, want 4.14.3 (fallback to first)", op.Version)
	}
}

func TestExtractClusterOperatorInfo_NoStatus(t *testing.T) {
	client := &ClusterClient{Name: "test"}

	co := &unstructured.Unstructured{
		Object: map[string]any{
			"metadata": map[string]any{"name": "bare"},
		},
	}

	op := client.extractClusterOperatorInfo(co)
	if op == nil {
		t.Fatal("expected non-nil operator even without status")
	}
	if op.Name != "bare" {
		t.Errorf("Name = %q", op.Name)
	}
	if op.Version != "" {
		t.Errorf("Version = %q, want empty", op.Version)
	}
}

func TestExtractOperatorInfo(t *testing.T) {
	client := &ClusterClient{Name: "test"}

	csv := &unstructured.Unstructured{
		Object: map[string]any{
			"metadata": map[string]any{
				"name":              "my-operator.v1.2.3",
				"namespace":        "openshift-operators",
				"creationTimestamp": "2025-01-01T00:00:00Z",
			},
			"spec": map[string]any{
				"displayName": "My Operator",
				"version":     "1.2.3",
				"provider":    map[string]any{"name": "Acme Corp"},
				"installModes": []any{
					map[string]any{"type": "OwnNamespace", "supported": true},
					map[string]any{"type": "SingleNamespace", "supported": true},
					map[string]any{"type": "MultiNamespace", "supported": false},
					map[string]any{"type": "AllNamespaces", "supported": true},
				},
			},
			"status": map[string]any{
				"phase":          "Succeeded",
				"lastUpdateTime": "2025-01-02T12:00:00Z",
			},
		},
	}

	sub := &unstructured.Unstructured{
		Object: map[string]any{
			"spec": map[string]any{
				"installPlanApproval": "Automatic",
			},
		},
	}

	op := client.extractOperatorInfo(csv, sub)
	if op == nil {
		t.Fatal("expected non-nil operator")
	}
	if op.DisplayName != "My Operator" {
		t.Errorf("DisplayName = %q", op.DisplayName)
	}
	if op.Version != "1.2.3" {
		t.Errorf("Version = %q", op.Version)
	}
	if op.Provider != "Acme Corp" {
		t.Errorf("Provider = %q", op.Provider)
	}
	if op.Status != "Succeeded" {
		t.Errorf("Status = %q", op.Status)
	}
	if !op.IsClusterWide {
		t.Error("expected IsClusterWide = true (AllNamespaces supported)")
	}
	if op.InstallMode != "AllNamespaces" {
		t.Errorf("InstallMode = %q, want AllNamespaces", op.InstallMode)
	}
	if len(op.AvailableInNamespaces) != 1 || op.AvailableInNamespaces[0] != "*" {
		t.Errorf("AvailableInNamespaces = %v, want [*]", op.AvailableInNamespaces)
	}
	if op.Subscription["installPlanApproval"] != "Automatic" {
		t.Errorf("Subscription = %v", op.Subscription)
	}
}

func TestExtractOperatorInfo_SingleNamespace(t *testing.T) {
	client := &ClusterClient{Name: "test"}

	csv := &unstructured.Unstructured{
		Object: map[string]any{
			"metadata": map[string]any{
				"name":              "local-op.v1.0.0",
				"namespace":        "my-project",
				"creationTimestamp": "2025-01-01T00:00:00Z",
				"annotations": map[string]any{
					"olm.targetNamespaces": "my-project,other-ns",
				},
			},
			"spec": map[string]any{
				"version": "1.0.0",
				"installModes": []any{
					map[string]any{"type": "OwnNamespace", "supported": true},
					map[string]any{"type": "SingleNamespace", "supported": true},
				},
			},
			"status": map[string]any{
				"phase": "Succeeded",
			},
		},
	}

	sub := &unstructured.Unstructured{Object: map[string]any{}}

	op := client.extractOperatorInfo(csv, sub)
	if op == nil {
		t.Fatal("expected non-nil operator")
	}
	if op.IsClusterWide {
		t.Error("expected IsClusterWide = false")
	}
	if op.InstallMode != "SingleNamespace" {
		t.Errorf("InstallMode = %q, want SingleNamespace", op.InstallMode)
	}
	// Should use olm.targetNamespaces annotation
	if len(op.AvailableInNamespaces) != 2 {
		t.Errorf("AvailableInNamespaces = %v, want [my-project, other-ns]", op.AvailableInNamespaces)
	}
	// Display name falls back to CSV name when not set
	if op.DisplayName != "local-op.v1.0.0" {
		t.Errorf("DisplayName = %q, want 'local-op.v1.0.0'", op.DisplayName)
	}
}

func TestExtractOperatorInfo_NoSpec(t *testing.T) {
	client := &ClusterClient{Name: "test"}

	csv := &unstructured.Unstructured{
		Object: map[string]any{
			"metadata": map[string]any{
				"name":              "broken.v0.0.1",
				"namespace":        "ns",
				"creationTimestamp": "2025-01-01T00:00:00Z",
			},
		},
	}
	sub := &unstructured.Unstructured{Object: map[string]any{}}

	op := client.extractOperatorInfo(csv, sub)
	if op != nil {
		t.Error("expected nil when spec is missing")
	}
}

func TestGetLastUsed(t *testing.T) {
	client := &ClusterClient{lastUsed: time.Now()}
	before := client.GetLastUsed()
	client.updateLastUsed()
	after := client.GetLastUsed()
	if !after.After(before) && after != before {
		t.Error("expected lastUsed to be updated")
	}
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func newFakeClusterClient(t *testing.T, objs ...runtime.Object) *ClusterClient {
	t.Helper()
	return &ClusterClient{
		Name:           "test-cluster",
		clientset:      k8sfake.NewSimpleClientset(objs...),
		circuitBreaker: utils.NewCircuitBreaker(5, 60*time.Second),
		lastUsed:       time.Now(),
	}
}

func int32Ptr(v int32) *int32 { return &v }

// ---------------------------------------------------------------------------
// GetNodeMetrics
// ---------------------------------------------------------------------------

func TestGetNodeMetrics(t *testing.T) {
	node1 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Status: corev1.NodeStatus{
			Conditions:  []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			Capacity:    corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4")},
			Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4")},
		},
	}
	node2 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-2"},
		Status: corev1.NodeStatus{
			Conditions:  []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			Capacity:    corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("8")},
			Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("8")},
		},
	}
	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	pod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	pod3 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-3", Namespace: "kube-system"},
		Spec:       corev1.PodSpec{NodeName: "node-2"},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}

	c := newFakeClusterClient(t, node1, node2, pod1, pod2, pod3)
	metrics, err := c.GetNodeMetrics(t.Context())
	if err != nil {
		t.Fatalf("GetNodeMetrics() error = %v", err)
	}
	if len(metrics) != 2 {
		t.Fatalf("got %d NodeMetrics, want 2", len(metrics))
	}

	// Build a lookup by name for stable assertions
	byName := map[string]types.NodeMetrics{}
	for _, m := range metrics {
		byName[m.Name] = m
	}

	// node-1 should have 2 pods
	if n1 := byName["node-1"]; n1.PodsTotal != 2 {
		t.Errorf("node-1 PodsTotal = %d, want 2", n1.PodsTotal)
	}
	// node-2 should have 1 pod
	if n2 := byName["node-2"]; n2.PodsTotal != 1 {
		t.Errorf("node-2 PodsTotal = %d, want 1", n2.PodsTotal)
	}
}

func TestGetNodeMetrics_Empty(t *testing.T) {
	c := newFakeClusterClient(t)
	metrics, err := c.GetNodeMetrics(t.Context())
	if err != nil {
		t.Fatalf("GetNodeMetrics() error = %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("got %d NodeMetrics, want 0", len(metrics))
	}
}

// ---------------------------------------------------------------------------
// GetClusterMetrics
// ---------------------------------------------------------------------------

func TestGetClusterMetrics(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Status: corev1.NodeStatus{
			Conditions:  []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			Capacity:    corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("8"), corev1.ResourceMemory: resource.MustParse("32Gi")},
			Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("8"), corev1.ResourceMemory: resource.MustParse("32Gi")},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	ns1 := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	ns2 := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}}
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec:       appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
	}

	c := newFakeClusterClient(t, node, pod, ns1, ns2, dep)
	m, err := c.GetClusterMetrics(t.Context())
	if err != nil {
		t.Fatalf("GetClusterMetrics() error = %v", err)
	}
	if m.Nodes != 1 {
		t.Errorf("Nodes = %d, want 1", m.Nodes)
	}
	if m.NodesReady != 1 {
		t.Errorf("NodesReady = %d, want 1", m.NodesReady)
	}
	if m.Namespaces != 2 {
		t.Errorf("Namespaces = %d, want 2", m.Namespaces)
	}
	if m.Deployments != 1 {
		t.Errorf("Deployments = %d, want 1", m.Deployments)
	}
	if m.Pods != 1 {
		t.Errorf("Pods = %d, want 1", m.Pods)
	}
	if m.PodsRunning != 1 {
		t.Errorf("PodsRunning = %d, want 1", m.PodsRunning)
	}
	if m.CPUCapacity != 8 {
		t.Errorf("CPUCapacity = %v, want 8", m.CPUCapacity)
	}
}

// ---------------------------------------------------------------------------
// GetNamespaces
// ---------------------------------------------------------------------------

func TestGetNamespaces(t *testing.T) {
	ns1 := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "alpha"}}
	ns2 := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "bravo"}}
	ns3 := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "charlie"}}

	c := newFakeClusterClient(t, ns1, ns2, ns3)
	got, err := c.GetNamespaces(t.Context())
	if err != nil {
		t.Fatalf("GetNamespaces() error = %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d namespaces, want 3", len(got))
	}
	slices.Sort(got)
	want := []string{"alpha", "bravo", "charlie"}
	if !slices.Equal(got, want) {
		t.Errorf("namespaces = %v, want %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// TestConnection
// ---------------------------------------------------------------------------

func TestTestConnection(t *testing.T) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	c := newFakeClusterClient(t, ns)
	if err := c.TestConnection(t.Context()); err != nil {
		t.Fatalf("TestConnection() error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// collectDeployments
// ---------------------------------------------------------------------------

func TestCollectDeployments(t *testing.T) {
	dep1 := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default", Labels: map[string]string{"app": "api"}},
		Spec:       appsv1.DeploymentSpec{Replicas: int32Ptr(3)},
		Status:     appsv1.DeploymentStatus{ReadyReplicas: 2},
	}
	dep2 := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "jobs"},
		Spec:       appsv1.DeploymentSpec{Replicas: int32Ptr(1)},
		Status:     appsv1.DeploymentStatus{ReadyReplicas: 1},
	}

	c := newFakeClusterClient(t, dep1, dep2)
	cfg := types.CollectionConfig{Enabled: true, MaxDeployments: 10, IncludeLabels: true}
	deps, truncated := c.collectDeployments(t.Context(), cfg)
	if truncated {
		t.Error("expected truncated = false")
	}
	if len(deps) != 2 {
		t.Fatalf("got %d deployments, want 2", len(deps))
	}

	// Find api deployment
	idx := slices.IndexFunc(deps, func(d types.DeploymentSummary) bool { return d.Name == "api" })
	if idx < 0 {
		t.Fatal("deployment 'api' not found")
	}
	if deps[idx].Replicas != 3 {
		t.Errorf("api Replicas = %d, want 3", deps[idx].Replicas)
	}
	if deps[idx].Ready != 2 {
		t.Errorf("api Ready = %d, want 2", deps[idx].Ready)
	}
	if deps[idx].Labels["app"] != "api" {
		t.Errorf("api Labels = %v, want app=api", deps[idx].Labels)
	}
}

// ---------------------------------------------------------------------------
// collectServices
// ---------------------------------------------------------------------------

func TestCollectServices(t *testing.T) {
	svc1 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "frontend", Namespace: "web"},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: "10.0.0.1"},
	}
	svc2 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "lb", Namespace: "web"},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, ClusterIP: "10.0.0.2"},
	}

	c := newFakeClusterClient(t, svc1, svc2)
	cfg := types.CollectionConfig{Enabled: true, MaxServices: 10}
	svcs, truncated := c.collectServices(t.Context(), cfg)
	if truncated {
		t.Error("expected truncated = false")
	}
	if len(svcs) != 2 {
		t.Fatalf("got %d services, want 2", len(svcs))
	}

	idx := slices.IndexFunc(svcs, func(s types.ServiceSummary) bool { return s.Name == "frontend" })
	if idx < 0 {
		t.Fatal("service 'frontend' not found")
	}
	if svcs[idx].Type != string(corev1.ServiceTypeClusterIP) {
		t.Errorf("frontend Type = %q, want ClusterIP", svcs[idx].Type)
	}
	if svcs[idx].ClusterIP != "10.0.0.1" {
		t.Errorf("frontend ClusterIP = %q, want 10.0.0.1", svcs[idx].ClusterIP)
	}
}

// ---------------------------------------------------------------------------
// collectStatefulSets
// ---------------------------------------------------------------------------

func TestCollectStatefulSets(t *testing.T) {
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "redis", Namespace: "cache"},
		Spec:       appsv1.StatefulSetSpec{Replicas: int32Ptr(3)},
		Status:     appsv1.StatefulSetStatus{ReadyReplicas: 3},
	}

	c := newFakeClusterClient(t, sts)
	cfg := types.CollectionConfig{Enabled: true, MaxDeployments: 10}
	sets, truncated := c.collectStatefulSets(t.Context(), cfg)
	if truncated {
		t.Error("expected truncated = false")
	}
	if len(sets) != 1 {
		t.Fatalf("got %d statefulsets, want 1", len(sets))
	}
	if sets[0].Name != "redis" {
		t.Errorf("Name = %q, want redis", sets[0].Name)
	}
	if sets[0].Replicas != 3 {
		t.Errorf("Replicas = %d, want 3", sets[0].Replicas)
	}
	if sets[0].Ready != 3 {
		t.Errorf("Ready = %d, want 3", sets[0].Ready)
	}
}

// ---------------------------------------------------------------------------
// collectDaemonSets
// ---------------------------------------------------------------------------

func TestCollectDaemonSets(t *testing.T) {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "fluentd", Namespace: "logging"},
		Status: appsv1.DaemonSetStatus{
			DesiredNumberScheduled: 5,
			CurrentNumberScheduled: 5,
			NumberReady:            4,
		},
	}

	c := newFakeClusterClient(t, ds)
	cfg := types.CollectionConfig{Enabled: true}
	sets, truncated := c.collectDaemonSets(t.Context(), cfg)
	if truncated {
		t.Error("expected truncated = false")
	}
	if len(sets) != 1 {
		t.Fatalf("got %d daemonsets, want 1", len(sets))
	}
	if sets[0].Name != "fluentd" {
		t.Errorf("Name = %q, want fluentd", sets[0].Name)
	}
	if sets[0].DesiredNumber != 5 {
		t.Errorf("DesiredNumber = %d, want 5", sets[0].DesiredNumber)
	}
	if sets[0].ReadyNumber != 4 {
		t.Errorf("ReadyNumber = %d, want 4", sets[0].ReadyNumber)
	}
}

// ---------------------------------------------------------------------------
// GetResourceCollection
// ---------------------------------------------------------------------------

func TestGetResourceCollection(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "d1", Namespace: "default"},
		Spec:       appsv1.DeploymentSpec{Replicas: int32Ptr(1)},
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "default"},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: "10.0.0.1"},
	}
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "ss1", Namespace: "default"},
		Spec:       appsv1.StatefulSetSpec{Replicas: int32Ptr(1)},
	}
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "ds1", Namespace: "default"},
		Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 1, NumberReady: 1},
	}

	c := newFakeClusterClient(t, pod, dep, svc, sts, ds)
	cfg := types.CollectionConfig{
		Enabled:        true,
		MaxTotalPods:   100,
		MaxDeployments: 100,
		MaxServices:    100,
	}
	rc, err := c.GetResourceCollection(t.Context(), cfg)
	if err != nil {
		t.Fatalf("GetResourceCollection() error = %v", err)
	}
	if rc == nil {
		t.Fatal("expected non-nil ResourceCollection")
	}
	// Fake clientset ignores field selectors, so the pod is returned regardless
	if len(rc.Pods) != 1 {
		t.Errorf("Pods = %d, want 1", len(rc.Pods))
	}
	if len(rc.Deployments) != 1 {
		t.Errorf("Deployments = %d, want 1", len(rc.Deployments))
	}
	if len(rc.Services) != 1 {
		t.Errorf("Services = %d, want 1", len(rc.Services))
	}
	if len(rc.StatefulSets) != 1 {
		t.Errorf("StatefulSets = %d, want 1", len(rc.StatefulSets))
	}
	if len(rc.DaemonSets) != 1 {
		t.Errorf("DaemonSets = %d, want 1", len(rc.DaemonSets))
	}
	if rc.TotalResources != 5 {
		t.Errorf("TotalResources = %d, want 5", rc.TotalResources)
	}
}

func TestGetResourceCollection_Disabled(t *testing.T) {
	c := newFakeClusterClient(t)
	cfg := types.CollectionConfig{Enabled: false}
	rc, err := c.GetResourceCollection(t.Context(), cfg)
	if err != nil {
		t.Fatalf("GetResourceCollection() error = %v", err)
	}
	if rc != nil {
		t.Errorf("expected nil ResourceCollection when disabled, got %+v", rc)
	}
}
