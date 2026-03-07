package collector

import (
	"encoding/json"
	"testing"

	"github.com/clusterpulse/cluster-controller/pkg/types"
	pb "github.com/clusterpulse/cluster-controller/proto/collectorpb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestToFloat64(t *testing.T) {
	tests := []struct {
		name string
		v    any
		want float64
		ok   bool
	}{
		{"float64", float64(3.14), 3.14, true},
		{"float32", float32(2.5), 2.5, true},
		{"int", int(42), 42, true},
		{"int64", int64(100), 100, true},
		{"int32", int32(50), 50, true},
		{"unsupported", "hello", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := toFloat64(tt.v)
			if ok != tt.ok {
				t.Errorf("ok = %v, want %v", ok, tt.ok)
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractNodeMetrics(t *testing.T) {
	agent := &Agent{config: &Config{}}
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
			Labels: map[string]string{
				"node-role.kubernetes.io/master": "",
				"node-role.kubernetes.io/worker": "",
				"other-label":                    "val",
			},
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
			},
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:              resource.MustParse("8"),
				corev1.ResourceMemory:           resource.MustParse("32Gi"),
				corev1.ResourceEphemeralStorage: resource.MustParse("100Gi"),
				corev1.ResourcePods:             resource.MustParse("110"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:              resource.MustParse("7"),
				corev1.ResourceMemory:           resource.MustParse("30Gi"),
				corev1.ResourceEphemeralStorage: resource.MustParse("90Gi"),
				corev1.ResourcePods:             resource.MustParse("110"),
			},
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				{Type: corev1.NodeHostName, Address: "node-1.local"},
			},
			NodeInfo: corev1.NodeSystemInfo{
				KernelVersion:           "5.14.0",
				OSImage:                 "RHEL 9",
				ContainerRuntimeVersion: "cri-o://1.28",
				KubeletVersion:          "v1.28.0",
				Architecture:            "amd64",
			},
		},
	}

	pods := []corev1.Pod{
		{
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("500m"),
							corev1.ResourceMemory: resource.MustParse("256Mi"),
						},
					}},
				},
			},
		},
		{Status: corev1.PodStatus{Phase: corev1.PodPending}},
		{Status: corev1.PodStatus{Phase: corev1.PodFailed}},
	}

	nm := agent.extractNodeMetrics(node, pods)

	if nm.Name != "node-1" {
		t.Errorf("Name = %q", nm.Name)
	}
	if nm.Status != "Ready" {
		t.Errorf("Status = %q, want Ready", nm.Status)
	}
	if len(nm.Roles) != 2 {
		t.Errorf("Roles count = %d, want 2", len(nm.Roles))
	}
	roleSet := map[string]bool{}
	for _, r := range nm.Roles {
		roleSet[r] = true
	}
	if !roleSet["master"] || !roleSet["worker"] {
		t.Errorf("Roles = %v, want master and worker", nm.Roles)
	}
	if nm.PodsRunning != 1 || nm.PodsPending != 1 || nm.PodsFailed != 1 {
		t.Errorf("Pod counts: running=%d pending=%d failed=%d", nm.PodsRunning, nm.PodsPending, nm.PodsFailed)
	}
	if nm.PodsTotal != 3 {
		t.Errorf("PodsTotal = %d, want 3", nm.PodsTotal)
	}
	if nm.InternalIp != "10.0.0.1" {
		t.Errorf("InternalIP = %q", nm.InternalIp)
	}
	if nm.Hostname != "node-1.local" {
		t.Errorf("Hostname = %q", nm.Hostname)
	}
	if nm.KubeletVersion != "v1.28.0" {
		t.Errorf("KubeletVersion = %q", nm.KubeletVersion)
	}
	if nm.CpuUsagePercent <= 0 {
		t.Error("CPU usage percent should be > 0 with running pods")
	}
}

func TestExtractNodeMetrics_Unschedulable(t *testing.T) {
	agent := &Agent{config: &Config{}}
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-2"},
		Spec:       corev1.NodeSpec{Unschedulable: true},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
			},
			Capacity:    corev1.ResourceList{},
			Allocatable: corev1.ResourceList{},
		},
	}

	nm := agent.extractNodeMetrics(node, nil)
	if nm.Status != "SchedulingDisabled" {
		t.Errorf("Status = %q, want SchedulingDisabled", nm.Status)
	}
}

func TestStrVal(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]any
		key  string
		want string
	}{
		{"present", map[string]any{"type": "Available"}, "type", "Available"},
		{"missing", map[string]any{"type": "Available"}, "status", ""},
		{"non-string", map[string]any{"count": 42}, "count", ""},
		{"nil value", map[string]any{"x": nil}, "x", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strVal(tt.m, tt.key)
			if got != tt.want {
				t.Errorf("strVal() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApplyConfig(t *testing.T) {
	agent := &Agent{config: &Config{CollectIntervalSeconds: 60}}

	src := types.CompiledMetricSource{
		Name:      "test-source",
		Namespace: "default",
		Fields: []types.CompiledField{
			{Name: "status", Path: ".status.phase", Index: 0},
			{Name: "replicas", Path: ".spec.replicas", Index: 1},
		},
	}
	srcJSON, _ := json.Marshal(src)

	update := &pb.ConfigUpdate{
		MetricSourcesJson:      [][]byte{srcJSON},
		DefaultIntervalSeconds: 30,
	}

	agent.applyConfig(update)

	if len(agent.sources) != 1 {
		t.Fatalf("sources count = %d, want 1", len(agent.sources))
	}
	if agent.sources[0].Name != "test-source" {
		t.Errorf("source name = %q", agent.sources[0].Name)
	}
	if agent.sources[0].FieldNameToIndex["status"] != 0 {
		t.Error("FieldNameToIndex not rebuilt")
	}
	if agent.sources[0].FieldNameToIndex["replicas"] != 1 {
		t.Error("FieldNameToIndex[replicas] wrong")
	}
	if agent.config.CollectIntervalSeconds != 30 {
		t.Errorf("interval = %d, want 30", agent.config.CollectIntervalSeconds)
	}
}

func TestApplyConfig_InvalidJSON(t *testing.T) {
	agent := &Agent{config: &Config{CollectIntervalSeconds: 60}}

	update := &pb.ConfigUpdate{
		MetricSourcesJson: [][]byte{[]byte("invalid json")},
	}

	agent.applyConfig(update)

	if len(agent.sources) != 0 {
		t.Errorf("sources count = %d, want 0 (invalid JSON skipped)", len(agent.sources))
	}
}

func TestApplyConfig_NoIntervalOverride(t *testing.T) {
	agent := &Agent{config: &Config{CollectIntervalSeconds: 60}}

	update := &pb.ConfigUpdate{
		DefaultIntervalSeconds: 0, // zero means don't override
	}

	agent.applyConfig(update)

	if agent.config.CollectIntervalSeconds != 60 {
		t.Errorf("interval = %d, want 60 (no override)", agent.config.CollectIntervalSeconds)
	}
}

func TestExtractOperatorProto(t *testing.T) {
	agent := &Agent{config: &Config{}}

	csv := &unstructured.Unstructured{
		Object: map[string]any{
			"metadata": map[string]any{
				"name":      "prometheus.v0.65.0",
				"namespace": "openshift-operators",
			},
			"spec": map[string]any{
				"displayName": "Prometheus Operator",
				"version":     "0.65.0",
				"provider":    map[string]any{"name": "CoreOS"},
				"installModes": []any{
					map[string]any{"type": "OwnNamespace", "supported": true},
					map[string]any{"type": "AllNamespaces", "supported": true},
				},
			},
			"status": map[string]any{
				"phase": "Succeeded",
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

	op := agent.extractOperatorProto(csv, sub)
	if op == nil {
		t.Fatal("expected non-nil operator")
	}
	if op.DisplayName != "Prometheus Operator" {
		t.Errorf("DisplayName = %q", op.DisplayName)
	}
	if op.Version != "0.65.0" {
		t.Errorf("Version = %q", op.Version)
	}
	if op.Provider != "CoreOS" {
		t.Errorf("Provider = %q", op.Provider)
	}
	if !op.IsClusterWide {
		t.Error("expected IsClusterWide = true")
	}
	if op.InstallMode != "AllNamespaces" {
		t.Errorf("InstallMode = %q", op.InstallMode)
	}
	if len(op.AvailableInNamespaces) != 1 || op.AvailableInNamespaces[0] != "*" {
		t.Errorf("AvailableInNamespaces = %v", op.AvailableInNamespaces)
	}
	if op.Status != "Succeeded" {
		t.Errorf("Status = %q", op.Status)
	}
	if op.Subscription["installPlanApproval"] != "Automatic" {
		t.Errorf("Subscription = %v", op.Subscription)
	}
}

func TestExtractOperatorProto_NoSpec(t *testing.T) {
	agent := &Agent{config: &Config{}}
	csv := &unstructured.Unstructured{
		Object: map[string]any{"metadata": map[string]any{"name": "broken"}},
	}
	sub := &unstructured.Unstructured{Object: map[string]any{}}
	if agent.extractOperatorProto(csv, sub) != nil {
		t.Error("expected nil when spec missing")
	}
}

func TestExtractClusterOperatorProto(t *testing.T) {
	agent := &Agent{config: &Config{}}

	co := &unstructured.Unstructured{
		Object: map[string]any{
			"metadata": map[string]any{"name": "kube-apiserver"},
			"status": map[string]any{
				"conditions": []any{
					map[string]any{"type": "Available", "status": "True", "message": "ok"},
					map[string]any{"type": "Degraded", "status": "False"},
					map[string]any{"type": "Upgradeable", "status": "True"},
				},
				"versions": []any{
					map[string]any{"name": "operator", "version": "4.14.5"},
					map[string]any{"name": "raw-internal", "version": "1.27.8"},
				},
				"relatedObjects": []any{
					map[string]any{"group": "", "resource": "namespaces", "name": "openshift-kube-apiserver"},
				},
			},
		},
	}

	info := agent.extractClusterOperatorProto(co)
	if info.Name != "kube-apiserver" {
		t.Errorf("Name = %q", info.Name)
	}
	if !info.Available {
		t.Error("expected Available = true")
	}
	if info.Degraded {
		t.Error("expected Degraded = false")
	}
	if !info.Upgradeable {
		t.Error("expected Upgradeable = true")
	}
	if info.Version != "4.14.5" {
		t.Errorf("Version = %q, want 4.14.5", info.Version)
	}
	if len(info.Conditions) != 3 {
		t.Errorf("Conditions count = %d", len(info.Conditions))
	}
	if len(info.Versions) != 2 {
		t.Errorf("Versions count = %d", len(info.Versions))
	}
	if len(info.RelatedObjects) != 1 {
		t.Errorf("RelatedObjects count = %d", len(info.RelatedObjects))
	}
}

func TestExtractClusterOperatorProto_Degraded(t *testing.T) {
	agent := &Agent{config: &Config{}}

	co := &unstructured.Unstructured{
		Object: map[string]any{
			"metadata": map[string]any{"name": "dns"},
			"status": map[string]any{
				"conditions": []any{
					map[string]any{"type": "Available", "status": "False", "message": "unavail", "reason": "Down"},
					map[string]any{"type": "Degraded", "status": "True", "message": "DNS broken", "reason": "Error"},
				},
				"versions": []any{
					map[string]any{"name": "dns", "version": "4.14.0"},
				},
			},
		},
	}

	info := agent.extractClusterOperatorProto(co)
	if !info.Degraded {
		t.Error("expected Degraded = true")
	}
	// Degraded message takes priority
	if info.Message != "DNS broken" {
		t.Errorf("Message = %q, want 'DNS broken'", info.Message)
	}
	if info.Reason != "Error" {
		t.Errorf("Reason = %q", info.Reason)
	}
	// Version fallback to first
	if info.Version != "4.14.0" {
		t.Errorf("Version = %q, want 4.14.0", info.Version)
	}
}

func TestExtractClusterOperatorProto_NoStatus(t *testing.T) {
	agent := &Agent{config: &Config{}}
	co := &unstructured.Unstructured{
		Object: map[string]any{"metadata": map[string]any{"name": "bare"}},
	}
	info := agent.extractClusterOperatorProto(co)
	if info.Name != "bare" {
		t.Errorf("Name = %q", info.Name)
	}
	if info.Version != "" {
		t.Errorf("Version = %q, want empty", info.Version)
	}
}
