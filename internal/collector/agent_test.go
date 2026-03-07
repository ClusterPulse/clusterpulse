package collector

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
