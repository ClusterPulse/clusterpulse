package ingester

import (
	"testing"

	pb "github.com/clusterpulse/cluster-controller/proto/collectorpb"
)

func TestProtoToClusterMetrics(t *testing.T) {
	p := &pb.ClusterMetrics{
		Nodes: 5, NodesReady: 4, Namespaces: 10,
		NamespaceList: []string{"default", "kube-system"},
		Pods: 100, PodsRunning: 80,
		CpuCapacity: 16.0, MemoryCapacity: 64000000000,
		Deployments: 20,
	}
	cm := protoToClusterMetrics(p)
	if cm.Nodes != 5 || cm.NodesReady != 4 {
		t.Errorf("Nodes=%d,Ready=%d", cm.Nodes, cm.NodesReady)
	}
	if cm.Namespaces != 10 || len(cm.NamespaceList) != 2 {
		t.Error("namespace fields wrong")
	}
	if cm.Pods != 100 || cm.PodsRunning != 80 {
		t.Error("pod fields wrong")
	}
	if cm.CPUCapacity != 16.0 || cm.MemoryCapacity != 64000000000 {
		t.Error("capacity fields wrong")
	}
	if cm.Deployments != 20 {
		t.Error("deployments wrong")
	}
}

func TestProtoToNodeMetrics(t *testing.T) {
	nodes := []*pb.NodeMetrics{
		{
			Name: "node-1", Status: "Ready",
			Roles: []string{"master", "worker"},
			CpuCapacity: 8.0, MemoryCapacity: 32000000000,
			PodsRunning: 10, PodsTotal: 15,
			KubeletVersion: "v1.28.0",
		},
		{
			Name: "node-2", Status: "NotReady",
		},
	}
	result := protoToNodeMetrics(nodes)
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
	if result[0].Name != "node-1" || result[0].Status != "Ready" {
		t.Error("node-1 fields wrong")
	}
	if len(result[0].Roles) != 2 {
		t.Errorf("roles = %v", result[0].Roles)
	}
	if result[0].CPUCapacity != 8.0 {
		t.Error("cpu capacity wrong")
	}
	if result[0].KubeletVersion != "v1.28.0" {
		t.Error("kubelet version wrong")
	}
}

func TestProtoToOperators(t *testing.T) {
	ops := []*pb.OperatorInfo{
		{
			Name: "cert-manager", DisplayName: "Cert Manager",
			Version: "1.12.0", Status: "Succeeded",
			InstalledNamespace: "cert-manager",
			InstallMode: "AllNamespaces", IsClusterWide: true,
			InstallModes: []string{"AllNamespaces"},
			AvailableInNamespaces: []string{"*"},
			AvailableCount: 1,
			Subscription: map[string]string{"installPlanApproval": "Automatic"},
		},
	}
	result := protoToOperators(ops)
	if len(result) != 1 {
		t.Fatalf("len = %d", len(result))
	}
	o := result[0]
	if o.Name != "cert-manager" || o.Version != "1.12.0" {
		t.Error("basic fields wrong")
	}
	if !o.IsClusterWide || o.InstallMode != "AllNamespaces" {
		t.Error("install mode wrong")
	}
	if o.AvailableCount != 1 {
		t.Errorf("available count = %d", o.AvailableCount)
	}
}

func TestProtoToClusterOperators(t *testing.T) {
	cops := []*pb.ClusterOperatorInfo{
		{
			Name: "console", Version: "4.14.0",
			Available: true, Progressing: false, Degraded: false, Upgradeable: true,
			Conditions: []*pb.ClusterOperatorCondition{
				{Type: "Available", Status: "True"},
			},
			Versions: []*pb.ClusterOperatorVersion{
				{Name: "operator", Version: "4.14.0"},
			},
			RelatedObjects: []*pb.RelatedObject{
				{Group: "", Resource: "namespaces", Name: "openshift-console"},
			},
		},
	}
	result := protoToClusterOperators(cops)
	if len(result) != 1 {
		t.Fatalf("len = %d", len(result))
	}
	co := result[0]
	if co.Name != "console" || !co.Available || co.Degraded {
		t.Error("basic fields wrong")
	}
	if len(co.Conditions) != 1 || co.Conditions[0].Type != "Available" {
		t.Error("conditions wrong")
	}
	if len(co.Versions) != 1 || co.Versions[0].Version != "4.14.0" {
		t.Error("versions wrong")
	}
	if len(co.RelatedObjects) != 1 || co.RelatedObjects[0].Name != "openshift-console" {
		t.Error("related objects wrong")
	}
}

func TestProtoToClusterInfo(t *testing.T) {
	p := &pb.ClusterInfo{
		ApiUrl: "https://api.cluster.example.com:6443",
		Version: "4.14.0", Platform: "OpenShift",
		ConsoleUrl: "https://console.cluster.example.com",
		Channel: "stable-4.14", ClusterId: "abc-123",
	}
	info := protoToClusterInfo(p)
	if info["api_url"] != p.ApiUrl {
		t.Error("api_url wrong")
	}
	if info["console_url"] != p.ConsoleUrl {
		t.Error("console_url wrong")
	}
	if info["channel"] != p.Channel {
		t.Error("channel wrong")
	}
	if info["cluster_id"] != p.ClusterId {
		t.Error("cluster_id wrong")
	}
}

func TestProtoToClusterInfo_OptionalOmitted(t *testing.T) {
	p := &pb.ClusterInfo{ApiUrl: "https://api", Version: "1.28", Platform: "Kubernetes"}
	info := protoToClusterInfo(p)
	if _, ok := info["console_url"]; ok {
		t.Error("console_url should be omitted when empty")
	}
	if _, ok := info["channel"]; ok {
		t.Error("channel should be omitted when empty")
	}
}

func TestProtoToCustomResources(t *testing.T) {
	crBatch := &pb.CustomResourceBatch{
		SourceId:      "ns/source",
		ResourceCount: 2,
		Truncated:     false,
		DurationMs:    150,
		Resources: []*pb.CustomCollectedResource{
			{Id: "r1", Namespace: "default", Name: "vm-1", ValuesJson: []byte(`{"cpu":4}`)},
			{Id: "r2", Namespace: "prod", Name: "vm-2"},
		},
		AggregationValues: map[string]float64{"total_cpu": 8.0},
	}
	coll, agg := protoToCustomResources(crBatch, "cluster-1")
	if coll.SourceID != "ns/source" || coll.ClusterName != "cluster-1" {
		t.Error("collection basic fields wrong")
	}
	if len(coll.Resources) != 2 {
		t.Fatalf("resources len = %d", len(coll.Resources))
	}
	if coll.Resources[0].Values["cpu"] != float64(4) {
		t.Error("values not parsed from JSON")
	}
	if agg == nil {
		t.Fatal("aggregations should be set")
	}
	if agg.Values["total_cpu"] != 8.0 {
		t.Error("aggregation values wrong")
	}
}

func TestProtoToCustomResources_NilAggregations(t *testing.T) {
	crBatch := &pb.CustomResourceBatch{SourceId: "ns/s"}
	_, agg := protoToCustomResources(crBatch, "c")
	if agg != nil {
		t.Error("nil aggregations should produce nil")
	}
}
