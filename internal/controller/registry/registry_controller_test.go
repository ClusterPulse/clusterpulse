package registry

import (
	"encoding/json"
	"net"
	"strconv"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
	"github.com/clusterpulse/cluster-controller/internal/client/registry"
	"github.com/clusterpulse/cluster-controller/internal/config"
	store "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/clusterpulse/cluster-controller/pkg/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestGetReconcileInterval_Default(t *testing.T) {
	r := &RegistryReconciler{}
	conn := &v1alpha1.RegistryConnection{}
	if got := r.getReconcileInterval(conn); got != 60 {
		t.Errorf("got %d, want 60", got)
	}
}

func TestGetReconcileInterval_SpecOverride(t *testing.T) {
	r := &RegistryReconciler{}
	conn := &v1alpha1.RegistryConnection{}
	conn.Spec.Monitoring.Interval = 90
	if got := r.getReconcileInterval(conn); got != 90 {
		t.Errorf("got %d, want 90", got)
	}
}

func TestGetReconcileInterval_BelowMinimum(t *testing.T) {
	r := &RegistryReconciler{}
	conn := &v1alpha1.RegistryConnection{}
	conn.Spec.Monitoring.Interval = 15
	if got := r.getReconcileInterval(conn); got != 30 {
		t.Errorf("got %d, want 30 (minimum)", got)
	}
}

func TestCalculateRegistryHealth_Healthy(t *testing.T) {
	r := &RegistryReconciler{}
	result := &registry.HealthCheckResult{Available: true, ResponseTime: 200}
	if got := r.calculateRegistryHealth(result); got != types.HealthHealthy {
		t.Errorf("got %v, want Healthy", got)
	}
}

func TestCalculateRegistryHealth_Unavailable(t *testing.T) {
	r := &RegistryReconciler{}
	result := &registry.HealthCheckResult{Available: false}
	if got := r.calculateRegistryHealth(result); got != types.HealthUnhealthy {
		t.Errorf("got %v, want Unhealthy", got)
	}
}

func TestCalculateRegistryHealth_Degraded(t *testing.T) {
	r := &RegistryReconciler{}
	result := &registry.HealthCheckResult{Available: true, ResponseTime: 6000}
	if got := r.calculateRegistryHealth(result); got != types.HealthDegraded {
		t.Errorf("got %v, want Degraded", got)
	}
}

func TestGenerateHealthMessage_Healthy(t *testing.T) {
	r := &RegistryReconciler{}
	result := &registry.HealthCheckResult{Available: true, ResponseTime: 150, RepositoryCount: 42}
	msg := r.generateHealthMessage(result, types.HealthHealthy)
	if msg != "Registry is healthy (response time: 150ms), 42 repositories" {
		t.Errorf("msg = %q", msg)
	}
}

func TestGenerateHealthMessage_Unavailable(t *testing.T) {
	r := &RegistryReconciler{}
	result := &registry.HealthCheckResult{Available: false, Error: "connection refused"}
	msg := r.generateHealthMessage(result, types.HealthUnhealthy)
	if msg != "Registry unavailable: connection refused" {
		t.Errorf("msg = %q", msg)
	}
}

func TestGenerateHealthMessage_Slow(t *testing.T) {
	r := &RegistryReconciler{}
	result := &registry.HealthCheckResult{Available: true, ResponseTime: 7000}
	msg := r.generateHealthMessage(result, types.HealthDegraded)
	if msg != "Registry is slow (response time: 7000ms)" {
		t.Errorf("msg = %q", msg)
	}
}

func TestShouldUpdateStatus_PhaseChanged(t *testing.T) {
	r := &RegistryReconciler{}
	conn := &v1alpha1.RegistryConnection{}
	conn.Status.Phase = "Connecting" // not "Connected"
	result := &registry.HealthCheckResult{Available: true, ResponseTime: 100}
	if !r.shouldUpdateStatus(conn, result, types.HealthHealthy, "ok") {
		t.Error("should update when phase != Connected")
	}
}

func TestShouldUpdateStatus_NoChange(t *testing.T) {
	r := &RegistryReconciler{}
	conn := &v1alpha1.RegistryConnection{}
	conn.Status.Phase = "Connected"
	conn.Status.Health = "healthy"
	conn.Status.Available = true
	conn.Status.Message = "ok"
	conn.Status.Version = "2.0"
	result := &registry.HealthCheckResult{Available: true, ResponseTime: 100, Version: "2.0"}
	if r.shouldUpdateStatus(conn, result, types.HealthHealthy, "ok") {
		t.Error("should not update when nothing changed")
	}
}

func TestMapsEqual(t *testing.T) {
	a := map[string]bool{"x": true, "y": false}
	b := map[string]bool{"x": true, "y": false}
	if !mapsEqual(a, b) {
		t.Error("identical maps should be equal")
	}

	c := map[string]bool{"x": true}
	if mapsEqual(a, c) {
		t.Error("different-length maps should not be equal")
	}
}

func newTestRegistryReconciler(t *testing.T, objs ...k8sclient.Object) (*RegistryReconciler, *miniredis.Miniredis) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(objs...).WithStatusSubresource(&v1alpha1.RegistryConnection{}).Build()
	mr := miniredis.RunT(t)
	host, portStr, _ := net.SplitHostPort(mr.Addr())
	port, _ := strconv.Atoi(portStr)
	cfg := &config.Config{RedisHost: host, RedisPort: port, CacheTTL: 600, MetricsRetention: 3600}
	redisClient, _ := store.NewClient(cfg)
	return &RegistryReconciler{
		Client: client, Scheme: scheme, RedisClient: redisClient, Config: cfg,
	}, mr
}

func TestReconcile_NotFound(t *testing.T) {
	r, _ := newTestRegistryReconciler(t)

	result, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: k8stypes.NamespacedName{Name: "nonexistent", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want 0", result.RequeueAfter)
	}
}

func TestReconcile_DeletionTimestamp(t *testing.T) {
	now := metav1.Now()
	conn := &v1alpha1.RegistryConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "deleting-reg",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{"test-finalizer"}, // required for fake client to accept DeletionTimestamp
		},
		Spec: v1alpha1.RegistryConnectionSpec{
			Endpoint: "https://registry.example.com",
		},
	}

	r, mr := newTestRegistryReconciler(t, conn)

	// Pre-store data so we can verify cleanup
	mr.Set("registry:deleting-reg:spec", "data")
	mr.Set("registry:deleting-reg:status", "data")

	result, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: k8stypes.NamespacedName{Name: "deleting-reg", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want 0", result.RequeueAfter)
	}

	// Verify Redis keys were cleaned up
	if mr.Exists("registry:deleting-reg:spec") {
		t.Error("registry spec should be deleted from Redis")
	}
	if mr.Exists("registry:deleting-reg:status") {
		t.Error("registry status should be deleted from Redis")
	}
}

func TestHandleDeletion(t *testing.T) {
	r, mr := newTestRegistryReconciler(t)
	ctx := t.Context()

	// Pre-store registry data
	mr.Set("registry:test-reg:spec", `{"endpoint":"https://r.io"}`)
	mr.Set("registry:test-reg:status", `{"available":true}`)
	mr.Set("registry:test-reg:metrics:latest", `{"response_time":100}`)
	mr.SAdd("registries:all", "test-reg")

	result, err := r.handleDeletion(ctx, "test-reg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want 0", result.RequeueAfter)
	}

	// Verify all keys removed
	for _, key := range []string{"registry:test-reg:spec", "registry:test-reg:status", "registry:test-reg:metrics:latest"} {
		if mr.Exists(key) {
			t.Errorf("key %s should be deleted", key)
		}
	}

	// Verify removed from registries:all set
	members, _ := mr.Members("registries:all")
	for _, m := range members {
		if m == "test-reg" {
			t.Error("test-reg should be removed from registries:all")
		}
	}
}

func TestStoreRegistryData(t *testing.T) {
	r, mr := newTestRegistryReconciler(t)
	ctx := t.Context()

	spec := map[string]any{
		"display_name": "My Registry",
		"endpoint":     "https://registry.example.com",
		"type":         "harbor",
	}
	health := &registry.HealthCheckResult{
		Available:       true,
		ResponseTime:    150,
		Version:         "2.8.0",
		RepositoryCount: 42,
		Repositories:    []string{"app/web", "app/api"},
		Features:        map[string]bool{"catalog": true},
	}

	if err := r.storeRegistryData(ctx, "my-reg", spec, health); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify spec stored
	specData, err := mr.Get("registry:my-reg:spec")
	if err != nil {
		t.Fatalf("spec not stored: %v", err)
	}
	var gotSpec map[string]any
	if err := json.Unmarshal([]byte(specData), &gotSpec); err != nil {
		t.Fatalf("invalid spec JSON: %v", err)
	}
	if gotSpec["endpoint"] != "https://registry.example.com" {
		t.Errorf("spec endpoint = %v", gotSpec["endpoint"])
	}

	// Verify status stored
	statusData, err := mr.Get("registry:my-reg:status")
	if err != nil {
		t.Fatalf("status not stored: %v", err)
	}
	var gotStatus map[string]any
	if err := json.Unmarshal([]byte(statusData), &gotStatus); err != nil {
		t.Fatalf("invalid status JSON: %v", err)
	}
	if gotStatus["available"] != true {
		t.Errorf("status available = %v", gotStatus["available"])
	}
	if gotStatus["version"] != "2.8.0" {
		t.Errorf("status version = %v", gotStatus["version"])
	}

	// Verify metrics stored (latest key)
	latestData, err := mr.Get("registry:my-reg:metrics:latest")
	if err != nil {
		t.Fatalf("latest metrics not stored: %v", err)
	}
	var gotMetrics map[string]any
	if err := json.Unmarshal([]byte(latestData), &gotMetrics); err != nil {
		t.Fatalf("invalid metrics JSON: %v", err)
	}
	// response_time is stored as float64 via JSON
	if rt, ok := gotMetrics["response_time"].(float64); !ok || int64(rt) != 150 {
		t.Errorf("metrics response_time = %v", gotMetrics["response_time"])
	}

	// Verify added to registries:all
	members, _ := mr.Members("registries:all")
	found := false
	for _, m := range members {
		if m == "my-reg" {
			found = true
			break
		}
	}
	if !found {
		t.Error("my-reg should be in registries:all")
	}
}

func TestStoreRegistryData_WithError(t *testing.T) {
	r, mr := newTestRegistryReconciler(t)
	ctx := t.Context()

	spec := map[string]any{
		"display_name": "Failing Registry",
		"endpoint":     "https://bad-registry.example.com",
	}
	health := &registry.HealthCheckResult{
		Available:    false,
		ResponseTime: 0,
		Error:        "connection refused",
	}

	if err := r.storeRegistryData(ctx, "bad-reg", spec, health); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the error field is present in stored status
	statusData, err := mr.Get("registry:bad-reg:status")
	if err != nil {
		t.Fatalf("status not stored: %v", err)
	}
	var gotStatus map[string]any
	if err := json.Unmarshal([]byte(statusData), &gotStatus); err != nil {
		t.Fatalf("invalid status JSON: %v", err)
	}
	if gotStatus["error"] != "connection refused" {
		t.Errorf("status error = %v, want %q", gotStatus["error"], "connection refused")
	}
	if gotStatus["available"] != false {
		t.Errorf("status available = %v, want false", gotStatus["available"])
	}
}
