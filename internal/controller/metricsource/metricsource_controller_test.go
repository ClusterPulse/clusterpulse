package metricsource

import (
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
	"github.com/clusterpulse/cluster-controller/internal/config"
	"github.com/clusterpulse/cluster-controller/internal/metricsource/collector"
	store "github.com/clusterpulse/cluster-controller/internal/store"
	pkgtypes "github.com/clusterpulse/cluster-controller/pkg/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func newTestMetricSourceReconciler(t *testing.T, objs ...k8sclient.Object) (*MetricSourceReconciler, *miniredis.Miniredis) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(objs...).WithStatusSubresource(&v1alpha1.MetricSource{}).Build()
	mr := miniredis.RunT(t)
	host, portStr, _ := net.SplitHostPort(mr.Addr())
	port, _ := strconv.Atoi(portStr)
	cfg := &config.Config{RedisHost: host, RedisPort: port, CacheTTL: 600, MetricsRetention: 3600}
	redisClient, _ := store.NewClient(cfg)
	return &MetricSourceReconciler{
		Client:         client,
		Scheme:         scheme,
		RedisClient:    redisClient,
		Config:         cfg,
		compiledCache:  make(map[string]*pkgtypes.CompiledMetricSource),
		clusterClients: make(map[string]dynamic.Interface),
	}, mr
}

func TestInvalidateClusterClient(t *testing.T) {
	r, _ := newTestMetricSourceReconciler(t)

	// Seed the map with a nil entry (we only care about key presence).
	r.clusterClientsMu.Lock()
	r.clusterClients["cluster-a"] = nil
	r.clusterClientsMu.Unlock()

	r.InvalidateClusterClient("cluster-a")

	r.clusterClientsMu.RLock()
	_, exists := r.clusterClients["cluster-a"]
	r.clusterClientsMu.RUnlock()

	if exists {
		t.Error("cluster client should have been invalidated")
	}
}

func TestGetCachedMetricSource(t *testing.T) {
	r, _ := newTestMetricSourceReconciler(t)

	compiled := &pkgtypes.CompiledMetricSource{Name: "vms", Namespace: "default", Hash: "abc"}
	r.compiledCacheMu.Lock()
	r.compiledCache["default/vms"] = compiled
	r.compiledCacheMu.Unlock()

	got, ok := r.GetCachedMetricSource("default/vms")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.Hash != "abc" {
		t.Errorf("hash = %q, want %q", got.Hash, "abc")
	}
}

func TestGetCachedMetricSource_Miss(t *testing.T) {
	r, _ := newTestMetricSourceReconciler(t)

	_, ok := r.GetCachedMetricSource("nonexistent/source")
	if ok {
		t.Error("expected cache miss for non-existent key")
	}
}

func TestHandleDeletion_MetricSource(t *testing.T) {
	r, _ := newTestMetricSourceReconciler(t)
	ctx := t.Context()

	// Pre-seed compiled cache.
	r.compiledCache["default/vms"] = &pkgtypes.CompiledMetricSource{
		Name: "vms", Namespace: "default", Hash: "h1",
	}

	// Pre-seed Redis.
	src := &pkgtypes.CompiledMetricSource{
		Name:      "vms",
		Namespace: "default",
		Source: pkgtypes.CompiledSourceTarget{
			APIVersion: "kubevirt.io/v1",
			Kind:       "VirtualMachine",
		},
		RBAC:       pkgtypes.CompiledRBAC{ResourceTypeName: "virtualmachines"},
		CompiledAt: "2025-01-01T00:00:00Z",
		Hash:       "h1",
	}
	if err := r.RedisClient.StoreCompiledMetricSource(ctx, src); err != nil {
		t.Fatal(err)
	}

	result, err := r.handleDeletion(ctx, "default", "vms")
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue, got %v", result.RequeueAfter)
	}

	// Verify removed from local cache.
	if _, ok := r.GetCachedMetricSource("default/vms"); ok {
		t.Error("compiled cache entry should be removed")
	}

	// Verify removed from Redis.
	_, err = r.RedisClient.GetCompiledMetricSource(ctx, "default", "vms")
	if err == nil {
		t.Error("MetricSource should be deleted from Redis")
	}
}

func TestUpdateStatusSuccess(t *testing.T) {
	ms := &v1alpha1.MetricSource{
		ObjectMeta: metav1.ObjectMeta{Name: "vms", Namespace: "default"},
		Spec: v1alpha1.MetricSourceSpec{
			Source: v1alpha1.MetricSourceTarget{
				APIVersion: "kubevirt.io/v1",
				Kind:       "VirtualMachine",
			},
		},
	}
	r, _ := newTestMetricSourceReconciler(t, ms)
	ctx := t.Context()

	summary := &CollectionSummary{
		TotalResources:    42,
		ClustersCollected: 3,
		TotalErrors:       0,
		ClusterResults:    map[string]*collector.CollectResult{},
	}

	if err := r.updateStatusSuccess(ctx, ms, summary, 500*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	// Re-fetch to verify persisted status.
	var updated v1alpha1.MetricSource
	if err := r.Get(ctx, types.NamespacedName{Name: "vms", Namespace: "default"}, &updated); err != nil {
		t.Fatal(err)
	}

	if updated.Status.Phase != "Active" {
		t.Errorf("phase = %q, want Active", updated.Status.Phase)
	}
	if updated.Status.ResourcesCollected != 42 {
		t.Errorf("resources = %d, want 42", updated.Status.ResourcesCollected)
	}
	if updated.Status.ClustersCollected != 3 {
		t.Errorf("clusters = %d, want 3", updated.Status.ClustersCollected)
	}
	if updated.Status.Message != "Collection successful" {
		t.Errorf("message = %q", updated.Status.Message)
	}
	if len(updated.Status.Conditions) != 1 || updated.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Errorf("conditions = %+v", updated.Status.Conditions)
	}
}

func TestUpdateStatusError_MetricSource(t *testing.T) {
	ms := &v1alpha1.MetricSource{
		ObjectMeta: metav1.ObjectMeta{Name: "vms", Namespace: "default"},
		Spec: v1alpha1.MetricSourceSpec{
			Source: v1alpha1.MetricSourceTarget{
				APIVersion: "v1",
				Kind:       "Pod",
			},
		},
	}
	r, _ := newTestMetricSourceReconciler(t, ms)
	ctx := t.Context()

	result, err := r.updateStatusError(ctx, ms, errors.New("compilation failed"))
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != 30*time.Second {
		t.Errorf("requeue = %v, want 30s", result.RequeueAfter)
	}

	// Re-fetch to verify persisted status.
	var updated v1alpha1.MetricSource
	if err := r.Get(ctx, types.NamespacedName{Name: "vms", Namespace: "default"}, &updated); err != nil {
		t.Fatal(err)
	}

	if updated.Status.Phase != "Error" {
		t.Errorf("phase = %q, want Error", updated.Status.Phase)
	}
	if updated.Status.Message != "compilation failed" {
		t.Errorf("message = %q", updated.Status.Message)
	}
	if len(updated.Status.Conditions) != 1 || updated.Status.Conditions[0].Status != metav1.ConditionFalse {
		t.Errorf("conditions = %+v", updated.Status.Conditions)
	}
}

func TestReconcile_NotFound_MetricSource(t *testing.T) {
	r, _ := newTestMetricSourceReconciler(t)
	ctx := t.Context()

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "gone", Namespace: "default"},
	}

	result, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue for NotFound, got %v", result.RequeueAfter)
	}
}

func TestReconcile_DeletionTimestamp_MetricSource(t *testing.T) {
	now := metav1.Now()
	ms := &v1alpha1.MetricSource{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "vms",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{"keep-alive"}, // required for fake client to accept DeletionTimestamp
		},
		Spec: v1alpha1.MetricSourceSpec{
			Source: v1alpha1.MetricSourceTarget{
				APIVersion: "kubevirt.io/v1",
				Kind:       "VirtualMachine",
			},
		},
	}
	r, _ := newTestMetricSourceReconciler(t, ms)
	ctx := t.Context()

	// Pre-seed cache so handleDeletion has something to clean up.
	r.compiledCache["default/vms"] = &pkgtypes.CompiledMetricSource{
		Name: "vms", Namespace: "default",
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "vms", Namespace: "default"},
	}

	result, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue after deletion, got %v", result.RequeueAfter)
	}

	// Verify cache was cleaned.
	if _, ok := r.GetCachedMetricSource("default/vms"); ok {
		t.Error("compiled cache should be cleared after deletion")
	}
}
