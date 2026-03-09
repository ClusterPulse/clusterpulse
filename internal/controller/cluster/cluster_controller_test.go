package cluster

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
	"github.com/clusterpulse/cluster-controller/internal/client/pool"
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

func newTestClusterReconciler(t *testing.T, objs ...k8sclient.Object) (*ClusterReconciler, *miniredis.Miniredis) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(objs...).WithStatusSubresource(&v1alpha1.ClusterConnection{}).Build()
	mr := miniredis.RunT(t)
	host, portStr, _ := net.SplitHostPort(mr.Addr())
	port, _ := strconv.Atoi(portStr)
	cfg := &config.Config{RedisHost: host, RedisPort: port, CacheTTL: 600, MetricsRetention: 3600, ReconciliationInterval: 60, ConnectTimeout: 10, OperatorScanInterval: 300}
	redisClient, _ := store.NewClient(cfg)
	return &ClusterReconciler{
		Client: client, Scheme: scheme, RedisClient: redisClient, Config: cfg,
		clientPool:        pool.NewClientPool(30 * time.Minute),
		lastOperatorFetch: make(map[string]time.Time),
	}, mr
}

func TestGetReconcileInterval_Default(t *testing.T) {
	r := &ClusterReconciler{Config: &config.Config{ReconciliationInterval: 60}}
	conn := &v1alpha1.ClusterConnection{}
	if got := r.getReconcileInterval(conn); got != 60 {
		t.Errorf("got %d, want 60", got)
	}
}

func TestGetReconcileInterval_SpecOverride(t *testing.T) {
	r := &ClusterReconciler{Config: &config.Config{ReconciliationInterval: 60}}
	conn := &v1alpha1.ClusterConnection{}
	conn.Spec.Monitoring.Interval = 120
	if got := r.getReconcileInterval(conn); got != 120 {
		t.Errorf("got %d, want 120", got)
	}
}

func TestGetReconcileInterval_BelowMinimum(t *testing.T) {
	r := &ClusterReconciler{Config: &config.Config{ReconciliationInterval: 60}}
	conn := &v1alpha1.ClusterConnection{}
	conn.Spec.Monitoring.Interval = 10
	if got := r.getReconcileInterval(conn); got != 30 {
		t.Errorf("got %d, want 30 (minimum)", got)
	}
}

func TestStatusEqual(t *testing.T) {
	r := &ClusterReconciler{}
	a := v1alpha1.ClusterConnectionStatus{Phase: "Connected", Health: "healthy", Message: "ok"}
	b := v1alpha1.ClusterConnectionStatus{Phase: "Connected", Health: "healthy", Message: "ok"}
	if !r.statusEqual(a, b) {
		t.Error("identical statuses should be equal")
	}

	c := v1alpha1.ClusterConnectionStatus{Phase: "Connected", Health: "degraded", Message: "ok"}
	if r.statusEqual(a, c) {
		t.Error("different health should not be equal")
	}
}

func TestCountAvailable(t *testing.T) {
	ops := []types.ClusterOperatorInfo{
		{Available: true},
		{Available: false},
		{Available: true},
	}
	if got := countAvailable(ops); got != 2 {
		t.Errorf("got %d, want 2", got)
	}
}

func TestCountDegraded(t *testing.T) {
	ops := []types.ClusterOperatorInfo{
		{Degraded: true},
		{Degraded: false},
		{Degraded: true},
		{Degraded: true},
	}
	if got := countDegraded(ops); got != 3 {
		t.Errorf("got %d, want 3", got)
	}
}

func TestReconcile_NotFound_Cluster(t *testing.T) {
	r, _ := newTestClusterReconciler(t)
	req := reconcile.Request{NamespacedName: k8stypes.NamespacedName{Name: "missing", Namespace: "default"}}
	result, err := r.Reconcile(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue, got %v", result.RequeueAfter)
	}
}

func TestReconcile_DeletionTimestamp_Cluster(t *testing.T) {
	now := metav1.Now()
	cc := &v1alpha1.ClusterConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name: "del-cluster", Namespace: "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{"test-finalizer"}, // required for DeletionTimestamp to survive fake client
		},
		Spec: v1alpha1.ClusterConnectionSpec{
			Endpoint:       "https://example.com",
			CredentialsRef: v1alpha1.CredentialsReference{Name: "secret", Namespace: "default"},
		},
	}
	r, mr := newTestClusterReconciler(t, cc)

	// Pre-store data so deletion has something to clean.
	mr.Set("cluster:del-cluster:status", `{"health":"healthy"}`)

	req := reconcile.Request{NamespacedName: k8stypes.NamespacedName{Name: "del-cluster", Namespace: "default"}}
	result, err := r.Reconcile(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue, got %v", result.RequeueAfter)
	}
	if mr.Exists("cluster:del-cluster:status") {
		t.Error("expected cluster status key to be deleted")
	}
}

func TestHandleDeletion_Cluster(t *testing.T) {
	r, mr := newTestClusterReconciler(t)

	// Pre-store cluster data in Redis.
	mr.Set("cluster:test-cluster:spec", `{"displayName":"Test"}`)
	mr.Set("cluster:test-cluster:status", `{"health":"healthy"}`)
	mr.Set("cluster:test-cluster:labels", `{"env":"prod"}`)

	result, err := r.handleDeletion(t.Context(), "test-cluster")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue, got %v", result.RequeueAfter)
	}
	for _, key := range []string{"cluster:test-cluster:spec", "cluster:test-cluster:status", "cluster:test-cluster:labels"} {
		if mr.Exists(key) {
			t.Errorf("expected key %s to be deleted", key)
		}
	}
}

func TestStoreCRDData(t *testing.T) {
	cc := &v1alpha1.ClusterConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "store-cluster", Namespace: "default"},
		Spec: v1alpha1.ClusterConnectionSpec{
			DisplayName:    "Store Test",
			Endpoint:       "https://api.store.example.com",
			CredentialsRef: v1alpha1.CredentialsReference{Name: "cred", Namespace: "default"},
			Labels:         map[string]string{"env": "staging", "team": "platform"},
			Monitoring:     v1alpha1.MonitoringConfig{Interval: 60, Timeout: 15},
		},
	}
	r, mr := newTestClusterReconciler(t, cc)

	r.storeCRDData(t.Context(), cc)

	if !mr.Exists("cluster:store-cluster:spec") {
		t.Fatal("expected cluster spec key to exist")
	}
	if !mr.Exists("cluster:store-cluster:labels") {
		t.Fatal("expected cluster labels key to exist")
	}

	labelsVal, err := mr.Get("cluster:store-cluster:labels")
	if err != nil {
		t.Fatalf("failed to get labels: %v", err)
	}
	if labelsVal == "" {
		t.Error("expected non-empty labels value")
	}
}

func TestUpdateClusterStatus(t *testing.T) {
	r, mr := newTestClusterReconciler(t)

	r.updateClusterStatus(t.Context(), "status-cluster", types.HealthHealthy, "all good")

	if !mr.Exists("cluster:status-cluster:status") {
		t.Fatal("expected cluster status key to exist")
	}
}

func TestGetClusterClient_SecretNotFound(t *testing.T) {
	cc := &v1alpha1.ClusterConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "no-secret-cluster", Namespace: "default"},
		Spec: v1alpha1.ClusterConnectionSpec{
			Endpoint:       "https://api.example.com",
			CredentialsRef: v1alpha1.CredentialsReference{Name: "nonexistent-secret", Namespace: "default"},
		},
	}
	r, _ := newTestClusterReconciler(t, cc)

	_, err := r.getClusterClient(t.Context(), cc)
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
}

func TestGetClusterClient_EmptyToken(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "empty-token-secret", Namespace: "default"},
		Data:       map[string][]byte{"token": {}},
	}
	cc := &v1alpha1.ClusterConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "empty-token-cluster", Namespace: "default"},
		Spec: v1alpha1.ClusterConnectionSpec{
			Endpoint:       "https://api.example.com",
			CredentialsRef: v1alpha1.CredentialsReference{Name: "empty-token-secret", Namespace: "default"},
		},
	}
	r, _ := newTestClusterReconciler(t, cc, secret)

	_, err := r.getClusterClient(t.Context(), cc)
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}
