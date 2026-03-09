package policy

import (
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
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

func newTestPolicyReconciler(t *testing.T, objs ...k8sclient.Object) (*PolicyReconciler, *miniredis.Miniredis) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(objs...).WithStatusSubresource(&v1alpha1.MonitorAccessPolicy{}).Build()
	mr := miniredis.RunT(t)
	host, portStr, _ := net.SplitHostPort(mr.Addr())
	port, _ := strconv.Atoi(portStr)
	cfg := &config.Config{RedisHost: host, RedisPort: port, CacheTTL: 600, MetricsRetention: 3600}
	redisClient, _ := store.NewClient(cfg)
	return &PolicyReconciler{
		Client:      client,
		Scheme:      scheme,
		RedisClient: redisClient,
		Config:      cfg,
		compiler:    NewCompiler(),
	}, mr
}

func newValidPolicy(name, namespace string) *v1alpha1.MonitorAccessPolicy {
	return &v1alpha1.MonitorAccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: v1alpha1.MonitorAccessPolicySpec{
			Identity: v1alpha1.PolicyIdentity{
				Subjects: v1alpha1.PolicySubjects{
					Users:  []string{"alice@example.com"},
					Groups: []string{"sre-team"},
				},
				Priority: 100,
			},
			Access: v1alpha1.PolicyAccess{
				Effect:  "Allow",
				Enabled: new(true),
			},
			Scope: v1alpha1.PolicyScope{
				Clusters: v1alpha1.PolicyClusters{
					Default: "deny",
					Rules: []v1alpha1.PolicyClusterRule{{
						Selector: v1alpha1.PolicyClusterSelector{
							MatchNames: []string{"prod-*"},
						},
					}},
				},
			},
		},
	}
}

func TestReconcile_CreatePolicy(t *testing.T) {
	policy := newValidPolicy("test-policy", "default")
	r, _ := newTestPolicyReconciler(t, policy)

	result, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: k8stypes.NamespacedName{Name: "test-policy", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %v", result.RequeueAfter)
	}

	// Verify CRD status updated
	updated := &v1alpha1.MonitorAccessPolicy{}
	if err := r.Get(t.Context(), k8stypes.NamespacedName{Name: "test-policy", Namespace: "default"}, updated); err != nil {
		t.Fatalf("failed to get updated policy: %v", err)
	}
	if updated.Status.State != "Active" {
		t.Errorf("expected status Active, got %q", updated.Status.State)
	}
	if updated.Status.AffectedUsers != 1 {
		t.Errorf("expected 1 affected user, got %d", updated.Status.AffectedUsers)
	}
	if updated.Status.AffectedGroups != 1 {
		t.Errorf("expected 1 affected group, got %d", updated.Status.AffectedGroups)
	}
	if updated.Status.Hash == "" {
		t.Error("expected non-empty hash")
	}
	if updated.Status.CompiledAt == "" {
		t.Error("expected non-empty compiledAt")
	}

	// Verify policy stored in Redis
	stored, err := r.RedisClient.GetPolicy(t.Context(), "default", "test-policy")
	if err != nil {
		t.Fatalf("policy not found in Redis: %v", err)
	}
	if stored.Effect != "Allow" {
		t.Errorf("expected effect Allow in Redis, got %q", stored.Effect)
	}
}

func TestReconcile_NotFound(t *testing.T) {
	r, _ := newTestPolicyReconciler(t)

	result, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: k8stypes.NamespacedName{Name: "nonexistent", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Fatalf("expected empty result, got %v", result)
	}
}

func TestReconcile_DeletionTimestamp(t *testing.T) {
	now := metav1.Now()
	policy := newValidPolicy("deleting-policy", "default")
	policy.DeletionTimestamp = &now
	policy.Finalizers = []string{"test-finalizer"} // required for fake client to accept DeletionTimestamp

	r, _ := newTestPolicyReconciler(t, policy)

	result, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: k8stypes.NamespacedName{Name: "deleting-policy", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %v", result.RequeueAfter)
	}
}

func TestReconcile_CompilationError(t *testing.T) {
	policy := newValidPolicy("bad-policy", "default")
	policy.Spec.Access.Effect = "" // empty effect triggers compilation error

	r, _ := newTestPolicyReconciler(t, policy)

	result, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: k8stypes.NamespacedName{Name: "bad-policy", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 30*time.Second {
		t.Fatalf("expected 30s requeue, got %v", result.RequeueAfter)
	}

	// Verify status set to Error
	updated := &v1alpha1.MonitorAccessPolicy{}
	if err := r.Get(t.Context(), k8stypes.NamespacedName{Name: "bad-policy", Namespace: "default"}, updated); err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if updated.Status.State != "Error" {
		t.Errorf("expected status Error, got %q", updated.Status.State)
	}
	if updated.Status.Message == "" {
		t.Error("expected non-empty error message")
	}
}

func TestHandleDeletion(t *testing.T) {
	r, _ := newTestPolicyReconciler(t)
	ctx := t.Context()

	// Pre-store a policy in Redis
	compiled := &types.CompiledPolicy{
		PolicyName: "to-delete",
		Namespace:  "default",
		Priority:   100,
		Effect:     "Allow",
		Enabled:    true,
		Users:      []string{"bob"},
		Groups:     []string{},
		ServiceAccounts:     []string{},
		DefaultClusterAccess: "deny",
		ClusterRules:         []types.CompiledClusterRule{},
		CompiledAt:           time.Now().UTC().Format(time.RFC3339),
		Hash:                 "abc123",
		CustomResourceTypes:  []string{},
	}
	if err := r.RedisClient.StorePolicy(ctx, compiled); err != nil {
		t.Fatalf("failed to pre-store policy: %v", err)
	}

	// Verify it exists
	if _, err := r.RedisClient.GetPolicy(ctx, "default", "to-delete"); err != nil {
		t.Fatalf("policy should exist before deletion: %v", err)
	}

	// Call handleDeletion
	result, err := r.handleDeletion(ctx, "default", "to-delete")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %v", result.RequeueAfter)
	}

	// Verify removed from Redis
	_, err = r.RedisClient.GetPolicy(ctx, "default", "to-delete")
	if err == nil {
		t.Fatal("expected policy to be removed from Redis")
	}
}

func TestUpdateStatusError(t *testing.T) {
	policy := newValidPolicy("err-policy", "default")
	r, _ := newTestPolicyReconciler(t, policy)
	ctx := t.Context()

	// Fetch the live object (needed for status update)
	live := &v1alpha1.MonitorAccessPolicy{}
	if err := r.Get(ctx, k8stypes.NamespacedName{Name: "err-policy", Namespace: "default"}, live); err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}

	testErr := errors.New("test compilation failure")
	result, err := r.updateStatusError(ctx, live, testErr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 30*time.Second {
		t.Fatalf("expected 30s requeue, got %v", result.RequeueAfter)
	}

	// Re-fetch and verify status
	updated := &v1alpha1.MonitorAccessPolicy{}
	if err := r.Get(ctx, k8stypes.NamespacedName{Name: "err-policy", Namespace: "default"}, updated); err != nil {
		t.Fatalf("failed to get updated policy: %v", err)
	}
	if updated.Status.State != "Error" {
		t.Errorf("expected state Error, got %q", updated.Status.State)
	}
	if updated.Status.Message == "" {
		t.Error("expected non-empty error message")
	}
}

func TestEvalCacheCleaner_Start(t *testing.T) {
	mr := miniredis.RunT(t)
	host, portStr, _ := net.SplitHostPort(mr.Addr())
	port, _ := strconv.Atoi(portStr)
	cfg := &config.Config{RedisHost: host, RedisPort: port, CacheTTL: 600, MetricsRetention: 3600}
	redisClient, err := store.NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create redis client: %v", err)
	}

	// Seed eval cache keys
	mr.Set("policy:eval:user1:cluster1", "data1")
	mr.Set("policy:eval:user2:cluster2", "data2")
	mr.Set("policy:eval:sa1:cluster3", "data3")
	// Seed a non-eval key that should NOT be removed
	mr.Set("policy:default:keep-me", "keep")

	cleaner := &EvalCacheCleaner{RedisClient: redisClient}
	if err := cleaner.Start(t.Context()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify eval keys cleared
	for _, key := range []string{"policy:eval:user1:cluster1", "policy:eval:user2:cluster2", "policy:eval:sa1:cluster3"} {
		if mr.Exists(key) {
			t.Errorf("expected key %q to be cleared", key)
		}
	}

	// Verify non-eval key preserved
	if !mr.Exists("policy:default:keep-me") {
		t.Error("expected non-eval key to be preserved")
	}
}
