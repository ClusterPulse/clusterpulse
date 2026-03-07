package cluster

import (
	"testing"

	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
	"github.com/clusterpulse/cluster-controller/internal/config"
	"github.com/clusterpulse/cluster-controller/pkg/types"
)

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
