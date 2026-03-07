package registry

import (
	"testing"

	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
	"github.com/clusterpulse/cluster-controller/internal/client/registry"
	"github.com/clusterpulse/cluster-controller/pkg/types"
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
