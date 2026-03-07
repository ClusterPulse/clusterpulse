package ingester

import (
	"testing"
	"time"
)

func newTestServer() *Server {
	return &Server{
		connections: make(map[string]*collectorConn),
	}
}

func TestConnectionLifecycle(t *testing.T) {
	s := newTestServer()

	// Not connected initially
	if s.IsConnected("cluster-1") {
		t.Error("should not be connected before add")
	}

	// Add connection
	s.addConnection("cluster-1", "v1.0")
	if !s.IsConnected("cluster-1") {
		t.Error("should be connected after add")
	}

	// GetConnectionInfo
	connected, hb, version := s.GetConnectionInfo("cluster-1")
	if !connected {
		t.Error("GetConnectionInfo: should be connected")
	}
	if version != "v1.0" {
		t.Errorf("version = %q, want v1.0", version)
	}
	if time.Since(hb) > time.Second {
		t.Error("lastHeartbeat should be recent")
	}

	// Remove connection
	s.removeConnection("cluster-1")
	if s.IsConnected("cluster-1") {
		t.Error("should not be connected after remove")
	}

	connected, _, _ = s.GetConnectionInfo("cluster-1")
	if connected {
		t.Error("GetConnectionInfo: should return false after remove")
	}
}

func TestUpdateHeartbeat(t *testing.T) {
	s := newTestServer()
	s.addConnection("cluster-1", "v1.0")

	// Record initial heartbeat
	_, hb1, _ := s.GetConnectionInfo("cluster-1")

	// Small sleep to ensure time difference
	time.Sleep(5 * time.Millisecond)

	s.updateHeartbeat("cluster-1")

	_, hb2, _ := s.GetConnectionInfo("cluster-1")
	if !hb2.After(hb1) {
		t.Error("heartbeat should be updated after updateHeartbeat")
	}
}

func TestUpdateHeartbeat_NotConnected(t *testing.T) {
	s := newTestServer()
	// Should not panic when cluster is not connected
	s.updateHeartbeat("nonexistent")
}
