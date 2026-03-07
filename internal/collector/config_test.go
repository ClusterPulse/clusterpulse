package collector

import (
	"testing"
	"time"
)

func TestReconnectBackoff(t *testing.T) {
	cfg := &Config{}

	// First backoff should be 2s (1 << 1)
	d := cfg.ReconnectBackoff()
	if d != 2*time.Second {
		t.Errorf("first backoff = %v, want 2s", d)
	}

	// Second backoff should be 4s (1 << 2)
	d = cfg.ReconnectBackoff()
	if d != 4*time.Second {
		t.Errorf("second backoff = %v, want 4s", d)
	}
}

func TestReconnectBackoffCap(t *testing.T) {
	cfg := &Config{reconnectAttempts: 20}

	d := cfg.ReconnectBackoff()
	if d != 5*time.Minute {
		t.Errorf("capped backoff = %v, want 5m", d)
	}
}

func TestResetBackoff(t *testing.T) {
	cfg := &Config{}

	// Bump attempts a few times
	cfg.ReconnectBackoff()
	cfg.ReconnectBackoff()
	cfg.ReconnectBackoff()

	cfg.ResetBackoff()

	// After reset, first backoff should be 2s again
	d := cfg.ReconnectBackoff()
	if d != 2*time.Second {
		t.Errorf("backoff after reset = %v, want 2s", d)
	}
}
