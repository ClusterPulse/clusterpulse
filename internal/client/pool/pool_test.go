package pool

import (
	"sync"
	"testing"
	"time"

	"github.com/clusterpulse/cluster-controller/internal/client/cluster"
)

// newTestPool constructs a ClientPool directly, avoiding NewClientPool
// which spawns a cleanup goroutine that would leak in tests.
func newTestPool(maxIdle time.Duration) *ClientPool {
	return &ClientPool{
		clients: make(map[string]*cluster.ClusterClient),
		maxIdle: maxIdle,
	}
}

func TestRemove_ExistingClient(t *testing.T) {
	p := newTestPool(time.Hour)
	p.clients["c1"] = &cluster.ClusterClient{Name: "c1"}

	p.Remove("c1")

	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.clients) != 0 {
		t.Fatalf("expected 0 clients, got %d", len(p.clients))
	}
}

func TestRemove_NonExistent(t *testing.T) {
	p := newTestPool(time.Hour)

	// Must not panic on missing key.
	p.Remove("nonexistent")

	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.clients) != 0 {
		t.Fatalf("expected 0 clients, got %d", len(p.clients))
	}
}

func TestClose(t *testing.T) {
	p := newTestPool(time.Hour)
	for _, name := range []string{"a", "b", "c"} {
		p.clients[name] = &cluster.ClusterClient{Name: name}
	}

	p.Close()

	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.clients) != 0 {
		t.Fatalf("expected 0 clients after Close, got %d", len(p.clients))
	}
}

func TestCleanupIdleClients_AllIdle(t *testing.T) {
	// ClusterClient zero value has lastUsed = time.Time{} (year 0001),
	// so time.Since(lastUsed) vastly exceeds any maxIdle.
	p := newTestPool(time.Second)
	p.clients["idle1"] = &cluster.ClusterClient{Name: "idle1"}
	p.clients["idle2"] = &cluster.ClusterClient{Name: "idle2"}

	p.cleanupIdleClients()

	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.clients) != 0 {
		t.Fatalf("expected all idle clients removed, got %d", len(p.clients))
	}
}

func TestCleanupIdleClients_EmptyPool(t *testing.T) {
	// Cleanup on an empty pool must not panic or alter state.
	p := newTestPool(time.Second)

	p.cleanupIdleClients()

	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.clients) != 0 {
		t.Fatalf("expected 0 clients, got %d", len(p.clients))
	}
}

func TestRemove_ConcurrentAccess(t *testing.T) {
	p := newTestPool(time.Hour)
	names := make([]string, 100)
	for i := range names {
		names[i] = "c" + time.Duration(i).String()
		p.clients[names[i]] = &cluster.ClusterClient{Name: names[i]}
	}

	var wg sync.WaitGroup
	for _, name := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Remove(name)
		}()
	}
	wg.Wait()

	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.clients) != 0 {
		t.Fatalf("expected 0 clients after concurrent Remove, got %d", len(p.clients))
	}
}
