package collector

import (
	"sync"
	"testing"

	pb "github.com/clusterpulse/cluster-controller/proto/collectorpb"
)

func TestNewBuffer_PositiveSize(t *testing.T) {
	b := NewBuffer(5)
	if b.maxSize != 5 {
		t.Errorf("maxSize = %d, want 5", b.maxSize)
	}
}

func TestNewBuffer_ZeroClamped(t *testing.T) {
	b := NewBuffer(0)
	if b.maxSize != 10 {
		t.Errorf("maxSize = %d, want 10 (clamped)", b.maxSize)
	}
}

func TestNewBuffer_NegativeClamped(t *testing.T) {
	b := NewBuffer(-5)
	if b.maxSize != 10 {
		t.Errorf("maxSize = %d, want 10 (clamped)", b.maxSize)
	}
}

func TestBuffer_PushUnderCapacity(t *testing.T) {
	b := NewBuffer(3)
	b.Push(&pb.MetricsBatch{ClusterName: "a"})
	b.Push(&pb.MetricsBatch{ClusterName: "b"})
	if b.Len() != 2 {
		t.Errorf("Len() = %d, want 2", b.Len())
	}
}

func TestBuffer_PushDropsOldest(t *testing.T) {
	b := NewBuffer(2)
	b.Push(&pb.MetricsBatch{ClusterName: "a"})
	b.Push(&pb.MetricsBatch{ClusterName: "b"})
	b.Push(&pb.MetricsBatch{ClusterName: "c"})

	if b.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", b.Len())
	}

	first := b.Pop()
	if first.ClusterName != "b" {
		t.Errorf("first Pop = %q, want %q (oldest 'a' should be dropped)", first.ClusterName, "b")
	}
}

func TestBuffer_PopEmpty(t *testing.T) {
	b := NewBuffer(5)
	if got := b.Pop(); got != nil {
		t.Errorf("Pop() on empty = %v, want nil", got)
	}
}

func TestBuffer_PopFIFO(t *testing.T) {
	b := NewBuffer(5)
	b.Push(&pb.MetricsBatch{ClusterName: "first"})
	b.Push(&pb.MetricsBatch{ClusterName: "second"})
	b.Push(&pb.MetricsBatch{ClusterName: "third"})

	names := []string{"first", "second", "third"}
	for _, want := range names {
		got := b.Pop()
		if got == nil {
			t.Fatalf("Pop() = nil, want %q", want)
		}
		if got.ClusterName != want {
			t.Errorf("Pop() = %q, want %q", got.ClusterName, want)
		}
	}
}

func TestBuffer_InterleavedPushPop(t *testing.T) {
	b := NewBuffer(3)
	b.Push(&pb.MetricsBatch{ClusterName: "a"})
	b.Push(&pb.MetricsBatch{ClusterName: "b"})

	got := b.Pop()
	if got.ClusterName != "a" {
		t.Errorf("first Pop = %q, want %q", got.ClusterName, "a")
	}

	b.Push(&pb.MetricsBatch{ClusterName: "c"})
	if b.Len() != 2 {
		t.Errorf("Len() = %d, want 2", b.Len())
	}

	got = b.Pop()
	if got.ClusterName != "b" {
		t.Errorf("second Pop = %q, want %q", got.ClusterName, "b")
	}
}

func TestBuffer_ConcurrentAccess(t *testing.T) {
	b := NewBuffer(100)
	var wg sync.WaitGroup

	// Push from multiple goroutines
	for range 10 {
		wg.Go(func() {
			for range 50 {
				b.Push(&pb.MetricsBatch{ClusterName: "test"})
			}
		})
	}

	// Pop from multiple goroutines
	for range 5 {
		wg.Go(func() {
			for range 20 {
				b.Pop()
			}
		})
	}

	wg.Wait()

	// Just verify no panic/race — exact count depends on scheduling
	if b.Len() < 0 {
		t.Error("Len() should not be negative")
	}
}
