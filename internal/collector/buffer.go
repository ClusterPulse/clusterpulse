package collector

import (
	"sync"

	pb "github.com/clusterpulse/cluster-controller/proto/collectorpb"
)

// Buffer is a bounded FIFO buffer for MetricsBatch messages during network outages.
// When the buffer is full, the oldest batch is dropped.
type Buffer struct {
	mu      sync.Mutex
	items   []*pb.MetricsBatch
	maxSize int
}

// NewBuffer creates a new buffer with the given capacity.
func NewBuffer(maxSize int) *Buffer {
	if maxSize <= 0 {
		maxSize = 10
	}
	return &Buffer{
		items:   make([]*pb.MetricsBatch, 0, maxSize),
		maxSize: maxSize,
	}
}

// Push adds a batch to the buffer. If full, the oldest batch is dropped.
func (b *Buffer) Push(batch *pb.MetricsBatch) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.items) >= b.maxSize {
		// Drop oldest
		b.items = b.items[1:]
	}
	b.items = append(b.items, batch)
}

// Pop removes and returns the oldest batch, or nil if empty.
func (b *Buffer) Pop() *pb.MetricsBatch {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.items) == 0 {
		return nil
	}
	batch := b.items[0]
	b.items = b.items[1:]
	return batch
}

// Len returns the number of buffered batches.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}
