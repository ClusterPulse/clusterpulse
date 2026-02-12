package pool

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/clusterpulse/cluster-controller/internal/client/cluster"
	"github.com/sirupsen/logrus"
)

// ClientPool manages a pool of cluster clients with automatic cleanup
type ClientPool struct {
	clients map[string]*cluster.ClusterClient
	mu      sync.RWMutex
	maxIdle time.Duration
}

// NewClientPool creates a new client pool
func NewClientPool(maxIdle time.Duration) *ClientPool {
	pool := &ClientPool{
		clients: make(map[string]*cluster.ClusterClient),
		maxIdle: maxIdle,
	}

	// Start cleanup goroutine
	go pool.cleanupLoop()

	return pool
}

// Get retrieves or creates a client for the given cluster
func (p *ClientPool) Get(name, endpoint, token string, caCert []byte) (*cluster.ClusterClient, error) {
	p.mu.RLock()
	client, exists := p.clients[name]
	p.mu.RUnlock()

	if exists {
		// Test if connection is still valid
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := client.TestConnection(ctx); err == nil {
			return client, nil
		}

		// Connection failed, remove and recreate
		logrus.Debugf("Client for %s failed connection test, recreating", name)
		p.Remove(name)
	}

	// Create new client
	client, err := cluster.NewClusterClient(name, endpoint, token, caCert)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	p.mu.Lock()
	p.clients[name] = client
	p.mu.Unlock()

	logrus.Debugf("Created new client for cluster %s", name)

	return client, nil
}

// Remove removes a client from the pool
func (p *ClientPool) Remove(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if client, exists := p.clients[name]; exists {
		client.Close()
		delete(p.clients, name)
		logrus.Debugf("Removed client for cluster %s", name)
	}
}

// cleanupLoop periodically removes idle clients
func (p *ClientPool) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		p.cleanupIdleClients()
	}
}

func (p *ClientPool) cleanupIdleClients() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	cleaned := 0
	for name, client := range p.clients {
		if now.Sub(client.GetLastUsed()) > p.maxIdle {
			logrus.Debugf("Removing idle client for cluster %s", name)
			client.Close()
			delete(p.clients, name)
			cleaned++
		}
	}

	if cleaned > 0 {
		logrus.Debugf("Cleaned up %d idle clients", cleaned)
	}
}

// Close closes all clients in the pool
func (p *ClientPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for name, client := range p.clients {
		client.Close()
		delete(p.clients, name)
	}

	logrus.Debug("Closed all clients in pool")
}
