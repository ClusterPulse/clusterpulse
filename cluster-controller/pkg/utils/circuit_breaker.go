package utils

import (
    "context"
    "fmt"
    "sync"
    "time"
)

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
    failureThreshold int
    recoveryTimeout  time.Duration
    failureCount     int
    lastFailureTime  time.Time
    state            string
    mu               sync.RWMutex
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
    return &CircuitBreaker{
        failureThreshold: threshold,
        recoveryTimeout:  timeout,
        state:            "closed",
    }
}

// Call executes a function with circuit breaker protection
func (cb *CircuitBreaker) Call(ctx context.Context, fn func(context.Context) error) error {
    cb.mu.Lock()
    
    if cb.state == "open" {
        if time.Since(cb.lastFailureTime) > cb.recoveryTimeout {
            cb.state = "half-open"
        } else {
            cb.mu.Unlock()
            return fmt.Errorf("circuit breaker is open")
        }
    }
    cb.mu.Unlock()
    
    err := fn(ctx)
    
    cb.mu.Lock()
    defer cb.mu.Unlock()
    
    if err != nil {
        cb.failureCount++
        cb.lastFailureTime = time.Now()
        
        if cb.failureCount >= cb.failureThreshold {
            cb.state = "open"
        }
        return err
    }
    
    if cb.state == "half-open" {
        cb.state = "closed"
        cb.failureCount = 0
    }
    
    return nil
}
