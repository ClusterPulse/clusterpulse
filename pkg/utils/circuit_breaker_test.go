package utils

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCircuitBreaker_ClosedState(t *testing.T) {
	cb := NewCircuitBreaker(3, time.Second)
	err := cb.Call(t.Context(), func(_ context.Context) error {
		return nil
	})
	if err != nil {
		t.Errorf("closed circuit should pass: %v", err)
	}
}

func TestCircuitBreaker_OpensOnThreshold(t *testing.T) {
	cb := NewCircuitBreaker(2, time.Second)
	fail := errors.New("fail")

	for range 2 {
		cb.Call(t.Context(), func(_ context.Context) error { return fail })
	}

	err := cb.Call(t.Context(), func(_ context.Context) error { return nil })
	if err == nil {
		t.Fatal("circuit should be open after threshold failures")
	}
	if err.Error() != "circuit breaker is open" {
		t.Errorf("got %q, want circuit breaker is open", err.Error())
	}
}

func TestCircuitBreaker_RejectsWhenOpen(t *testing.T) {
	cb := NewCircuitBreaker(1, time.Hour)
	cb.Call(t.Context(), func(_ context.Context) error { return errors.New("x") })

	err := cb.Call(t.Context(), func(_ context.Context) error { return nil })
	if err == nil {
		t.Error("open circuit should reject")
	}
}

func TestCircuitBreaker_HalfOpenAfterTimeout(t *testing.T) {
	cb := NewCircuitBreaker(1, time.Millisecond)
	cb.Call(t.Context(), func(_ context.Context) error { return errors.New("x") })
	time.Sleep(5 * time.Millisecond)

	// Should transition to half-open and allow the call
	err := cb.Call(t.Context(), func(_ context.Context) error { return nil })
	if err != nil {
		t.Errorf("half-open should allow call: %v", err)
	}
}

func TestCircuitBreaker_ClosesOnSuccess(t *testing.T) {
	cb := NewCircuitBreaker(1, time.Millisecond)
	cb.Call(t.Context(), func(_ context.Context) error { return errors.New("x") })
	time.Sleep(5 * time.Millisecond)

	// Success in half-open -> closed
	cb.Call(t.Context(), func(_ context.Context) error { return nil })

	// Should be closed now, multiple calls should work
	for range 3 {
		err := cb.Call(t.Context(), func(_ context.Context) error { return nil })
		if err != nil {
			t.Fatalf("circuit should be closed: %v", err)
		}
	}
}

func TestCircuitBreaker_ReopensOnFailure(t *testing.T) {
	cb := NewCircuitBreaker(1, time.Millisecond)
	cb.Call(t.Context(), func(_ context.Context) error { return errors.New("x") })
	time.Sleep(5 * time.Millisecond)

	// Failure in half-open -> open again
	cb.Call(t.Context(), func(_ context.Context) error { return errors.New("y") })

	err := cb.Call(t.Context(), func(_ context.Context) error { return nil })
	if err == nil {
		t.Error("circuit should be open again after failure in half-open")
	}
}
