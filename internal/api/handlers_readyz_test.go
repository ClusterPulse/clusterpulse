package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadyHandler_RedisUp(t *testing.T) {
	s, _, _ := newTestStoreAndEngine(t)

	handler := ReadyHandler(s)
	req := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestReadyHandler_RedisDown(t *testing.T) {
	s, _, mr := newTestStoreAndEngine(t)
	mr.Close()

	handler := ReadyHandler(s)
	req := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}
