package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListRegistriesStatus_Unauthenticated(t *testing.T) {
	s, _, _ := newTestStoreAndEngine(t)
	h := NewRegistryHandler(s)

	req := httptest.NewRequest("GET", "/api/v1/registries/status", nil)
	w := httptest.NewRecorder()
	h.ListRegistriesStatus(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestListRegistriesStatus_Empty(t *testing.T) {
	s, _, _ := newTestStoreAndEngine(t)
	h := NewRegistryHandler(s)

	req := httptest.NewRequest("GET", "/api/v1/registries/status", nil)
	req = requestWithPrincipal(req, testPrincipal())
	w := httptest.NewRecorder()
	h.ListRegistriesStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 0 {
		t.Errorf("expected empty array, got %d items", len(resp))
	}
}

func TestListRegistriesStatus_WithData(t *testing.T) {
	s, _, _ := newTestStoreAndEngine(t)
	ctx := t.Context()
	h := NewRegistryHandler(s)

	s.StoreRegistrySpec(ctx, "quay", map[string]any{"url": "https://quay.io"})
	s.StoreRegistryStatus(ctx, "quay", map[string]any{"health": "healthy"})

	req := httptest.NewRequest("GET", "/api/v1/registries/status", nil)
	req = requestWithPrincipal(req, testPrincipal())
	w := httptest.NewRecorder()
	h.ListRegistriesStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp []map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 1 {
		t.Fatalf("expected 1 registry, got %d", len(resp))
	}
	if resp[0]["name"] != "quay" {
		t.Errorf("name = %v", resp[0]["name"])
	}
}
