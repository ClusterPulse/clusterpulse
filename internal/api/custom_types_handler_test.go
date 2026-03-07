package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListCustomTypes_Unauthenticated(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	h := NewCustomTypeHandler(s, engine)

	req := httptest.NewRequest("GET", "/api/v1/custom-types", nil)
	w := httptest.NewRecorder()
	h.ListCustomTypes(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestListCustomTypes_Empty(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	h := NewCustomTypeHandler(s, engine)

	req := httptest.NewRequest("GET", "/api/v1/custom-types", nil)
	req = requestWithPrincipal(req, testPrincipal())
	w := httptest.NewRecorder()
	h.ListCustomTypes(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp []map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 0 {
		t.Errorf("expected empty, got %d", len(resp))
	}
}

func TestGetCustomResourceCounts_Unauthenticated(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	h := NewCustomTypeHandler(s, engine)

	req := httptest.NewRequest("GET", "/api/v1/custom-types/clusters?type=vms", nil)
	w := httptest.NewRecorder()
	h.GetCustomResourceCounts(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestGetCustomResourceCounts_NoTypeParam(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	h := NewCustomTypeHandler(s, engine)

	req := httptest.NewRequest("GET", "/api/v1/custom-types/clusters", nil)
	req = requestWithPrincipal(req, testPrincipal())
	w := httptest.NewRecorder()
	h.GetCustomResourceCounts(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestGetCustomResourceCounts_DeniedType(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	h := NewCustomTypeHandler(s, engine)

	// Policy without custom resource type grants → type access denied
	seedAllowPolicy(t, s, "alice", []string{"admins"})

	req := httptest.NewRequest("GET", "/api/v1/custom-types/clusters?type=virtualmachines", nil)
	req = requestWithPrincipal(req, testPrincipal())
	w := httptest.NewRecorder()
	h.GetCustomResourceCounts(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}
