package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthStatus_Authenticated(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	h := NewAuthHandler(s, engine, testAPIConfig())

	req := httptest.NewRequest("GET", "/api/v1/auth/status", nil)
	req = requestWithPrincipal(req, testPrincipal())
	w := httptest.NewRecorder()

	h.AuthStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["authenticated"] != true {
		t.Errorf("authenticated = %v", resp["authenticated"])
	}
	user := resp["user"].(map[string]any)
	if user["username"] != "alice" {
		t.Errorf("username = %v", user["username"])
	}
}

func TestAuthStatus_Unauthenticated(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	h := NewAuthHandler(s, engine, testAPIConfig())

	req := httptest.NewRequest("GET", "/api/v1/auth/status", nil)
	w := httptest.NewRecorder()

	h.AuthStatus(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["authenticated"] != false {
		t.Errorf("authenticated = %v", resp["authenticated"])
	}
}

func TestGetMe_Authenticated(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	h := NewAuthHandler(s, engine, testAPIConfig())

	req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	req = requestWithPrincipal(req, testPrincipal())
	w := httptest.NewRecorder()

	h.GetMe(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["username"] != "alice" {
		t.Errorf("username = %v", resp["username"])
	}
	if resp["email"] != "alice@example.com" {
		t.Errorf("email = %v", resp["email"])
	}
}

func TestGetMe_Unauthenticated(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	h := NewAuthHandler(s, engine, testAPIConfig())

	req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	w := httptest.NewRecorder()
	h.GetMe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestGetPermissions_Unauthenticated(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	h := NewAuthHandler(s, engine, testAPIConfig())

	req := httptest.NewRequest("GET", "/api/v1/auth/permissions", nil)
	w := httptest.NewRecorder()
	h.GetPermissions(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestGetPermissions_Authenticated(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	h := NewAuthHandler(s, engine, testAPIConfig())

	req := httptest.NewRequest("GET", "/api/v1/auth/permissions", nil)
	req = requestWithPrincipal(req, testPrincipal())
	w := httptest.NewRecorder()
	h.GetPermissions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["user"] == nil {
		t.Error("response should include user")
	}
	if resp["summary"] == nil {
		t.Error("response should include summary")
	}
}

func TestLogout(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	cfg := testAPIConfig()
	h := NewAuthHandler(s, engine, cfg)

	req := httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	req = requestWithPrincipal(req, testPrincipal())
	w := httptest.NewRecorder()
	h.Logout(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["message"] != "Logout successful" {
		t.Errorf("message = %v", resp["message"])
	}
}

func TestClearCache(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	h := NewAuthHandler(s, engine, testAPIConfig())

	req := httptest.NewRequest("POST", "/api/v1/auth/cache/clear", nil)
	req = requestWithPrincipal(req, testPrincipal())
	w := httptest.NewRecorder()
	h.ClearCache(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["user"] != "alice" {
		t.Errorf("user = %v", resp["user"])
	}
}
