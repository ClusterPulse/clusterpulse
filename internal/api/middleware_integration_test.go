package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthMiddleware_ValidUser(t *testing.T) {
	cfg := testAPIConfig()
	cfg.OAuthProxyEnabled = true

	var gotPrincipal bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := GetPrincipal(r)
		gotPrincipal = p != nil && p.Username == "alice"
		w.WriteHeader(http.StatusOK)
	})

	handler := AuthMiddleware(cfg)(inner)
	req := httptest.NewRequest("GET", "/api/v1/clusters", nil)
	req.Header.Set("X-Forwarded-User", "alice")
	req.Header.Set("X-Forwarded-Email", "alice@example.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
	if !gotPrincipal {
		t.Error("principal should be set in context")
	}
}

func TestAuthMiddleware_MissingUser(t *testing.T) {
	cfg := testAPIConfig()
	cfg.OAuthProxyEnabled = true

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})

	handler := AuthMiddleware(cfg)(inner)
	req := httptest.NewRequest("GET", "/api/v1/clusters", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestAuthMiddleware_SkipsHealthz(t *testing.T) {
	cfg := testAPIConfig()
	cfg.OAuthProxyEnabled = true

	var called bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := AuthMiddleware(cfg)(inner)
	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("healthz should bypass auth")
	}
}

func TestAuthMiddleware_DevModeFallback(t *testing.T) {
	cfg := testAPIConfig()
	cfg.Environment = "development"
	cfg.OAuthProxyEnabled = false
	cfg.EnableDevAuth = true

	var username string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := GetPrincipal(r)
		if p != nil {
			username = p.Username
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := AuthMiddleware(cfg)(inner)
	req := httptest.NewRequest("GET", "/api/v1/clusters", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if username != "dev-user" {
		t.Errorf("username = %q, want dev-user", username)
	}
}

func TestOptionalAuthMiddleware_NoUser(t *testing.T) {
	cfg := testAPIConfig()
	cfg.OAuthProxyEnabled = true

	var called bool
	var principalNil bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		principalNil = GetPrincipal(r) == nil
		w.WriteHeader(http.StatusOK)
	})

	handler := OptionalAuthMiddleware(cfg)(inner)
	req := httptest.NewRequest("GET", "/api/v1/auth/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("handler should be called with optional auth")
	}
	if !principalNil {
		t.Error("principal should be nil when no user header")
	}
}

func TestOptionalAuthMiddleware_WithUser(t *testing.T) {
	cfg := testAPIConfig()
	cfg.OAuthProxyEnabled = true

	var gotUsername string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := GetPrincipal(r)
		if p != nil {
			gotUsername = p.Username
		}
	})

	handler := OptionalAuthMiddleware(cfg)(inner)
	req := httptest.NewRequest("GET", "/api/v1/auth/status", nil)
	req.Header.Set("X-Forwarded-User", "bob")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if gotUsername != "bob" {
		t.Errorf("username = %q, want bob", gotUsername)
	}
}

func TestSecurityHeaders_Integration(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	expected := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":       "DENY",
		"X-XSS-Protection":      "1; mode=block",
		"Referrer-Policy":       "strict-origin-when-cross-origin",
	}
	for header, want := range expected {
		if got := w.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

