package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clusterpulse/cluster-controller/internal/rbac"
)

func TestGetPrincipal_FromContext(t *testing.T) {
	p := &rbac.Principal{Username: "alice"}
	ctx := context.WithValue(t.Context(), principalKey, p)
	r, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	got := GetPrincipal(r)
	if got == nil || got.Username != "alice" {
		t.Errorf("got %v, want alice", got)
	}
}

func TestGetPrincipal_Missing(t *testing.T) {
	r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	if got := GetPrincipal(r); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestSecurityHeaders(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	handler.ServeHTTP(w, r)

	expected := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":       "DENY",
		"X-Xss-Protection":      "1; mode=block",
		"Referrer-Policy":       "strict-origin-when-cross-origin",
	}
	for k, v := range expected {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

func TestResolveGroups_NilClient_Dev(t *testing.T) {
	groups := resolveGroups(t.Context(), nil, "user", true)
	if len(groups) != 2 || groups[0] != "developers" {
		t.Errorf("dev mode nil client should return dev groups, got %v", groups)
	}
}

func TestResolveGroups_NilClient_Prod(t *testing.T) {
	groups := resolveGroups(t.Context(), nil, "user", false)
	if groups != nil {
		t.Errorf("prod mode nil client should return nil, got %v", groups)
	}
}
