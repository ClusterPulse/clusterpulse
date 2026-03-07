package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	store "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/go-chi/chi/v5"
)

func seedAllowPolicy(t *testing.T, s *store.Client, principal string, groups []string) {
	t.Helper()
	p := &types.CompiledPolicy{
		PolicyName:           "allow-all",
		Namespace:            "default",
		Priority:             100,
		Effect:               "Allow",
		Enabled:              true,
		Users:                []string{principal},
		Groups:               groups,
		DefaultClusterAccess: "allow",
		CompiledAt:           "2025-01-01T00:00:00Z",
		Hash:                 "test",
		ClusterRules: []types.CompiledClusterRule{
			{
				ClusterSelector: types.CompiledClusterSelector{MatchPattern: ".*"},
				Permissions:     map[string]bool{"view": true, "viewMetrics": true},
			},
		},
	}
	if err := s.StorePolicy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
}

func TestListClusters_Unauthenticated(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	h := NewClusterHandler(s, engine)

	req := httptest.NewRequest("GET", "/api/v1/clusters", nil)
	w := httptest.NewRecorder()
	h.ListClusters(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestListClusters_Empty(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	h := NewClusterHandler(s, engine)

	seedAllowPolicy(t, s, "alice", []string{"admins"})

	req := httptest.NewRequest("GET", "/api/v1/clusters", nil)
	req = requestWithPrincipal(req, testPrincipal())
	w := httptest.NewRecorder()
	h.ListClusters(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp []map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 0 {
		t.Errorf("expected empty, got %d", len(resp))
	}
}

func TestListClusters_WithData(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	ctx := t.Context()
	h := NewClusterHandler(s, engine)

	seedAllowPolicy(t, s, "alice", []string{"admins"})
	s.StoreClusterStatus(ctx, "cluster-1", map[string]any{"health": "healthy"})

	req := httptest.NewRequest("GET", "/api/v1/clusters", nil)
	req = requestWithPrincipal(req, testPrincipal())
	w := httptest.NewRecorder()
	h.ListClusters(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp []map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 1 {
		t.Fatalf("expected 1 cluster, got %d", len(resp))
	}
	if resp[0]["name"] != "cluster-1" {
		t.Errorf("name = %v", resp[0]["name"])
	}
}

func TestGetCluster_Accessible(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	ctx := t.Context()
	h := NewClusterHandler(s, engine)

	seedAllowPolicy(t, s, "alice", []string{"admins"})
	s.StoreClusterStatus(ctx, "c1", map[string]any{"health": "healthy"})
	s.StoreClusterInfo(ctx, "c1", map[string]any{"version": "4.14"})

	// Use chi router context for URL params
	r := chi.NewRouter()
	r.Get("/api/v1/clusters/{name}", func(w http.ResponseWriter, req *http.Request) {
		req = requestWithPrincipal(req, testPrincipal())
		h.GetCluster(w, req)
	})

	req := httptest.NewRequest("GET", "/api/v1/clusters/c1", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["name"] != "c1" {
		t.Errorf("name = %v", resp["name"])
	}
}

func TestGetCluster_Denied(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	ctx := t.Context()
	h := NewClusterHandler(s, engine)

	// No allow policy seeded → access denied
	s.StoreClusterStatus(ctx, "c1", map[string]any{"health": "healthy"})

	r := chi.NewRouter()
	r.Get("/api/v1/clusters/{name}", func(w http.ResponseWriter, req *http.Request) {
		req = requestWithPrincipal(req, testPrincipal())
		h.GetCluster(w, req)
	})

	req := httptest.NewRequest("GET", "/api/v1/clusters/c1", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestGetClusterNodes_Empty(t *testing.T) {
	s, engine, _ := newTestStoreAndEngine(t)
	h := NewClusterHandler(s, engine)

	seedAllowPolicy(t, s, "alice", []string{"admins"})
	s.StoreClusterStatus(t.Context(), "c1", map[string]any{"health": "ok"})

	r := chi.NewRouter()
	r.Get("/api/v1/clusters/{name}/nodes", func(w http.ResponseWriter, req *http.Request) {
		req = requestWithPrincipal(req, testPrincipal())
		h.GetClusterNodes(w, req)
	})

	req := httptest.NewRequest("GET", "/api/v1/clusters/c1/nodes", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp []map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 0 {
		t.Errorf("expected empty nodes, got %d", len(resp))
	}
}
