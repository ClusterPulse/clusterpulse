package registry

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewDockerV2Client(t *testing.T) {
	tests := []struct {
		name         string
		endpoint     string
		user, pass   string
		wantEndpoint string
		wantAuth     bool
	}{
		{
			"adds https",
			"registry.example.com",
			"", "",
			"https://registry.example.com",
			false,
		},
		{
			"preserves https",
			"https://registry.example.com",
			"", "",
			"https://registry.example.com",
			false,
		},
		{
			"preserves http",
			"http://registry.local",
			"", "",
			"http://registry.local",
			false,
		},
		{
			"strips trailing slash",
			"https://registry.example.com/",
			"", "",
			"https://registry.example.com",
			false,
		},
		{
			"sets basic auth",
			"registry.example.com",
			"admin", "secret",
			"https://registry.example.com",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewDockerV2Client(tt.endpoint, tt.user, tt.pass, false, false)
			if c.endpoint != tt.wantEndpoint {
				t.Errorf("endpoint = %q, want %q", c.endpoint, tt.wantEndpoint)
			}
			if tt.wantAuth && c.authHeader == "" {
				t.Error("expected authHeader to be set")
			}
			if !tt.wantAuth && c.authHeader != "" {
				t.Error("expected authHeader to be empty")
			}
		})
	}
}

func TestNewDockerV2Client_AuthEncoding(t *testing.T) {
	c := NewDockerV2Client("registry.example.com", "user", "pass", false, false)
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
	if c.authHeader != expected {
		t.Errorf("authHeader = %q, want %q", c.authHeader, expected)
	}
}

func TestHealthCheck_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewDockerV2Client(srv.URL, "", "", false, false)
	result, err := c.HealthCheck(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Available {
		t.Error("expected Available = true")
	}
	if result.Version != "registry/2.0" {
		t.Errorf("Version = %q, want registry/2.0", result.Version)
	}
	if !result.Features["docker_v2_api"] {
		t.Error("expected docker_v2_api feature")
	}
	if result.ResponseTime <= 0 {
		t.Error("expected positive response time")
	}
}

func TestHealthCheck_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := NewDockerV2Client(srv.URL, "", "", false, false)
	result, err := c.HealthCheck(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Available {
		t.Error("expected Available = true (401 means registry exists)")
	}
	if !result.Features["requires_auth"] {
		t.Error("expected requires_auth feature")
	}
}

func TestHealthCheck_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewDockerV2Client(srv.URL, "", "", false, false)
	result, err := c.HealthCheck(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Available {
		t.Error("expected Available = false for 500")
	}
	if result.Error == "" {
		t.Error("expected error message")
	}
}

func TestHealthCheck_ConnectionRefused(t *testing.T) {
	c := NewDockerV2Client("http://127.0.0.1:1", "", "", false, false)
	result, err := c.HealthCheck(t.Context())
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
	if result.Available {
		t.Error("expected Available = false")
	}
}

func TestHealthCheck_SendsAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewDockerV2Client(srv.URL, "admin", "secret", false, false)
	_, err := c.HealthCheck(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth == "" {
		t.Error("expected Authorization header to be sent")
	}
	if gotAuth != c.authHeader {
		t.Errorf("auth header = %q, want %q", gotAuth, c.authHeader)
	}
}

func TestCheckCatalog_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/_catalog" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		resp := CatalogResponse{Repositories: []string{"app/frontend", "app/backend", "lib/redis"}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := NewDockerV2Client(srv.URL, "", "", false, false)
	catalog, err := c.CheckCatalog(t.Context(), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(catalog.Repositories) != 3 {
		t.Errorf("repo count = %d, want 3", len(catalog.Repositories))
	}
}

func TestCheckCatalog_WithMaxEntries(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		json.NewEncoder(w).Encode(CatalogResponse{})
	}))
	defer srv.Close()

	c := NewDockerV2Client(srv.URL, "", "", false, false)
	_, err := c.CheckCatalog(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery != "n=10" {
		t.Errorf("query = %q, want n=10", gotQuery)
	}
}

func TestCheckCatalog_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "access denied")
	}))
	defer srv.Close()

	c := NewDockerV2Client(srv.URL, "", "", false, false)
	_, err := c.CheckCatalog(t.Context(), 0)
	if err == nil {
		t.Fatal("expected error for 403")
	}
}

func TestDetectRegistryInfo(t *testing.T) {
	tests := []struct {
		name          string
		headers       map[string]string
		wantVersion   string
		wantFeatures  map[string]bool
	}{
		{
			"docker v2 api version",
			map[string]string{"Docker-Distribution-Api-Version": "registry/2.0"},
			"registry/2.0",
			map[string]bool{"docker_v2_api": true},
		},
		{
			"harbor detected",
			map[string]string{"Server": "Harbor/2.9.0"},
			"",
			map[string]bool{"harbor_detected": true},
		},
		{
			"artifactory detected",
			map[string]string{"Server": "Artifactory/7.x"},
			"",
			map[string]bool{"artifactory_detected": true},
		},
		{
			"nexus detected",
			map[string]string{"Server": "Nexus/3.x"},
			"",
			map[string]bool{"nexus_detected": true},
		},
		{
			"content digest",
			map[string]string{"Docker-Content-Digest": "sha256:abc123"},
			"",
			map[string]bool{"content_digest": true},
		},
		{
			"pagination support",
			map[string]string{"Link": "</v2/_catalog?n=10&last=repo>; rel=\"next\""},
			"",
			map[string]bool{"pagination": true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}

			result := &HealthCheckResult{Features: make(map[string]bool)}
			c := NewDockerV2Client("https://example.com", "", "", false, false)
			c.detectRegistryInfo(resp, result)

			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			for k, v := range tt.wantFeatures {
				if result.Features[k] != v {
					t.Errorf("Feature[%s] = %v, want %v", k, result.Features[k], v)
				}
			}
		})
	}
}

func TestExtendedHealthCheck_WithCatalog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/":
			w.WriteHeader(http.StatusOK)
		case "/v2/_catalog":
			json.NewEncoder(w).Encode(CatalogResponse{
				Repositories: []string{"app/web", "app/api"},
			})
		}
	}))
	defer srv.Close()

	c := NewDockerV2Client(srv.URL, "", "", false, false)
	result, err := c.ExtendedHealthCheck(t.Context(), true, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Available {
		t.Error("expected Available = true")
	}
	if !result.Features["catalog_accessible"] {
		t.Error("expected catalog_accessible = true")
	}
	if result.RepositoryCount != 2 {
		t.Errorf("RepositoryCount = %d, want 2", result.RepositoryCount)
	}
	if len(result.Repositories) != 2 {
		t.Errorf("Repositories count = %d, want 2 (<=20 so included)", len(result.Repositories))
	}
}

func TestExtendedHealthCheck_CatalogFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/":
			w.WriteHeader(http.StatusOK)
		case "/v2/_catalog":
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()

	c := NewDockerV2Client(srv.URL, "", "", false, false)
	result, err := c.ExtendedHealthCheck(t.Context(), true, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Available {
		t.Error("expected Available = true (v2 works)")
	}
	if result.Features["catalog_accessible"] {
		t.Error("expected catalog_accessible = false")
	}
}

func TestExtendedHealthCheck_SkipCatalog(t *testing.T) {
	catalogCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/_catalog" {
			catalogCalled = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewDockerV2Client(srv.URL, "", "", false, false)
	_, err := c.ExtendedHealthCheck(t.Context(), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if catalogCalled {
		t.Error("catalog should not be called when checkCatalog=false")
	}
}
