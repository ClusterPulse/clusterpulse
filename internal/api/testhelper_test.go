package api

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/clusterpulse/cluster-controller/internal/config"
	"github.com/clusterpulse/cluster-controller/internal/rbac"
	store "github.com/clusterpulse/cluster-controller/internal/store"
)

func newTestStoreAndEngine(t *testing.T) (*store.Client, *rbac.Engine, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	host, portStr, _ := net.SplitHostPort(mr.Addr())
	port, _ := strconv.Atoi(portStr)
	cfg := &config.Config{RedisHost: host, RedisPort: port, CacheTTL: 600, MetricsRetention: 3600}
	s, err := store.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	engine := rbac.NewEngine(s, 0)
	return s, engine, mr
}

func testAPIConfig() *APIConfig {
	return &APIConfig{
		Config:          &config.Config{CacheTTL: 600, MetricsRetention: 3600},
		Port:            8080,
		Host:            "127.0.0.1",
		Environment:     "development",
		OAuthHeaderUser: "X-Forwarded-User",
		OAuthHeaderEmail: "X-Forwarded-Email",
	}
}

func testPrincipal() *rbac.Principal {
	return &rbac.Principal{
		Username: "alice",
		Email:    "alice@example.com",
		Groups:   []string{"admins"},
	}
}

func requestWithPrincipal(r *http.Request, p *rbac.Principal) *http.Request {
	ctx := context.WithValue(r.Context(), principalKey, p)
	return r.WithContext(ctx)
}
