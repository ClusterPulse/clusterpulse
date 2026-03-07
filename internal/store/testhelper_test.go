package redis

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/clusterpulse/cluster-controller/internal/config"
	goredis "github.com/go-redis/redis/v8"
)

func newTestClient(t *testing.T) (*Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	cfg := &config.Config{
		CacheTTL:         600,
		MetricsRetention: 3600,
	}
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	return &Client{client: rdb, config: cfg}, mr
}
