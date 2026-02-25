package collector

import (
	"math"
	"os"
	"strconv"
	"time"
)

// Config holds collector agent configuration, loaded from environment variables.
type Config struct {
	ClusterName            string
	IngesterAddress        string
	Token                  string
	CollectIntervalSeconds int
	BufferSize             int

	// Internal: tracks consecutive reconnection failures for backoff
	reconnectAttempts int
}

// LoadConfig loads collector configuration from environment variables.
func LoadConfig() *Config {
	return &Config{
		ClusterName:            getEnv("CLUSTER_NAME", ""),
		IngesterAddress:        getEnv("INGESTER_ADDRESS", "ingester:9443"),
		Token:                  getEnv("COLLECTOR_TOKEN", ""),
		CollectIntervalSeconds: getEnvInt("COLLECT_INTERVAL", 60),
		BufferSize:             getEnvInt("BUFFER_SIZE", 10),
	}
}

// ReconnectBackoff returns the next backoff duration using exponential backoff
// with a cap of 5 minutes.
func (c *Config) ReconnectBackoff() time.Duration {
	c.reconnectAttempts++
	secs := math.Min(float64(int(1)<<c.reconnectAttempts), 300)
	return time.Duration(secs) * time.Second
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
