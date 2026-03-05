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
	TLSEnabled             bool
	TLSCACert              string
	TLSServerName          string

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
		TLSEnabled:             getEnvBool("INGESTER_TLS_ENABLED", false),
		TLSCACert:              getEnv("INGESTER_TLS_CA", ""),
		TLSServerName:          getEnv("INGESTER_TLS_SERVER_NAME", ""),
	}
}

// ReconnectBackoff returns the next backoff duration using exponential backoff
// with a cap of 5 minutes.
func (c *Config) ReconnectBackoff() time.Duration {
	c.reconnectAttempts++
	secs := math.Min(float64(int(1)<<c.reconnectAttempts), 300)
	return time.Duration(secs) * time.Second
}

// ResetBackoff resets the reconnect backoff counter after a successful connection.
func (c *Config) ResetBackoff() {
	c.reconnectAttempts = 0
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		return v == "true" || v == "1" || v == "yes"
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
