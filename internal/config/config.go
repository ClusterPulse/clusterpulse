package config

import (
	"github.com/sirupsen/logrus"
	"os"
	"strconv"
)

// Config holds application configuration
type Config struct {
	// Operator settings
	Namespace string

	// Redis settings
	RedisHost     string
	RedisPort     int
	RedisPassword string
	RedisDB       int

	// Timing configuration (in seconds)
	ReconciliationInterval int
	OperatorScanInterval   int
	CacheTTL               int
	MetricsRetention       int
	ConnectTimeout         int

	// Policy Controller Settings
	PolicyCacheTTL           int
	GroupCacheTTL            int
	MaxPoliciesPerUser       int
	PolicyValidationInterval int

	// Ingester Settings
	IngesterEnabled bool
	IngesterPort    int

	// VictoriaMetrics Settings
	VMEnabled  bool
	VMEndpoint string
}

// Load loads configuration from environment variables
func Load() *Config {
	cfg := &Config{
		Namespace:              getEnv("NAMESPACE", "clusterpulse"),
		RedisHost:              getEnv("REDIS_HOST", "redis"),
		RedisPort:              getEnvInt("REDIS_PORT", 6379),
		RedisPassword:          getEnv("REDIS_PASSWORD", ""),
		RedisDB:                getEnvInt("REDIS_DB", 0),
		ReconciliationInterval: getEnvIntWithMin("RECONCILIATION_INTERVAL", 30, 30),
		OperatorScanInterval:   getEnvIntWithMin("OPERATOR_SCAN_INTERVAL", 300, 60),
		CacheTTL:               getEnvIntWithMin("CACHE_TTL", 600, 60),
		MetricsRetention:       getEnvIntWithMin("METRICS_RETENTION", 3600, 300),
		ConnectTimeout:         getEnvIntWithMin("CONNECT_TIMEOUT", 10, 5),

		// Policy Controller Configuration
		PolicyCacheTTL:           getEnvIntWithMin("POLICY_CACHE_TTL", 300, 60),
		GroupCacheTTL:            getEnvIntWithMin("GROUP_CACHE_TTL", 300, 60),
		MaxPoliciesPerUser:       getEnvIntWithMin("MAX_POLICIES_PER_USER", 100, 1),
		PolicyValidationInterval: getEnvIntWithMin("POLICY_VALIDATION_INTERVAL", 300, 60),

		// Ingester Configuration
		IngesterEnabled: getEnvBool("INGESTER_ENABLED", true),
		IngesterPort:    getEnvIntWithMin("INGESTER_PORT", 9443, 1024),

		// VictoriaMetrics Configuration
		VMEnabled:  getEnvBool("VM_ENABLED", false),
		VMEndpoint: getEnv("VM_ENDPOINT", "http://victoriametrics:8428"),
	}

	// Only log essential configuration at Info level
	logrus.WithFields(logrus.Fields{
		"namespace":         cfg.Namespace,
		"redis":             cfg.RedisHost + ":" + strconv.Itoa(cfg.RedisPort),
		"reconcileInterval": cfg.ReconciliationInterval,
	}).Info("Configuration loaded")

	// Log detailed configuration at Debug level
	logrus.Debugf("  Operator Scan Interval: %d seconds", cfg.OperatorScanInterval)
	logrus.Debugf("  Cache TTL: %d seconds", cfg.CacheTTL)

	return cfg
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		} else {
			logrus.Debugf("Invalid integer value for %s: %s, using default %d", key, value, defaultValue)
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1" || value == "yes"
	}
	return defaultValue
}

func getEnvIntWithMin(key string, defaultValue, minValue int) int {
	value := getEnvInt(key, defaultValue)
	if value < minValue {
		logrus.Debugf("%s value %d is below minimum %d, using minimum", key, value, minValue)
		return minValue
	}
	return value
}
