package config

import (
	"github.com/clusterpulse/cluster-controller/pkg/types"
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
	NodeMetricsInterval    int
	OperatorScanInterval   int
	CacheTTL               int
	MetricsRetention       int
	ConnectTimeout         int

	// Resource thresholds
	CPUWarningThreshold     float64
	CPUCriticalThreshold    float64
	MemoryWarningThreshold  float64
	MemoryCriticalThreshold float64
	NodeUnhealthyThreshold  float64

	// Resource Collection Settings
	ResourceCollection types.CollectionConfig
}

// Load loads configuration from environment variables
func Load() *Config {
	cfg := &Config{
		Namespace:               getEnv("NAMESPACE", "clusterpulse"),
		RedisHost:               getEnv("REDIS_HOST", "redis"),
		RedisPort:               getEnvInt("REDIS_PORT", 6379),
		RedisPassword:           getEnv("REDIS_PASSWORD", ""),
		RedisDB:                 getEnvInt("REDIS_DB", 0),
		ReconciliationInterval:  getEnvIntWithMin("RECONCILIATION_INTERVAL", 30, 30),
		NodeMetricsInterval:     getEnvIntWithMin("NODE_METRICS_INTERVAL", 15, 15),
		OperatorScanInterval:    getEnvIntWithMin("OPERATOR_SCAN_INTERVAL", 300, 60),
		CacheTTL:                getEnvIntWithMin("CACHE_TTL", 600, 60),
		MetricsRetention:        getEnvIntWithMin("METRICS_RETENTION", 3600, 300),
		ConnectTimeout:          getEnvIntWithMin("CONNECT_TIMEOUT", 10, 5),
		CPUWarningThreshold:     getEnvFloat("CPU_WARNING_THRESHOLD", 85),
		CPUCriticalThreshold:    getEnvFloat("CPU_CRITICAL_THRESHOLD", 90),
		MemoryWarningThreshold:  getEnvFloat("MEMORY_WARNING_THRESHOLD", 85),
		MemoryCriticalThreshold: getEnvFloat("MEMORY_CRITICAL_THRESHOLD", 90),
		NodeUnhealthyThreshold:  getEnvFloat("NODE_UNHEALTHY_THRESHOLD", 0.5),

		// Resource Collection Configuration
		ResourceCollection: types.CollectionConfig{
			// Enable/disable resource collection (default: enabled)
			Enabled: getEnvBool("RESOURCE_COLLECTION_ENABLED", true),

			// Limits to prevent memory issues on large clusters
			MaxPodsPerNS:   getEnvIntWithMin("MAX_PODS_PER_NAMESPACE", 100, 10),
			MaxTotalPods:   getEnvIntWithMin("MAX_TOTAL_PODS", 1000, 50),
			MaxDeployments: getEnvIntWithMin("MAX_DEPLOYMENTS", 500, 10),
			MaxServices:    getEnvIntWithMin("MAX_SERVICES", 500, 10),

			// Include labels (increases memory usage but needed for RBAC)
			IncludeLabels: getEnvBool("COLLECT_RESOURCE_LABELS", false),

			// Optional namespace filter (e.g., to exclude system namespaces)
			NamespaceFilter: getEnv("RESOURCE_NAMESPACE_FILTER", ""),
		},
	}

	// Only log essential configuration at Info level
	logrus.WithFields(logrus.Fields{
		"namespace":         cfg.Namespace,
		"redis":             cfg.RedisHost + ":" + strconv.Itoa(cfg.RedisPort),
		"reconcileInterval": cfg.ReconciliationInterval,
	}).Info("Configuration loaded")

	// Log detailed configuration at Debug level
	logrus.Debugf("Detailed configuration:")
	logrus.Debugf("  Node Metrics Interval: %d seconds", cfg.NodeMetricsInterval)
	logrus.Debugf("  Operator Scan Interval: %d seconds", cfg.OperatorScanInterval)
	logrus.Debugf("  Cache TTL: %d seconds", cfg.CacheTTL)
	logrus.Debugf("  CPU Warning Threshold: %.0f%%", cfg.CPUWarningThreshold)
	logrus.Debugf("  CPU Critical Threshold: %.0f%%", cfg.CPUCriticalThreshold)
	logrus.Debugf("  Memory Warning Threshold: %.0f%%", cfg.MemoryWarningThreshold)
	logrus.Debugf("  Memory Critical Threshold: %.0f%%", cfg.MemoryCriticalThreshold)

	if cfg.ResourceCollection.Enabled {
		logrus.Debug("Resource collection enabled")
		logrus.Debugf("  Max Pods per Namespace: %d", cfg.ResourceCollection.MaxPodsPerNS)
		logrus.Debugf("  Max Total Pods: %d", cfg.ResourceCollection.MaxTotalPods)
		logrus.Debugf("  Max Deployments: %d", cfg.ResourceCollection.MaxDeployments)
		logrus.Debugf("  Max Services: %d", cfg.ResourceCollection.MaxServices)
		logrus.Debugf("  Include Labels: %v", cfg.ResourceCollection.IncludeLabels)
	}

	return cfg
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		} else {
			logrus.Debugf("Invalid boolean value for %s: %s, using default %v", key, value, defaultValue)
		}
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

func getEnvIntWithMin(key string, defaultValue, minValue int) int {
	value := getEnvInt(key, defaultValue)
	if value < minValue {
		logrus.Debugf("%s value %d is below minimum %d, using minimum", key, value, minValue)
		return minValue
	}
	return value
}

func getEnvFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
			return floatVal
		} else {
			logrus.Debugf("Invalid float value for %s: %s, using default %f", key, value, defaultValue)
		}
	}
	return defaultValue
}
