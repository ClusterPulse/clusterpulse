package api

import (
	"os"
	"strconv"
	"strings"

	"github.com/clusterpulse/cluster-controller/internal/config"
	"github.com/sirupsen/logrus"
)

// APIConfig holds API-specific configuration, embedding the shared Config.
type APIConfig struct {
	*config.Config

	Port              int
	Host              string
	CORSOrigins       []string
	OAuthProxyEnabled bool
	OAuthHeaderUser   string
	OAuthHeaderEmail  string
	Environment       string
	RBACCacheTTL      int
}

// LoadAPIConfig loads API configuration from environment variables.
func LoadAPIConfig() *APIConfig {
	cfg := &APIConfig{
		Config:            config.Load(),
		Port:              envInt("API_PORT", 8080),
		Host:              envStr("API_HOST", "0.0.0.0"),
		CORSOrigins:       strings.Split(envStr("CORS_ORIGINS", "*"), ","),
		OAuthProxyEnabled: envBool("OAUTH_PROXY_ENABLED", true),
		OAuthHeaderUser:   envStr("OAUTH_HEADER_USER", "X-Forwarded-User"),
		OAuthHeaderEmail:  envStr("OAUTH_HEADER_EMAIL", "X-Forwarded-Email"),
		Environment:       envStr("ENVIRONMENT", "production"),
		RBACCacheTTL:      envInt("RBAC_CACHE_TTL", 0),
	}

	logrus.WithFields(logrus.Fields{
		"port":        cfg.Port,
		"environment": cfg.Environment,
		"oauthProxy":  cfg.OAuthProxyEnabled,
		"cacheTTL":    cfg.RBACCacheTTL,
	}).Info("API configuration loaded")

	return cfg
}

// IsDevelopment returns true if running in development mode.
func (c *APIConfig) IsDevelopment() bool {
	return c.Environment == "development"
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}
