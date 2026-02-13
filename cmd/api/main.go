package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/clusterpulse/cluster-controller/internal/api"
	"github.com/clusterpulse/cluster-controller/internal/rbac"
	store "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/clusterpulse/cluster-controller/internal/version"
	"github.com/sirupsen/logrus"
)

func main() {
	// Configure logging
	logLevel := strings.ToLower(os.Getenv("LOG_LEVEL"))
	switch logLevel {
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "warn", "warning":
		logrus.SetLevel(logrus.WarnLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	case "trace":
		logrus.SetLevel(logrus.TraceLevel)
	default:
		logrus.SetLevel(logrus.InfoLevel)
	}

	logrus.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: "15:04:05",
		DisableColors:   false,
	})

	logrus.WithFields(logrus.Fields{
		"version": version.Version,
		"commit":  version.GitCommit,
	}).Info("ClusterPulse API starting")

	// Load configuration
	cfg := api.LoadAPIConfig()

	// Connect to Redis
	redisClient, err := store.NewClient(cfg.Config)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to connect to Redis")
	}
	defer redisClient.Close()
	logrus.Info("Connected to Redis")

	// Create RBAC engine
	engine := rbac.NewEngine(redisClient, cfg.RBACCacheTTL)
	logrus.WithField("cacheTTL", cfg.RBACCacheTTL).Info("RBAC engine initialized")

	// Create and start server
	server := api.NewServer(cfg, redisClient, engine)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if err := server.Start(ctx); err != nil {
		logrus.WithError(err).Fatal("API server error")
	}

	logrus.Info("API server stopped")
}
