package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/clusterpulse/cluster-controller/internal/collector"
	"github.com/clusterpulse/cluster-controller/internal/version"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	// Configure logging
	logLevel := strings.ToLower(os.Getenv("LOG_LEVEL"))
	switch logLevel {
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "warn":
		logrus.SetLevel(logrus.WarnLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	default:
		logrus.SetLevel(logrus.InfoLevel)
	}
	logrus.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: "15:04:05",
	})

	cfg := collector.LoadConfig()

	if cfg.ClusterName == "" {
		logrus.Fatal("CLUSTER_NAME environment variable is required")
	}

	logrus.WithFields(logrus.Fields{
		"cluster":  cfg.ClusterName,
		"ingester": cfg.IngesterAddress,
		"version":  version.Version,
	}).Info("ClusterPulse Collector Agent starting")

	// Create in-cluster k8s client
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get in-cluster config")
	}

	dynamicClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create dynamic client")
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create kubernetes clientset")
	}

	agent := collector.NewAgent(cfg, dynamicClient, clientset)

	// Run with signal handling
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT, syscall.SIGTERM,
	)
	defer cancel()

	if err := agent.Run(ctx); err != nil {
		logrus.WithError(err).Fatal("Agent exited with error")
	}
}
