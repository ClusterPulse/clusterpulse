package main

import (
	"flag"
	"os"
	"strings"

	"github.com/clusterpulse/cluster-controller/internal/config"
	clusterctrl "github.com/clusterpulse/cluster-controller/internal/controller/cluster"
	metricsourcectrl "github.com/clusterpulse/cluster-controller/internal/controller/metricsource"
	policyctrl "github.com/clusterpulse/cluster-controller/internal/controller/policy"
	registryctrl "github.com/clusterpulse/cluster-controller/internal/controller/registry"
	redis "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	clusterv1alpha1 "github.com/clusterpulse/cluster-controller/api/v1alpha1"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(clusterv1alpha1.AddToScheme(scheme))
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var watchNamespace string

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&watchNamespace, "namespace", "", "Namespace to watch for ClusterConnections. If empty, uses NAMESPACE env var")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")

	opts := zap.Options{
		Development: false,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	// Configure log level from environment
	logLevel := strings.ToLower(os.Getenv("LOG_LEVEL"))
	if logLevel == "" {
		logLevel = "info"
	}

	switch logLevel {
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
		opts.Development = true
	case "warn", "warning":
		logrus.SetLevel(logrus.WarnLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	case "trace":
		logrus.SetLevel(logrus.TraceLevel)
	default:
		logrus.SetLevel(logrus.InfoLevel)
		logLevel = "info"
	}

	logrus.SetFormatter(&logrus.TextFormatter{
		DisableTimestamp: false,
		TimestampFormat:  "15:04:05",
		DisableColors:    false,
		QuoteEmptyFields: false,
	})

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Load configuration
	cfg := config.Load()

	// Determine namespace to watch
	if watchNamespace == "" {
		watchNamespace = cfg.Namespace
	}

	if watchNamespace == "" {
		setupLog.Error(nil, "namespace must be specified via --namespace flag or NAMESPACE env var")
		os.Exit(1)
	}

	logrus.WithFields(logrus.Fields{
		"namespace": watchNamespace,
		"logLevel":  logLevel,
		"version":   "0.3.0",
	}).Info("ClusterPulse Cluster Controller starting")

	// Initialize Redis client
	redisClient, err := redis.NewClient(cfg)
	if err != nil {
		setupLog.Error(err, "unable to create redis client")
		os.Exit(1)
	}
	defer redisClient.Close()

	logrus.Info("Connected to Redis successfully")

	// Create manager with namespace scope
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		Cache: cache.Options{
			DefaultNamespaces: map[string]cache.Config{
				watchNamespace: {},
			},
		},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          enableLeaderElection,
		LeaderElectionID:        "cluster-controller.clusterpulse.io",
		LeaderElectionNamespace: watchNamespace,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Setup cluster controller
	if err = (&clusterctrl.ClusterReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		RedisClient:    redisClient,
		Config:         cfg,
		WatchNamespace: watchNamespace,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterConnection")
		os.Exit(1)
	}

	// Setup registry controller
	if err = (&registryctrl.RegistryReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		RedisClient:    redisClient,
		Config:         cfg,
		WatchNamespace: watchNamespace,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "RegistryConnection")
		os.Exit(1)
	}

	// Setup MetricSource controller
	if err = (&metricsourcectrl.MetricSourceReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		RedisClient:    redisClient,
		Config:         cfg,
		WatchNamespace: watchNamespace,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "MetricSource")
		os.Exit(1)
	}

	// Setup Policy controller
	if err = (&policyctrl.PolicyReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		RedisClient:    redisClient,
		Config:         cfg,
		WatchNamespace: watchNamespace,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "MonitorAccessPolicy")
		os.Exit(1)
	}

	// Register periodic policy validator
	if err = mgr.Add(&policyctrl.PeriodicValidator{
		RedisClient: redisClient,
		Config:      cfg,
	}); err != nil {
		setupLog.Error(err, "unable to add periodic policy validator")
		os.Exit(1)
	}

	// Register startup eval cache cleaner
	if err = mgr.Add(&policyctrl.EvalCacheCleaner{
		RedisClient: redisClient,
	}); err != nil {
		setupLog.Error(err, "unable to add eval cache cleaner")
		os.Exit(1)
	}

	logrus.Info("Controllers initialized successfully")

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	logrus.Info("Starting controller manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
