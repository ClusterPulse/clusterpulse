package cluster

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
	"github.com/clusterpulse/cluster-controller/internal/client/cluster"
	"github.com/clusterpulse/cluster-controller/internal/client/pool"
	"github.com/clusterpulse/cluster-controller/internal/config"
	"github.com/clusterpulse/cluster-controller/internal/ingester"
	"github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// ClusterReconciler reconciles a ClusterConnection object
type ClusterReconciler struct {
	k8sclient.Client
	Scheme            *runtime.Scheme
	RedisClient       *redis.Client
	Config            *config.Config
	WatchNamespace    string
	Ingester          *ingester.Server
	clientPool        *pool.ClientPool
	lastOperatorFetch map[string]time.Time // Track last operator fetch time per cluster
}

// SetupWithManager sets up the controller with the Manager
func (r *ClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.clientPool = pool.NewClientPool(30 * time.Minute)
	r.lastOperatorFetch = make(map[string]time.Time)

	// Only reconcile on spec changes (generation bump) or creation/deletion.
	// Status-only patches do not increment generation, so they won't re-trigger.
	// Periodic reconciliation still works via RequeueAfter.
	pred := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ClusterConnection{}).
		WithEventFilter(pred).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 3,
		}).
		Complete(r)
}

// getReconcileInterval determines the reconciliation interval for a cluster
func (r *ClusterReconciler) getReconcileInterval(clusterConn *v1alpha1.ClusterConnection) int {
	// Default to config value
	interval := r.Config.ReconciliationInterval

	// Override with spec value if set and valid
	if clusterConn.Spec.Monitoring.Interval > 0 {
		specInterval := int(clusterConn.Spec.Monitoring.Interval)
		// Enforce minimum interval of 30 seconds
		if specInterval >= 30 {
			interval = specInterval
		} else {
			logrus.WithField("cluster", clusterConn.Name).Debugf("Requested interval %d, using minimum of 30",
				specInterval)
			interval = 30
		}
	}

	return interval
}

// Reconcile handles ClusterConnection reconciliation
func (r *ClusterReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	startTime := time.Now()

	log := logrus.WithFields(logrus.Fields{
		"cluster":   req.Name,
		"namespace": req.Namespace,
	})

	// Fetch the ClusterConnection instance
	clusterConn := &v1alpha1.ClusterConnection{}
	err := r.Get(ctx, req.NamespacedName, clusterConn)
	if err != nil {
		if errors.IsNotFound(err) {
			// Object deleted
			log.Debug("ClusterConnection deleted, cleaning up")
			delete(r.lastOperatorFetch, clusterConn.Name)
			return r.handleDeletion(ctx, req.Name)
		}
		return reconcile.Result{}, err
	}

	// Handle deletion
	if !clusterConn.DeletionTimestamp.IsZero() {
		delete(r.lastOperatorFetch, clusterConn.Name)
		return r.handleDeletion(ctx, req.Name)
	}

	// Determine reconciliation interval
	interval := r.getReconcileInterval(clusterConn)

	log.Debug("Starting reconciliation")

	// For push-mode clusters, update collector status and skip pull-based collection
	// if the collector is actively connected.
	if clusterConn.Spec.CollectionMode == "push" && r.Ingester != nil {
		connected, lastHeartbeat, ver := r.Ingester.GetConnectionInfo(clusterConn.Name)

		// Only patch CollectorStatus if it actually changed
		cs := clusterConn.Status.CollectorStatus
		statusChanged := cs == nil ||
			cs.Connected != connected ||
			cs.Version != ver

		if statusChanged {
			originalClusterConn := clusterConn.DeepCopy()
			if clusterConn.Status.CollectorStatus == nil {
				clusterConn.Status.CollectorStatus = &v1alpha1.CollectorAgentStatus{}
			}
			clusterConn.Status.CollectorStatus.Connected = connected
			clusterConn.Status.CollectorStatus.Version = ver
			if !lastHeartbeat.IsZero() {
				hb := metav1.NewTime(lastHeartbeat)
				clusterConn.Status.CollectorStatus.LastHeartbeat = &hb
			}

			if err := r.Status().Patch(ctx, clusterConn, k8sclient.MergeFrom(originalClusterConn)); err != nil {
				log.WithError(err).Debug("Failed to patch collector status")
			}
		}

		if connected {
			log.Debug("Push-mode collector connected, skipping pull-based collection")
			return reconcile.Result{RequeueAfter: time.Duration(interval) * time.Second}, nil
		}

		// Collector not connected — ensure it's deployed, then wait
		if err := r.ensureCollectorDeployed(ctx, clusterConn); err != nil {
			log.WithError(err).Warn("Failed to deploy collector agent")
		}

		log.Debug("Push-mode collector not yet connected, waiting for connection")
		return reconcile.Result{RequeueAfter: time.Duration(interval) * time.Second}, nil
	}

	// Reconcile the cluster (pull-based)
	if err := r.reconcileCluster(ctx, clusterConn); err != nil {
		log.WithError(err).Error("Failed to reconcile cluster")

		// Update status to reflect error
		clusterConn.Status.Phase = "Error"
		clusterConn.Status.Health = string(types.HealthUnhealthy)
		clusterConn.Status.Message = err.Error()

		// Use patch instead of update to avoid triggering reconciliation
		if patchErr := r.Status().Patch(ctx, clusterConn, k8sclient.MergeFrom(clusterConn)); patchErr != nil {
			log.WithError(patchErr).Debug("Failed to patch status")
		}

		r.updateClusterStatus(ctx, req.Name, types.HealthUnhealthy, err.Error())

		// On error, retry after 1 minute or the configured interval, whichever is smaller
		retryInterval := time.Duration(interval) * time.Second
		if retryInterval > time.Minute {
			retryInterval = time.Minute
		}

		log.Debugf("Reconciliation failed, retrying in %v", retryInterval)
		return reconcile.Result{RequeueAfter: retryInterval}, nil
	}

	// Calculate time taken
	duration := time.Since(startTime)

	// Only log at Info level for significant events or slow reconciliations
	if duration > 5*time.Second {
		log.Infof("Cluster %s reconciled (took %v)", clusterConn.Name, duration)
	} else {
		log.Debugf("Reconciliation completed in %v, next in %ds", duration, interval)
	}

	// IMPORTANT: Always return RequeueAfter for periodic reconciliation
	// This ensures the controller continues to reconcile even without external events
	return reconcile.Result{RequeueAfter: time.Duration(interval) * time.Second}, nil
}

func (r *ClusterReconciler) reconcileCluster(ctx context.Context, clusterConn *v1alpha1.ClusterConnection) error {
	log := logrus.WithField("cluster", clusterConn.Name)

	// Get cluster client
	clusterClient, err := r.getClusterClient(ctx, clusterConn)
	if err != nil {
		return fmt.Errorf("failed to get cluster client: %w", err)
	}

	// Test connection with configured timeout
	timeout := r.Config.ConnectTimeout
	if clusterConn.Spec.Monitoring.Timeout > 0 {
		timeout = int(clusterConn.Spec.Monitoring.Timeout)
	}

	connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	if err := clusterClient.TestConnection(connCtx); err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}

	// Store cluster spec for backend compatibility
	specData := map[string]interface{}{
		"displayName": clusterConn.Spec.DisplayName,
		"endpoint":    clusterConn.Spec.Endpoint,
		"credentialsRef": map[string]interface{}{
			"name":      clusterConn.Spec.CredentialsRef.Name,
			"namespace": clusterConn.Spec.CredentialsRef.Namespace,
		},
		"labels": clusterConn.Spec.Labels,
		"monitoring": map[string]interface{}{
			"interval": clusterConn.Spec.Monitoring.Interval,
			"timeout":  clusterConn.Spec.Monitoring.Timeout,
		},
	}

	if err := r.RedisClient.StoreClusterSpec(ctx, clusterConn.Name, specData); err != nil {
		log.WithError(err).Debug("Failed to store cluster spec")
	}

	// Collect metrics in parallel
	g, gctx := errgroup.WithContext(ctx)

	var nodeMetrics []types.NodeMetrics
	var clusterInfo map[string]interface{}
	var operators []types.OperatorInfo
	var clusterOperators []types.ClusterOperatorInfo

	// Node metrics
	g.Go(func() error {
		var err error
		nodeMetrics, err = clusterClient.GetNodeMetrics(gctx)
		if err != nil {
			return fmt.Errorf("failed to get node metrics: %w", err)
		}
		return nil
	})

	// Cluster info
	g.Go(func() error {
		var err error
		clusterInfo, err = clusterClient.GetClusterInfo(gctx)
		if err != nil {
			log.Debug("Failed to get cluster info")
			// Non-critical, don't fail reconciliation
		}
		return nil
	})

	// Collect ClusterOperators (for OpenShift clusters)
	g.Go(func() error {
		var err error
		clusterOperators, err = clusterClient.GetClusterOperators(gctx)
		if err != nil {
			// Log but don't fail - ClusterOperators are OpenShift-specific
			log.Debug("ClusterOperators not available (likely not OpenShift)")
			return nil // Don't fail reconciliation
		}

		if len(clusterOperators) > 0 {
			available := countAvailable(clusterOperators)
			degraded := countDegraded(clusterOperators)
			log.Debugf("ClusterOperators: %d total, %d available, %d degraded",
				len(clusterOperators), available, degraded)

			// Only log at Info if there are issues
			if degraded > 0 {
				log.Warnf("Cluster has %d degraded operators", degraded)
			}
		}

		return nil
	})

	// Operators - check based on operator scan interval
	g.Go(func() error {
		// Check if we need to fetch operators based on the operator scan interval
		lastFetch, exists := r.lastOperatorFetch[clusterConn.Name]
		needsRefresh := !exists || time.Since(lastFetch) >= time.Duration(r.Config.OperatorScanInterval)*time.Second

		if needsRefresh {
			log.Debug("Fetching operators")
			var err error
			operators, err = clusterClient.GetOperators(gctx)
			if err != nil {
				// Operators are optional, don't fail reconciliation
				log.Debug("Failed to get operators (may not be installed)")
				operators = []types.OperatorInfo{}
			} else {
				// Update last fetch time only on successful fetch
				r.lastOperatorFetch[clusterConn.Name] = time.Now()
				if len(operators) > 0 {
					log.Debugf("Found %d operators", len(operators))
				}
			}
		} else {
			timeUntilNextFetch := time.Duration(r.Config.OperatorScanInterval)*time.Second - time.Since(lastFetch)
			log.Debugf("Skipping operator fetch (next in %v)", timeUntilNextFetch.Round(time.Second))
		}
		return nil
	})

	// Wait for all operations to complete
	if err := g.Wait(); err != nil {
		return err
	}

	// Store metrics in Redis
	if err := r.RedisClient.StoreNodeMetrics(ctx, clusterConn.Name, nodeMetrics); err != nil {
		log.WithError(err).Debug("Failed to store node metrics")
	}

	if clusterInfo != nil {
		if err := r.RedisClient.StoreClusterInfo(ctx, clusterConn.Name, clusterInfo); err != nil {
			log.WithError(err).Debug("Failed to store cluster info")
		}
	}

	if len(operators) > 0 {
		if err := r.RedisClient.StoreOperators(ctx, clusterConn.Name, operators); err != nil {
			log.WithError(err).Debug("Failed to store operators")
		}
	}

	// Store the ClusterOperators
	if len(clusterOperators) > 0 {
		if err := r.RedisClient.StoreClusterOperators(ctx, clusterConn.Name, clusterOperators); err != nil {
			log.WithError(err).Debug("Failed to store ClusterOperators")
		}
	}

	// Store cluster labels if present
	if len(clusterConn.Spec.Labels) > 0 {
		r.RedisClient.StoreClusterLabels(ctx, clusterConn.Name, clusterConn.Spec.Labels)
	}

	// Health: cluster is reachable and we have node/operator data
	health := types.HealthHealthy
	message := "Cluster is reachable"

	// Update CRD status - use patch to avoid triggering reconciliation
	originalClusterConn := clusterConn.DeepCopy()
	clusterConn.Status.Phase = "Connected"
	clusterConn.Status.Health = string(health)
	clusterConn.Status.Message = message
	now := metav1.Now()
	clusterConn.Status.LastSyncTime = &now
	// Only patch if status actually changed
	if !r.statusEqual(originalClusterConn.Status, clusterConn.Status) {
		if err := r.Status().Patch(ctx, clusterConn, k8sclient.MergeFrom(originalClusterConn)); err != nil {
			log.WithError(err).Debug("Failed to patch ClusterConnection status")
		}
	}

	// Update Redis status
	r.updateClusterStatus(ctx, clusterConn.Name, health, message)

	// Publish event
	r.RedisClient.PublishEvent("cluster.reconciled", clusterConn.Name, map[string]interface{}{
		"health":       health,
		"display_name": clusterConn.Spec.DisplayName,
	})

	// Log health status changes at Info level
	if originalClusterConn.Status.Health != string(health) {
		log.Infof("Cluster %s health changed to %s: %s", clusterConn.Name, health, message)
	}

	return nil
}

// statusEqual checks if two statuses are equal (excluding timestamp)
func (r *ClusterReconciler) statusEqual(a, b v1alpha1.ClusterConnectionStatus) bool {
	return a.Phase == b.Phase &&
		a.Health == b.Health &&
		a.Message == b.Message
}

func (r *ClusterReconciler) getClusterClient(ctx context.Context, clusterConn *v1alpha1.ClusterConnection) (*cluster.ClusterClient, error) {
	// Get credentials from secret
	secretName := clusterConn.Spec.CredentialsRef.Name
	secretNamespace := clusterConn.Spec.CredentialsRef.Namespace
	if secretNamespace == "" {
		secretNamespace = clusterConn.Namespace
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, k8sclient.ObjectKey{Name: secretName, Namespace: secretNamespace}, secret); err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	token := string(secret.Data["token"])
	if token == "" {
		// Try base64 decoding if needed
		if tokenB64, ok := secret.Data["token"]; ok {
			decoded, err := base64.StdEncoding.DecodeString(string(tokenB64))
			if err == nil {
				token = string(decoded)
			}
		}
	}

	if token == "" {
		return nil, fmt.Errorf("no token found in secret")
	}

	caCert := secret.Data["ca.crt"]

	// Use display name if available, otherwise use resource name
	clientName := clusterConn.Spec.DisplayName
	if clientName == "" {
		clientName = clusterConn.Name
	}

	return r.clientPool.Get(
		clientName,
		clusterConn.Spec.Endpoint,
		token,
		caCert,
	)
}

func countAvailable(operators []types.ClusterOperatorInfo) int {
	count := 0
	for _, op := range operators {
		if op.Available {
			count++
		}
	}
	return count
}

func countDegraded(operators []types.ClusterOperatorInfo) int {
	count := 0
	for _, op := range operators {
		if op.Degraded {
			count++
		}
	}
	return count
}

func (r *ClusterReconciler) updateClusterStatus(ctx context.Context, name string, health types.ClusterHealth, message string) {
	status := map[string]interface{}{
		"health":     health,
		"message":    message,
		"last_check": time.Now().Format(time.RFC3339),
	}

	if err := r.RedisClient.StoreClusterStatus(ctx, name, status); err != nil {
		logrus.WithField("cluster", name).WithError(err).Debug("Failed to update cluster status")
	}
}

func (r *ClusterReconciler) handleDeletion(ctx context.Context, name string) (reconcile.Result, error) {
	log := logrus.WithField("cluster", name)

	// Clean up Redis data
	if err := r.RedisClient.DeleteClusterData(ctx, name); err != nil {
		log.WithError(err).Debug("Failed to delete cluster data from Redis")
	}

	// Remove from client pool
	r.clientPool.Remove(name)

	// Publish deletion event
	r.RedisClient.PublishEvent("cluster.deleted", name, nil)

	log.Info("Cluster connection removed")

	return reconcile.Result{}, nil
}
