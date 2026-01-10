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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// ClusterReconciler reconciles a ClusterConnection object
type ClusterReconciler struct {
	k8sclient.Client
	Scheme            *runtime.Scheme
	RedisClient       *redis.Client
	Config            *config.Config
	WatchNamespace    string
	clientPool        *pool.ClientPool
	lastOperatorFetch map[string]time.Time
}

// SetupWithManager sets up the controller with the Manager
func (r *ClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.clientPool = pool.NewClientPool(30 * time.Minute)
	r.lastOperatorFetch = make(map[string]time.Time)

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ClusterConnection{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 3,
		}).
		Complete(r)
}

// getReconcileInterval determines the reconciliation interval for a cluster
func (r *ClusterReconciler) getReconcileInterval(clusterConn *v1alpha1.ClusterConnection) int {
	interval := r.Config.ReconciliationInterval

	if clusterConn.Spec.Monitoring.Interval > 0 {
		specInterval := int(clusterConn.Spec.Monitoring.Interval)
		if specInterval >= 30 {
			interval = specInterval
		} else {
			logrus.Debugf("Cluster %s requested interval %d, using minimum of 30",
				clusterConn.Name, specInterval)
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

	clusterConn := &v1alpha1.ClusterConnection{}
	err := r.Get(ctx, req.NamespacedName, clusterConn)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Debug("ClusterConnection deleted, cleaning up")
			delete(r.lastOperatorFetch, clusterConn.Name)
			r.cleanupMonitorCollection(req.Name)
			return r.handleDeletion(ctx, req.Name)
		}
		return reconcile.Result{}, err
	}

	if !clusterConn.DeletionTimestamp.IsZero() {
		delete(r.lastOperatorFetch, clusterConn.Name)
		r.cleanupMonitorCollection(clusterConn.Name)
		return r.handleDeletion(ctx, req.Name)
	}

	interval := r.getReconcileInterval(clusterConn)

	log.Debug("Starting reconciliation")

	if err := r.reconcileCluster(ctx, clusterConn); err != nil {
		log.WithError(err).Error("Failed to reconcile cluster")

		clusterConn.Status.Phase = "Error"
		clusterConn.Status.Health = string(types.HealthUnhealthy)
		clusterConn.Status.Message = err.Error()

		if patchErr := r.Status().Patch(ctx, clusterConn, k8sclient.MergeFrom(clusterConn)); patchErr != nil {
			log.WithError(patchErr).Debug("Failed to patch status")
		}

		r.updateClusterStatus(ctx, req.Name, types.HealthUnhealthy, err.Error())

		retryInterval := time.Duration(interval) * time.Second
		if retryInterval > time.Minute {
			retryInterval = time.Minute
		}

		log.Debugf("Reconciliation failed, retrying in %v", retryInterval)
		return reconcile.Result{RequeueAfter: retryInterval}, nil
	}

	duration := time.Since(startTime)

	if duration > 5*time.Second {
		log.Infof("Cluster %s reconciled (took %v)", clusterConn.Name, duration)
	} else {
		log.Debugf("Reconciliation completed in %v, next in %ds", duration, interval)
	}

	return reconcile.Result{RequeueAfter: time.Duration(interval) * time.Second}, nil
}

func (r *ClusterReconciler) reconcileCluster(ctx context.Context, clusterConn *v1alpha1.ClusterConnection) error {
	log := logrus.WithField("cluster", clusterConn.Name)

	clusterClient, err := r.getClusterClient(ctx, clusterConn)
	if err != nil {
		return fmt.Errorf("failed to get cluster client: %w", err)
	}

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
	var clusterMetrics *types.ClusterMetrics
	var clusterInfo map[string]interface{}
	var operators []types.OperatorInfo
	var resourceCollection *types.ResourceCollection
	var namespaceList []string
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

	// Cluster metrics
	g.Go(func() error {
		var err error
		clusterMetrics, err = clusterClient.GetClusterMetrics(gctx)
		if err != nil {
			return fmt.Errorf("failed to get cluster metrics: %w", err)
		}
		log.Debugf("Retrieved cluster metrics: %d namespaces, %d nodes",
			clusterMetrics.Namespaces, clusterMetrics.Nodes)
		return nil
	})

	// Namespace collection
	g.Go(func() error {
		var err error
		namespaceList, err = clusterClient.GetNamespaces(gctx)
		if err != nil {
			log.Debug("Failed to get namespaces directly")
		} else {
			log.Debugf("Retrieved %d namespaces", len(namespaceList))
		}
		return nil
	})

	// Cluster info
	g.Go(func() error {
		var err error
		clusterInfo, err = clusterClient.GetClusterInfo(gctx)
		if err != nil {
			log.Debug("Failed to get cluster info")
		}
		return nil
	})

	// ClusterOperators (OpenShift)
	g.Go(func() error {
		var err error
		clusterOperators, err = clusterClient.GetClusterOperators(gctx)
		if err != nil {
			log.Debug("ClusterOperators not available (likely not OpenShift)")
			return nil
		}

		if len(clusterOperators) > 0 {
			available := countAvailable(clusterOperators)
			degraded := countDegraded(clusterOperators)
			log.Debugf("ClusterOperators: %d total, %d available, %d degraded",
				len(clusterOperators), available, degraded)

			if degraded > 0 {
				log.Warnf("Cluster has %d degraded operators", degraded)
			}
		}

		return nil
	})

	// Legacy resource collection (for backward compatibility)
	if r.Config.ResourceCollection.Enabled {
		g.Go(func() error {
			var err error
			collectionCtx, cancel := context.WithTimeout(gctx, 10*time.Second)
			defer cancel()

			resourceCollection, err = clusterClient.GetResourceCollection(collectionCtx, r.Config.ResourceCollection)
			if err != nil {
				log.Debug("Failed to collect detailed resources")
				return nil
			}

			if resourceCollection != nil {
				log.Debugf("Collected resources: %d pods, %d deployments, %d services (took %dms)",
					len(resourceCollection.Pods),
					len(resourceCollection.Deployments),
					len(resourceCollection.Services),
					resourceCollection.CollectionTimeMs)
			}

			return nil
		})
	}

	// Operators (OLM)
	g.Go(func() error {
		lastFetch, exists := r.lastOperatorFetch[clusterConn.Name]
		needsRefresh := !exists || time.Since(lastFetch) >= time.Duration(r.Config.OperatorScanInterval)*time.Second

		if needsRefresh {
			log.Debug("Fetching operators")
			var err error
			operators, err = clusterClient.GetOperators(gctx)
			if err != nil {
				log.Debug("Failed to get operators (may not be installed)")
				operators = []types.OperatorInfo{}
			} else {
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

	if err := g.Wait(); err != nil {
		return err
	}

	// Merge namespace lists
	if clusterMetrics != nil && len(clusterMetrics.NamespaceList) == 0 && len(namespaceList) > 0 {
		log.Debug("Using directly collected namespaces")
		clusterMetrics.NamespaceList = namespaceList
		clusterMetrics.Namespaces = len(namespaceList)
	}

	// Store all collected data
	if err := r.RedisClient.StoreNodeMetrics(ctx, clusterConn.Name, nodeMetrics); err != nil {
		log.WithError(err).Debug("Failed to store node metrics")
	}

	if err := r.RedisClient.StoreClusterMetrics(ctx, clusterConn.Name, clusterMetrics); err != nil {
		log.WithError(err).Debug("Failed to store cluster metrics")
	}

	if len(namespaceList) > 0 {
		if err := r.RedisClient.StoreNamespaces(ctx, clusterConn.Name, namespaceList); err != nil {
			log.WithError(err).Debug("Failed to store namespaces")
		}
	}

	if clusterInfo != nil {
		if err := r.RedisClient.StoreClusterInfo(ctx, clusterConn.Name, clusterInfo); err != nil {
			log.WithError(err).Debug("Failed to store cluster info")
		}
	}

	if operators != nil && len(operators) > 0 {
		if err := r.RedisClient.StoreOperators(ctx, clusterConn.Name, operators); err != nil {
			log.WithError(err).Debug("Failed to store operators")
		}
	}

	if len(clusterOperators) > 0 {
		if err := r.RedisClient.StoreClusterOperators(ctx, clusterConn.Name, clusterOperators); err != nil {
			log.WithError(err).Debug("Failed to store ClusterOperators")
		}
	}

	if resourceCollection != nil {
		if err := r.RedisClient.StoreResourceCollection(ctx, clusterConn.Name, resourceCollection); err != nil {
			log.WithError(err).Debug("Failed to store resource collection")
		}
	}

	if len(clusterConn.Spec.Labels) > 0 {
		r.RedisClient.StoreClusterLabels(ctx, clusterConn.Name, clusterConn.Spec.Labels)
	}

	// Collect dynamic resources from ResourceMonitors
	r.collectDynamicResources(ctx, clusterConn, clusterClient)

	// Calculate health
	health := r.calculateClusterHealth(clusterMetrics)
	message := r.generateHealthMessage(clusterMetrics, health)

	// Update CRD status
	originalClusterConn := clusterConn.DeepCopy()
	clusterConn.Status.Phase = "Connected"
	clusterConn.Status.Health = string(health)
	clusterConn.Status.Message = message
	now := metav1.Now()
	clusterConn.Status.LastSyncTime = &now
	clusterConn.Status.Nodes = clusterMetrics.Nodes
	clusterConn.Status.Namespaces = clusterMetrics.Namespaces

	if !r.statusEqual(originalClusterConn.Status, clusterConn.Status) {
		if err := r.Status().Patch(ctx, clusterConn, k8sclient.MergeFrom(originalClusterConn)); err != nil {
			log.WithError(err).Debug("Failed to patch ClusterConnection status")
		}
	}

	r.updateClusterStatus(ctx, clusterConn.Name, health, message)

	r.RedisClient.PublishEvent("cluster.reconciled", clusterConn.Name, map[string]interface{}{
		"health":       health,
		"nodes":        clusterMetrics.Nodes,
		"nodes_ready":  clusterMetrics.NodesReady,
		"namespaces":   clusterMetrics.Namespaces,
		"display_name": clusterConn.Spec.DisplayName,
	})

	if originalClusterConn.Status.Health != string(health) {
		if health == types.HealthHealthy {
			log.Infof("Cluster %s is healthy (%d nodes, %d namespaces)",
				clusterConn.Name, clusterMetrics.Nodes, clusterMetrics.Namespaces)
		} else if health == types.HealthDegraded {
			log.Warnf("Cluster %s is degraded: %s", clusterConn.Name, message)
		} else if health == types.HealthUnhealthy {
			log.Errorf("Cluster %s is unhealthy: %s", clusterConn.Name, message)
		}
	}

	return nil
}

func (r *ClusterReconciler) statusEqual(a, b v1alpha1.ClusterConnectionStatus) bool {
	return a.Phase == b.Phase &&
		a.Health == b.Health &&
		a.Message == b.Message &&
		a.Nodes == b.Nodes &&
		a.Namespaces == b.Namespaces
}

func (r *ClusterReconciler) getClusterClient(ctx context.Context, clusterConn *v1alpha1.ClusterConnection) (*cluster.ClusterClient, error) {
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

func (r *ClusterReconciler) calculateClusterHealth(metrics *types.ClusterMetrics) types.ClusterHealth {
	if metrics.NodesNotReady > 0 {
		notReadyRatio := float64(metrics.NodesNotReady) / float64(metrics.Nodes)
		if notReadyRatio >= 0.5 {
			return types.HealthUnhealthy
		}
		return types.HealthDegraded
	}

	if metrics.CPUUsagePercent > r.Config.CPUCriticalThreshold {
		return types.HealthDegraded
	}

	if metrics.MemoryUsagePercent > r.Config.MemoryCriticalThreshold {
		return types.HealthDegraded
	}

	return types.HealthHealthy
}

func (r *ClusterReconciler) generateHealthMessage(metrics *types.ClusterMetrics, health types.ClusterHealth) string {
	if health == types.HealthHealthy {
		return "Cluster is healthy"
	}

	var messages []string

	if metrics.NodesNotReady > 0 {
		messages = append(messages, fmt.Sprintf("%d nodes not ready", metrics.NodesNotReady))
	}

	if metrics.CPUUsagePercent > r.Config.CPUWarningThreshold {
		messages = append(messages, fmt.Sprintf("High CPU usage: %.2f%%", metrics.CPUUsagePercent))
	}

	if metrics.MemoryUsagePercent > r.Config.MemoryWarningThreshold {
		messages = append(messages, fmt.Sprintf("High memory usage: %.2f%%", metrics.MemoryUsagePercent))
	}

	if len(messages) > 0 {
		return fmt.Sprintf("Issues: %s", messages[0])
	}

	return "Unknown issues"
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
		logrus.WithError(err).Debug("Failed to update cluster status")
	}
}

func (r *ClusterReconciler) handleDeletion(ctx context.Context, name string) (reconcile.Result, error) {
	log := logrus.WithField("cluster", name)

	if err := r.RedisClient.DeleteClusterData(ctx, name); err != nil {
		log.WithError(err).Debug("Failed to delete cluster data from Redis")
	}

	r.clientPool.Remove(name)

	r.RedisClient.PublishEvent("cluster.deleted", name, nil)

	log.Info("Cluster connection removed")

	return reconcile.Result{}, nil
}
