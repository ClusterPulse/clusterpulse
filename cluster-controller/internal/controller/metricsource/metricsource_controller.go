package metricsource

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
	"github.com/clusterpulse/cluster-controller/internal/config"
	"github.com/clusterpulse/cluster-controller/internal/metricsource/collector"
	"github.com/clusterpulse/cluster-controller/internal/metricsource/compiler"
	redis "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// MetricSourceReconciler reconciles MetricSource objects
type MetricSourceReconciler struct {
	k8sclient.Client
	Scheme         *runtime.Scheme
	RedisClient    *redis.Client
	Config         *config.Config
	WatchNamespace string

	compiler  *compiler.Compiler
	collector *collector.Collector

	// Cache of compiled MetricSources for quick access during collection
	compiledCache   map[string]*types.CompiledMetricSource
	compiledCacheMu sync.RWMutex

	// Track cluster connections for dynamic client creation
	clusterClients   map[string]dynamic.Interface
	clusterClientsMu sync.RWMutex
}

// SetupWithManager configures the controller with the manager
func (r *MetricSourceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.compiler = compiler.NewCompiler()
	r.collector = collector.NewCollector()
	r.compiledCache = make(map[string]*types.CompiledMetricSource)
	r.clusterClients = make(map[string]dynamic.Interface)

	// Create predicate to filter out status-only updates
	pred := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return true
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldMS, okOld := e.ObjectOld.(*v1alpha1.MetricSource)
			newMS, okNew := e.ObjectNew.(*v1alpha1.MetricSource)

			if !okOld || !okNew {
				return true
			}

			// Only reconcile if generation changed (spec change)
			if oldMS.Generation != newMS.Generation {
				logrus.Debugf("MetricSource %s generation changed, reconciling", newMS.Name)
				return true
			}

			// Reconcile if deletion timestamp was added
			if oldMS.DeletionTimestamp.IsZero() && !newMS.DeletionTimestamp.IsZero() {
				return true
			}

			// Ignore status-only updates to prevent reconciliation loops
			return false
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return false
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.MetricSource{}).
		WithEventFilter(pred).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 2,
		}).
		Complete(r)
}

// Reconcile handles MetricSource create/update/delete events
func (r *MetricSourceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	startTime := time.Now()

	log := logrus.WithFields(logrus.Fields{
		"metricsource": req.Name,
		"namespace":    req.Namespace,
	})

	// Fetch the MetricSource
	ms := &v1alpha1.MetricSource{}
	err := r.Get(ctx, req.NamespacedName, ms)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Debug("MetricSource deleted, cleaning up")
			return r.handleDeletion(ctx, req.Namespace, req.Name)
		}
		return reconcile.Result{}, err
	}

	// Handle deletion
	if !ms.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, req.Namespace, req.Name)
	}

	log.Debug("Starting reconciliation")

	// Compile the MetricSource
	compiled, err := r.compiler.Compile(ms)
	if err != nil {
		log.WithError(err).Error("Failed to compile MetricSource")
		return r.updateStatusError(ctx, ms, err)
	}

	// Store compiled definition in Redis
	if err := r.RedisClient.StoreCompiledMetricSource(ctx, compiled); err != nil {
		log.WithError(err).Error("Failed to store compiled MetricSource")
		return r.updateStatusError(ctx, ms, err)
	}

	// Update local cache
	r.compiledCacheMu.Lock()
	r.compiledCache[req.Namespace+"/"+req.Name] = compiled
	r.compiledCacheMu.Unlock()

	// Collect from all connected clusters
	collectionResult, err := r.collectFromAllClusters(ctx, compiled)
	if err != nil {
		log.WithError(err).Error("Collection failed")
		return r.updateStatusError(ctx, ms, err)
	}

	// Update status with collection results
	if err := r.updateStatusSuccess(ctx, ms, collectionResult, time.Since(startTime)); err != nil {
		log.WithError(err).Debug("Failed to update status")
	}

	// Publish event
	r.RedisClient.PublishMetricSourceEvent("reconciled", req.Namespace+"/"+req.Name, map[string]interface{}{
		"resources": collectionResult.TotalResources,
		"clusters":  collectionResult.ClustersCollected,
		"errors":    collectionResult.TotalErrors,
	})

	// Calculate requeue interval
	interval := time.Duration(compiled.Collection.IntervalSeconds) * time.Second
	if collectionResult.TotalErrors > 0 {
		// Retry sooner if there were errors
		interval = interval / 2
		if interval < 30*time.Second {
			interval = 30 * time.Second
		}
	}

	duration := time.Since(startTime)

	// Log at Info level for significant events or slow reconciliations
	if duration > 5*time.Second {
		log.Infof("MetricSource %s reconciled (took %v)", ms.Name, duration)
	} else if collectionResult.TotalErrors > 0 {
		log.Warnf("MetricSource %s reconciled with %d errors (%d resources from %d clusters)",
			ms.Name, collectionResult.TotalErrors, collectionResult.TotalResources, collectionResult.ClustersCollected)
	} else {
		log.Debugf("Reconciliation completed in %v, next in %v", duration, interval)
	}

	return reconcile.Result{RequeueAfter: interval}, nil
}

// CollectionSummary holds aggregate results from collecting across all clusters
type CollectionSummary struct {
	TotalResources       int
	ClustersCollected    int
	TotalErrors          int
	AggregationsComputed bool
	ClusterResults       map[string]*collector.CollectResult
}

// collectFromAllClusters collects resources from all connected clusters
func (r *MetricSourceReconciler) collectFromAllClusters(ctx context.Context, source *types.CompiledMetricSource) (*CollectionSummary, error) {
	clusterConns := &v1alpha1.ClusterConnectionList{}
	if err := r.List(ctx, clusterConns, k8sclient.InNamespace(r.WatchNamespace)); err != nil {
		return nil, fmt.Errorf("failed to list cluster connections: %w", err)
	}

	if len(clusterConns.Items) == 0 {
		logrus.Debug("No cluster connections found")
		return &CollectionSummary{
			ClusterResults: make(map[string]*collector.CollectResult),
		}, nil
	}

	summary := &CollectionSummary{
		ClusterResults:       make(map[string]*collector.CollectResult),
		AggregationsComputed: len(source.Aggregations) > 0,
	}

	g, gctx := errgroup.WithContext(ctx)
	var mu sync.Mutex

	for i := range clusterConns.Items {
		cc := &clusterConns.Items[i]

		if cc.Status.Phase != "Connected" {
			logrus.Debugf("Skipping cluster %s (status: %s)", cc.Name, cc.Status.Phase)
			continue
		}

		g.Go(func() error {
			result, err := r.collectFromCluster(gctx, cc, source)
			if err != nil {
				logrus.WithError(err).Warnf("Failed to collect from cluster %s", cc.Name)
				mu.Lock()
				summary.TotalErrors++
				mu.Unlock()
				return nil
			}

			mu.Lock()
			summary.ClusterResults[cc.Name] = result
			summary.TotalResources += result.Collection.ResourceCount
			summary.ClustersCollected++
			summary.TotalErrors += len(result.Errors)
			mu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return summary, err
	}

	return summary, nil
}

// collectFromCluster collects resources from a single cluster
func (r *MetricSourceReconciler) collectFromCluster(ctx context.Context, cc *v1alpha1.ClusterConnection, source *types.CompiledMetricSource) (*collector.CollectResult, error) {
	log := logrus.WithFields(logrus.Fields{
		"cluster":      cc.Name,
		"metricsource": source.Namespace + "/" + source.Name,
	})

	dynamicClient, err := r.getDynamicClient(ctx, cc)
	if err != nil {
		return nil, fmt.Errorf("failed to get dynamic client: %w", err)
	}

	timeout := time.Duration(source.Collection.TimeoutSeconds) * time.Second
	collectCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := r.collector.Collect(collectCtx, dynamicClient, source, cc.Name)
	if err != nil {
		return nil, err
	}

	// Store resource collection results
	if err := r.RedisClient.StoreCustomResourceCollection(ctx, cc.Name, result.Collection); err != nil {
		log.WithError(err).Debug("Failed to store collection results")
	}

	// Store aggregation results if computed
	if result.Aggregations != nil {
		if err := r.RedisClient.StoreAggregationResults(ctx, cc.Name, result.Aggregations); err != nil {
			log.WithError(err).Debug("Failed to store aggregation results")
		}
	}

	return result, nil
}

// getDynamicClient gets or creates a dynamic client for a cluster
func (r *MetricSourceReconciler) getDynamicClient(ctx context.Context, cc *v1alpha1.ClusterConnection) (dynamic.Interface, error) {
	// Check cache first
	r.clusterClientsMu.RLock()
	client, exists := r.clusterClients[cc.Name]
	r.clusterClientsMu.RUnlock()

	if exists {
		return client, nil
	}

	// Get credentials from secret
	secretName := cc.Spec.CredentialsRef.Name
	secretNamespace := cc.Spec.CredentialsRef.Namespace
	if secretNamespace == "" {
		secretNamespace = cc.Namespace
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, k8sclient.ObjectKey{Name: secretName, Namespace: secretNamespace}, secret); err != nil {
		return nil, fmt.Errorf("failed to get credentials secret: %w", err)
	}

	token := string(secret.Data["token"])
	if token == "" {
		return nil, fmt.Errorf("no token found in secret")
	}

	caCert := secret.Data["ca.crt"]

	// Create rest config
	config := &rest.Config{
		Host:        cc.Spec.Endpoint,
		BearerToken: token,
		Timeout:     30 * time.Second,
		QPS:         50,
		Burst:       100,
	}

	if len(caCert) > 0 {
		config.TLSClientConfig = rest.TLSClientConfig{
			CAData: caCert,
		}
	} else {
		config.TLSClientConfig = rest.TLSClientConfig{
			Insecure: true,
		}
	}

	// Create dynamic client
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	// Cache the client
	r.clusterClientsMu.Lock()
	r.clusterClients[cc.Name] = dynamicClient
	r.clusterClientsMu.Unlock()

	logrus.Debugf("Created dynamic client for cluster %s", cc.Name)

	return dynamicClient, nil
}

// handleDeletion cleans up resources when a MetricSource is deleted
func (r *MetricSourceReconciler) handleDeletion(ctx context.Context, namespace, name string) (reconcile.Result, error) {
	sourceID := namespace + "/" + name

	// Remove from local cache
	r.compiledCacheMu.Lock()
	delete(r.compiledCache, sourceID)
	r.compiledCacheMu.Unlock()

	// Delete from Redis
	if err := r.RedisClient.DeleteMetricSource(ctx, namespace, name); err != nil {
		logrus.WithError(err).Debugf("Error deleting MetricSource %s from Redis", sourceID)
	}

	// Publish deletion event
	r.RedisClient.PublishMetricSourceEvent("deleted", sourceID, nil)

	logrus.Infof("MetricSource %s deleted", sourceID)

	return reconcile.Result{}, nil
}

// updateStatusSuccess updates the MetricSource status after successful collection
func (r *MetricSourceReconciler) updateStatusSuccess(ctx context.Context, ms *v1alpha1.MetricSource, summary *CollectionSummary, duration time.Duration) error {
	ms.Status.Phase = "Active"
	now := metav1.Now()
	ms.Status.LastCollectionTime = &now
	ms.Status.LastCollectionDuration = duration.Round(time.Millisecond).String()
	ms.Status.ResourcesCollected = summary.TotalResources
	ms.Status.ClustersCollected = summary.ClustersCollected
	ms.Status.ErrorsLastRun = summary.TotalErrors

	if summary.TotalErrors > 0 {
		ms.Status.Message = fmt.Sprintf("Collected with %d errors", summary.TotalErrors)
	} else {
		ms.Status.Message = "Collection successful"
	}

	// Update conditions
	ms.Status.Conditions = []metav1.Condition{
		{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			LastTransitionTime: now,
			Reason:             "CollectionSuccessful",
			Message:            fmt.Sprintf("Collected %d resources from %d clusters", summary.TotalResources, summary.ClustersCollected),
		},
	}

	return r.Status().Update(ctx, ms)
}

// updateStatusError updates the MetricSource status after an error
func (r *MetricSourceReconciler) updateStatusError(ctx context.Context, ms *v1alpha1.MetricSource, err error) (reconcile.Result, error) {
	ms.Status.Phase = "Error"
	ms.Status.Message = err.Error()
	ms.Status.ErrorsLastRun++

	now := metav1.Now()
	ms.Status.Conditions = []metav1.Condition{
		{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			LastTransitionTime: now,
			Reason:             "Error",
			Message:            err.Error(),
		},
	}

	if statusErr := r.Status().Update(ctx, ms); statusErr != nil {
		logrus.WithError(statusErr).Debug("Failed to update error status")
	}

	// Retry after a shorter interval on error
	return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
}

// InvalidateClusterClient removes a cached cluster client (call when cluster connection changes)
func (r *MetricSourceReconciler) InvalidateClusterClient(clusterName string) {
	r.clusterClientsMu.Lock()
	delete(r.clusterClients, clusterName)
	r.clusterClientsMu.Unlock()
}

// GetCachedMetricSource retrieves a MetricSource from the local cache
func (r *MetricSourceReconciler) GetCachedMetricSource(sourceID string) (*types.CompiledMetricSource, bool) {
	r.compiledCacheMu.RLock()
	defer r.compiledCacheMu.RUnlock()
	source, ok := r.compiledCache[sourceID]
	return source, ok
}
