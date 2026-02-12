package registry

import (
	"context"
	"fmt"
	"time"

	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
	"github.com/clusterpulse/cluster-controller/internal/client/registry"
	"github.com/clusterpulse/cluster-controller/internal/config"
	redis "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/sirupsen/logrus"
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

// RegistryReconciler reconciles a RegistryConnection object
type RegistryReconciler struct {
	k8sclient.Client
	Scheme         *runtime.Scheme
	RedisClient    *redis.Client
	Config         *config.Config
	WatchNamespace string
}

// SetupWithManager sets up the controller with the Manager
func (r *RegistryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Create a predicate that filters out status-only updates
	pred := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			// Always reconcile on create
			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			// Always reconcile on delete
			return true
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Only reconcile if the spec or metadata (excluding resourceVersion) changed
			oldReg, okOld := e.ObjectOld.(*v1alpha1.RegistryConnection)
			newReg, okNew := e.ObjectNew.(*v1alpha1.RegistryConnection)

			if !okOld || !okNew {
				return true
			}

			// Check if generation changed (spec change)
			if oldReg.Generation != newReg.Generation {
				logrus.Debugf("Registry %s generation changed", newReg.Name)
				return true
			}

			// Check if deletion timestamp was added
			if oldReg.DeletionTimestamp.IsZero() && !newReg.DeletionTimestamp.IsZero() {
				return true
			}

			// Ignore status-only updates
			return false
		},
		GenericFunc: func(e event.GenericEvent) bool {
			// We don't use generic events
			return false
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.RegistryConnection{}).
		WithEventFilter(pred). // Add the predicate to filter events
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 5, // Registries are typically quick to check
		}).
		Complete(r)
}

// Reconcile handles RegistryConnection reconciliation
func (r *RegistryReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	startTime := time.Now()

	log := logrus.WithFields(logrus.Fields{
		"registry":  req.Name,
		"namespace": req.Namespace,
	})

	// Fetch the RegistryConnection instance
	regConn := &v1alpha1.RegistryConnection{}
	err := r.Get(ctx, req.NamespacedName, regConn)
	if err != nil {
		if errors.IsNotFound(err) {
			// Object deleted
			log.Debug("RegistryConnection deleted, cleaning up")
			return r.handleDeletion(ctx, req.Name)
		}
		return reconcile.Result{}, err
	}

	// Handle deletion
	if !regConn.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, req.Name)
	}

	// Determine reconciliation interval
	interval := r.getReconcileInterval(regConn)

	log.Debug("Starting registry reconciliation")

	// Reconcile the registry
	if err := r.reconcileRegistry(ctx, regConn); err != nil {
		log.WithError(err).Error("Failed to reconcile registry")

		// Update status to reflect error
		regConn.Status.Phase = "Error"
		regConn.Status.Health = string(types.HealthUnhealthy)
		regConn.Status.Available = false
		regConn.Status.Message = err.Error()

		// Use subresource client to avoid triggering reconciliation
		if patchErr := r.Status().Update(ctx, regConn); patchErr != nil {
			log.WithError(patchErr).Debug("Failed to update status")
		}

		// On error, retry after 1 minute
		return reconcile.Result{RequeueAfter: time.Minute}, nil
	}

	duration := time.Since(startTime)

	// Only log slow reconciliations at Info level
	if duration > 2*time.Second {
		log.Infof("Registry %s reconciled (took %v)", regConn.Name, duration)
	} else {
		log.Debugf("Registry reconciliation completed in %v", duration)
	}

	// Always return RequeueAfter for periodic reconciliation
	return reconcile.Result{RequeueAfter: time.Duration(interval) * time.Second}, nil
}

func (r *RegistryReconciler) getReconcileInterval(regConn *v1alpha1.RegistryConnection) int {
	// Default to 60 seconds for registries
	interval := 60

	// Override with spec value if set and valid
	if regConn.Spec.Monitoring.Interval > 0 {
		specInterval := int(regConn.Spec.Monitoring.Interval)
		if specInterval >= 30 {
			interval = specInterval
		} else {
			logrus.Debugf("Registry %s requested interval %d, using minimum of 30",
				regConn.Name, specInterval)
			interval = 30
		}
	}

	return interval
}

func (r *RegistryReconciler) reconcileRegistry(ctx context.Context, regConn *v1alpha1.RegistryConnection) error {
	log := logrus.WithField("registry", regConn.Name)

	// Get registry client
	regClient, err := r.getRegistryClient(ctx, regConn)
	if err != nil {
		return fmt.Errorf("failed to create registry client: %w", err)
	}

	// Set timeout for health check
	timeout := 10
	if regConn.Spec.Monitoring.Timeout > 0 {
		timeout = int(regConn.Spec.Monitoring.Timeout)
	}

	checkCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	// Perform extended health check
	checkCatalog := regConn.Spec.Monitoring.CheckCatalog
	maxCatalogEntries := int(regConn.Spec.Monitoring.MaxCatalogEntries)
	if maxCatalogEntries == 0 {
		maxCatalogEntries = 100
	}

	healthResult, err := regClient.ExtendedHealthCheck(checkCtx, checkCatalog, maxCatalogEntries)
	if err != nil {
		// Even if health check fails, we got some info
		if healthResult == nil {
			return fmt.Errorf("health check failed: %w", err)
		}
		log.Debug("Health check completed with errors")
	}

	// Store registry spec for backend compatibility
	specData := map[string]interface{}{
		"display_name": regConn.Spec.DisplayName,
		"endpoint":     regConn.Spec.Endpoint,
		"type":         regConn.Spec.Type, // Optional, informational only
		"insecure":     regConn.Spec.Insecure,
		"skip_tls":     regConn.Spec.SkipTLSVerify,
		"labels":       regConn.Spec.Labels,
		"monitoring": map[string]interface{}{
			"interval":            regConn.Spec.Monitoring.Interval,
			"timeout":             regConn.Spec.Monitoring.Timeout,
			"check_catalog":       regConn.Spec.Monitoring.CheckCatalog,
			"max_catalog_entries": regConn.Spec.Monitoring.MaxCatalogEntries,
		},
	}

	if regConn.Spec.CredentialsRef != nil {
		specData["credentials_ref"] = map[string]interface{}{
			"name":      regConn.Spec.CredentialsRef.Name,
			"namespace": regConn.Spec.CredentialsRef.Namespace,
		}
	}

	// Store in Redis
	if err := r.storeRegistryData(ctx, regConn.Name, specData, healthResult); err != nil {
		log.WithError(err).Debug("Failed to store registry data in Redis")
	}

	// Calculate health status
	health := r.calculateRegistryHealth(healthResult)
	message := r.generateHealthMessage(healthResult, health)

	// Only update status if there are significant changes
	if r.shouldUpdateStatus(regConn, healthResult, health, message) {
		// Update CRD status using subresource client
		previousHealth := regConn.Status.Health

		regConn.Status.Phase = "Connected"
		regConn.Status.Health = string(health)
		regConn.Status.Available = healthResult.Available
		now := metav1.Now()
		regConn.Status.LastCheckTime = &now
		regConn.Status.ResponseTime = healthResult.ResponseTime
		regConn.Status.Message = message
		regConn.Status.Version = healthResult.Version
		regConn.Status.Features = healthResult.Features

		if checkCatalog {
			regConn.Status.RepositoryCount = healthResult.RepositoryCount
		}

		// Use Status().Update() instead of Patch() to update only the status subresource
		// This won't trigger a new reconciliation due to our predicate
		if err := r.Status().Update(ctx, regConn); err != nil {
			log.WithError(err).Debug("Failed to update RegistryConnection status")
		}

		// Log health changes at appropriate level
		if previousHealth != string(health) {
			if health == types.HealthHealthy {
				log.Infof("Registry %s is healthy (response: %dms)",
					regConn.Name, healthResult.ResponseTime)
			} else if health == types.HealthDegraded {
				log.Warnf("Registry %s is degraded: %s", regConn.Name, message)
			} else if health == types.HealthUnhealthy {
				log.Errorf("Registry %s is unhealthy: %s", regConn.Name, message)
			}
		}
	}

	// Publish event
	r.RedisClient.PublishEvent("registry.reconciled", regConn.Name, map[string]interface{}{
		"health":        health,
		"available":     healthResult.Available,
		"response_time": healthResult.ResponseTime,
		"display_name":  regConn.Spec.DisplayName,
		"type":          regConn.Spec.Type,
	})

	log.Debugf("Registry health: %s, response time: %dms", health, healthResult.ResponseTime)

	return nil
}

// shouldUpdateStatus determines if status needs updating based on significant changes
func (r *RegistryReconciler) shouldUpdateStatus(regConn *v1alpha1.RegistryConnection,
	healthResult *registry.HealthCheckResult, health types.ClusterHealth, message string) bool {

	// Always update if phase, health, or availability changed
	if regConn.Status.Phase != "Connected" ||
		regConn.Status.Health != string(health) ||
		regConn.Status.Available != healthResult.Available {
		return true
	}

	// Update if message changed
	if regConn.Status.Message != message {
		return true
	}

	// Update if version changed
	if regConn.Status.Version != healthResult.Version {
		return true
	}

	// Update if repository count changed significantly (more than 10% or 10 repos)
	if healthResult.RepositoryCount > 0 {
		diff := abs(regConn.Status.RepositoryCount - healthResult.RepositoryCount)
		if diff > 10 || float64(diff)/float64(regConn.Status.RepositoryCount+1) > 0.1 {
			return true
		}
	}

	// Update if response time changed significantly (more than 1000ms or 50%)
	if regConn.Status.ResponseTime > 0 {
		diff := abs64(regConn.Status.ResponseTime - healthResult.ResponseTime)
		if diff > 1000 || float64(diff)/float64(regConn.Status.ResponseTime) > 0.5 {
			return true
		}
	}

	// Check if features changed
	if !mapsEqual(regConn.Status.Features, healthResult.Features) {
		return true
	}

	return false
}

// Helper functions
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func mapsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func (r *RegistryReconciler) getRegistryClient(ctx context.Context, regConn *v1alpha1.RegistryConnection) (*registry.DockerV2Client, error) {
	var username, password string

	// Get credentials if specified
	if regConn.Spec.CredentialsRef != nil {
		secretName := regConn.Spec.CredentialsRef.Name
		secretNamespace := regConn.Spec.CredentialsRef.Namespace
		if secretNamespace == "" {
			secretNamespace = regConn.Namespace
		}

		secret := &corev1.Secret{}
		if err := r.Get(ctx, k8sclient.ObjectKey{Name: secretName, Namespace: secretNamespace}, secret); err != nil {
			logrus.Debug("No credentials secret found, proceeding without auth")
		} else {
			username = string(secret.Data["username"])
			password = string(secret.Data["password"])
		}
	}

	return registry.NewDockerV2Client(
		regConn.Spec.Endpoint,
		username,
		password,
		regConn.Spec.Insecure,
		regConn.Spec.SkipTLSVerify,
	), nil
}

func (r *RegistryReconciler) calculateRegistryHealth(result *registry.HealthCheckResult) types.ClusterHealth {
	if !result.Available {
		return types.HealthUnhealthy
	}

	// Check response time
	if result.ResponseTime > 5000 { // > 5 seconds
		return types.HealthDegraded
	}

	if result.ResponseTime > 10000 { // > 10 seconds
		return types.HealthUnhealthy
	}

	return types.HealthHealthy
}

func (r *RegistryReconciler) generateHealthMessage(result *registry.HealthCheckResult, health types.ClusterHealth) string {
	if !result.Available {
		if result.Error != "" {
			return fmt.Sprintf("Registry unavailable: %s", result.Error)
		}
		return "Registry is not available"
	}

	if health == types.HealthHealthy {
		msg := fmt.Sprintf("Registry is healthy (response time: %dms)", result.ResponseTime)
		if result.RepositoryCount > 0 {
			msg = fmt.Sprintf("%s, %d repositories", msg, result.RepositoryCount)
		}
		return msg
	}

	if result.ResponseTime > 5000 {
		return fmt.Sprintf("Registry is slow (response time: %dms)", result.ResponseTime)
	}

	return "Registry health degraded"
}

func (r *RegistryReconciler) storeRegistryData(ctx context.Context, name string, spec map[string]interface{}, healthResult *registry.HealthCheckResult) error {
	// Store spec
	if err := r.RedisClient.StoreRegistrySpec(ctx, name, spec); err != nil {
		return fmt.Errorf("failed to store registry spec: %w", err)
	}

	// Store health status
	status := map[string]interface{}{
		"available":        healthResult.Available,
		"response_time":    healthResult.ResponseTime,
		"version":          healthResult.Version,
		"repository_count": healthResult.RepositoryCount,
		"features":         healthResult.Features,
		"repositories":     healthResult.Repositories,
		"last_check":       time.Now().Format(time.RFC3339),
	}

	if healthResult.Error != "" {
		status["error"] = healthResult.Error
	}

	if err := r.RedisClient.StoreRegistryStatus(ctx, name, status); err != nil {
		return fmt.Errorf("failed to store registry status: %w", err)
	}

	// Store metrics for time series
	metrics := map[string]interface{}{
		"timestamp":     time.Now().Unix(),
		"response_time": healthResult.ResponseTime,
		"available":     healthResult.Available,
	}

	if err := r.RedisClient.StoreRegistryMetrics(ctx, name, metrics); err != nil {
		return fmt.Errorf("failed to store registry metrics: %w", err)
	}

	return nil
}

func (r *RegistryReconciler) handleDeletion(ctx context.Context, name string) (reconcile.Result, error) {
	log := logrus.WithField("registry", name)

	// Clean up Redis data
	if err := r.RedisClient.DeleteRegistryData(ctx, name); err != nil {
		log.WithError(err).Debug("Failed to delete registry data from Redis")
	}

	// Publish deletion event
	r.RedisClient.PublishEvent("registry.deleted", name, nil)

	log.Info("Registry connection removed")

	return reconcile.Result{}, nil
}
