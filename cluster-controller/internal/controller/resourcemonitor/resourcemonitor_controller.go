package resourcemonitor

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
	"github.com/clusterpulse/cluster-controller/internal/config"
	redis "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Reserved field names that cannot be used in schema.fields
var reservedFieldNames = map[string]bool{
	"_meta":             true,
	"name":              true,
	"namespace":         true,
	"uid":               true,
	"labels":            true,
	"annotations":       true,
	"creationTimestamp": true,
}

// Valid transform operations
var validTransforms = map[string]bool{
	"":       true, // no transform
	"keys":   true,
	"count":  true,
	"first":  true,
	"last":   true,
	"join":   true,
	"exists": true,
}

// Valid field types
var validFieldTypes = map[string]bool{
	"":          true, // defaults to string
	"string":    true,
	"boolean":   true,
	"integer":   true,
	"object":    true,
	"array":     true,
	"timestamp": true,
}

// ResourceMonitorReconciler reconciles ResourceMonitor objects
type ResourceMonitorReconciler struct {
	k8sclient.Client
	Scheme         *runtime.Scheme
	RedisClient    *redis.Client
	Config         *config.Config
	WatchNamespace string
}

// SetupWithManager sets up the controller with the Manager
func (r *ResourceMonitorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ResourceMonitor{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 2,
		}).
		Complete(r)
}

// Reconcile handles ResourceMonitor reconciliation
func (r *ResourceMonitorReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := logrus.WithFields(logrus.Fields{
		"monitor":   req.Name,
		"namespace": req.Namespace,
	})

	// Fetch the ResourceMonitor
	monitor := &v1alpha1.ResourceMonitor{}
	err := r.Get(ctx, req.NamespacedName, monitor)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Debug("ResourceMonitor deleted, cleaning up")
			return r.handleDeletion(ctx, req.Name)
		}
		return reconcile.Result{}, err
	}

	// Handle deletion
	if !monitor.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, req.Name)
	}

	log.Debug("Reconciling ResourceMonitor")

	// Validate the monitor spec
	validationErrors := r.validateMonitor(monitor)
	now := metav1.Now()
	monitor.Status.LastValidated = &now

	if len(validationErrors) > 0 {
		monitor.Status.State = "Error"
		monitor.Status.Message = strings.Join(validationErrors, "; ")
		log.WithField("errors", validationErrors).Warn("ResourceMonitor validation failed")
	} else {
		if monitor.IsEnabled() {
			monitor.Status.State = "Active"
			monitor.Status.Message = "Monitor is active and ready for collection"
		} else {
			monitor.Status.State = "Disabled"
			monitor.Status.Message = "Monitor is disabled"
		}
	}

	// Update status
	if err := r.Status().Update(ctx, monitor); err != nil {
		log.WithError(err).Debug("Failed to update ResourceMonitor status")
	}

	// Store monitor spec in Redis for cluster controllers to pick up
	if monitor.Status.State == "Active" {
		if err := r.storeMonitorSpec(ctx, monitor); err != nil {
			log.WithError(err).Warn("Failed to store monitor spec in Redis")
		}
	} else {
		// Remove from Redis if not active
		if err := r.removeMonitorSpec(ctx, monitor.Name); err != nil {
			log.WithError(err).Debug("Failed to remove monitor spec from Redis")
		}
	}

	// Publish event
	r.RedisClient.PublishEvent("monitor.reconciled", monitor.Name, map[string]interface{}{
		"state":       monitor.Status.State,
		"target_kind": monitor.Spec.Target.Kind,
		"target_api":  monitor.Spec.Target.APIVersion,
	})

	log.WithField("state", monitor.Status.State).Debug("ResourceMonitor reconciliation complete")

	// Requeue periodically to refresh status
	return reconcile.Result{RequeueAfter: 5 * time.Minute}, nil
}

// validateMonitor validates the ResourceMonitor spec and returns any errors
func (r *ResourceMonitorReconciler) validateMonitor(monitor *v1alpha1.ResourceMonitor) []string {
	var errs []string

	// Target validation
	if monitor.Spec.Target.APIVersion == "" {
		errs = append(errs, "target.apiVersion is required")
	}
	if monitor.Spec.Target.Kind == "" {
		errs = append(errs, "target.kind is required")
	}

	// Validate the apiVersion format
	if monitor.Spec.Target.APIVersion != "" {
		if _, err := schema.ParseGroupVersion(monitor.Spec.Target.APIVersion); err != nil {
			errs = append(errs, fmt.Sprintf("invalid target.apiVersion: %v", err))
		}
	}

	// Collection validation
	if monitor.Spec.Collection.IntervalSeconds != 0 && monitor.Spec.Collection.IntervalSeconds < 30 {
		errs = append(errs, "collection.intervalSeconds must be at least 30")
	}

	// Schema validation
	fieldNames := make(map[string]bool)
	for i, field := range monitor.Spec.Schema.Fields {
		// Check for reserved names
		if reservedFieldNames[field.Name] {
			errs = append(errs, fmt.Sprintf("schema.fields[%d].name '%s' is reserved", i, field.Name))
		}

		// Check for duplicates
		if fieldNames[field.Name] {
			errs = append(errs, fmt.Sprintf("schema.fields[%d].name '%s' is duplicate", i, field.Name))
		}
		fieldNames[field.Name] = true

		// Validate field name format
		if field.Name == "" {
			errs = append(errs, fmt.Sprintf("schema.fields[%d].name is required", i))
		} else if !isValidFieldName(field.Name) {
			errs = append(errs, fmt.Sprintf("schema.fields[%d].name '%s' must be alphanumeric with underscores", i, field.Name))
		}

		// Validate path
		if field.Path == "" {
			errs = append(errs, fmt.Sprintf("schema.fields[%d].path is required", i))
		} else if !strings.HasPrefix(field.Path, "{") {
			errs = append(errs, fmt.Sprintf("schema.fields[%d].path must be a JSONPath expression starting with '{'", i))
		}

		// Validate transform
		if !validTransforms[field.Transform] {
			errs = append(errs, fmt.Sprintf("schema.fields[%d].transform '%s' is invalid", i, field.Transform))
		}

		// Validate type
		if !validFieldTypes[field.Type] {
			errs = append(errs, fmt.Sprintf("schema.fields[%d].type '%s' is invalid", i, field.Type))
		}
	}

	// Health mapping validation
	if monitor.Spec.Health != nil {
		if monitor.Spec.Health.Field != "" && monitor.Spec.Health.Expression != "" {
			errs = append(errs, "health.field and health.expression are mutually exclusive")
		}
		if monitor.Spec.Health.Field == "" && monitor.Spec.Health.Expression == "" {
			errs = append(errs, "health requires either field or expression")
		}

		// Validate that health field exists in schema or is a standard field
		if monitor.Spec.Health.Field != "" {
			standardFields := map[string]bool{"name": true, "namespace": true, "phase": true, "status": true}
			if !fieldNames[monitor.Spec.Health.Field] && !standardFields[monitor.Spec.Health.Field] {
				errs = append(errs, fmt.Sprintf("health.field '%s' must be defined in schema.fields or be a standard field", monitor.Spec.Health.Field))
			}
		}
	}

	// Namespace selector validation
	if monitor.Spec.Collection.NamespaceSelector != nil {
		for i, pattern := range monitor.Spec.Collection.NamespaceSelector.Include {
			if _, err := compileGlobPattern(pattern); err != nil {
				errs = append(errs, fmt.Sprintf("namespaceSelector.include[%d] '%s' is invalid: %v", i, pattern, err))
			}
		}
		for i, pattern := range monitor.Spec.Collection.NamespaceSelector.Exclude {
			if _, err := compileGlobPattern(pattern); err != nil {
				errs = append(errs, fmt.Sprintf("namespaceSelector.exclude[%d] '%s' is invalid: %v", i, pattern, err))
			}
		}
	}

	return errs
}

// isValidFieldName checks if a field name is valid (alphanumeric + underscores)
func isValidFieldName(name string) bool {
	if len(name) == 0 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	// Must start with a letter
	return (name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z')
}

// compileGlobPattern validates and compiles a glob pattern to regex
func compileGlobPattern(pattern string) (*regexp.Regexp, error) {
	// Convert glob to regex
	regexPattern := "^"
	for _, c := range pattern {
		switch c {
		case '*':
			regexPattern += ".*"
		case '?':
			regexPattern += "."
		case '.', '+', '^', '$', '[', ']', '(', ')', '{', '}', '|', '\\':
			regexPattern += "\\" + string(c)
		default:
			regexPattern += string(c)
		}
	}
	regexPattern += "$"

	return regexp.Compile(regexPattern)
}

func (r *ResourceMonitorReconciler) storeMonitorSpec(ctx context.Context, monitor *v1alpha1.ResourceMonitor) error {
	return r.RedisClient.StoreResourceMonitor(ctx, monitor.Name, monitor.Spec)
}

func (r *ResourceMonitorReconciler) removeMonitorSpec(ctx context.Context, name string) error {
	return r.RedisClient.DeleteResourceMonitor(ctx, name)
}

func (r *ResourceMonitorReconciler) handleDeletion(ctx context.Context, name string) (reconcile.Result, error) {
	log := logrus.WithField("monitor", name)

	// Clean up Redis data
	if err := r.removeMonitorSpec(ctx, name); err != nil {
		log.WithError(err).Debug("Failed to delete monitor from Redis")
	}

	// Publish deletion event
	r.RedisClient.PublishEvent("monitor.deleted", name, nil)

	log.Info("ResourceMonitor removed")

	return reconcile.Result{}, nil
}
