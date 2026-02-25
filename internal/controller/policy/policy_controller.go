package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
	"github.com/clusterpulse/cluster-controller/internal/config"
	redis "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// PolicyReconciler reconciles MonitorAccessPolicy objects
type PolicyReconciler struct {
	k8sclient.Client
	Scheme         *runtime.Scheme
	RedisClient    *redis.Client
	Config         *config.Config
	WatchNamespace string

	compiler *Compiler
}

// SetupWithManager configures the controller with the manager
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.compiler = NewCompiler()

	pred := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return true
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldP, okOld := e.ObjectOld.(*v1alpha1.MonitorAccessPolicy)
			newP, okNew := e.ObjectNew.(*v1alpha1.MonitorAccessPolicy)
			if !okOld || !okNew {
				return true
			}
			if oldP.Generation != newP.Generation {
				return true
			}
			if oldP.DeletionTimestamp.IsZero() && !newP.DeletionTimestamp.IsZero() {
				return true
			}
			return false
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return false
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.MonitorAccessPolicy{}).
		WithEventFilter(pred).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 3,
		}).
		Complete(r)
}

// Reconcile handles MonitorAccessPolicy create/update/delete events
func (r *PolicyReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := logrus.WithFields(logrus.Fields{
		"policy":    req.Name,
		"namespace": req.Namespace,
	})

	// Fetch the policy
	policy := &v1alpha1.MonitorAccessPolicy{}
	err := r.Get(ctx, req.NamespacedName, policy)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Debug("MonitorAccessPolicy deleted, cleaning up")
			return r.handleDeletion(ctx, req.Namespace, req.Name)
		}
		return reconcile.Result{}, err
	}

	if !policy.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, req.Namespace, req.Name)
	}

	log.Info("Compiling policy")

	// Compile the policy
	compiled, err := r.compiler.Compile(req.Name, req.Namespace, &policy.Spec)
	if err != nil {
		log.WithError(err).Error("Failed to compile policy")
		return r.updateStatusError(ctx, policy, err)
	}

	// Store in Redis
	if err := r.RedisClient.StorePolicy(ctx, compiled); err != nil {
		log.WithError(err).Error("Failed to store policy in Redis")
		return r.updateStatusError(ctx, policy, err)
	}

	// Validate lifecycle
	state, message := ValidateCompiledPolicy(compiled)

	// Update CRD status
	policy.Status.State = state
	policy.Status.Message = message
	policy.Status.CompiledAt = compiled.CompiledAt
	policy.Status.Hash = compiled.Hash
	policy.Status.AffectedUsers = len(compiled.Users)
	policy.Status.AffectedGroups = len(compiled.Groups)
	policy.Status.AffectedServiceAccounts = len(compiled.ServiceAccounts)
	policy.Status.CustomResourceTypes = len(compiled.CustomResourceTypes)

	if err := r.Status().Update(ctx, policy); err != nil {
		log.WithError(err).Debug("Failed to update status")
	}

	// Update Redis status
	r.RedisClient.UpdatePolicyStatus(ctx, req.Namespace, req.Name, map[string]any{
		"state":                   state,
		"message":                 message,
		"compiledAt":              compiled.CompiledAt,
		"hash":                    compiled.Hash,
		"affectedUsers":           len(compiled.Users),
		"affectedGroups":          len(compiled.Groups),
		"affectedServiceAccounts": len(compiled.ServiceAccounts),
		"customResourceTypes":     len(compiled.CustomResourceTypes),
	})

	// Publish event
	r.RedisClient.PublishPolicyEvent("compiled", req.Namespace, req.Name)

	log.Infof("Policy compiled successfully (%d custom resource types)", len(compiled.CustomResourceTypes))

	return reconcile.Result{}, nil
}

func (r *PolicyReconciler) handleDeletion(ctx context.Context, namespace, name string) (reconcile.Result, error) {
	if err := r.RedisClient.RemovePolicy(ctx, namespace, name); err != nil {
		logrus.WithError(err).Debugf("Error removing policy %s/%s from Redis", namespace, name)
	}

	r.RedisClient.PublishPolicyEvent("deleted", namespace, name)
	logrus.Infof("MonitorAccessPolicy %s/%s deleted", namespace, name)

	return reconcile.Result{}, nil
}

func (r *PolicyReconciler) updateStatusError(ctx context.Context, policy *v1alpha1.MonitorAccessPolicy, err error) (reconcile.Result, error) {
	policy.Status.State = "Error"
	policy.Status.Message = fmt.Sprintf("Compilation failed: %s", err.Error())

	if statusErr := r.Status().Update(ctx, policy); statusErr != nil {
		logrus.WithError(statusErr).Debug("Failed to update error status")
	}

	r.RedisClient.UpdatePolicyStatus(ctx, policy.Namespace, policy.Name, map[string]any{
		"state":    "Error",
		"message":  policy.Status.Message,
		"error_at": time.Now().UTC().Format(time.RFC3339),
	})

	return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
}

// EvalCacheCleaner clears stale eval caches on startup.
// Implements manager.Runnable.
type EvalCacheCleaner struct {
	RedisClient *redis.Client
}

// Start runs the one-time cleanup
func (e *EvalCacheCleaner) Start(ctx context.Context) error {
	count, err := e.RedisClient.ClearStaleEvalCaches(ctx)
	if err != nil {
		logrus.WithError(err).Warn("Error clearing stale eval caches on startup")
	} else {
		logrus.Infof("Cleared %d stale evaluation cache entries on startup", count)
	}
	return nil
}
