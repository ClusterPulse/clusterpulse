package policy

import (
	"context"
	"time"

	"github.com/clusterpulse/cluster-controller/internal/config"
	redis "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/sirupsen/logrus"
)

// ValidatePolicy checks a policy's lifecycle validity and returns its status
func ValidatePolicy(spec map[string]interface{}) (string, string) {
	now := time.Now().UTC()

	lifecycle, _ := spec["lifecycle"].(map[string]interface{})
	if lifecycle != nil {
		validity, _ := lifecycle["validity"].(map[string]interface{})
		if validity != nil {
			if nb, ok := validity["notBefore"].(string); ok && nb != "" {
				notBefore, err := time.Parse(time.RFC3339, nb)
				if err == nil && now.Before(notBefore) {
					return types.PolicyStateInactive, "Policy not yet valid (starts at " + nb + ")"
				}
			}

			if na, ok := validity["notAfter"].(string); ok && na != "" {
				notAfter, err := time.Parse(time.RFC3339, na)
				if err == nil && now.After(notAfter) {
					return types.PolicyStateExpired, "Policy expired at " + na
				}
			}
		}
	}

	access, _ := spec["access"].(map[string]interface{})
	if access != nil {
		if enabled, ok := access["enabled"].(bool); ok && !enabled {
			return types.PolicyStateInactive, "Policy is disabled"
		}
	}

	return types.PolicyStateActive, "Policy is active"
}

// ValidateCompiledPolicy checks validity from a compiled policy
func ValidateCompiledPolicy(policy *types.CompiledPolicy) (string, string) {
	now := time.Now().UTC()

	if policy.NotBefore != nil && *policy.NotBefore != "" {
		notBefore, err := time.Parse(time.RFC3339, *policy.NotBefore)
		if err == nil && now.Before(notBefore) {
			return types.PolicyStateInactive, "Policy not yet valid"
		}
	}

	if policy.NotAfter != nil && *policy.NotAfter != "" {
		notAfter, err := time.Parse(time.RFC3339, *policy.NotAfter)
		if err == nil && now.After(notAfter) {
			return types.PolicyStateExpired, "Policy expired"
		}
	}

	if !policy.Enabled {
		return types.PolicyStateInactive, "Policy is disabled"
	}

	return types.PolicyStateActive, "Policy is active"
}

// PeriodicValidator validates all policies periodically.
// Implements manager.Runnable.
type PeriodicValidator struct {
	RedisClient *redis.Client
	Config      *config.Config
}

// Start runs the periodic validation loop until context is cancelled
func (v *PeriodicValidator) Start(ctx context.Context) error {
	interval := time.Duration(v.Config.PolicyValidationInterval) * time.Second
	logrus.Infof("Starting periodic policy validator (interval: %v)", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logrus.Info("Periodic policy validator stopped")
			return nil
		case <-ticker.C:
			v.validateAll(ctx)
		}
	}
}

func (v *PeriodicValidator) validateAll(ctx context.Context) {
	policies, err := v.RedisClient.ListPolicies(ctx, false)
	if err != nil {
		logrus.WithError(err).Error("Failed to list policies for validation")
		return
	}

	for _, policyKey := range policies {
		ns, name := parsePolicyKey(policyKey)
		if ns == "" {
			continue
		}

		policy, err := v.RedisClient.GetPolicy(ctx, ns, name)
		if err != nil {
			logrus.WithError(err).Debugf("Failed to get policy %s for validation", policyKey)
			continue
		}

		state, message := ValidateCompiledPolicy(policy)

		status := map[string]interface{}{
			"state":        state,
			"message":      message,
			"validated_at": time.Now().UTC().Format(time.RFC3339),
		}

		if err := v.RedisClient.UpdatePolicyStatus(ctx, ns, name, status); err != nil {
			logrus.WithError(err).Debugf("Failed to update status for policy %s", policyKey)
		}

		if state == types.PolicyStateExpired {
			logrus.Infof("Policy %s/%s has expired", ns, name)
			// Remove from enabled set
			v.RedisClient.PublishPolicyEvent("expired", ns, name)
		}
	}
}

// parsePolicyKey extracts namespace and name from "policy:{ns}:{name}"
func parsePolicyKey(key string) (string, string) {
	// key format: "policy:{namespace}:{name}"
	if len(key) < 8 || key[:7] != "policy:" {
		return "", ""
	}
	rest := key[7:]
	idx := indexByte(rest, ':')
	if idx < 0 {
		return "", ""
	}
	return rest[:idx], rest[idx+1:]
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
