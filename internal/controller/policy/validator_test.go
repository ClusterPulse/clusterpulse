package policy

import (
	"testing"
	"time"

	"github.com/clusterpulse/cluster-controller/pkg/types"
)

func TestValidateCompiledPolicy_Active(t *testing.T) {
	p := &types.CompiledPolicy{Enabled: true}
	state, msg := ValidateCompiledPolicy(p)
	if state != types.PolicyStateActive {
		t.Errorf("state = %q, want Active", state)
	}
	if msg != "Policy is active" {
		t.Errorf("msg = %q", msg)
	}
}

func TestValidateCompiledPolicy_NotYetValid(t *testing.T) {
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	p := &types.CompiledPolicy{Enabled: true, NotBefore: &future}
	state, _ := ValidateCompiledPolicy(p)
	if state != types.PolicyStateInactive {
		t.Errorf("state = %q, want Inactive", state)
	}
}

func TestValidateCompiledPolicy_Expired(t *testing.T) {
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	p := &types.CompiledPolicy{Enabled: true, NotAfter: &past}
	state, _ := ValidateCompiledPolicy(p)
	if state != types.PolicyStateExpired {
		t.Errorf("state = %q, want Expired", state)
	}
}

func TestValidateCompiledPolicy_Disabled(t *testing.T) {
	p := &types.CompiledPolicy{Enabled: false}
	state, msg := ValidateCompiledPolicy(p)
	if state != types.PolicyStateInactive {
		t.Errorf("state = %q, want Inactive", state)
	}
	if msg != "Policy is disabled" {
		t.Errorf("msg = %q", msg)
	}
}

func TestParsePolicyKey_Valid(t *testing.T) {
	ns, name := parsePolicyKey("policy:my-ns:my-policy")
	if ns != "my-ns" || name != "my-policy" {
		t.Errorf("got (%q, %q), want (my-ns, my-policy)", ns, name)
	}
}

func TestParsePolicyKey_Malformed(t *testing.T) {
	tests := []string{"invalid", "policy:", "other:ns:name", "policy:nosep"}
	for _, key := range tests {
		t.Run(key, func(t *testing.T) {
			ns, name := parsePolicyKey(key)
			if ns != "" || name != "" {
				t.Errorf("parsePolicyKey(%q) = (%q, %q), want empty", key, ns, name)
			}
		})
	}
}
