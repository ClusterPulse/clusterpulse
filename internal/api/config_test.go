package api

import (
	"testing"
)

func TestEnvStr_Default(t *testing.T) {
	if got := envStr("TEST_ENVSTR_UNSET_KEY_XYZ", "fallback"); got != "fallback" {
		t.Errorf("got %q, want %q", got, "fallback")
	}
}

func TestEnvStr_Override(t *testing.T) {
	t.Setenv("TEST_ENVSTR_KEY", "custom")
	if got := envStr("TEST_ENVSTR_KEY", "fallback"); got != "custom" {
		t.Errorf("got %q, want %q", got, "custom")
	}
}

func TestEnvInt_Default(t *testing.T) {
	if got := envInt("TEST_ENVINT_UNSET_KEY_XYZ", 42); got != 42 {
		t.Errorf("got %d, want 42", got)
	}
}

func TestEnvInt_Valid(t *testing.T) {
	t.Setenv("TEST_ENVINT_KEY", "99")
	if got := envInt("TEST_ENVINT_KEY", 0); got != 99 {
		t.Errorf("got %d, want 99", got)
	}
}

func TestEnvInt_Invalid(t *testing.T) {
	t.Setenv("TEST_ENVINT_KEY", "notanumber")
	if got := envInt("TEST_ENVINT_KEY", 7); got != 7 {
		t.Errorf("got %d, want 7 (default on invalid)", got)
	}
}

func TestEnvBool_Default(t *testing.T) {
	if got := envBool("TEST_ENVBOOL_UNSET_KEY_XYZ", true); !got {
		t.Error("got false, want true")
	}
}

func TestEnvBool_Values(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"true", true},
		{"false", false},
		{"1", true},
		{"0", false},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			t.Setenv("TEST_ENVBOOL_KEY", tt.value)
			if got := envBool("TEST_ENVBOOL_KEY", !tt.want); got != tt.want {
				t.Errorf("envBool(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestIsDevelopment(t *testing.T) {
	dev := &APIConfig{Environment: "development"}
	prod := &APIConfig{Environment: "production"}

	if !dev.IsDevelopment() {
		t.Error("development environment should return true")
	}
	if prod.IsDevelopment() {
		t.Error("production environment should return false")
	}
}
