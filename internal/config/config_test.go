package config

import "testing"

func TestGetEnv(t *testing.T) {
	t.Run("default when unset", func(t *testing.T) {
		got := getEnv("TEST_UNSET_VAR_XYZ", "default_val")
		if got != "default_val" {
			t.Errorf("got %q, want %q", got, "default_val")
		}
	})

	t.Run("returns value when set", func(t *testing.T) {
		t.Setenv("TEST_GETENV_SET", "custom_val")
		got := getEnv("TEST_GETENV_SET", "default_val")
		if got != "custom_val" {
			t.Errorf("got %q, want %q", got, "custom_val")
		}
	})

	t.Run("empty string returns default", func(t *testing.T) {
		t.Setenv("TEST_GETENV_EMPTY", "")
		got := getEnv("TEST_GETENV_EMPTY", "fallback")
		if got != "fallback" {
			t.Errorf("got %q, want %q", got, "fallback")
		}
	})
}

func TestGetEnvInt(t *testing.T) {
	t.Run("default when unset", func(t *testing.T) {
		got := getEnvInt("TEST_UNSET_INT_XYZ", 42)
		if got != 42 {
			t.Errorf("got %d, want 42", got)
		}
	})

	t.Run("valid int", func(t *testing.T) {
		t.Setenv("TEST_ENVINT_VALID", "99")
		got := getEnvInt("TEST_ENVINT_VALID", 0)
		if got != 99 {
			t.Errorf("got %d, want 99", got)
		}
	})

	t.Run("invalid string returns default", func(t *testing.T) {
		t.Setenv("TEST_ENVINT_INVALID", "not_a_number")
		got := getEnvInt("TEST_ENVINT_INVALID", 10)
		if got != 10 {
			t.Errorf("got %d, want 10", got)
		}
	})
}

func TestGetEnvBool(t *testing.T) {
	t.Run("default when unset", func(t *testing.T) {
		got := getEnvBool("TEST_UNSET_BOOL_XYZ", true)
		if !got {
			t.Error("got false, want true")
		}
	})

	trueInputs := []string{"true", "1", "yes"}
	for _, input := range trueInputs {
		t.Run("returns true for "+input, func(t *testing.T) {
			t.Setenv("TEST_ENVBOOL", input)
			if !getEnvBool("TEST_ENVBOOL", false) {
				t.Errorf("getEnvBool(%q) = false, want true", input)
			}
		})
	}

	falseInputs := []string{"false", "0", "no"}
	for _, input := range falseInputs {
		t.Run("returns false for "+input, func(t *testing.T) {
			t.Setenv("TEST_ENVBOOL", input)
			if getEnvBool("TEST_ENVBOOL", true) {
				t.Errorf("getEnvBool(%q) = true, want false", input)
			}
		})
	}

	// "TRUE" is not recognized (exact match, no ToLower)
	t.Run("TRUE returns false (case sensitive)", func(t *testing.T) {
		t.Setenv("TEST_ENVBOOL_CASE", "TRUE")
		if getEnvBool("TEST_ENVBOOL_CASE", false) {
			t.Error("getEnvBool(\"TRUE\") = true, want false (case sensitive)")
		}
	})
}

func TestGetEnvIntWithMin(t *testing.T) {
	t.Run("above minimum", func(t *testing.T) {
		t.Setenv("TEST_MININT_ABOVE", "100")
		got := getEnvIntWithMin("TEST_MININT_ABOVE", 50, 30)
		if got != 100 {
			t.Errorf("got %d, want 100", got)
		}
	})

	t.Run("below minimum clamps", func(t *testing.T) {
		t.Setenv("TEST_MININT_BELOW", "5")
		got := getEnvIntWithMin("TEST_MININT_BELOW", 50, 30)
		if got != 30 {
			t.Errorf("got %d, want 30 (minimum)", got)
		}
	})

	t.Run("equal to minimum", func(t *testing.T) {
		t.Setenv("TEST_MININT_EQ", "30")
		got := getEnvIntWithMin("TEST_MININT_EQ", 50, 30)
		if got != 30 {
			t.Errorf("got %d, want 30", got)
		}
	})
}

func TestLoad_Defaults(t *testing.T) {
	// Clear any env vars that would override defaults
	for _, key := range []string{"NAMESPACE", "REDIS_HOST", "REDIS_PORT", "CACHE_TTL"} {
		t.Setenv(key, "")
	}

	cfg := Load()
	if cfg.Namespace != "clusterpulse" {
		t.Errorf("Namespace = %q, want %q", cfg.Namespace, "clusterpulse")
	}
	if cfg.RedisHost != "redis" {
		t.Errorf("RedisHost = %q, want %q", cfg.RedisHost, "redis")
	}
	if cfg.RedisPort != 6379 {
		t.Errorf("RedisPort = %d, want 6379", cfg.RedisPort)
	}
	// CacheTTL default is 600, min is 60
	if cfg.CacheTTL != 600 {
		t.Errorf("CacheTTL = %d, want 600", cfg.CacheTTL)
	}
	if cfg.ReconciliationInterval != 30 {
		t.Errorf("ReconciliationInterval = %d, want 30", cfg.ReconciliationInterval)
	}
	if cfg.RedisDB != 0 {
		t.Errorf("RedisDB = %d, want 0", cfg.RedisDB)
	}
}
