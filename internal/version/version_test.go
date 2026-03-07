package version

import "testing"

func TestDefaultVersionValues(t *testing.T) {
	if Version != "dev" {
		t.Errorf("Version = %q, want dev", Version)
	}
	if GitCommit != "unknown" {
		t.Errorf("GitCommit = %q, want unknown", GitCommit)
	}
	if GitTreeState != "unknown" {
		t.Errorf("GitTreeState = %q, want unknown", GitTreeState)
	}
	if BuildDate != "unknown" {
		t.Errorf("BuildDate = %q, want unknown", BuildDate)
	}
}
