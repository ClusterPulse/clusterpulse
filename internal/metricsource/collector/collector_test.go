package collector

import (
	"regexp"
	"testing"

	"github.com/clusterpulse/cluster-controller/pkg/types"
)

func TestFilterNamespaces(t *testing.T) {
	c := NewCollector()

	tests := []struct {
		name       string
		namespaces []string
		patterns   *types.CompiledPatterns
		want       []string
	}{
		{
			"nil patterns returns all",
			[]string{"default", "kube-system", "my-app"},
			nil,
			[]string{"default", "kube-system", "my-app"},
		},
		{
			"exclude only",
			[]string{"default", "kube-system", "kube-public", "my-app"},
			&types.CompiledPatterns{
				Exclude: []*regexp.Regexp{regexp.MustCompile("^kube-")},
			},
			[]string{"default", "my-app"},
		},
		{
			"include only",
			[]string{"default", "kube-system", "my-app", "my-other"},
			&types.CompiledPatterns{
				Include: []*regexp.Regexp{regexp.MustCompile("^my-")},
			},
			[]string{"my-app", "my-other"},
		},
		{
			"include and exclude (exclude wins)",
			[]string{"app-prod", "app-staging", "app-test", "system"},
			&types.CompiledPatterns{
				Include: []*regexp.Regexp{regexp.MustCompile("^app-")},
				Exclude: []*regexp.Regexp{regexp.MustCompile("-test$")},
			},
			[]string{"app-prod", "app-staging"},
		},
		{
			"empty include means allow all (just apply excludes)",
			[]string{"ns1", "ns2", "excluded"},
			&types.CompiledPatterns{
				Include: []*regexp.Regexp{},
				Exclude: []*regexp.Regexp{regexp.MustCompile("^excluded$")},
			},
			[]string{"ns1", "ns2"},
		},
		{
			"multiple include patterns",
			[]string{"alpha", "beta", "gamma", "delta"},
			&types.CompiledPatterns{
				Include: []*regexp.Regexp{
					regexp.MustCompile("^alpha$"),
					regexp.MustCompile("^gamma$"),
				},
			},
			[]string{"alpha", "gamma"},
		},
		{
			"no matches",
			[]string{"x", "y", "z"},
			&types.CompiledPatterns{
				Include: []*regexp.Regexp{regexp.MustCompile("^nonexistent$")},
			},
			nil,
		},
		{
			"wildcard include all",
			[]string{"a", "b", "c"},
			&types.CompiledPatterns{
				Include: []*regexp.Regexp{regexp.MustCompile(".*")},
			},
			[]string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := &types.CompiledMetricSource{
				NamespacePatterns: tt.patterns,
			}
			got := c.filterNamespaces(tt.namespaces, source)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("index %d: got %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestUseClusterWideList(t *testing.T) {
	tests := []struct {
		name string
		ns   *types.NamespaceConfig
		want bool
	}{
		{
			"nil namespaces — collect all",
			nil,
			true,
		},
		{
			"exclude present — needs cluster-wide",
			&types.NamespaceConfig{
				Include: []string{"app-*"},
				Exclude: []string{"app-test"},
			},
			true,
		},
		{
			"wildcard in include — needs cluster-wide",
			&types.NamespaceConfig{
				Include: []string{"prod-*"},
			},
			true,
		},
		{
			"question mark wildcard — needs cluster-wide",
			&types.NamespaceConfig{
				Include: []string{"ns?"},
			},
			true,
		},
		{
			"exact names only — per-namespace",
			&types.NamespaceConfig{
				Include: []string{"default", "kube-system"},
			},
			false,
		},
		{
			"single exact name — per-namespace",
			&types.NamespaceConfig{
				Include: []string{"my-namespace"},
			},
			false,
		},
		{
			"empty include with exclude — needs cluster-wide",
			&types.NamespaceConfig{
				Exclude: []string{"kube-*"},
			},
			true,
		},
		{
			"mixed exact and wildcard — needs cluster-wide",
			&types.NamespaceConfig{
				Include: []string{"default", "app-*"},
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := &types.CompiledMetricSource{
				Source: types.CompiledSourceTarget{
					Namespaces: tt.ns,
				},
			}
			got := useClusterWideList(source)
			if got != tt.want {
				t.Errorf("useClusterWideList() = %v, want %v", got, tt.want)
			}
		})
	}
}
