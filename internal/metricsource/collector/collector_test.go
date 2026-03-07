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
