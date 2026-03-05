package rbac

import (
	"regexp"

	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/sirupsen/logrus"
)

// buildMatcherFromCompiled converts a CompiledResourceFilter into a ResourceMatcher.
func buildMatcherFromCompiled(crf *types.CompiledResourceFilter) *ResourceMatcher {
	m := &ResourceMatcher{
		Visibility: Visibility(crf.Visibility),
		Labels:     crf.Labels,
	}

	if hasNameFilters(crf) {
		m.Names = buildMatchSpec(crf.AllowedNames, crf.DeniedNames, crf.NamePatterns, crf.DenyNamePatterns)
	}

	if hasNSFilters(crf) {
		m.Namespaces = buildMatchSpec(crf.AllowedNS, crf.DeniedNS, crf.NSPatterns, crf.DenyNSPatterns)
	}

	if len(crf.FieldFilters) > 0 {
		m.FieldFilters = make(map[string]*MatchSpec, len(crf.FieldFilters))
		for name, ff := range crf.FieldFilters {
			m.FieldFilters[name] = buildFieldMatchSpec(ff)
		}
	}

	return m
}

func hasNameFilters(crf *types.CompiledResourceFilter) bool {
	return len(crf.AllowedNames) > 0 || len(crf.DeniedNames) > 0 ||
		len(crf.NamePatterns) > 0 || len(crf.DenyNamePatterns) > 0
}

func hasNSFilters(crf *types.CompiledResourceFilter) bool {
	return len(crf.AllowedNS) > 0 || len(crf.DeniedNS) > 0 ||
		len(crf.NSPatterns) > 0 || len(crf.DenyNSPatterns) > 0
}

func buildMatchSpec(allowed, denied []string, allowedPatterns, deniedPatterns [][2]string) *MatchSpec {
	ms := &MatchSpec{
		Include: make(map[string]struct{}, len(allowed)),
		Exclude: make(map[string]struct{}, len(denied)),
	}
	for _, s := range allowed {
		ms.Include[s] = struct{}{}
	}
	for _, s := range denied {
		ms.Exclude[s] = struct{}{}
	}
	ms.IncludePatterns = compilePatternPairs(allowedPatterns)
	ms.ExcludePatterns = compilePatternPairs(deniedPatterns)
	return ms
}

func buildFieldMatchSpec(ff *types.CompiledFieldFilter) *MatchSpec {
	return buildMatchSpec(ff.AllowedLiterals, ff.DeniedLiterals, ff.AllowedPatterns, ff.DeniedPatterns)
}

func compilePatternPairs(pairs [][2]string) []CompiledPattern {
	if len(pairs) == 0 {
		return nil
	}
	compiled := make([]CompiledPattern, 0, len(pairs))
	for _, p := range pairs {
		re, err := regexp.Compile(p[1])
		if err != nil {
			logrus.Warnf("Invalid regex pattern %q: %v", p[1], err)
			continue
		}
		compiled = append(compiled, CompiledPattern{Original: p[0], Regexp: re})
	}
	return compiled
}
