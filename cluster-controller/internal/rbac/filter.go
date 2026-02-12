package rbac

import (
	"regexp"

	"github.com/sirupsen/logrus"
)

// parseFilterSpecs compiles literal values and pattern specifications.
// patterns is [][2]string where [0]=original, [1]=regex.
func parseFilterSpecs(literals []string, patterns [][2]string) (map[string]struct{}, []CompiledPattern) {
	literalSet := make(map[string]struct{}, len(literals))
	for _, l := range literals {
		literalSet[l] = struct{}{}
	}

	var compiled []CompiledPattern
	for _, spec := range patterns {
		re, err := regexp.Compile(spec[1])
		if err != nil {
			logrus.Warnf("Invalid regex pattern '%s': %v", spec[1], err)
			continue
		}
		compiled = append(compiled, CompiledPattern{Original: spec[0], Regexp: re})
	}

	return literalSet, compiled
}

// parseFilterSpecsFromAny handles the JSON-decoded format where patterns come as []any.
func parseFilterSpecsFromAny(literals []any, patterns []any) (map[string]struct{}, []CompiledPattern) {
	literalSet := make(map[string]struct{}, len(literals))
	for _, l := range literals {
		if s, ok := l.(string); ok {
			literalSet[s] = struct{}{}
		}
	}

	var compiled []CompiledPattern
	for _, p := range patterns {
		switch v := p.(type) {
		case []any:
			if len(v) >= 2 {
				orig, _ := v[0].(string)
				regex, _ := v[1].(string)
				if regex != "" {
					re, err := regexp.Compile(regex)
					if err != nil {
						logrus.Warnf("Invalid regex pattern '%s': %v", regex, err)
						continue
					}
					compiled = append(compiled, CompiledPattern{Original: orig, Regexp: re})
				}
			}
		case string:
			re, err := regexp.Compile("^" + regexp.QuoteMeta(v))
			if err != nil {
				continue
			}
			compiled = append(compiled, CompiledPattern{Original: v, Regexp: re})
		}
	}

	return literalSet, compiled
}

// buildFilter constructs a Filter from a compiled policy filter spec (map from JSON).
func buildFilter(filterSpec map[string]any) *Filter {
	visStr, _ := filterSpec["visibility"].(string)
	visibility := Visibility(visStr)
	if visibility != VisibilityAll && visibility != VisibilityNone && visibility != VisibilityFiltered {
		visibility = VisibilityAll
	}

	f := NewFilter(visibility)
	if visibility == VisibilityNone {
		return f
	}

	// Allowed literals
	if lits, ok := filterSpec["allowed_literals"].([]any); ok {
		for _, l := range lits {
			if s, ok := l.(string); ok {
				f.Include[s] = struct{}{}
			}
		}
	}

	// Denied literals
	if lits, ok := filterSpec["denied_literals"].([]any); ok {
		for _, l := range lits {
			if s, ok := l.(string); ok {
				f.Exclude[s] = struct{}{}
			}
		}
	}

	// Allowed patterns
	if pats, ok := filterSpec["allowed_patterns"].([]any); ok {
		for _, p := range pats {
			if pair, ok := p.([]any); ok && len(pair) >= 2 {
				orig, _ := pair[0].(string)
				regex, _ := pair[1].(string)
				if regex != "" {
					re, err := regexp.Compile(regex)
					if err == nil {
						f.Patterns = append(f.Patterns, CompiledPattern{Original: orig, Regexp: re})
					}
				}
			}
		}
	}

	// Label selectors
	if labels, ok := filterSpec["label_selectors"].(map[string]any); ok {
		for k, v := range labels {
			if s, ok := v.(string); ok {
				f.Labels[k] = s
			}
		}
	}

	return f
}

// compilePatternList compiles a list of [pattern_str, regex] pairs from cache data.
func compilePatternList(patterns []any) []CompiledPattern {
	var compiled []CompiledPattern
	for _, p := range patterns {
		if pair, ok := p.([]any); ok && len(pair) >= 2 {
			orig, _ := pair[0].(string)
			regex, _ := pair[1].(string)
			if regex != "" {
				re, err := regexp.Compile(regex)
				if err == nil {
					compiled = append(compiled, CompiledPattern{Original: orig, Regexp: re})
				}
			}
		}
	}
	return compiled
}

// toStringSet converts []any to map[string]struct{}.
func toStringSet(items []any) map[string]struct{} {
	s := make(map[string]struct{}, len(items))
	for _, item := range items {
		if str, ok := item.(string); ok {
			s[str] = struct{}{}
		}
	}
	return s
}
