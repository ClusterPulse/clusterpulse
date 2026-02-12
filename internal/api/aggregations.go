package api

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"
)

// recomputeAggregations recomputes aggregation values from a filtered resource list.
// Used when a user has partial access and filterAggregations is enabled.
func recomputeAggregations(resources []map[string]any, specs []map[string]any) map[string]any {
	results := make(map[string]any, len(specs))

	for _, spec := range specs {
		name, _ := spec["name"].(string)
		function, _ := spec["function"].(string)
		field, _ := spec["field"].(string)
		filterSpec, _ := spec["filter"].(map[string]any)
		groupBy, _ := spec["groupBy"].(string)

		filtered := resources
		if filterSpec != nil {
			var matched []map[string]any
			for _, r := range resources {
				if matchesFilter(r, filterSpec) {
					matched = append(matched, r)
				}
			}
			filtered = matched
		}

		var val any
		var err error
		if groupBy != "" {
			val, err = computeGrouped(filtered, function, field, groupBy)
		} else {
			val, err = computeSingle(filtered, function, field, spec)
		}

		if err != nil {
			logrus.Warnf("Failed to compute aggregation '%s': %v", name, err)
			results[name] = nil
		} else {
			results[name] = val
		}
	}

	return results
}

// getFieldValue extracts a field value from a resource, checking values dict,
// root level, underscore-prefixed fields, and dot notation.
func getFieldValue(resource map[string]any, field string) any {
	// Check values dict first (collector nests extracted fields there)
	if values, ok := resource["values"].(map[string]any); ok {
		if v, ok := values[field]; ok {
			return v
		}
	}

	// Root level
	if v, ok := resource[field]; ok {
		return v
	}

	// Underscore-prefixed fields
	switch field {
	case "namespace", "name", "id", "labels":
		if v, ok := resource["_"+field]; ok {
			return v
		}
	}

	// Dot notation for nested paths
	if strings.Contains(field, ".") {
		parts := strings.Split(field, ".")
		var current any = resource
		for _, part := range parts {
			m, ok := current.(map[string]any)
			if !ok {
				return nil
			}
			current = m[part]
		}
		return current
	}

	return nil
}

// matchesFilter checks if a resource matches a filter specification.
func matchesFilter(resource map[string]any, filterSpec map[string]any) bool {
	if filterSpec == nil {
		return true
	}

	field, _ := filterSpec["field"].(string)
	operator, _ := filterSpec["operator"].(string)
	if operator == "" {
		operator = "equals"
	}
	value := filterSpec["value"]

	fieldValue := getFieldValue(resource, field)

	switch operator {
	case "equals":
		return fmt.Sprintf("%v", fieldValue) == fmt.Sprintf("%v", value)
	case "notEquals":
		return fmt.Sprintf("%v", fieldValue) != fmt.Sprintf("%v", value)
	case "greaterThan":
		return fieldValue != nil && toFloat(fieldValue) > toFloat(value)
	case "lessThan":
		return fieldValue != nil && toFloat(fieldValue) < toFloat(value)
	case "contains":
		if fieldValue == nil {
			return false
		}
		return strings.Contains(fmt.Sprintf("%v", fieldValue), fmt.Sprintf("%v", value))
	case "in":
		if list, ok := value.([]any); ok {
			fvStr := fmt.Sprintf("%v", fieldValue)
			for _, item := range list {
				if fmt.Sprintf("%v", item) == fvStr {
					return true
				}
			}
		}
		return false
	}

	return true
}

// computeSingle computes a single aggregation value.
func computeSingle(resources []map[string]any, function, field string, spec map[string]any) (any, error) {
	if function == "count" {
		return len(resources), nil
	}

	if field == "" {
		return nil, nil
	}

	var values []float64
	for _, r := range resources {
		v := getFieldValue(r, field)
		if v != nil {
			values = append(values, toFloat(v))
		}
	}

	if len(values) == 0 {
		if function == "sum" || function == "count" {
			return 0, nil
		}
		return nil, nil
	}

	switch function {
	case "sum":
		sum := 0.0
		for _, v := range values {
			sum += v
		}
		return sum, nil
	case "avg":
		sum := 0.0
		for _, v := range values {
			sum += v
		}
		return sum / float64(len(values)), nil
	case "min":
		m := values[0]
		for _, v := range values[1:] {
			if v < m {
				m = v
			}
		}
		return m, nil
	case "max":
		m := values[0]
		for _, v := range values[1:] {
			if v > m {
				m = v
			}
		}
		return m, nil
	case "percentile":
		p := 95.0
		if pv, ok := spec["percentile"].(float64); ok {
			p = pv
		}
		sort.Float64s(values)
		idx := int(float64(len(values)) * p / 100)
		if idx >= len(values) {
			idx = len(values) - 1
		}
		return values[idx], nil
	case "distinct":
		seen := make(map[float64]struct{})
		for _, v := range values {
			seen[v] = struct{}{}
		}
		return len(seen), nil
	}

	return nil, nil
}

// computeGrouped computes a grouped aggregation.
func computeGrouped(resources []map[string]any, function, field, groupBy string) (map[string]any, error) {
	groups := make(map[string][]map[string]any)

	for _, r := range resources {
		key := "unknown"
		if v := getFieldValue(r, groupBy); v != nil {
			key = fmt.Sprintf("%v", v)
		}
		groups[key] = append(groups[key], r)
	}

	result := make(map[string]any, len(groups))
	for k, v := range groups {
		val, _ := computeSingle(v, function, field, map[string]any{})
		result[k] = val
	}
	return result, nil
}

// toFloat converts any numeric value to float64.
func toFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case int32:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	default:
		// Try parsing string as number
		var f float64
		fmt.Sscanf(fmt.Sprintf("%v", v), "%f", &f)
		return f
	}
}

