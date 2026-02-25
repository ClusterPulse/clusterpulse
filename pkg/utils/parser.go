package utils

import (
	"strconv"
	"strings"
)

// ParseCPU parses CPU string to cores
func ParseCPU(cpu string) float64 {
	if cpu == "" {
		return 0.0
	}

	// Remove any whitespace
	cpu = strings.TrimSpace(cpu)

	// Check if it's already a number
	if val, err := strconv.ParseFloat(cpu, 64); err == nil {
		return val
	}

	// Handle millicores (e.g., "100m")
	if rest, ok := strings.CutSuffix(cpu, "m"); ok {
		val, err := strconv.ParseFloat(rest, 64)
		if err == nil {
			return val / 1000
		}
	}

	// Handle microcores
	if rest, ok := strings.CutSuffix(cpu, "u"); ok {
		val, err := strconv.ParseFloat(rest, 64)
		if err == nil {
			return val / 1000000
		}
	}

	// Handle nanocores
	if rest, ok := strings.CutSuffix(cpu, "n"); ok {
		val, err := strconv.ParseFloat(rest, 64)
		if err == nil {
			return val / 1000000000
		}
	}

	return 0.0
}

// ParseMemory parses memory string to bytes
func ParseMemory(mem string) int64 {
	if mem == "" {
		return 0
	}

	mem = strings.TrimSpace(mem)

	// Try parsing as plain number first
	if val, err := strconv.ParseInt(mem, 10, 64); err == nil {
		return val
	}

	units := map[string]int64{
		"Ki": 1024,
		"Mi": 1024 * 1024,
		"Gi": 1024 * 1024 * 1024,
		"Ti": 1024 * 1024 * 1024 * 1024,
		"Pi": 1024 * 1024 * 1024 * 1024 * 1024,
		"K":  1000,
		"M":  1000 * 1000,
		"G":  1000 * 1000 * 1000,
		"T":  1000 * 1000 * 1000 * 1000,
		"P":  1000 * 1000 * 1000 * 1000 * 1000,
		"k":  1024,
		"m":  1024 * 1024,
		"g":  1024 * 1024 * 1024,
	}

	for suffix, multiplier := range units {
		if rest, ok := strings.CutSuffix(mem, suffix); ok {
			if val, err := strconv.ParseFloat(rest, 64); err == nil {
				return int64(val * float64(multiplier))
			}
		}
	}

	return 0
}
