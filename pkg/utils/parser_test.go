package utils

import (
	"math"
	"testing"
)

func TestParseCPU(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  float64
	}{
		{"empty string", "", 0.0},
		{"whitespace only", "   ", 0.0},
		{"plain integer", "2", 2.0},
		{"plain float", "1.5", 1.5},
		{"zero", "0", 0.0},
		{"millicores", "500m", 0.5},
		{"millicores small", "100m", 0.1},
		{"millicores 1000", "1000m", 1.0},
		{"microcores", "1000000u", 1.0},
		{"nanocores", "1000000000n", 1.0},
		{"with leading whitespace", "  500m", 0.5},
		{"with trailing whitespace", "500m  ", 0.5},
		{"invalid suffix", "500x", 0.0},
		{"invalid number with m", "abcm", 0.0},
		{"invalid number with u", "abcu", 0.0},
		{"invalid number with n", "abcn", 0.0},
		{"float millicores", "250.5m", 0.2505},
		{"negative number", "-1", -1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseCPU(tt.input)
			if math.Abs(got-tt.want) > 1e-9 {
				t.Errorf("ParseCPU(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseMemory(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int64
	}{
		{"empty string", "", 0},
		{"whitespace only", "   ", 0},
		{"plain number", "1024", 1024},
		{"zero", "0", 0},
		{"Ki", "1Ki", 1024},
		{"Mi", "1Mi", 1024 * 1024},
		{"Gi", "1Gi", 1024 * 1024 * 1024},
		{"Ti", "1Ti", 1024 * 1024 * 1024 * 1024},
		{"Pi", "1Pi", 1024 * 1024 * 1024 * 1024 * 1024},
		{"K (decimal)", "1K", 1000},
		{"M (decimal)", "1M", 1000 * 1000},
		{"G (decimal)", "1G", 1000 * 1000 * 1000},
		{"T (decimal)", "1T", 1000 * 1000 * 1000 * 1000},
		{"P (decimal)", "1P", 1000 * 1000 * 1000 * 1000 * 1000},
		{"lowercase k", "1k", 1024},
		{"lowercase m", "1m", 1024 * 1024},
		{"lowercase g", "1g", 1024 * 1024 * 1024},
		{"float value Ki", "1.5Ki", 1536},
		{"float value Mi", "2.5Mi", int64(2.5 * 1024 * 1024)},
		{"with whitespace", "  1Gi  ", 1024 * 1024 * 1024},
		{"invalid suffix", "100X", 0},
		{"invalid number", "abcMi", 0},
		{"just suffix", "Ki", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseMemory(tt.input)
			if got != tt.want {
				t.Errorf("ParseMemory(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
