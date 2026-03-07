package api

import (
	"testing"
)

func TestExtractNames_WithItems(t *testing.T) {
	source := map[string]any{
		"fields": []any{
			map[string]any{"name": "cpu"},
			map[string]any{"name": "memory"},
		},
	}
	got := extractNames(source, "fields")
	if len(got) != 2 || got[0] != "cpu" || got[1] != "memory" {
		t.Errorf("got %v, want [cpu memory]", got)
	}
}

func TestExtractNames_Empty(t *testing.T) {
	source := map[string]any{"fields": []any{}}
	got := extractNames(source, "fields")
	if len(got) != 0 {
		t.Errorf("got %v, want []", got)
	}
}

func TestExtractNames_MissingNameSkipped(t *testing.T) {
	source := map[string]any{
		"fields": []any{
			map[string]any{"name": "cpu"},
			map[string]any{"other": "val"},
			nil,
		},
	}
	got := extractNames(source, "fields")
	if len(got) != 1 || got[0] != "cpu" {
		t.Errorf("got %v, want [cpu]", got)
	}
}
