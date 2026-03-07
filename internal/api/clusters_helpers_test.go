package api

import (
	"net/http"
	"net/url"
	"testing"
)

func TestPaginate_Basic(t *testing.T) {
	items := make([]map[string]any, 25)
	p := paginate(items, 1, 10)

	if p["total"] != 25 {
		t.Errorf("total = %v, want 25", p["total"])
	}
	if p["totalPages"] != 3 {
		t.Errorf("totalPages = %v, want 3", p["totalPages"])
	}
	if p["hasNext"] != true {
		t.Error("page 1 should hasNext")
	}
	if p["hasPrevious"] != false {
		t.Error("page 1 should not hasPrevious")
	}
}

func TestPaginate_Empty(t *testing.T) {
	p := paginate(nil, 1, 10)
	if p["totalPages"] != 1 {
		t.Errorf("empty list totalPages = %v, want 1", p["totalPages"])
	}
	if p["hasNext"] != false {
		t.Error("empty list should not hasNext")
	}
}

func TestPaginate_LastPage(t *testing.T) {
	items := make([]map[string]any, 20)
	p := paginate(items, 2, 10)
	if p["hasNext"] != false {
		t.Error("last page should not hasNext")
	}
	if p["hasPrevious"] != true {
		t.Error("page 2 should hasPrevious")
	}
}

func TestQueryInt_Default(t *testing.T) {
	r := &http.Request{URL: &url.URL{RawQuery: ""}}
	if got := queryInt(r, "page", 1); got != 1 {
		t.Errorf("got %d, want 1", got)
	}
}

func TestQueryInt_Valid(t *testing.T) {
	r := &http.Request{URL: &url.URL{RawQuery: "page=5"}}
	if got := queryInt(r, "page", 1); got != 5 {
		t.Errorf("got %d, want 5", got)
	}
}

func TestQueryInt_Invalid(t *testing.T) {
	r := &http.Request{URL: &url.URL{RawQuery: "page=abc"}}
	if got := queryInt(r, "page", 1); got != 1 {
		t.Errorf("got %d, want 1 (default on invalid)", got)
	}
}

func TestQueryInt_Negative(t *testing.T) {
	r := &http.Request{URL: &url.URL{RawQuery: "page=-1"}}
	if got := queryInt(r, "page", 1); got != 1 {
		t.Errorf("got %d, want 1 (default on negative)", got)
	}
}

func TestGetStringSliceFromMap_AnySlice(t *testing.T) {
	m := map[string]any{"roles": []any{"master", "worker"}}
	got := getStringSliceFromMap(m, "roles")
	if len(got) != 2 || got[0] != "master" || got[1] != "worker" {
		t.Errorf("got %v, want [master worker]", got)
	}
}

func TestGetStringSliceFromMap_StringSlice(t *testing.T) {
	m := map[string]any{"roles": []string{"master"}}
	got := getStringSliceFromMap(m, "roles")
	if len(got) != 1 || got[0] != "master" {
		t.Errorf("got %v, want [master]", got)
	}
}

func TestGetStringSliceFromMap_Missing(t *testing.T) {
	m := map[string]any{}
	if got := getStringSliceFromMap(m, "roles"); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestStatusWithFallback_Nil(t *testing.T) {
	got := statusWithFallback(nil)
	if got["health"] != "unknown" {
		t.Errorf("health = %v, want unknown", got["health"])
	}
}

func TestStatusWithFallback_NonNil(t *testing.T) {
	s := map[string]any{"health": "healthy"}
	got := statusWithFallback(s)
	if got["health"] != "healthy" {
		t.Errorf("health = %v, want healthy", got["health"])
	}
}

func TestEnsureMap_Nil(t *testing.T) {
	got := ensureMap(nil)
	if got == nil {
		t.Fatal("nil input should return empty map")
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

func TestEnsureMap_NonNil(t *testing.T) {
	m := map[string]any{"key": "val"}
	got := ensureMap(m)
	if got["key"] != "val" {
		t.Error("should return same map")
	}
}
