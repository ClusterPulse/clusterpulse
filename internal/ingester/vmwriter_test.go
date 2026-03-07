package ingester

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFormatLine_WithNode(t *testing.T) {
	line := formatLine("metric_name", "cluster-1", "node-1", 42, 1000)
	want := `metric_name{cluster="cluster-1",node="node-1"} 42 1000`
	if line != want {
		t.Errorf("got %q, want %q", line, want)
	}
}

func TestFormatLine_WithoutNode(t *testing.T) {
	line := formatLine("metric_name", "cluster-1", "", 3.14, 2000)
	want := `metric_name{cluster="cluster-1"} 3.14 2000`
	if line != want {
		t.Errorf("got %q, want %q", line, want)
	}
}

func TestBoolToInt(t *testing.T) {
	if boolToInt(true) != 1 {
		t.Error("true should be 1")
	}
	if boolToInt(false) != 0 {
		t.Error("false should be 0")
	}
}

func TestVMWriter_Send(t *testing.T) {
	var gotBody string
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		gotBody = string(buf)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	w := NewVMWriter(srv.URL)
	w.send(t.Context(), []string{
		`test_metric{cluster="c1"} 42 1000`,
		`test_metric2{cluster="c1"} 3.14 1000`,
	})

	if gotContentType != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", gotContentType)
	}
	if !strings.Contains(gotBody, "test_metric") {
		t.Errorf("body missing metric lines: %q", gotBody)
	}
	if !strings.HasSuffix(gotBody, "\n") {
		t.Error("body should end with newline")
	}
}
