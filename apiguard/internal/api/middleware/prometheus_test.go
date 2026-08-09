package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValueToFloat(t *testing.T) {
	tests := []struct {
		name string
		v    expvarStringer
		want string
	}{
		{name: "integer", v: expvarStringerFunc(func() string { return "42" }), want: "42"},
		{name: "float", v: expvarStringerFunc(func() string { return "3.14" }), want: "3.14"},
		{name: "non-numeric falls back to zero", v: expvarStringerFunc(func() string { return "not-a-number" }), want: "0"},
		{name: "empty string falls back to zero", v: expvarStringerFunc(func() string { return "" }), want: "0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := valueToFloat(tc.v); got != tc.want {
				t.Errorf("valueToFloat(%q) = %q, want %q", tc.v.String(), got, tc.want)
			}
		})
	}
}

// expvarStringer is a minimal stand-in for expvar.Var (which just requires
// String() string), letting the test supply arbitrary raw values without
// depending on expvar's concrete types.
type expvarStringer interface {
	String() string
}

type expvarStringerFunc func() string

func (f expvarStringerFunc) String() string { return f() }

func TestPrometheusHandler_StatusCode(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics/prometheus", nil)
	rr := httptest.NewRecorder()

	PrometheusHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestPrometheusHandler_ContentType(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics/prometheus", nil)
	rr := httptest.NewRecorder()

	PrometheusHandler().ServeHTTP(rr, req)

	want := "text/plain; version=0.0.4; charset=utf-8"
	got := rr.Header().Get("Content-Type")
	if got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
}

func TestPrometheusHandler_ContainsMetricNames(t *testing.T) {
	// Ensure the expvar variables exist before the handler runs.
	// NewMetricsCollector is idempotent — safe to call multiple times.
	NewMetricsCollector()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics/prometheus", nil)
	rr := httptest.NewRecorder()

	PrometheusHandler().ServeHTTP(rr, req)

	body := rr.Body.String()

	wantMetrics := []string{
		"apiguard_http_requests_active",
		"apiguard_http_errors_total",
	}

	for _, metric := range wantMetrics {
		if !strings.Contains(body, metric) {
			t.Errorf("response body does not contain metric %q\nbody:\n%s", metric, body)
		}
	}
}
