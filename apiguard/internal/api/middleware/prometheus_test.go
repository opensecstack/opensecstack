package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrometheusHandler_StatusCode(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/metrics/prometheus", nil)
	rr := httptest.NewRecorder()

	PrometheusHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestPrometheusHandler_ContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/metrics/prometheus", nil)
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

	req := httptest.NewRequest(http.MethodGet, "/metrics/prometheus", nil)
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
