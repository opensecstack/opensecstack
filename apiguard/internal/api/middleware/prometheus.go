package middleware

import (
	"expvar"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// PrometheusHandler returns an http.HandlerFunc that reads from the expvar
// registry and renders all apiguard metrics in Prometheus text exposition
// format (version 0.0.4).  No external dependencies are required.
func PrometheusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		var sb strings.Builder

		expvar.Do(func(kv expvar.KeyValue) {
			switch kv.Key {

			// ── http_requests_total map → apiguard_http_requests_total counter ──
			case "http_requests_total":
				m, ok := kv.Value.(*expvar.Map)
				if !ok {
					return
				}
				sb.WriteString("# HELP apiguard_http_requests_total Total HTTP requests processed, partitioned by method and status code.\n")
				sb.WriteString("# TYPE apiguard_http_requests_total counter\n")
				m.Do(func(entry expvar.KeyValue) {
					// key format: "METHOD:status"  e.g. "GET:200"
					parts := strings.SplitN(entry.Key, ":", 2)
					if len(parts) != 2 {
						return
					}
					method := parts[0]
					status := parts[1]
					val := valueToFloat(entry.Value)
					fmt.Fprintf(&sb, "apiguard_http_requests_total{method=%q,status=%q} %s\n",
						method, status, val)
				})

			// ── http_request_duration_ms map → apiguard_http_request_duration_ms gauge ──
			case "http_request_duration_ms":
				m, ok := kv.Value.(*expvar.Map)
				if !ok {
					return
				}
				sb.WriteString("# HELP apiguard_http_request_duration_ms Cumulative HTTP request duration in milliseconds, partitioned by method and path.\n")
				sb.WriteString("# TYPE apiguard_http_request_duration_ms gauge\n")
				m.Do(func(entry expvar.KeyValue) {
					// key format: "METHOD:/path"  e.g. "GET:/api/v1/scans"
					parts := strings.SplitN(entry.Key, ":", 2)
					if len(parts) != 2 {
						return
					}
					method := parts[0]
					path := parts[1]
					val := valueToFloat(entry.Value)
					fmt.Fprintf(&sb, "apiguard_http_request_duration_ms{method=%q,path=%q} %s\n",
						method, path, val)
				})

			// ── http_active_requests int → apiguard_http_requests_active gauge ──
			case "http_active_requests":
				iv, ok := kv.Value.(*expvar.Int)
				if !ok {
					return
				}
				sb.WriteString("# HELP apiguard_http_requests_active Number of HTTP requests currently being processed.\n")
				sb.WriteString("# TYPE apiguard_http_requests_active gauge\n")
				fmt.Fprintf(&sb, "apiguard_http_requests_active %d\n", iv.Value())

			// ── http_errors_total int → apiguard_http_errors_total counter ──
			case "http_errors_total":
				iv, ok := kv.Value.(*expvar.Int)
				if !ok {
					return
				}
				sb.WriteString("# HELP apiguard_http_errors_total Total HTTP 5xx responses returned by the server.\n")
				sb.WriteString("# TYPE apiguard_http_errors_total counter\n")
				fmt.Fprintf(&sb, "apiguard_http_errors_total %d\n", iv.Value())
			}
		})

		fmt.Fprint(w, sb.String())
	}
}

// valueToFloat converts an expvar.Value to its string representation suitable
// for Prometheus (integer or float).  Falls back to "0" on parse failure.
func valueToFloat(v expvar.Var) string {
	raw := v.String()
	// expvar integers serialise as plain decimal; floats include a dot.
	if _, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return raw
	}
	if _, err := strconv.ParseFloat(raw, 64); err == nil {
		return raw
	}
	return "0"
}
