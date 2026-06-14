package handlers

import (
	"net/http"
	"os"
	"time"
)

// HealthCheck returns detailed service status.
// startTime should be captured once when the server starts and passed in via closure.
func HealthCheck(d Deps, startTime time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		version := os.Getenv("APP_VERSION")
		if version == "" {
			version = "dev"
		}

		dbStart := time.Now()
		dbErr := d.Pool.Ping(r.Context())
		dbLatencyMS := time.Since(dbStart).Milliseconds()
		dbOK := dbErr == nil

		statusCode := http.StatusOK
		if !dbOK {
			statusCode = http.StatusServiceUnavailable
		}

		writeJSON(w, statusCode, map[string]any{
			"ok":             dbOK,
			"version":        version,
			"uptime_seconds": int(time.Since(startTime).Seconds()),
			"db": map[string]any{
				"ok":         dbOK,
				"latency_ms": dbLatencyMS,
			},
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// ReadinessCheck is a lightweight liveness probe that verifies DB reachability.
func ReadinessCheck(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := d.Pool.Ping(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ready":  false,
				"reason": "db unreachable",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ready": true,
		})
	}
}
