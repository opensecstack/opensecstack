// Health, liveness, readiness, and version handlers for CyberPath.
package handlers

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/opensecstack/cyberpath/internal/version"
)

// Ready is a process-wide readiness flag flipped to false during graceful
// shutdown so Kubernetes drains traffic before the listener stops.
var Ready atomic.Bool

func init() { Ready.Store(true) }

// Healthz is the simple liveness probe — always 200 while the process runs.
func Healthz() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := version.Get()
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "alive",
			"version": info.Version,
			"commit":  info.GitCommit,
		})
	}
}

// Readyz checks Ready flag + DB ping.
func Readyz(pinger Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !Ready.Load() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status": "draining",
				"db":     "skipped",
			})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		dbStatus := "ok"
		if pinger == nil {
			dbStatus = "no_pinger"
		} else if err := pinger.Ping(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status": "not_ready",
				"db":     "fail",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ready",
			"db":     dbStatus,
		})
	}
}

// Version returns build metadata.
func Version() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, version.Get())
	}
}
