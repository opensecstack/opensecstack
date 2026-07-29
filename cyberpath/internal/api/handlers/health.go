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

// NIS2HealthChecker abstracts the NIS2 Compass connectivity check
// (internal/nis2.Client.Health) so Readyz can report it in the
// `integrations.nis2compass` field documented in docs/api.md without
// this package depending on internal/nis2 directly.
type NIS2HealthChecker interface {
	Health(ctx context.Context) (bool, error)
}

// Readyz checks Ready flag + DB ping, plus NIS2 Compass connectivity
// when a checker is configured (nil disables the integrations report,
// e.g. in dev without NIS2_BASE_URL set).
func Readyz(pinger Pinger, nis2Checker NIS2HealthChecker) http.HandlerFunc {
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

		body := map[string]any{
			"status": "ready",
			"db":     dbStatus,
		}
		if nis2Checker != nil {
			nis2Status := "connected"
			if ok, err := nis2Checker.Health(ctx); err != nil || !ok {
				nis2Status = "unreachable"
			}
			// nis2compass is a best-effort dependency (see internal/nis2
			// package doc): its unreachability degrades readiness
			// reporting but does not fail /readyz itself.
			body["integrations"] = map[string]any{"nis2compass": nis2Status}
		}
		writeJSON(w, http.StatusOK, body)
	}
}

// Version returns build metadata.
func Version() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, version.Get())
	}
}
