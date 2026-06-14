// Package handlers wires HTTP handlers for VertGuard's API.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/opensecstack/vertguard/internal/version"
)

// MediaBinaryPath is set by cmd/server at startup to the configured
// c2pa-verify binary path. Empty means "not configured"; the health
// handler reports media as inactive in that case. Package-level so
// the handler doesn't need restructuring to take config as a dep.
var MediaBinaryPath atomic.Value // string

func mediaModuleStatus() string {
	v, _ := MediaBinaryPath.Load().(string)
	if v == "" {
		return "inactive (binary_path unset)"
	}
	if _, err := os.Stat(v); err != nil {
		return "inactive (binary missing at " + v + ")"
	}
	return "active"
}

// Pinger abstracts the DB (or any dependency) the health handler
// verifies.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Ready is a process-wide readiness flag flipped to false during graceful
// shutdown so Kubernetes drains traffic before the listener stops.
// Package-level so cmd/server can flip it without holding a Server ref.
var Ready atomic.Bool

func init() {
	// Default to ready — flipped off during shutdown.
	Ready.Store(true)
}

type moduleStatus struct {
	Prompt     string `json:"prompt"`
	ThreatFeed string `json:"threatfeed"`
	Media      string `json:"media"`
	Phishing   string `json:"phishing"`
	Identity   string `json:"identity"`
}

type integrationStatus struct {
	CITADEL    string `json:"citadel"`
	ThreatFlow string `json:"threatflow"`
}

type healthResponse struct {
	Status       string            `json:"status"`
	DB           string            `json:"db"`
	Version      string            `json:"version"`
	Commit       string            `json:"commit"`
	Built        string            `json:"built"`
	Modules      moduleStatus      `json:"modules"`
	Integrations integrationStatus `json:"integrations"`
}

type liveResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type readyResponse struct {
	Status string `json:"status"`
	DB     string `json:"db"`
}

// Live returns a probe handler that always reports the process is alive.
// No dependency checks: kubelet uses this to decide whether to kill the
// pod, and a transient DB blip must not trigger a restart.
func Live() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := version.Get()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(liveResponse{
			Status:  "alive",
			Version: info.Version,
			Commit:  info.GitCommit,
		})
	}
}

// Ready returns a probe handler that gates traffic on dependency health
// AND the process-wide Ready flag. During shutdown the flag is flipped
// to false so the load balancer drains the pod before the listener
// stops accepting connections.
func ReadyHandler(pinger Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Drain flag wins over DB health: even a healthy pod must report
		// not-ready once shutdown begins.
		if !Ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(readyResponse{Status: "draining", DB: "skipped"})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		resp := readyResponse{Status: "ready", DB: "ok"}
		if pinger == nil {
			resp.DB = "no_pinger"
		} else if err := pinger.Ping(ctx); err != nil {
			resp.Status = "not_ready"
			resp.DB = "fail"
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// Health is the legacy combined probe — prefer /livez and /readyz on
// new deployments. Kept for backwards compatibility with existing
// dashboards and the pre-split deployment manifests.
func Health(pinger Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		info := version.Get()

		resp := healthResponse{
			Status:  "ok",
			Version: info.Version,
			Commit:  info.GitCommit,
			Built:   info.BuildDate,
			Modules: moduleStatus{
				Prompt:     "active",
				ThreatFeed: "active",
				Media:      mediaModuleStatus(),
				Phishing:   "inactive (Phase 4.2)",
				Identity:   "inactive (Phase 4.3)",
			},
			Integrations: integrationStatus{
				CITADEL:    "standalone",
				ThreatFlow: "standalone",
			},
		}

		// DB ping
		if pinger == nil {
			resp.DB = "no_pinger"
			resp.Status = "degraded"
		} else if err := pinger.Ping(ctx); err != nil {
			resp.DB = "fail"
			resp.Status = "degraded"
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			resp.DB = "ok"
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
