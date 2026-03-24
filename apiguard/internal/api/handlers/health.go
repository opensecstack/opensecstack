package handlers

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"github.com/rs/zerolog"
)

var startTime = time.Now()

// Health handles health and version endpoints.
type Health struct {
	logger zerolog.Logger
}

// NewHealth creates a new Health handler.
func NewHealth(logger zerolog.Logger) *Health {
	return &Health{
		logger: logger.With().Str("handler", "health").Logger(),
	}
}

// HealthResponse is the JSON response for the health endpoint.
type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Uptime    string `json:"uptime"`
}

// VersionResponse is the JSON response for the version endpoint.
type VersionResponse struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Build-time variables (same as CLI, injected via ldflags).
var (
	version   = "dev"
	gitCommit = "unknown"
	buildDate = "unknown"
)

// Health returns the server health status.
func (h *Health) Health(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{
		Status:    "ok",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Uptime:    time.Since(startTime).Round(time.Second).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error().Err(err).Msg("failed to encode health response")
	}
}

// Version returns the server version information.
func (h *Health) Version(w http.ResponseWriter, r *http.Request) {
	resp := VersionResponse{
		Version:   version,
		GitCommit: gitCommit,
		BuildDate: buildDate,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error().Err(err).Msg("failed to encode version response")
	}
}
