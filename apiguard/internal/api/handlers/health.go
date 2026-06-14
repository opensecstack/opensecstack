package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/db"
	"github.com/opensecstack/apiguard/internal/version"
)

var startTime = time.Now()

// Health handles health and version endpoints.
type Health struct {
	logger zerolog.Logger
	db     *db.DB
}

// NewHealth creates a new Health handler (shallow health only).
func NewHealth(logger zerolog.Logger) *Health {
	return &Health{
		logger: logger.With().Str("handler", "health").Logger(),
	}
}

// NewHealthWithDB creates a Health handler with deep health checks (DB ping).
func NewHealthWithDB(logger zerolog.Logger, database *db.DB) *Health {
	return &Health{
		logger: logger.With().Str("handler", "health").Logger(),
		db:     database,
	}
}

// HealthResponse is the JSON response for the health endpoint.
type HealthResponse struct {
	Status    string            `json:"status"`
	Timestamp string            `json:"timestamp"`
	Uptime    string            `json:"uptime"`
	Checks    map[string]string `json:"checks,omitempty"`
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

// Health returns the server health status.
// When created with NewHealthWithDB, it also pings the database.
func (h *Health) Health(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	httpStatus := http.StatusOK
	checks := map[string]string{}

	// Deep health: DB ping
	if h.db != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := h.db.Pool.Ping(ctx); err != nil {
			checks["database"] = "unhealthy: " + err.Error()
			status = "degraded"
			httpStatus = http.StatusServiceUnavailable
			h.logger.Warn().Err(err).Msg("health check: database ping failed")
		} else {
			checks["database"] = "ok"
		}
	}

	resp := HealthResponse{
		Status:    status,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Uptime:    time.Since(startTime).Round(time.Second).String(),
	}
	if len(checks) > 0 {
		resp.Checks = checks
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error().Err(err).Msg("failed to encode health response")
	}
}

// Version returns the server version information.
func (h *Health) Version(w http.ResponseWriter, r *http.Request) {
	resp := VersionResponse{
		Version:   version.Version,
		GitCommit: version.GitCommit,
		BuildDate: version.BuildDate,
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
