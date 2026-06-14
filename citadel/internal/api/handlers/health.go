package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/opensecstack/citadel/internal/db"
	"github.com/opensecstack/citadel/internal/version"
)

// Health handles GET /api/v1/health.
type Health struct {
	logger zerolog.Logger
	db     *db.DB
}

// NewHealth creates a Health handler.
func NewHealth(logger zerolog.Logger, database *db.DB) *Health {
	return &Health{logger: logger, db: database}
}

// ServeHTTP returns server health status.
func (h *Health) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	resp := map[string]string{
		"status":  "ok",
		"version": version.Version,
		"commit":  version.GitCommit,
		"built":   version.BuildDate,
	}

	if h.db != nil {
		if err := h.db.Ping(ctx); err != nil {
			h.logger.Error().Err(err).Msg("health: database ping failed")
			resp["status"] = "degraded"
			resp["db"] = "unreachable"
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		resp["db"] = "ok"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
