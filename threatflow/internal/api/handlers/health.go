package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/version"
)

// Health handles health and version endpoints.
type Health struct {
	logger zerolog.Logger
}

// NewHealth creates a new Health handler.
func NewHealth(logger zerolog.Logger) *Health {
	return &Health{logger: logger.With().Str("handler", "health").Logger()}
}

// Health responds with the service health status.
func (h *Health) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Encode errors are ignored: status + Content-Type are already on the
	// wire, and clients must already tolerate truncated bodies for any
	// connection-level issue.
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "threatflow",
	})
}

// Version responds with the current version.
func (h *Health) Version(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"version":    version.Version,
		"git_commit": version.GitCommit,
		"build_date": version.BuildDate,
	})
}
