package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"
)

// Scans handles scan-related API endpoints.
type Scans struct {
	logger zerolog.Logger
}

// NewScans creates a new Scans handler.
func NewScans(logger zerolog.Logger) *Scans {
	return &Scans{
		logger: logger.With().Str("handler", "scans").Logger(),
	}
}

func notImplemented(w http.ResponseWriter, resource string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   "not_implemented",
		"message": resource + " endpoint is not yet implemented",
	})
}

// Create handles POST /api/v1/scans.
func (s *Scans) Create(w http.ResponseWriter, r *http.Request) {
	notImplemented(w, "create scan")
}

// List handles GET /api/v1/scans.
func (s *Scans) List(w http.ResponseWriter, r *http.Request) {
	notImplemented(w, "list scans")
}

// Get handles GET /api/v1/scans/{id}.
func (s *Scans) Get(w http.ResponseWriter, r *http.Request) {
	notImplemented(w, "get scan")
}

// Findings handles GET /api/v1/scans/{id}/findings.
func (s *Scans) Findings(w http.ResponseWriter, r *http.Request) {
	notImplemented(w, "scan findings")
}

// Report handles GET /api/v1/scans/{id}/report.
func (s *Scans) Report(w http.ResponseWriter, r *http.Request) {
	notImplemented(w, "scan report")
}

// Delete handles DELETE /api/v1/scans/{id}.
func (s *Scans) Delete(w http.ResponseWriter, r *http.Request) {
	notImplemented(w, "delete scan")
}
