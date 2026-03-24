package handlers

import (
	"net/http"

	"github.com/rs/zerolog"
)

// Findings handles finding-related API endpoints.
type Findings struct {
	logger zerolog.Logger
}

// NewFindings creates a new Findings handler.
func NewFindings(logger zerolog.Logger) *Findings {
	return &Findings{
		logger: logger.With().Str("handler", "findings").Logger(),
	}
}

// List handles GET /api/v1/findings.
func (f *Findings) List(w http.ResponseWriter, r *http.Request) {
	notImplemented(w, "list findings")
}

// Get handles GET /api/v1/findings/{id}.
func (f *Findings) Get(w http.ResponseWriter, r *http.Request) {
	notImplemented(w, "get finding")
}

// Update handles PATCH /api/v1/findings/{id}.
func (f *Findings) Update(w http.ResponseWriter, r *http.Request) {
	notImplemented(w, "update finding")
}
