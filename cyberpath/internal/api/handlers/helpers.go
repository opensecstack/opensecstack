// Package handlers wires HTTP handlers for CyberPath's API.
//
// All handlers return JSON, set Content-Type, and use a single error
// envelope: {"error": {"code": "...", "message": "..."}}.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/log"
)

// Pinger abstracts the DB (or any dependency) the readiness probe checks.
type Pinger interface {
	Ping(ctx context.Context) error
}

// writeJSON encodes v as JSON with the given status. Errors are logged.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Error().Err(err).Msg("encode response")
	}
}

// writeError emits the standard error envelope.
func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}
