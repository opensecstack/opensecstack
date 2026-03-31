package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
)

// IOC handles threat intelligence indicator endpoints.
// This is a scaffold — full implementation will add DB persistence,
// STIX 2.1 parsing, feed polling, and CITADEL WORM logging.
type IOC struct {
	logger zerolog.Logger
}

// NewIOC creates a new IOC handler.
func NewIOC(logger zerolog.Logger) *IOC {
	return &IOC{logger: logger.With().Str("handler", "ioc").Logger()}
}

// List returns all IOCs (placeholder).
func (h *IOC) List(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"items": []any{},
		"total": 0,
	})
}

// Ingest accepts a new IOC (placeholder).
func (h *IOC) Ingest(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}
	h.logger.Info().Interface("ioc", body).Msg("IOC ingested (scaffold — not persisted)")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}

// Get returns a single IOC by ID (placeholder).
func (h *IOC) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": "ioc not found", "id": id})
}

// ListBundles returns STIX 2.1 bundles (placeholder).
func (h *IOC) ListBundles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"bundles": []any{},
		"total":   0,
	})
}

// IngestBundle accepts a STIX 2.1 bundle (placeholder).
func (h *IOC) IngestBundle(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}
	h.logger.Info().Msg("STIX bundle ingested (scaffold — not persisted)")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}
