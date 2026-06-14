package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/attack"
	"github.com/opensecstack/threatflow/internal/db/store"
)

// Technique serves MITRE ATT&CK endpoints.
type Technique struct {
	logger zerolog.Logger
	ttps   *store.TTPStore
}

// NewTechnique creates a Technique handler. ttps may be nil to serve static
// lookups only.
func NewTechnique(logger zerolog.Logger, ttps *store.TTPStore) *Technique {
	return &Technique{
		logger: logger.With().Str("handler", "technique").Logger(),
		ttps:   ttps,
	}
}

// List returns a summary of technique usage across all IOCs plus the embedded
// catalogue. ?limit controls the summary rows.
func (h *Technique) List(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	var summary []store.TechniqueCount
	if h.ttps != nil {
		s, err := h.ttps.Summary(r.Context(), limit)
		if err != nil {
			h.logger.Error().Err(err).Msg("summary")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "summary failed"})
			return
		}
		summary = s
	}

	// Enrich summary rows with technique name + tactic from the embedded catalogue.
	type row struct {
		TechniqueID string `json:"technique_id"`
		Name        string `json:"name,omitempty"`
		Tactic      string `json:"tactic,omitempty"`
		Count       int    `json:"count"`
	}
	enriched := make([]row, 0, len(summary))
	for _, s := range summary {
		t, _ := attack.Lookup(s.TechniqueID)
		enriched = append(enriched, row{
			TechniqueID: s.TechniqueID,
			Name:        t.Name,
			Tactic:      t.Tactic,
			Count:       s.Count,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"summary":   enriched,
		"catalogue": attack.Techniques,
	})
}

// ForIOC returns the technique tags attached to a single IOC.
func (h *Technique) ForIOC(w http.ResponseWriter, r *http.Request) {
	if h.ttps == nil {
		writeJSON(w, http.StatusOK, map[string]any{"tags": []any{}})
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	tags, err := h.ttps.ForIOC(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "ioc not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetch failed"})
		return
	}

	type enrichedTag struct {
		*store.TTPTag
		Name   string `json:"name,omitempty"`
		Tactic string `json:"tactic,omitempty"`
	}
	out := make([]enrichedTag, 0, len(tags))
	for _, t := range tags {
		tech, _ := attack.Lookup(t.TechniqueID)
		out = append(out, enrichedTag{TTPTag: t, Name: tech.Name, Tactic: tech.Tactic})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tags": out})
}
