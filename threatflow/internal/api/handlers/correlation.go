package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/db/store"
)

// Correlation serves ioc_correlations endpoints.
type Correlation struct {
	logger zerolog.Logger
	store  *store.CorrelationStore
}

// NewCorrelation creates a Correlation handler.
func NewCorrelation(logger zerolog.Logger, s *store.CorrelationStore) *Correlation {
	return &Correlation{
		logger: logger.With().Str("handler", "correlation").Logger(),
		store:  s,
	}
}

// ForIOC returns every correlation that touches the queried IOC, in either
// direction, enriched with the counterparty's type + value.
func (h *Correlation) ForIOC(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusOK, map[string]any{"correlations": []any{}})
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	items, err := h.store.ForIOC(r.Context(), id)
	if err != nil {
		h.logger.Error().Err(err).Msg("list correlations")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetch failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"correlations": items, "total": len(items)})
}

// Summary returns per-relationship counts across the whole database.
func (h *Correlation) Summary(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusOK, map[string]any{"summary": []any{}})
		return
	}
	rows, err := h.store.Summary(r.Context())
	if err != nil {
		h.logger.Error().Err(err).Msg("summary")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "summary failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"summary": rows})
}
