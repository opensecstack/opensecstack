// Content version read handler.
//
// GET /api/v1/content/versions/{id} returns the content version record
// identified by its UUID primary key. Intended for auditor reads — an
// external verifier can cross-check the content_version_id stamped on a
// completion record against this endpoint to confirm the exact lesson
// revision the learner completed.
package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"

	"github.com/opensecstack/cyberpath/internal/db"
)

// ContentVersionByIDGetter is the narrow store interface this handler needs.
type ContentVersionByIDGetter interface {
	GetByID(ctx context.Context, id uuid.UUID) (*db.ContentVersion, error)
}

// ContentVersionsHandler serves GET /api/v1/content/versions/{id}.
type ContentVersionsHandler struct {
	Store  ContentVersionByIDGetter
	Logger *zerolog.Logger
}

// NewContentVersionsHandler wires a ContentVersionsHandler.
func NewContentVersionsHandler(store ContentVersionByIDGetter, logger *zerolog.Logger) *ContentVersionsHandler {
	return &ContentVersionsHandler{Store: store, Logger: logger}
}

// Get handles GET /api/v1/content/versions/{id}.
func (h *ContentVersionsHandler) Get(w http.ResponseWriter, r *http.Request) {
	raw := chi.URLParam(r, "id")
	id, err := uuid.Parse(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "content version id must be a UUID")
		return
	}

	cv, err := h.Store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "not_found", "content version not found")
			return
		}
		h.log().Error().Err(err).Str("id", raw).Msg("content_versions.get")
		writeError(w, http.StatusInternalServerError, "internal_error", "content version lookup failed")
		return
	}

	writeJSON(w, http.StatusOK, cv)
}

func (h *ContentVersionsHandler) log() *zerolog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	z := zerolog.Nop()
	return &z
}
