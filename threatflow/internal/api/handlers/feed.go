package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/citadel"
	"github.com/opensecstack/threatflow/internal/db/store"
)

// Feed handles CRUD for the feeds table.
type Feed struct {
	logger  zerolog.Logger
	store   *store.FeedStore
	citadel *citadel.Client
}

// NewFeed creates a Feed handler. citadelC may be nil — governance disabled.
func NewFeed(logger zerolog.Logger, s *store.FeedStore, citadelC *citadel.Client) *Feed {
	return &Feed{
		logger:  logger.With().Str("handler", "feed").Logger(),
		store:   s,
		citadel: citadelC,
	}
}

// gate runs MARSHAL Evaluate for a mutation. Returns true when the caller
// may proceed; writes the error response and returns false otherwise.
func (h *Feed) gate(w http.ResponseWriter, r *http.Request, action, description string) bool {
	if h.citadel == nil || !h.citadel.Enabled() {
		return true
	}
	actorUserID, actorRole, actorToken := actorFromRequest(r)
	decision, err := h.citadel.Evaluate(r.Context(), action, description, actorUserID, "", actorRole, actorToken)
	if err != nil {
		h.logger.Error().Err(err).Msg("marshal evaluate")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "governance check failed"})
		return false
	}
	if !decision.Allowed() {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":   "refused by citadel",
			"outcome": decision.Outcome,
			"reasons": decision.Reasons,
		})
		return false
	}
	return true
}

type feedRequest struct {
	Name           string `json:"name"`
	FeedType       string `json:"feed_type"`
	URL            string `json:"url"`
	PollInterval   string `json:"poll_interval"`
	ConfidenceBase int    `json:"confidence_base"`
	AccuracyRatio  float64 `json:"accuracy_ratio"`
	Enabled        *bool  `json:"enabled"`
}

// List returns all feeds. ?enabled=true restricts to enabled only.
func (h *Feed) List(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusOK, map[string]any{"feeds": []any{}})
		return
	}
	enabledOnly := r.URL.Query().Get("enabled") == "true"
	feeds, err := h.store.List(r.Context(), enabledOnly)
	if err != nil {
		h.logger.Error().Err(err).Msg("list feeds")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "list failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"feeds": feeds})
}

// Create inserts a new feed row.
func (h *Feed) Create(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "persistence disabled"})
		return
	}
	var req feedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Name == "" || req.FeedType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and feed_type are required"})
		return
	}
	if !validFeedType(req.FeedType) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "feed_type must be one of taxii21, csv, misp, manual"})
		return
	}

	if !h.gate(w, r, citadel.ActionFeedCreate, "create feed "+req.Name+" ("+req.FeedType+")") {
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	accuracy := req.AccuracyRatio
	if accuracy == 0 {
		accuracy = 1.0
	}
	confidence := req.ConfidenceBase
	if confidence == 0 {
		confidence = 50
	}

	f := &store.Feed{
		Name:           req.Name,
		FeedType:       req.FeedType,
		URL:            req.URL,
		PollInterval:   req.PollInterval,
		ConfidenceBase: confidence,
		AccuracyRatio:  accuracy,
		Enabled:        enabled,
	}
	if err := h.store.Create(r.Context(), f); err != nil {
		h.logger.Error().Err(err).Msg("create feed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create failed"})
		return
	}
	if h.citadel != nil {
		h.citadel.EmitAsync("threatflow", citadel.ActionFeedCreate, map[string]any{
			"feed_id":   f.ID,
			"name":      f.Name,
			"feed_type": f.FeedType,
			"url":       f.URL,
		})
	}
	writeJSON(w, http.StatusCreated, f)
}

// Get fetches a single feed by UUID.
func (h *Feed) Get(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "feed not found"})
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	f, err := h.store.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "feed not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetch failed"})
		return
	}
	writeJSON(w, http.StatusOK, f)
}

// Patch toggles the enabled flag. Body: {"enabled": bool}.
func (h *Feed) Patch(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "persistence disabled"})
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must contain enabled boolean"})
		return
	}
	if !h.gate(w, r, citadel.ActionFeedToggle, fmt.Sprintf("toggle feed %s enabled=%v", id, *body.Enabled)) {
		return
	}
	if err := h.store.SetEnabled(r.Context(), id, *body.Enabled); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "feed not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "update failed"})
		return
	}
	if h.citadel != nil {
		h.citadel.EmitAsync("threatflow", citadel.ActionFeedToggle, map[string]any{
			"feed_id": id,
			"enabled": *body.Enabled,
		})
	}
	writeJSON(w, http.StatusNoContent, nil)
}

// Delete removes the feed row.
func (h *Feed) Delete(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "persistence disabled"})
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if !h.gate(w, r, citadel.ActionFeedDelete, "delete feed "+id.String()) {
		return
	}
	if err := h.store.Delete(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "feed not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
		return
	}
	if h.citadel != nil {
		h.citadel.EmitAsync("threatflow", citadel.ActionFeedDelete, map[string]any{
			"feed_id": id,
		})
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func validFeedType(t string) bool {
	switch t {
	case "taxii21", "csv", "misp", "manual":
		return true
	}
	return false
}
