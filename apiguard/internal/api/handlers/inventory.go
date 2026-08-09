package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/db"
)

// Inventory handles API inventory endpoints.
type Inventory struct {
	logger zerolog.Logger
	db     *db.DB
}

// NewInventory creates a new Inventory handler.
func NewInventory(logger zerolog.Logger, database *db.DB) *Inventory {
	return &Inventory{
		logger: logger.With().Str("handler", "inventory").Logger(),
		db:     database,
	}
}

// List handles GET /api/v1/inventory.
// Query params: limit (default 50), offset (default 0).
func (h *Inventory) List(w http.ResponseWriter, r *http.Request) {
	limit, offset := inventoryPagination(r)

	if h.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"items":  []any{},
			"total":  0,
			"limit":  limit,
			"offset": offset,
		})
		return
	}

	items, total, err := h.db.ListAPIInventory(r.Context(), limit, offset)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to list inventory")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if items == nil {
		items = []db.APIInventory{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// GetHistory handles GET /api/v1/inventory/{id}/history.
// Returns the scan history for a specific inventory item.
// Query params: limit (default 50), offset (default 0).
func (h *Inventory) GetHistory(w http.ResponseWriter, r *http.Request) {
	idParam := chi.URLParam(r, "id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid inventory id"})
		return
	}

	if h.db == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "inventory item not found"})
		return
	}

	// Verify the inventory item exists.
	inv, err := h.db.GetAPIInventoryByID(r.Context(), id)
	if err != nil || inv == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "inventory item not found"})
		return
	}

	limit, offset := inventoryPagination(r)
	scans, total, err := h.db.GetAPIInventoryHistory(r.Context(), id, limit, offset)
	if err != nil {
		h.logger.Error().Err(err).Str("inventory_id", id.String()).Msg("failed to get inventory history")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if scans == nil {
		scans = []db.Scan{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"inventory_id": id,
		"target_url":   inv.TargetURL,
		"scans":        scans,
		"total":        total,
		"limit":        limit,
		"offset":       offset,
	})
}

// inventoryPagination extracts limit/offset from query params for inventory endpoints.
func inventoryPagination(r *http.Request) (int, int) {
	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}
