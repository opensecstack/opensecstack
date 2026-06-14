// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/opensecstack/securelab/internal/db"
)

// ResultsHandler bundles dependencies for run result handlers.
type ResultsHandler struct {
	pool *pgxpool.Pool
	log  *zap.Logger
}

// NewResultsHandler constructs a ResultsHandler.
func NewResultsHandler(pool *pgxpool.Pool, log *zap.Logger) *ResultsHandler {
	return &ResultsHandler{pool: pool, log: log}
}

// ListRuns handles GET /api/v1/runs (analyst+).
// Returns all scenario run rows ordered by start time descending.
func (h *ResultsHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	list, err := db.ListRuns(r.Context(), h.pool)
	if err != nil {
		h.log.Error("list runs", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if list == nil {
		list = []*db.ScenarioRun{}
	}
	writeJSON(w, http.StatusOK, list)
}

// GetRun handles GET /api/v1/runs/{id} (analyst+).
// Returns 404 when the run does not exist.
func (h *ResultsHandler) GetRun(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	run, err := db.GetRun(r.Context(), h.pool, id)
	if err != nil {
		h.log.Error("get run", zap.String("id", id), zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if run == nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, run)
}
