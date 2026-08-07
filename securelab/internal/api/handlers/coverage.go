// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package handlers

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/opensecstack/securelab/internal/db"
)

// CoverageHandler bundles dependencies for the MITRE ATT&CK coverage handler.
type CoverageHandler struct {
	pool *pgxpool.Pool
	log  *zap.Logger
}

// NewCoverageHandler constructs a CoverageHandler.
func NewCoverageHandler(pool *pgxpool.Pool, log *zap.Logger) *CoverageHandler {
	return &CoverageHandler{pool: pool, log: log}
}

// GetCoverage handles GET /api/v1/coverage (analyst+).
// Returns all mitre_coverage rows as a JSON array. The rows are ordered by
// technique_id, providing a stable MITRE ATT&CK coverage matrix snapshot.
func (h *CoverageHandler) GetCoverage(w http.ResponseWriter, r *http.Request) {
	list, err := db.ListCoverage(r.Context(), h.pool)
	if err != nil {
		h.log.Error("list coverage", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if list == nil {
		list = []*db.MitreCoverage{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": list})
}
