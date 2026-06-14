// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/opensecstack/securelab/internal/db"
)

// EnvironmentsHandler bundles dependencies for environment-related handlers.
type EnvironmentsHandler struct {
	pool *pgxpool.Pool
	log  *zap.Logger
}

// NewEnvironmentsHandler constructs an EnvironmentsHandler.
func NewEnvironmentsHandler(pool *pgxpool.Pool, log *zap.Logger) *EnvironmentsHandler {
	return &EnvironmentsHandler{pool: pool, log: log}
}

// ListEnvironments handles GET /api/v1/environments.
func (h *EnvironmentsHandler) ListEnvironments(w http.ResponseWriter, r *http.Request) {
	list, err := db.ListEnvironments(r.Context(), h.pool)
	if err != nil {
		h.log.Error("list environments", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if list == nil {
		list = []*db.Environment{}
	}
	writeJSON(w, http.StatusOK, list)
}

// GetEnvironment handles GET /api/v1/environments/{id}.
func (h *EnvironmentsHandler) GetEnvironment(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	env, err := db.GetEnvironment(r.Context(), h.pool, id)
	if err != nil {
		h.log.Error("get environment", zap.String("id", id), zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if env == nil {
		http.Error(w, "environment not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, env)
}

// createEnvironmentRequest is the JSON body accepted by CreateEnvironment.
type createEnvironmentRequest struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	TargetURL string `json:"target_url"`
	NetworkID string `json:"network_id"`
}

// CreateEnvironment handles POST /api/v1/environments (admin only).
func (h *EnvironmentsHandler) CreateEnvironment(w http.ResponseWriter, r *http.Request) {
	var req createEnvironmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if req.Kind != "docker" && req.Kind != "wasm" {
		http.Error(w, "kind must be docker or wasm", http.StatusBadRequest)
		return
	}
	if req.TargetURL == "" {
		http.Error(w, "target_url is required", http.StatusBadRequest)
		return
	}

	env := &db.Environment{
		Name:      req.Name,
		Kind:      req.Kind,
		TargetURL: req.TargetURL,
		NetworkID: req.NetworkID,
		Status:    "ready",
	}

	id, err := db.InsertEnvironment(r.Context(), h.pool, env)
	if err != nil {
		h.log.Error("insert environment", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// DeleteEnvironment handles DELETE /api/v1/environments/{id} (admin only).
// Updates the environment status to "teardown". Full resource deletion is
// handled by a background cleanup process to avoid blocking the HTTP response.
func (h *EnvironmentsHandler) DeleteEnvironment(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	env, err := db.GetEnvironment(r.Context(), h.pool, id)
	if err != nil {
		h.log.Error("get environment for delete", zap.String("id", id), zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if env == nil {
		http.Error(w, "environment not found", http.StatusNotFound)
		return
	}
	if env.Status == "running" {
		http.Error(w, "cannot delete a running environment", http.StatusConflict)
		return
	}

	const sql = `UPDATE environments SET status = 'teardown', updated_at = now() WHERE id = $1`
	if _, err := h.pool.Exec(r.Context(), sql, id); err != nil {
		h.log.Error("mark environment teardown", zap.String("id", id), zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
