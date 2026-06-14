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
	"github.com/opensecstack/securelab/internal/scenarios"
)

// ScenariosHandler bundles the DB pool, scheduler, and logger needed by
// scenario-related HTTP handlers.
type ScenariosHandler struct {
	pool      *pgxpool.Pool
	scheduler *scenarios.Scheduler
	log       *zap.Logger
}

// NewScenariosHandler constructs a ScenariosHandler.
func NewScenariosHandler(pool *pgxpool.Pool, scheduler *scenarios.Scheduler, log *zap.Logger) *ScenariosHandler {
	return &ScenariosHandler{pool: pool, scheduler: scheduler, log: log}
}

// ListScenarios handles GET /api/v1/scenarios.
// Returns all scenario rows as a JSON array.
func (h *ScenariosHandler) ListScenarios(w http.ResponseWriter, r *http.Request) {
	list, err := db.ListScenarios(r.Context(), h.pool)
	if err != nil {
		h.log.Error("list scenarios", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if list == nil {
		list = []*db.Scenario{}
	}
	writeJSON(w, http.StatusOK, list)
}

// GetScenario handles GET /api/v1/scenarios/{id}.
// Returns 404 when the scenario does not exist.
func (h *ScenariosHandler) GetScenario(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	scenario, err := db.GetScenario(r.Context(), h.pool, id)
	if err != nil {
		h.log.Error("get scenario", zap.String("id", id), zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if scenario == nil {
		http.Error(w, "scenario not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, scenario)
}

// createScenarioRequest is the JSON body accepted by CreateScenario.
type createScenarioRequest struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	MitreTechniqueIDs []string `json:"mitre_technique_ids"`
	Tags              []string `json:"tags"`
	Severity          string   `json:"severity"`
	TimeoutSeconds    int      `json:"timeout_seconds"`
	YAMLContent       string   `json:"yaml_content"`
}

// CreateScenario handles POST /api/v1/scenarios (operator+).
// Parses the YAML content, validates the scenario spec, then persists the row.
func (h *ScenariosHandler) CreateScenario(w http.ResponseWriter, r *http.Request) {
	var req createScenarioRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.YAMLContent == "" {
		http.Error(w, "yaml_content is required", http.StatusBadRequest)
		return
	}

	spec, err := scenarios.LoadFromYAML([]byte(req.YAMLContent))
	if err != nil {
		http.Error(w, "invalid scenario YAML: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := scenarios.Validate(spec, nil); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	timeout := req.TimeoutSeconds
	if timeout <= 0 {
		timeout = 300
	}

	row := &db.Scenario{
		Name:              req.Name,
		Description:       req.Description,
		MitreTechniqueIDs: req.MitreTechniqueIDs,
		Tags:              req.Tags,
		Severity:          req.Severity,
		TimeoutSeconds:    timeout,
		YAMLContent:       req.YAMLContent,
	}

	id, err := db.InsertScenario(r.Context(), h.pool, row)
	if err != nil {
		h.log.Error("insert scenario", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// runScenarioRequest is the JSON body accepted by RunScenario.
type runScenarioRequest struct {
	EnvironmentID string `json:"environment_id"`
}

// RunScenario handles POST /api/v1/scenarios/{id}/run (operator+).
// Creates a scenario_runs row with status=pending, dispatches it to the
// scheduler, and returns 202 Accepted with the run ID.
func (h *ScenariosHandler) RunScenario(w http.ResponseWriter, r *http.Request) {
	scenarioID := chi.URLParam(r, "id")

	var req runScenarioRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.EnvironmentID == "" {
		http.Error(w, "environment_id is required", http.StatusBadRequest)
		return
	}

	scenario, err := db.GetScenario(r.Context(), h.pool, scenarioID)
	if err != nil {
		h.log.Error("get scenario for run", zap.String("id", scenarioID), zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if scenario == nil {
		http.Error(w, "scenario not found", http.StatusNotFound)
		return
	}

	env, err := db.GetEnvironment(r.Context(), h.pool, req.EnvironmentID)
	if err != nil {
		h.log.Error("get environment for run", zap.String("id", req.EnvironmentID), zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if env == nil {
		http.Error(w, "environment not found", http.StatusNotFound)
		return
	}
	if env.Status != "ready" {
		http.Error(w, "environment is not in ready state", http.StatusConflict)
		return
	}

	spec, err := scenarios.LoadFromYAML([]byte(scenario.YAMLContent))
	if err != nil {
		h.log.Error("parse scenario yaml", zap.String("id", scenarioID), zap.Error(err))
		http.Error(w, "scenario YAML is invalid: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := scenarios.Validate(spec, env); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	run := &db.ScenarioRun{
		ScenarioID:    scenarioID,
		EnvironmentID: req.EnvironmentID,
		Status:        "pending",
	}
	runID, err := db.InsertRun(r.Context(), h.pool, run)
	if err != nil {
		h.log.Error("insert run", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := h.scheduler.Schedule(r.Context(), runID, spec, env); err != nil {
		h.log.Error("schedule run", zap.String("run_id", runID), zap.Error(err))
		http.Error(w, "could not schedule run: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"run_id": runID})
}
