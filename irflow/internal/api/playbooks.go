package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/opensecstack/opensecstack/irflow/internal/playbook"
)

// playbookListResponse wraps a page of playbooks with pagination metadata.
type playbookListResponse struct {
	Data       []playbook.Playbook `json:"data"`
	Page       int                 `json:"page"`
	PerPage    int                 `json:"per_page"`
	TotalCount int                 `json:"total_count"`
}

// GET /api/v1/playbooks.
func (s *Server) handleListPlaybooks(w http.ResponseWriter, r *http.Request) {
	if s.playbooks == nil {
		writeError(w, http.StatusServiceUnavailable, "playbook service unavailable")
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	statusFilter := r.URL.Query().Get("status")

	results, total, err := s.playbooks.List(r.Context(), page, perPage, statusFilter)
	if err != nil {
		s.logger.Error("failed to list playbooks", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, playbookListResponse{
		Data:       results,
		Page:       page,
		PerPage:    perPage,
		TotalCount: total,
	})
}

// POST /api/v1/playbooks.
func (s *Server) handleCreatePlaybook(w http.ResponseWriter, r *http.Request) {
	if s.playbooks == nil {
		writeError(w, http.StatusServiceUnavailable, "playbook service unavailable")
		return
	}
	var req playbook.CreatePlaybookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	pb, err := s.playbooks.Create(r.Context(), &req)
	if err != nil {
		if errors.Is(err, playbook.ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.logger.Error("failed to create playbook", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusCreated, pb)
}

// GET /api/v1/playbooks/{playbookID}.
func (s *Server) handleGetPlaybook(w http.ResponseWriter, r *http.Request) {
	if s.playbooks == nil {
		writeError(w, http.StatusServiceUnavailable, "playbook service unavailable")
		return
	}
	id := chi.URLParam(r, "playbookID")
	pb, err := s.playbooks.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, playbook.ErrNotFound) {
			writeError(w, http.StatusNotFound, "playbook not found")
			return
		}
		s.logger.Error("failed to get playbook", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, pb)
}

// PATCH /api/v1/playbooks/{playbookID}.
func (s *Server) handlePatchPlaybook(w http.ResponseWriter, r *http.Request) {
	if s.playbooks == nil {
		writeError(w, http.StatusServiceUnavailable, "playbook service unavailable")
		return
	}
	id := chi.URLParam(r, "playbookID")
	var req playbook.PatchPlaybookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	pb, err := s.playbooks.Patch(r.Context(), id, &req)
	if err != nil {
		if errors.Is(err, playbook.ErrNotFound) {
			writeError(w, http.StatusNotFound, "playbook not found")
			return
		}
		s.logger.Error("failed to patch playbook", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, pb)
}

// DELETE /api/v1/playbooks/{playbookID}.
func (s *Server) handleDeletePlaybook(w http.ResponseWriter, r *http.Request) {
	if s.playbooks == nil {
		writeError(w, http.StatusServiceUnavailable, "playbook service unavailable")
		return
	}
	id := chi.URLParam(r, "playbookID")
	if err := s.playbooks.Delete(r.Context(), id); err != nil {
		if errors.Is(err, playbook.ErrNotFound) {
			writeError(w, http.StatusNotFound, "playbook not found")
			return
		}
		s.logger.Error("failed to delete playbook", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/v1/playbooks/{playbookID}/execute
// Launches an asynchronous execution and returns the Execution record in
// "pending" state. Clients poll GET /api/v1/executions/{id} for status.
func (s *Server) handleExecutePlaybook(w http.ResponseWriter, r *http.Request) {
	if s.playbooks == nil {
		writeError(w, http.StatusServiceUnavailable, "playbook service unavailable")
		return
	}
	id := chi.URLParam(r, "playbookID")
	var req playbook.ExecutePlaybookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.IncidentID == "" {
		writeError(w, http.StatusBadRequest, "incident_id is required")
		return
	}

	exec, err := s.playbooks.Execute(r.Context(), id, req.IncidentID)
	if err != nil {
		if errors.Is(err, playbook.ErrNotFound) {
			writeError(w, http.StatusNotFound, "playbook not found")
			return
		}
		if errors.Is(err, playbook.ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.logger.Error("failed to execute playbook", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusAccepted, exec)
}

// GET /api/v1/playbooks/{playbookID}/executions.
func (s *Server) handleListExecutions(w http.ResponseWriter, r *http.Request) {
	if s.playbooks == nil {
		writeError(w, http.StatusServiceUnavailable, "playbook service unavailable")
		return
	}
	id := chi.URLParam(r, "playbookID")
	execs, err := s.playbooks.ListExecutions(r.Context(), id)
	if err != nil {
		s.logger.Error("failed to list executions", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, execs)
}

// GET /api/v1/executions/{executionID}.
func (s *Server) handleGetExecution(w http.ResponseWriter, r *http.Request) {
	if s.playbooks == nil {
		writeError(w, http.StatusServiceUnavailable, "playbook service unavailable")
		return
	}
	id := chi.URLParam(r, "executionID")
	exec, err := s.playbooks.GetExecution(r.Context(), id)
	if err != nil {
		if errors.Is(err, playbook.ErrNotFound) {
			writeError(w, http.StatusNotFound, "execution not found")
			return
		}
		s.logger.Error("failed to get execution", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, exec)
}
