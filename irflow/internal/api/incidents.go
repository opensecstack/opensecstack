package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/opensecstack/opensecstack/irflow/internal/incident"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ---------------------------------------------------------------------------
// List incidents  GET /api/v1/incidents
// ---------------------------------------------------------------------------

// listResponse wraps a page of incidents with pagination metadata.
type listResponse struct {
	Data       []incident.Incident `json:"data"`
	Page       int                 `json:"page"`
	PerPage    int                 `json:"per_page"`
	TotalCount int                 `json:"total_count"`
}

func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	statusFilter := r.URL.Query().Get("status")
	severityFilter := r.URL.Query().Get("severity")
	sourceFilter := r.URL.Query().Get("source")

	results, totalCount, err := s.incidents.List(r.Context(), page, perPage, statusFilter, severityFilter, sourceFilter)
	if err != nil {
		s.logger.Error("failed to list incidents", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, listResponse{
		Data:       results,
		Page:       page,
		PerPage:    perPage,
		TotalCount: totalCount,
	})
}

// ---------------------------------------------------------------------------
// Create incident  POST /api/v1/incidents
// ---------------------------------------------------------------------------

func (s *Server) handleCreateIncident(w http.ResponseWriter, r *http.Request) {
	var req incident.CreateIncidentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Validation: title and severity are required.
	if req.Title == "" {
		writeError(w, http.StatusBadRequest, "title is required")
		return
	}
	if req.Severity == "" {
		writeError(w, http.StatusBadRequest, "severity is required")
		return
	}

	inc, err := s.incidents.Create(r.Context(), &req)
	if err != nil {
		s.logger.Error("failed to create incident", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusCreated, inc)
}

// ---------------------------------------------------------------------------
// Get incident  GET /api/v1/incidents/{incidentID}
// ---------------------------------------------------------------------------

func (s *Server) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "incidentID")
	if id == "" {
		writeError(w, http.StatusBadRequest, "incident ID is required")
		return
	}

	inc, err := s.incidents.Get(r.Context(), id)
	if err != nil {
		s.logger.Error("failed to get incident", zap.String("id", id), zap.Error(err))
		writeError(w, http.StatusNotFound, "incident not found")
		return
	}

	writeJSON(w, http.StatusOK, inc)
}

// ---------------------------------------------------------------------------
// Patch incident  PATCH /api/v1/incidents/{incidentID}
// ---------------------------------------------------------------------------

func (s *Server) handlePatchIncident(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "incidentID")
	if id == "" {
		writeError(w, http.StatusBadRequest, "incident ID is required")
		return
	}

	var req incident.PatchIncidentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	inc, err := s.incidents.Patch(r.Context(), id, &req)
	if err != nil {
		s.logger.Error("failed to patch incident", zap.String("id", id), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, inc)
}

// ---------------------------------------------------------------------------
// Delete incident  DELETE /api/v1/incidents/{incidentID}
// ---------------------------------------------------------------------------

func (s *Server) handleDeleteIncident(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "incidentID")
	if id == "" {
		writeError(w, http.StatusBadRequest, "incident ID is required")
		return
	}

	if err := s.incidents.Delete(r.Context(), id); err != nil {
		s.logger.Error("failed to delete incident", zap.String("id", id), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Submit action  POST /api/v1/incidents/{incidentID}/actions
// ---------------------------------------------------------------------------

func (s *Server) handleSubmitAction(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "incidentID")
	if id == "" {
		writeError(w, http.StatusBadRequest, "incident ID is required")
		return
	}

	var req incident.SubmitActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Separation of Duties: operator must not be the verifier.
	if req.OperatorID != "" && req.VerifierID != "" && req.OperatorID == req.VerifierID {
		writeError(w, http.StatusBadRequest, "operator and verifier must be different (separation of duties)")
		return
	}

	action, err := s.incidents.SubmitAction(r.Context(), id, &req)
	if err != nil {
		s.logger.Error("failed to submit action", zap.String("incidentID", id), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusCreated, action)
}

// ---------------------------------------------------------------------------
// List actions  GET /api/v1/incidents/{incidentID}/actions
// ---------------------------------------------------------------------------

func (s *Server) handleListActions(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "incidentID")
	if id == "" {
		writeError(w, http.StatusBadRequest, "incident ID is required")
		return
	}

	// SubmitAction handles creation; for listing we reuse the timeline which
	// includes actions.  A dedicated ListActions method can be added to the
	// service later.  For now, return the timeline filtered to action entries.
	timeline, err := s.incidents.GetTimeline(r.Context(), id)
	if err != nil {
		s.logger.Error("failed to list actions", zap.String("incidentID", id), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Filter to action-type entries only.
	actions := make([]incident.TimelineEntry, 0, len(timeline))
	for _, entry := range timeline {
		if entry.EntryType == "action" {
			actions = append(actions, entry)
		}
	}

	writeJSON(w, http.StatusOK, actions)
}

// ---------------------------------------------------------------------------
// Get timeline  GET /api/v1/incidents/{incidentID}/timeline
// ---------------------------------------------------------------------------

func (s *Server) handleGetTimeline(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "incidentID")
	if id == "" {
		writeError(w, http.StatusBadRequest, "incident ID is required")
		return
	}

	timeline, err := s.incidents.GetTimeline(r.Context(), id)
	if err != nil {
		s.logger.Error("failed to get timeline", zap.String("incidentID", id), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, timeline)
}

// ---------------------------------------------------------------------------
// Add IOC  POST /api/v1/incidents/{incidentID}/iocs
// ---------------------------------------------------------------------------

func (s *Server) handleAddIOC(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "incidentID")
	if id == "" {
		writeError(w, http.StatusBadRequest, "incident ID is required")
		return
	}

	var ioc incident.IOCEnrichment
	if err := json.NewDecoder(r.Body).Decode(&ioc); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	created, err := s.incidents.AddIOC(r.Context(), id, &ioc)
	if err != nil {
		s.logger.Error("failed to add IOC", zap.String("incidentID", id), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusCreated, created)
}

// ---------------------------------------------------------------------------
// List IOCs  GET /api/v1/incidents/{incidentID}/iocs
// ---------------------------------------------------------------------------

func (s *Server) handleListIOCs(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "incidentID")
	if id == "" {
		writeError(w, http.StatusBadRequest, "incident ID is required")
		return
	}

	iocs, err := s.incidents.ListIOCs(r.Context(), id)
	if err != nil {
		s.logger.Error("failed to list IOCs", zap.String("incidentID", id), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, iocs)
}
