package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/opensecstack/opensecstack/irflow/internal/auth"
	"github.com/opensecstack/opensecstack/irflow/internal/incident"
)

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Encode failures are ignored: the status and headers are already on the
	// wire, there is no recovery path, and the client will see a truncated
	// response (which it must already tolerate for any connection-level issue).
	_ = json.NewEncoder(w).Encode(v)
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
// Propose action  POST /api/v1/incidents/{incidentID}/actions
// ---------------------------------------------------------------------------
//
// This is step one of IRFlow's two-person-rule (Separation of Duties) flow.
// The Operator is the authenticated caller — derived from their own bearer
// token via auth.ClaimsFromContext, never from a client-supplied request
// field. Nothing here is submitted to CITADEL yet; the proposal is persisted
// as a PendingAction awaiting a SECOND, distinct authenticated user's
// decision via handleApproveAction or handleRejectAction.

func (s *Server) handleProposeAction(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "incidentID")
	if id == "" {
		writeError(w, http.StatusBadRequest, "incident ID is required")
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || claims.Subject == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req incident.ProposeActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.ActionType == "" {
		writeError(w, http.StatusBadRequest, "action_type is required")
		return
	}

	pa, err := s.incidents.ProposeAction(r.Context(), id, claims.Subject, claims.Role, &req)
	if err != nil {
		if errors.Is(err, incident.ErrNotFound) {
			writeError(w, http.StatusNotFound, "incident not found")
			return
		}
		s.logger.Error("failed to propose action",
			zap.String("incidentID", id), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusCreated, pa)
}

// ---------------------------------------------------------------------------
// Approve action  POST /api/v1/incidents/{incidentID}/actions/{actionID}/approve
// ---------------------------------------------------------------------------
//
// Step two: a SECOND, distinct authenticated user (the Verifier) approves the
// pending action with their OWN bearer token. Separation of Duties is
// enforced cryptographically — the Verifier's sinauth UUID (from their own
// claims) is compared against the Operator's stored UUID, not against any
// value either caller can supply. Only on approval is the action evaluated
// by CITADEL MARSHAL (with both real user IDs and the Verifier's real
// bearer token) and persisted as a real IncidentAction.

func (s *Server) handleApproveAction(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "incidentID")
	actionID := chi.URLParam(r, "actionID")
	if id == "" || actionID == "" {
		writeError(w, http.StatusBadRequest, "incident ID and action ID are required")
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || claims.Subject == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	verifierToken := auth.BearerToken(r)

	action, err := s.incidents.ApproveAction(r.Context(), id, actionID, claims.Subject, claims.Role, verifierToken)
	if err != nil {
		switch {
		case errors.Is(err, incident.ErrSelfApproval):
			writeError(w, http.StatusBadRequest, "verifier must be a different authenticated user than the operator (separation of duties)")
		case errors.Is(err, incident.ErrAlreadyDecided):
			writeError(w, http.StatusConflict, "pending action has already been decided")
		case errors.Is(err, incident.ErrPendingActionNotFound):
			writeError(w, http.StatusNotFound, "pending action not found")
		case errors.Is(err, incident.ErrMarshalHardStop):
			s.logger.Warn("marshal HARD_STOP on action approval",
				zap.String("incidentID", id), zap.Error(err))
			writeError(w, http.StatusForbidden, err.Error())
		case errors.Is(err, incident.ErrMarshalRefused):
			s.logger.Info("marshal refused action approval",
				zap.String("incidentID", id), zap.Error(err))
			writeError(w, http.StatusForbidden, err.Error())
		case errors.Is(err, incident.ErrNotFound):
			writeError(w, http.StatusNotFound, "incident not found")
		default:
			s.logger.Error("failed to approve action",
				zap.String("incidentID", id), zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	writeJSON(w, http.StatusCreated, action)
}

// ---------------------------------------------------------------------------
// Reject action  POST /api/v1/incidents/{incidentID}/actions/{actionID}/reject
// ---------------------------------------------------------------------------
//
// Lets the Verifier reject a pending action outright, without ever
// submitting it to CITADEL. Same identity rules as approval: the Verifier
// must be a distinct authenticated user from the Operator who proposed it.

func (s *Server) handleRejectAction(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "incidentID")
	actionID := chi.URLParam(r, "actionID")
	if id == "" || actionID == "" {
		writeError(w, http.StatusBadRequest, "incident ID and action ID are required")
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || claims.Subject == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	pa, err := s.incidents.RejectAction(r.Context(), id, actionID, claims.Subject, claims.Role)
	if err != nil {
		switch {
		case errors.Is(err, incident.ErrSelfApproval):
			writeError(w, http.StatusBadRequest, "verifier must be a different authenticated user than the operator (separation of duties)")
		case errors.Is(err, incident.ErrAlreadyDecided):
			writeError(w, http.StatusConflict, "pending action has already been decided")
		case errors.Is(err, incident.ErrPendingActionNotFound):
			writeError(w, http.StatusNotFound, "pending action not found")
		default:
			s.logger.Error("failed to reject action",
				zap.String("incidentID", id), zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	writeJSON(w, http.StatusOK, pa)
}

// ---------------------------------------------------------------------------
// List pending actions  GET /api/v1/incidents/{incidentID}/actions/pending
// ---------------------------------------------------------------------------

func (s *Server) handleListPendingActions(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "incidentID")
	if id == "" {
		writeError(w, http.StatusBadRequest, "incident ID is required")
		return
	}

	pending, err := s.incidents.ListPendingActions(r.Context(), id)
	if err != nil {
		s.logger.Error("failed to list pending actions",
			zap.String("incidentID", id), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, pending)
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

	// ProposeAction/ApproveAction handle creation; for listing we reuse the timeline which
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
